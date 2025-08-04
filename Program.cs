using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace ArloRTSPProxy
{
    public class ArloRTSPProxy
    {
        private readonly string _listenAddress = "0.0.0.0";
        private int _listenPort = 8556;
        private readonly string _arloHost = "Your Basestation IP";
        private readonly int _arloPort = 554;
        private readonly string _clientCertPath;
        private readonly string _clientKeyPath;

        private TcpListener _listener;
        private X509Certificate2 _clientCertificate;

        public ArloRTSPProxy(string clientCertPath, string clientKeyPath, string listenPort)
        {
            _clientCertPath = clientCertPath;
            _clientKeyPath = clientKeyPath;
            if (int.TryParse(listenPort, out int _l))
            {
                if (_listenPort <= 0 || _listenPort > 65535)
                {
                    throw new ArgumentException("Invalid listen port specified. Must be between 1 and 65535.");
                }
                _listenPort = _l;
            }
            else
            {
                throw new ArgumentException("Invalid listen port specified. Must be a valid integer.");
            }
            LoadClientCertificate();
        }

        private void LoadClientCertificate()
        {
            try
            {
                // Load client certificate for mTLS, simple x509 cert2
                var _certOnly = new X509Certificate2(_clientCertPath);

                // Read private key PEM
                var privKeyPem = File.ReadAllText(_clientKeyPath);

                //this should still be platform agnostic, passed my WSL tests, implementation should be the same on both
                // needed to do it this funny way because how schannel deals with private keys, and wants them to be "exportable"
                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportFromPem(privKeyPem.ToCharArray());
                    using (var certWithKey = _certOnly.CopyWithPrivateKey(rsa))
                    {
                        _clientCertificate = new X509Certificate2(certWithKey.Export(X509ContentType.Pkcs12));
                    }
                }

                Console.WriteLine($"Loaded client certificate: {_clientCertificate.Subject}");
                if (!_clientCertificate.HasPrivateKey)
                {
                    throw new Exception("Client certificate does not have a private key.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load client certificate: {ex.Message}");
                throw;
            }
        }

        public async Task StartAsync()
        {
            _listener = new TcpListener(IPAddress.Parse(_listenAddress), _listenPort);
            _listener.Start();

            Console.WriteLine($"Arlo RTSP Proxy listening on {_listenAddress}:{_listenPort}");
            Console.WriteLine($"Forwarding to Arlo: {_arloHost}:{_arloPort}");
            Console.WriteLine($"Try usage with: ffplay -rtsp_transport tcp -i 'rtsp://127.0.0.1:{_listenPort}/1234567890AB/tcp/hevc'");
            Console.WriteLine();

            while (true)
            {
                try
                {
                    var tcpClient = await _listener.AcceptTcpClientAsync();
                    Console.WriteLine($"Client connected: {tcpClient.Client.RemoteEndPoint}");

                    // Handle each client in parallel
                    _ = Task.Run(async () => await HandleClientAsync(tcpClient));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Accept error: {ex.Message}");
                }
            }
        }

        private async Task HandleClientAsync(TcpClient clientTcp)
        {
            TcpClient arloTcp = null;
            SslStream arloSslStream = null;
            NetworkStream clientStream = null;

            try
            {
                clientStream = clientTcp.GetStream();

                // Connect to Arlo with mTLS
                arloTcp = new TcpClient();
                await arloTcp.ConnectAsync(_arloHost, _arloPort);

                // Setup SSL stream with client certificate
                arloSslStream = new SslStream(arloTcp.GetStream(), false, ValidateServerCertificate);

                var clientCertificates = new X509CertificateCollection { _clientCertificate };
                await arloSslStream.AuthenticateAsClientAsync(_arloHost, clientCertificates, SslProtocols.Tls12, false);

                Console.WriteLine("mTLS connection established to Arlo");

                // Create RTSP session handler
                var sessionHandler = new RTSPSessionHandler(clientStream, arloSslStream, _arloHost, _arloPort);
                await sessionHandler.HandleSessionAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Client handler error: {ex.Message}");
            }
            finally
            {
                arloSslStream?.Close();
                arloTcp?.Close();
                clientStream?.Close();
                clientTcp?.Close();
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept any server certificate for testing
            return true;
        }
    }

    public class RTSPSessionHandler
    {
        private readonly NetworkStream _clientStream;
        private readonly SslStream _arloStream;
        private readonly string _arloHost;
        private readonly int _arloPort;

        private double _currentNonce = 0;
        private bool _isMediaMode = false;

        public RTSPSessionHandler(NetworkStream clientStream, SslStream arloStream, string arloHost, int arloPort)
        {
            _clientStream = clientStream;
            _arloStream = arloStream;
            _arloHost = arloHost;
            _arloPort = arloPort;
        }

        public async Task HandleSessionAsync()
        {
            try
            {
                // Start bidirectional forwarding
                var clientToArloTask = ForwardClientToArloAsync();
                var arloToClientTask = ForwardArloToClientAsync();

                // Wait for either direction to complete
                await Task.WhenAny(clientToArloTask, arloToClientTask);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Session error: {ex.Message}");
            }
        }

        private async Task ForwardClientToArloAsync()
        {
            var buffer = new byte[1500];

            try
            {
                while (true)
                {
                    var bytesRead = await _clientStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    var data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);

                    // Process RTSP requests
                    // use media mode to only have tougher MITM style stuff during the handshake phase
                    if (!_isMediaMode && IsRTSPRequest(data))
                    {
                        var modifiedData = ModifyRTSPRequest(data);
                        await _arloStream.WriteAsync(modifiedData, 0, modifiedData.Length);

                        // Check if this was PLAY command
                        var request = Encoding.UTF8.GetString(data);
                        if (request.StartsWith("PLAY"))
                        {
                            Console.WriteLine("PLAY sent - switching to media mode");
                            _isMediaMode = true;
                        }
                    }
                    else
                    {
                        // Pass through media data
                        await _arloStream.WriteAsync(data, 0, data.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!_isMediaMode)
                    Console.WriteLine($"Client->Arlo error: {ex.Message}");
            }
        }

        private async Task ForwardArloToClientAsync()
        {
            var buffer = new byte[1500];

            try
            {
                while (true)
                {
                    var bytesRead = await _arloStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("Connection closed, going back to handshake mode.");
                        _isMediaMode = false;
                        break;
                    }
                    

                    var data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);

                    // Parse RTSP responses for nonce updates
                    if (!_isMediaMode)
                    {
                        ParseResponseNonce(data);
                    }

                    // Forward to client
                    await _clientStream.WriteAsync(data, 0, data.Length);
                }
            }
            catch (Exception ex)
            {

                _isMediaMode = false; // Reset media mode on error
                Console.WriteLine("Connection closed, going back to handshake mode.");
                Console.WriteLine($"Arlo->Client error: {ex.Message}");
            }
        }

        private bool IsRTSPRequest(byte[] data)
        {
            var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 100));
            return text.StartsWith("OPTIONS") || text.StartsWith("DESCRIBE") ||
                   text.StartsWith("SETUP") || text.StartsWith("PLAY") ||
                   text.StartsWith("TEARDOWN");
        }



        private byte[] ModifyRTSPRequest(byte[] data)
        {
            var request = Encoding.UTF8.GetString(data);
            var lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);

            // Transform URL in request line
            if (lines.Length > 0)
            {
                var requestLine = lines[0];
                var parts = requestLine.Split(' ');
                if (parts.Length >= 3)
                {
                    var method = parts[0];
                    var url = parts[1];
                    var version = parts[2];

                    // Replace localhost with Arlo IP
                    // even though arlo is talking over a mutual tls session.. it still wants the protocol handler in the headers to show rtsp.. dont ask...

                    //in fact i found i didnt even need to rewrite -- but it still feels wrong to send loopback/bound ip to the arlo
                    var newUrl = Regex.Replace(url, @"rtsp://[^:/]+:\d+(/.*)",
                        $"rtsp://{_arloHost}:{_arloPort}$1");
                    //set first line to modified URL -- need to preserve og intended url
                    lines[0] = $"{method} {newUrl} {version}";

                    Console.WriteLine($"{method}: {url} -> {newUrl}");
                }
            }

            // Modify headers
            var modifiedLines = new List<string>();
            bool foundUserAgent = false;
            bool foundNonce = false;
            bool foundEmptyLine = false;

            foreach (var line in lines)
            {
                if (line.ToLower().StartsWith("user-agent:"))
                {
                    //found this user agent in arlo source -- dont think this matters
                    modifiedLines.Add("User-Agent: ijkplayer-android-6.2.2");
                    foundUserAgent = true;
                }
                else if (line.ToLower().StartsWith("nonce:"))
                {
                    //HECK YES this matters -- without this the arlo says bad request
                    modifiedLines.Add($"Nonce: {_currentNonce}");
                    foundNonce = true;
                }
                else if (line == "" && !foundEmptyLine)
                {
                    foundEmptyLine = true;

                    // Add missing headers before empty line
                    if (!foundUserAgent)
                        //found this user agent in arlo source -- dont think this matters
                        modifiedLines.Add("User-Agent: ijkplayer-android-6.2.2");
                    if (!foundNonce)
                    {
                        //HECK YES this matters -- without this the arlo says bad request
                        modifiedLines.Add($"Nonce: {_currentNonce}");
                        Console.WriteLine($"Added nonce: {_currentNonce}");
                    }

                    _currentNonce++;
                    modifiedLines.Add("");
                }
                else
                {
                    modifiedLines.Add(line);
                }
            }

            // If no empty line found, makle sure we have all the stuff we need, rather than modifying we are just straight adding to be sure we got it
            if (!foundEmptyLine)
            {
                if (!foundUserAgent)
                    //found this user agent in arlo source -- dont think this matters
                    modifiedLines.Add("User-Agent: ijkplayer-android-6.2.2");
                if (!foundNonce)
                {
                    //HECK YES this matters -- without this the arlo says bad request
                    modifiedLines.Add($"Nonce: {_currentNonce}");
                    Console.WriteLine($"Added nonce: {_currentNonce}");
                }
                //idk if these were all needed, but it seems to work so i keep it
                // honestly i think when it matters the previous request includes it and we increment it in the gather of that nonce, so this might be for nothing :|
                _currentNonce++;
                modifiedLines.Add("");
            }

            var modifiedRequest = string.Join("\r\n", modifiedLines);
            return Encoding.UTF8.GetBytes(modifiedRequest);
        }

        private void ParseResponseNonce(byte[] data)
        {
            try
            {
                var response = Encoding.UTF8.GetString(data);
                var lines = response.Split(new[] { "\r\n" }, StringSplitOptions.None);

                // Log response status
                if (lines.Length > 0)
                    Console.WriteLine($"{lines[0]}");

                //find the nonce line, if it exists replay it with a plus 1
                var foundLine = lines.FirstOrDefault(r => r.ToLower().StartsWith("nonce:"));
                if( foundLine != null)
                {
                    var offeredNonce = foundLine.ToLower().Replace("nonce:", "").Trim();
                    if (double.TryParse(offeredNonce, out double parsedNonce))
                    {
                        _currentNonce = parsedNonce + 1;
                        Console.WriteLine($"\tServer nonce: {parsedNonce}, next: {_currentNonce}");
                    }
                    
                }

            
                // Check for successful PLAY
                if (response.Contains("PLAY") && response.Contains("200 OK"))
                {
                    Console.WriteLine("PLAY successful - media should start flowing");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Nonce parse error: {ex.Message}");
            }
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: ArloRTSPProxy <client-cert.crt> <client-key.key> <listenerport | defaults to 8556>");
                Console.WriteLine("Example: ArloRTSPProxy client.crt client.key 8556");
                return;
            }

            var certPath = args[0];
            var keyPath = args[1];
            var listenPort = args.Length > 2 ? args[2] : "8556";

            if (!File.Exists(certPath))
            {
                Console.WriteLine($"Certificate file not found: {certPath}");
                return;
            }

            Console.WriteLine("Starting Arlo RTSP Proxy...");

            try
            {
                var proxy = new ArloRTSPProxy(certPath, keyPath, listenPort);
                await proxy.StartAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Proxy failed: {ex.Message}");
            }
        }
    }
}