**Arlo Local RTSP Stream POC**

No TLDR here. This effort was a proof of concept and the more important thing is the readme here and not my trash AI fried code. Knowing the journey helps explain a lot of things that get missed when people just blindly copy/paste code. 

Background: In the Arlo VMB5000 base station (and potentially others) allows iOS and Android apps to locally connect to streams from the camera. The connection avoids cloud traffic entirely and allows for HEVC 4k streams (if the camera supports this). This greatly simplifies the traffic flow for on premise recording solutions that previously would proxy through the cloud to get a camera stream that’s right in the other room. Most of this work was done by looking through decompiled android source code and a mix of <https://github.com/twrecked/pyaarlo>, and <https://github.com/jesserockz/python-arlo-ratls-poc>

### Prerequisites/Callouts

- The fist part was written in PowerShell. Phase 2 was written using .NET 8… So you’ll need the runtime. It’s no python but it’s what I’m most comfortable with and the complexity behind this was enough to where i wanted to write in something closest to home.
- Get a token - at the time of writing this, tokens expire after 2 hours, and the process of getting them is difficult due to MFA. Getting a token is not covered by this. Its only needed for the first phase. Easiest path might be by using PyAarlo like this

```python
import pyaarlo
import time
arlo = pyaarlo.PyArlo(lookupimplementationdetails)
arlo.be._token
```

- A beer because this was a doozy to figure out, and I bet you will need some help too.

### High level Overview: 

I think this can be best split into two phases. The first phase involves generating the certs required for Mutual TLS (mTLS) against the base station. There is a a certificate enrollment endpoint in the Cloud API. Once the cert has been issued, you are practically done with the cloud. Phase 2 involves the custom proxy that was required for special RTSP header injection so that the camera accepts the RTSP from the client connecting (ffmpeg/vlc/etc).

## Phase 1:

This should be easily portable to other languages, hardest part was figuring out the parameters. First thing was to generate a RSA public/private key pair. Then you POST the public key up to their endpoint with two extra parameters that are unique to your setup. The script picks the first base station it finds and uses that information for this request. 
For UUID -- PyAARLO uses deviceId of the basestation, ratls-poc shows any value, and this can be backed up by the android source code which uses a unqiue ID to the phone. The important thing is that **if you generate a cert with the same id, the other issued certs get revoked within minutes**.
For uniqueIds array, use the unique id of the base station, which is comprised of userId_deviceId
the public key needs to be the base64 encoded publickey, without the headers and footers
```json
{
  "uuid": "SeeNote",
  "uniqueIds": [
    "userId_baseDeviceId -- AKA uniqueid of basestattion"
  ],
  "publicKey": "The public key without header and fooder"
}
```

Once you have the cert from the api, the script just dumps the files to a folder specifed in $OutputPath. Oh and **MAKE SURE YOU ARE USING THE MAIN ACCOUNT THROUGH THIS PROCESS**, other shared accounts don’t have the permission to request the cert… It was seriously each one of these little gotchas that ate up hours…

## Phase 2:

The Android source had pretty easy to read logic, to change the RTSP stream url if a local connection was deemed possible and the cameras supported it. What I was able to discover was that the base station listened on TCP port 554 and the URI in the RTSP header was rtsp://{ip}:554/{cameraId}/{tcp/udp}/{avc/hevc}. CameraId is the same camera id from the api, TCP/UDP was what the handshake would end up sending the stream over. AVC is 1080 via H264 HEVC is 4K via H265.
```java
    public String getLocalStreamingUrl(CameraInfo cameraInfo) {
        String baseHostnameLocalStreamingUrl = getBaseHostnameLocalStreamingUrl(cameraInfo);
        if (baseHostnameLocalStreamingUrl == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(baseHostnameLocalStreamingUrl);
        if (!cameraInfo.isCameraBuiltInBasestation()) {
            sb.append("/" + cameraInfo.getDeviceId());
            if (cameraInfo.isTCPLocalStreamingEnabled()) {
                sb.append("/tcp");
            } else {
                sb.append("/udp");
            }
            if (cameraInfo.getPropertiesData().getBestLocalLiveStreaming() == CameraInfo.BEST_LOCAL_STREAMING.on && is4kStreamAllowed(cameraInfo)) {
                sb.append("/hevc");
            } else {
                sb.append("/avc");
            }
        }
        return sb.toString();
    }

```


Just connecting anything to this url just plain old wouldn’t work. First off, you had to make sure the client would do mTLS, but then doing any sort of inspection on the traffic was impossible. What made things worse was that I still am not able to tell what type of support is in ffmpeg for client certs some sources made it seem like it was cross compatible on windows, but then some people said it uses SChannel rather than OpenSSL and just fails to send the client certs, and packet captures didn’t show a client cert getting sent at all. But all that became a moot point because of this _“nonce”_ header.

I first saw this header as an option configuration of the source code. If i was a local stream, an option was added called use-nonce. No where could i find information on what the heck this did, not in the source of the app, or IJK player which is what the app used to stream, or FFMPEG with IJK uses. Total black box. As a test to get some information I decided to do mTLS termination using stunnel, and then was able to attach Wireshark. Finally I was then able to see the rtsp handshake with certs getting in the way. I just kept getting Bad Request after the RTSP OPTIONS command.

The only thing I had to go off of, was this nonce header. In between all this troubleshooting i was able to see some useful logs from the ADB output of a test device connecting to the local stream. I saw a “Nonce: 0” in the initial options request and in further requests some random numbers. The random numbers were from a seed and constantly increasing. So I started work on this silly little proxy, that seemed to be a requirement at this point. The proxy does the mTLS termination and some header manipulations to make it look most like the android app, but the more important thing the proxy does is the nonce. It injects "__Nonce: 0__", and on the options response contains a Nonce with a random number, you increment that on the response and … viola… the handshake works perfectly. First time I saw the video stream... it was super slow. I got this to be better by shrinking the buffer size (i think it was putting too much into the buffer before flushing out and caused streams to fail), and implementing some logic surrounding if we are in handshake mode or media mode. There is no parsing or manipulation of data after the play command, and when the stream dies or disconnects we go back into handshake mode. With the proxy sitting in the middle, all clients i have connected to the rebroadcasted stream have been working all fine.

At this point, it looks like it’s working fine. It was stretch to get here, I currently have the RTSP scrypted plugin pointing at instances of my .net exe and it’s been working great. For compatibility in scrypted i have to use the AVC (1080) stream, but i think with some ffmpeg and rtsp-simple-server shenanigans i can transcode the 4k stream to H.264.

I was originally thinking about merging this into the scrypted plugin for Arlo, but i cant possibly do it, getting to this point was tough enough.

I don’t expect this to get any attention, but if it just helps one guy out, I’d feel like putting this out here was worth it.