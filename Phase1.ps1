function New-ArloCompatibleRSAKeyPair {
    Write-Host "Generating RSA key pair..."
    
    # Generate RSA key pair with exact same parameters as pyaarlo
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    

    $publicKeyBytes = $rsa.ExportSubjectPublicKeyInfo()  
    $publicKeyBase64 = [Convert]::ToBase64String($publicKeyBytes)
    
    $publicKeyPem = "-----BEGIN PUBLIC KEY-----`n"
    for ($i = 0; $i -lt $publicKeyBase64.Length; $i += 64) {
        $line = $publicKeyBase64.Substring($i, [Math]::Min(64, $publicKeyBase64.Length - $i))
        $publicKeyPem += "$line`n"
    }
    $publicKeyPem += "-----END PUBLIC KEY-----"
    
    # I wanted the variable to be the most "correct", and them pull the header and footeer for the api
    $cleanPublicKey = $publicKeyPem -replace "`n", "" -replace "`r", "" -replace "-----BEGIN PUBLIC KEY-----", "" -replace "-----END PUBLIC KEY-----", ""
    
    # Export private key for completeness
    $privateKeyBytes = $rsa.ExportRSAPrivateKey()
    $privateKeyBase64 = [Convert]::ToBase64String($privateKeyBytes)
    $privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----`n"
    for ($i = 0; $i -lt $privateKeyBase64.Length; $i += 64) {
        $line = $privateKeyBase64.Substring($i, [Math]::Min(64, $privateKeyBase64.Length - $i))
        $privateKeyPem += "$line`n"
    }
    $privateKeyPem += "-----END RSA PRIVATE KEY-----"
    
    $rsa.Dispose()
    
    return @{
        PublicKeyPem = $publicKeyPem
        PrivateKeyPem = $privateKeyPem
        CleanPublicKey = $cleanPublicKey
    }
}


$token = "YourTokenHere"
$baseHeaders = @{
    "Auth-Version" = "2"
    "Authorization" = $token
    "Content-Type" = "application/json; charset=UTF-8"
    "User-Agent" = "(iPhone15,2 18_1_1) iOS Arlo 5.4.3" 
}
$alldevices = Invoke-RestMethod -Uri "https://myapi.arlo.com/hmsweb/users/devices" -Headers $baseHeaders 
$baseStation = ($alldevices.data | Where-Object {$_.deviceType -eq "basestation"})[0]

$OutputPath = "C:\temp\arlo_certs"
if(!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory $OutputPath
}

$gen = New-ArloCompatibleRSAKeyPair

#pyaarlo shows this being the basestation id, but it looks like it can be anything,
#it should be unique to this though, as any further requests on the same "uuid" cause the cert to get
#revoked. The android source shows it using the device id from the android os, which apparently is per app too....
$BaseStationID = "ArloRP"
$baseStationUuid = $baseStation.uniqueId

# Create certificate request
$certificateRequest = @{
    uuid = $BaseStationID 
    publicKey = $gen.CleanPublicKey
    uniqueIds =  @($baseStationUuid) 
} | ConvertTo-Json -Depth 3
    
Write-Host "   Request Body: $($certificateRequest -replace '\s+', ' ')" -ForegroundColor Gray
    
$result = Invoke-RestMethod "https://myapi.arlo.com/hmsweb/users/devices/v2/security/cert/create" -Method "POST" -Headers $baseHeaders -Body $certificateRequest 

$result | ConvertTo-Json -Depth 10 | Out-File -FilePath "$OutputPath\certificate_response_SUCCESS.json" -Encoding utf8
    
$icacertraw = $result.data.icaCert 
$icacert = "-----BEGIN CERTIFICATE-----`n" + $icacertraw + "`n-----END CERTIFICATE-----"
$icacert | Out-File -FilePath "$OutputPath\ica.crt" -Encoding utf8


$devicecertraw = $result.data.certsData.deviceCert
$devicecert = "-----BEGIN CERTIFICATE-----`n" + $devicecertraw + "`n-----END CERTIFICATE-----"
$devicecert | Out-File -FilePath "$OutputPath\device.crt" -Encoding utf8

$peercertraw = $result.data.certsData.peercert
$peercert = "-----BEGIN CERTIFICATE-----`n" + $peercertraw + "`n-----END CERTIFICATE-----"
$peercert | Out-File -FilePath "$OutputPath\peer.crt" -Encoding utf8

$gen.PublicKeyPem | Out-File -FilePath "$OutputPath\public_key.key" -Encoding utf8
$gen.PrivateKeyPem | Out-File -FilePath "$OutputPath\private_key.key" -Encoding utf8












