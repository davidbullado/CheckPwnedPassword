$response = Read-host "Password ?" -AsSecureString
 
$StringBuilder = New-Object System.Text.StringBuilder
[System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($response)))) | foreach{
    [Void]$StringBuilder.Append($_.ToString("x2"))
}
$Hash = $StringBuilder.ToString()
 
$Hash_Prefix = $Hash.Substring(0,5)
$Uri = "https://api.pwnedpasswords.com/range/$Hash_Prefix"
 
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy1 : ICertificatePolicy {
   public bool CheckValidationResult(
       ServicePoint srvPoint, X509Certificate certificate,
       WebRequest request, int certificateProblem) {
       return true;
   }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy1
 
$ProfileResponse = Invoke-WebRequest -Uri $Uri
 
$suffix = $Hash.Substring(5,$Hash.Length-5).ToUpper()
 
if ($ProfileResponse.Content -match $suffix)
{
   
    $pline = $ProfileResponse.Content -split "`n" | Select-String -Pattern $suffix
    $nbPwned = ($pline -split ":")[1] -replace "`r" , ''
    $result = "Oh no -- pwned $nbPwned time(s)!"
}
else
{
    $result = "Seems OK!"
}
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup($result,0,"Password checked",0x1)
