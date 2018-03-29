[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline)]
    [string]
    $password_notsecure,

    [Parameter(ValueFromPipeline)]
    [SecureString]
    $password_secure
)

begin
{
   
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $sha1 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")
    $secProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $NbPass = 0
    $IsReadHost = $False


}
process
{

    $NbPass++

    if (!$password_secure -and !$password_notsecure) {
        $IsReadHost = $True
        $password_secure = Read-host "Password ?" -AsSecureString
    }

    if (!$password_notsecure) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_secure)
        $password_notsecure = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        $bstr = $null
    }

    $StringBuilder = New-Object System.Text.StringBuilder

    $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password_notsecure)) | foreach{
        [Void]$StringBuilder.Append($_.ToString("x2")) 
    } 

    $password_notsecure = ""
    $Hash = $StringBuilder.ToString() 

    $Uri = "https://api.pwnedpasswords.com/range/"+$Hash.Substring(0,5)

    [System.Net.ServicePointManager]::SecurityProtocol = 'Ssl3,Tls,Tls11,Tls12'
    
    $suffix = $Hash.Substring(5).ToUpper()

    if ((iwr $Uri).Content -match "${suffix}:(\d+)")
    {
        $hits = $matches[1]
        $result = "Oh no -- pwned $hits time(s)!"
    }
    else
    {
        $result = "Seems OK!"
    }

    if ($IsReadHost)
    {
        $wshell = New-Object -ComObject Wscript.Shell
        [void]$wshell.Popup($result,0,"Password checked",0x1)
    }
    else
    {
        @{
            ID    = $NbPass
            Pwned = $True
            Times = $hits
        }
    }
}
end
{
    [System.Net.ServicePointManager]::SecurityProtocol = $secProtocol
}
