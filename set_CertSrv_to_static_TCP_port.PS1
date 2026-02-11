<#
  Sets the CertSrv daemon (DCOM Service) to listen on a single static port.
  In this case, port TCP2701. This makes an MSPKI CA more firewall-friendly.
  Nice thing about doing it this way, you can avoid needing to drive a GUI,
  and you can make this part of a consistent, automated CA build process. 

  If you wonder why port 2701, read "Cryptonomicon" by Neal Stephenson. 
  Or just know it's the product of two primes that are mirror-images of
  each other (37 x 73). 
#>

$path = "HKLM:\SOFTWARE\Classes\AppID\{D99E6E74-FC88-11D0-B498-00A0C90312F3}" ;
$name = "Endpoints" ;
$newEntry = "ncacn_ip_tcp,0,2701" ;
 
try{
    $currentValue = Get-ItemProperty -Path $path -Name $name | Select-Object -ExpandProperty $name ;
    if ($currentValue -notcontains $newEntry) {
        $updatedValue = $currentValue + $newEntry ;
        Set-ItemProperty -Path $path -Name $name -Value $updatedValue ;
    }
} catch {
    New-ItemProperty -Path $Path -Name $Name -PropertyType MultiString -Value @($newEntry) ;
}
