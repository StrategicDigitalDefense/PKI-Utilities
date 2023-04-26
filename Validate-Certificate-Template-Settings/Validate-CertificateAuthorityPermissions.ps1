[cmdletBinding(DefaultParameterSetName="PermissionsOnly")]Param(
    [Parameter(Mandatory=$true,ParameterSetName="PermissionsOnly")]
        [string]
        $ADForest,
    [Parameter(Mandatory=$true,ParameterSetName="PermissionsOnly")]
        [string]
        $CASubjectCN
) ;
 
 
<#
    Much of this is borrowed from my "validate-CertTemplatePermissions" script
    Now I am adapting it to get information about permissions on a CA object from AD
#>
 
#######################################################################
## Setup needed by everything
if(!(Get-Module -Name ActiveDirectory)) {
    Import-Module -Name ActiveDirectory ;
}
[string]([datetime]::UtcNow.ToString() + ":`t" + "ADForest" + " : " + $ADForest) |Write-Verbose ;
$forest=(Get-ADDomain -Identity $ADForest -server $ADForest).Forest.toUpper() ;
[string]([datetime]::UtcNow.ToString() + ":`t" + "forest" + " : " + $forest) |Write-Verbose ;
$ForestShortName=(Get-ADDomain -Identity $forest -Server $forest).NetBIOSName ;
[string]([datetime]::UtcNow.ToString() + ":`t" + "ForestShortName" + " : " + $ForestShortName) |Write-Verbose ;
$forestDN=(Get-ADDomain -Identity $forest -Server $forest).DistinguishedName ;
[string]([datetime]::UtcNow.ToString() + ":`t" + "forestDN" + " : " + $forestDN) |Write-Verbose ;
if($ForestShortName -notin (Get-PSDrive).Name) {
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Adding PSDrive named " + $ForestShortName) |Write-Verbose ;
    New-PSDrive `
        -Name $ForestShortName `
        -PSProvider ActiveDirectory `
        -Server $forest `
        -Root "//RootDSE/" `
    |Out-Null ;
}
#######################################################################
 
#######################################################################
## Take a Subject CommonName of a CA (pKIEnrollmentService)
## and return the AD object
 
function Get-CAObject() {
    [cmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [string]
        $CAName
    ) ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-CAObject()") |Write-Verbose ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Getting CA object from AD named " + $CAName) |Write-Verbose ;
    try {
        $CALDAPFilter=[string](
            '(&(cn=' +
            $CAName +
            ')(ObjectClass=pKIEnrollmentService))'
        ) ;
 
        [string]([datetime]::UtcNow.ToString() + ":`t" + "CALDAPFilter" + " : " + $CALDAPFilter) |Write-Verbose ;
 
        $CAObject=Get-ADObject `
            -LDAPFilter $CALDAPFilter `
            -SearchScope OneLevel `
            -Server $forest `
            -SearchBase ([string](
                "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," +
                $forestDN
            )) `
            -Properties * ;
        if($CAObject) {
            return($CAObject) ;
        } else {
            throw ([string]("No CA found in " + $forest + " named " + $CAName)) ;
        }
    } catch {
 
    }
}
#######################################################################
 
 
#######################################################################
## Get a two-way mapping of AD GUIDs to special permissions
 
function Get-ExtendedRightsMap() {
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-ExtendedRightsMap()") |Write-Verbose ;
    try {
        $rootdse = Get-ADRootDSE -Server $forest ;
        $extendedrightsmap = @{} ;
        Get-ADObject `
            -Server $forest `
            -SearchBase ($rootdse.ConfigurationNamingContext) `
            -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" `
            -Properties displayName,rightsGuid `
        |% {
                $extendedrightsmap[[System.GUID]$_.rightsGuid]=$_.displayName ;
                $extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid ;
            }
        [string]([datetime]::UtcNow.ToString() + ":`t" + "extendedrightsmap" + " :`r`n" + (New-Object -TypeName pscustomobject -Property $extendedrightsmap)) |Write-Verbose ;
        return($extendedrightsmap) ;
    } catch {
 
    }
}
#######################################################################
 
 
#######################################################################
## Do the actual processing for a CA
function Get-CAPermissions() {
    [cmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [string]
        $CAName
    ) ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-CAPermissions()") |Write-Verbose ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Get-CAObject() with CAName " + $CAName) |Write-Verbose ;
    $CAObject=Get-CAObject -CAName $CAName ;
 
    $CAPath=[string](
        $ForestShortName +
        ":" +
        $CAObject.DistinguishedName
    )
    [string]([datetime]::UtcNow.ToString() + ":`t" + "CAPath" + " : " + $CAPath) |Write-Verbose ;
 
    $ACL=Get-Acl -Path $CAPath ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Getting ACL for AD object " + $CAPath) |Write-Verbose ;
 
    $Accumulator=@() ;
    foreach($ACE in $ACL.Access) {
        if($ACE.ActiveDirectoryRights.ToString() -eq "ExtendedRight" ) {
            $persimmon=$extendedrightsmap[$ACE.ObjectType] ;
        } else {
            $persimmon=$ACE.ActiveDirectoryRights.ToString() ;
        }
        if($ACE.IdentityReference.GetType() -eq [System.Security.Principal.SecurityIdentifier]) {
            try {
                $PrincipalName=$ACE.IdentityReference.Value.Translate([System.Security.Principal.NTAccount]) ;
            } catch {
                $PrincipalName=$ACE.IdentityReference.Value.ToString() ;
            }
        } elseif($ACE.IdentityReference.GetType() -eq [System.Security.Principal.NTAccount]) {
            $PrincipalName=$ACE.IdentityReference.Value.ToString() ;
        } else {
 
        }
        $Accumulator += New-Object -TypeName PSCustomObject -Property @{
            "Principal" = $PrincipalName ;
            "Rule" = $ACE.AccessControlType.ToString() ;
            "Persimmon" = $persimmon ;
        } ;
    }
 
    $CASettings=[ordered]@{} ;
    $CASettings["CAName"]=$CAObject["DisplayName"][0] ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + 'CASettings["CAName"]' + " : " + $CAObject["DisplayName"][0] ) |Write-Verbose ;
    $CASettings["Permissions"]=$Accumulator |Select-Object -Property "Principal","Rule","Persimmon" |Sort-Object -Property "Principal" ;
  
    return($CASettings) ;
}
 
#######################################################################
 
$extendedrightsmap=Get-ExtendedRightsMap ;
$CASettings= Get-CAPermissions -CAName $CASubjectCN ;
$CASettings |ConvertTo-Json -Depth 3 |Write-Output ;
 
Remove-PSDrive -Name $ForestShortName ;