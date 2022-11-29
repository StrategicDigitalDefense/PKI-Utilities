<#
    .SYNOPSIS
    This script retrieves the permissions (and optionally most of the rest of settings) 
    for a Certificate Template used by the Active Directory Certificate Services: 
    Certification Authority, from Active Directory and writes the output as a JSON-encoded
    struct

    This has been useful for reviewing and auditing templates, without having to flip through
    the many panels in the properties of the template in the MMC
    
#>


[cmdletBinding(DefaultParameterSetName="PermissionsOnly")]Param(
    [Parameter(Mandatory=$true,ParameterSetName="PermissionsOnly")]
    [Parameter(Mandatory=$true,ParameterSetName="MultiPermissionsOnly")]
        [string]
        $ADForest,
    [Parameter(Mandatory=$true,ParameterSetName="PermissionsOnly")]
        [string]
        $TemplateName,
    [Parameter(Mandatory=$true,ParameterSetName="MultiPermissionsOnly")]
        [string[]]
        $TemplateNames,
    [Parameter(Mandatory=$false,ParameterSetName="PermissionsOnly")]
    [Parameter(Mandatory=$false,ParameterSetName="MultiPermissionsOnly")]
        [switch]
        $AdditionalInformation,
    [Parameter(Mandatory=$false,ParameterSetName="PermissionsOnly")]
    [Parameter(Mandatory=$false,ParameterSetName="MultiPermissionsOnly")]
        [switch]
        $LongOutput
) ;
 
 
#######################################################################
## Borrowed from Vadims's webpage
## URL: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
 
function Convert-pKIPeriod ([Byte[]]$ByteArray) {
    [array]::Reverse($ByteArray)
    $LittleEndianByte = -join ($ByteArray | %{"{0:x2}" -f $_})
    $Value = [Convert]::ToInt64($LittleEndianByte,16) * -.0000001
    if (!($Value % 31536000) -and ($Value / 31536000) -ge 1) {[string]($Value / 31536000) + " years"}
    elseif (!($Value % 2592000) -and ($Value / 2592000) -ge 1) {[string]($Value / 2592000) + " months"}
    elseif (!($Value % 604800) -and ($Value / 604800) -ge 1) {[string]($Value / 604800) + " weeks"}
    elseif (!($Value % 86400) -and ($Value / 86400) -ge 1) {[string]($Value / 86400) + " days"}
    elseif (!($Value % 3600) -and ($Value / 3600) -ge 1) {[string]($Value / 3600) + " hours"}
    else {"0 hours"}
}
 
#######################################################################
 
 
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
## Take a template Name/DisplayName/CommonName and return the AD object
 
function Get-TemplateObject() {
    [cmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [string]
        $TemplateName
    ) ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-TemplateObject()") |Write-Verbose ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Getting Template object from AD named " + $TemplateName) |Write-Verbose ;
    try {
        $TemplateLDAPFilter=[string](
            '(&(|(displayName=' +
            $TemplateName +
            ')(cn=' +
            $TemplateName +
            ')(name=' +
            $TemplateName +
            '))(ObjectClass=pKICertificateTemplate))'
        ) ;
 
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateLDAPFilter" + " : " + $TemplateLDAPFilter) |Write-Verbose ;
 
        $TemplateObject=Get-ADObject `
            -LDAPFilter $TemplateLDAPFilter `
            -SearchScope OneLevel `
            -Server $forest `
            -SearchBase ([string](
                "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," +
                $forestDN
            )) `
            -Properties * ;
        if($TemplateObject) {
            return($TemplateObject) ;
        } else {
            throw ([string]("No template found in " + $forest + " named " + $TemplateName)) ;
        }
    } catch {
 
    }
}
#######################################################################
 
 
#######################################################################
## Take a template Name/DisplayName/CommonName and return the CAs that
## can issue on this template
 
function Get-CAsWithTemplate() {
    [cmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [string]
        $TemplateName
    ) ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-CAsWithTemplate()") |Write-Verbose ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Getting CAs that can issue " + $TemplateName) |Write-Verbose ;
    try {
        $LDAPFilter=[string](
            '(ObjectClass=pKIEnrollmentService)'
        ) ;
 
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateLDAPFilter" + " : " + $LDAPFilter) |Write-Verbose ;
 
        $Search=Get-ADObject `
            -LDAPFilter $LDAPFilter `
            -SearchScope OneLevel `
            -Server $forest `
            -SearchBase ([string](
                "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," +
                $forestDN
            )) `
            -Properties * ;
        $IssuingCAs=@() ;
        foreach($Record in $Search) {
            [string]([datetime]::UtcNow.ToString() + ":`t" + "Checking if CA " + $Record.Name + " can issue for template " + $TemplateName) |Write-Verbose ;
            [string]([datetime]::UtcNow.ToString() + "`r`n=====`r`n" + ($Record |Select-Object -ExpandProperty "certificateTemplates")) |Write-Verbose ;
            if(($Record |Select-Object -ExpandProperty "certificateTemplates") -contains $TemplateName) {
                [string]([datetime]::UtcNow.ToString() + ":`t" + "Yes, adding " + $Record.Name) |Write-Verbose ;
                $IssuingCAs += $Record.Name ;
            }
        }
        if($IssuingCAs.Count -gt 0) {
            return($IssuingCAs) ;
        } else {
            throw ([string]("No CAs found in " + $forest + " that issue " + $TemplateName)) ;
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
## Parse enrollment flags
 
function Parse-EnrollmentFlags() {
    [cmdletBinding(DefaultParameterSetName="")]Param(
        [Parameter(Mandatory=$true)]
            [int]
            $EnrollmentFlags
    )
 
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Now we are entering Parse-EnrollmentFlags() with flags value " + $EnrollmentFlags.ToString()) | Write-Verbose ;
 
    #######################################################################
    ## Bitmap values from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
    $bitmap=@{
        0x00000001 = "FLAG_INCLUDE_SYMMETRIC_ALGORITHMS"
        0x00000002 = "FLAG_PEND_ALL_REQUESTS"
        0x00000004 = "FLAG_PUBLISH_TO_KRA_CONTAINER"
        0x00000008 = "FLAG_PUBLISH_TO_DS"
        0x00000010 = "FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"
        0x00000020 = "FLAG_AUTO_ENROLLMENT"
        0x00000040 = "FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"
        0x00000100 = "FLAG_USER_INTERACTION_REQUIRED"
        0x00000400 = "FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"
        0x00000800 = "FLAG_ALLOW_ENROLL_ON_BEHALF_OF"
        0x00001000 = "FLAG_ADD_OCSP_NOCHECK"
        0x00002000 = "FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"
        0x00004000 = "FLAG_NO_REVOCATION_INFO_IN_ISSUED_CERTS"
        0x00008000 = "FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"
        0x00010000 = "FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"
        0x00020000 = "FLAG_ISSUANCE_POLICIES_FROM_REQUEST"
    } ;
 
    $Enrollment=[ordered]@{} ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Decoding msPKI-Enrollment-Flag") |Write-Verbose ;
    foreach($bit in $bitmap.Keys) {
        if([bool]($EnrollmentFlags -band $bit)) {
            $Enrollment[$bitmap[$bit]]=$true ;
            [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Enrollment"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $true) |Write-Verbose ;
        } else {
            if($LongOutput) {
                [string]([datetime]::UtcNow.ToString() + ":`t" + "We want all flags, not just the ones marked True") |Write-Verbose ;
                $Enrollment[$bitmap[$bit]]=$false ;
                [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Enrollment"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $false) |Write-Verbose ;
            }
        }
    }
    return($Enrollment) ;
}
#######################################################################
 
#######################################################################
## Parse Subject (Name) fags
 
function Parse-NameFlags() {
    [cmdletBinding(DefaultParameterSetName="")]Param(
        [Parameter(Mandatory=$true)]
            [int]
            $NameFlags
    )
 
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Now we are entering Parse-NameFlags() with flags value " + $NameFlags.ToString()) | Write-Verbose ;
 
    #######################################################################
    ## Bitmap values from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
    $bitmap=@{
        0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT'
        0x00010000 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME'
        0x00400000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS'
        0x01000000 = 'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID'
        0x02000000 = 'SUBJECT_ALT_REQUIRE_UPN'
        0x04000000 = 'SUBJECT_ALT_REQUIRE_EMAIL'
        0x08000000 = 'SUBJECT_ALT_REQUIRE_DNS'
        0x10000000 = 'SUBJECT_REQUIRE_DNS_AS_CN'
        0x20000000 = 'SUBJECT_REQUIRE_EMAIL'
        0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME'
        0x80000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH'
        0x00000008 = 'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME'
    }
 
    $Name=[ordered]@{} ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Decoding msPKI-Certificate-Name-Flag") |Write-Verbose ;
    foreach($bit in $bitmap.Keys) {
        if([bool]($NameFlags -band $bit)) {
            $Name[$bitmap[$bit]]=$true ;
            [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Name"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $true) |Write-Verbose ;
        } else {
            if($LongOutput) {
                [string]([datetime]::UtcNow.ToString() + ":`t" + "We want all flags, not just the ones marked True") |Write-Verbose ;
                $Name[$bitmap[$bit]]=$false ;
                [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Name"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $false) |Write-Verbose ;
            }
        }
    }
 
    return($Name) ;
}
#######################################################################
 
#######################################################################
## Parse General flags
 
function Parse-OtherFlags() {
    [cmdletBinding(DefaultParameterSetName="")]Param(
        [Parameter(Mandatory=$true)]
            [int]
            $OtherFlags
    )
 
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Now we are entering Parse-OtherFlags() with flags value " + $OtherFlags.ToString()) | Write-Verbose ;
 
    #######################################################################
    ## Bitmap values from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/6cc7eb79-3e84-477a-b398-b0ff2b68a6c0
    $bitmap=@{
        0x00000020 = 'AUTO_ENROLLMENT'
        0x00000040 = 'MACHINE_TYPE'
        0x00000080 = 'IS_CA'
        0x00000200 = 'ADD_TEMPLATE_NAME'
        0x00000800 = 'IS_CROSS_CA'
        0x00010000 = 'IS_DEFAULT'
        0x00020000 = 'IS_MODIFIED'
        0x00000400 = 'DO_NOT_PERSIST_IN_DB'
        0x00000002 = 'ADD_EMAIL'
        0x00000008 = 'PUBLISH_TO_DS'
        0x00000010 = 'EXPORTABLE_KEY'
    }
 
    $Flags=[ordered]@{} ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Decoding flags") |Write-Verbose ;
    foreach($bit in $bitmap.Keys) {
        if([bool]($TemplateObject.'flags' -band $bit)) {
            $Flags[$bitmap[$bit]]=$true ;
            [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Flags"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $true) |Write-Verbose ;
        } else {
            if($LongOutput) {
                [string]([datetime]::UtcNow.ToString() + ":`t" + "We want all flags, not just the ones marked True") |Write-Verbose ;
                $Flags[$bitmap[$bit]]=$false ;
                [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["Flags"][$bitmap[$bit]]' + " : " + $bitmap[$bit] + " : " + $false) |Write-Verbose ;
            }
        }
    }
    return($Flags) ;
}
#######################################################################
 
#######################################################################
## Do the actual processing for a template
function Get-TemplatePermissions() {
    [cmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [string]
        $TemplateName
    ) ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Entering Get-TemplatePermissions()") |Write-Verbose ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Get-TemplateObject() with TemplateName " + $TemplateName) |Write-Verbose ;
    $TemplateObject=Get-TemplateObject -TemplateName $TemplateName ;
 
    $TemplatePath=[string](
        $ForestShortName +
        ":" +
        $TemplateObject.DistinguishedName
    )
    [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplatePath" + " : " + $TemplatePath) |Write-Verbose ;
 
    $ACL=Get-Acl -Path $TemplatePath ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Getting ACL for AD object " + $TemplatePath) |Write-Verbose ;
 
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
 
    $TemplateSettings=[ordered]@{} ;
    $TemplateSettings["TemplateName"]=$TemplateObject["DisplayName"][0] ;
    [string]([datetime]::UtcNow.ToString() + ":`t" + 'TemplateSettings["TemplateName"]' + " : " + $TemplateObject["DisplayName"][0] ) |Write-Verbose ;
    $TemplateSettings["Permissions"]=$Accumulator |Select-Object -Property "Principal","Rule","Persimmon" |Sort-Object -Property "Principal" ;
    if($AdditionalInformation) {
        [string]([datetime]::UtcNow.ToString() + ":`t" + "We want more template data than just the persimmons") |Write-Verbose ;
        $TemplateSettings["Enrollment"]=Parse-EnrollmentFlags -EnrollmentFlags $TemplateObject.'msPKI-Enrollment-Flag' ;
        $TemplateSettings["Name"]=Parse-NameFlags -NameFlags $TemplateObject.'msPKI-Certificate-Name-Flag' ;
        $TemplateSettings["Flags"]=Parse-OtherFlags -OtherFlags $TemplateObject.'flags' ;
        $TemplateSettings["AdditionalSettings"]=[ordered]@{}
        $TemplateSettings["CAsWithTemplate"]=Get-CAsWithTemplate -TemplateName $TemplateObject["Name"] ;
 
        #######################################################################
        ## Values of possible EKU from https://tools.ietf.org/html/rfc5280#section-4.2.1.12
        [string]([datetime]::UtcNow.ToString() + ":`t" + "Decoding msPKI-Certificate-Application-Policy (Extended Key Use)") |Write-Verbose ;
        $EKU=@() ;
        foreach($ekuse in $TemplateObject.'msPKI-Certificate-Application-Policy') {
            switch($ekuse) {
                "1.3.6.1.5.5.7.3.1" { $EKU += "serverAuth" ; Break }
                "1.3.6.1.5.5.7.3.2" { $EKU += "clientAuth" ; Break }
                "1.3.6.1.5.5.7.3.3" { $EKU += "codeSigning" ; Break }
                "1.3.6.1.5.5.7.3.4" { $EKU += "emailProtection" ; Break }
                "1.3.6.1.5.5.7.3.8" { $EKU += "timeStamping" ; Break }
                "1.3.6.1.5.5.7.3.9" { $EKU += "OCSPSigning" ; Break }
                "1.3.6.1.4.1.311.10.3.4" { $EKU += "EncryptingFileSystem" ; Break }
                "1.3.6.1.4.1.311.10.3.12" { $EKU += "DocumentSigning" ; Break }
                "1.3.6.1.4.1.311.20.2.1" { $EKU += "Enrollment Agent" ; Break }
                "1.3.6.1.4.1.311.20.2.2" { $EKU += "Smartcard Login" ; Break }
            }
        }
        $TemplateSettings['AdditionalSettings']['Certificate-Application-Policy']=$EKU -join "; " ;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateSettings['AdditionalSettings']['Certificate-Application-Policy']" + " : " + ($EKU -join "; " )) |Write-Verbose ;
        $TemplateSettings['AdditionalSettings']['Minimal-Key-Size']=$TemplateObject.'msPKI-Minimal-Key-Size' ;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateSettings['AdditionalSettings']['Minimal-Key-Size']" + " : " + $TemplateObject.'msPKI-Minimal-Key-Size') |Write-Verbose ;
        $TemplateSettings['AdditionalSettings']['Critical-Extensions']=$TemplateObject.'pKICriticalExtensions' -join "; " ;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateSettings['AdditionalSettings']['Critical-Extensions']" + " : " + ($TemplateObject.'pKICriticalExtensions' -join "; " )) |Write-Verbose ;
 
        #######################################################################
        ## From https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ee5d75a7-8416-4a92-b708-ee8f6e8baffb
        [string]([datetime]::UtcNow.ToString() + ":`t" + "pKIDefaultKeySpec" + " : " + $TemplateObject.'pKIDefaultKeySpec') |Write-Verbose ;
        if($TemplateObject.'pKIDefaultKeySpec' -eq 1) {
            $TemplateSettings['AdditionalSettings']['Key-Specification']="Keys used to encrypt/decrypt session keys" ;
        } elseif($TemplateObject.'pKIDefaultKeySpec' -eq 2) {
            $TemplateSettings['AdditionalSettings']['Key-Specification']="Keys used to create and verify digital signatures" ;
        } else {
            $TemplateSettings['AdditionalSettings']['Key-Specification']="Unknown key specification" ;
        }
 
        #######################################################################
        ## This is a FILETIME. I was lazy and Vadims already solved this, so I am using his good work
        ## Look at URL: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
        [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Convert-pKIPeriod() with pKIExpirationPeriod " + $TemplateObject.pKIExpirationPeriod) |Write-Verbose ;
        $TemplateSettings['AdditionalSettings']['Certificate-Validity-Period']=Convert-pKIPeriod $TemplateObject.pKIExpirationPeriod ;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateSettings['AdditionalSettings']['Certificate-Validity-Period']" + " : " + $TemplateSettings['AdditionalSettings']['Certificate-Validity-Period']) |Write-Verbose ;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Convert-pKIPeriod() with pKIOverlapPeriod " + $TemplateObject.pKIOverlapPeriod) |Write-Verbose ;
        $TemplateSettings['AdditionalSettings']['Certificate-Renewal-Period']=Convert-pKIPeriod $TemplateObject.pKIOverlapPeriod;
        [string]([datetime]::UtcNow.ToString() + ":`t" + "TemplateSettings['AdditionalSettings']['Certificate-Renewal-Period']" + " : " + $TemplateSettings['AdditionalSettings']['Certificate-Renewal-Period']) |Write-Verbose ;
 
    }
 
    return($TemplateSettings) ;
}
 
#######################################################################
 
$extendedrightsmap=Get-ExtendedRightsMap ;
 
if($TemplateNames) {
    $TemplateSettings=@() ;
    foreach($TemplateName in $TemplateNames) {
        [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Get-TemplatePermissions() with TemplateName " + $TemplateName) |Write-Verbose ;
        $TemplateSettings += Get-TemplatePermissions -TemplateName $TemplateName ;
    }
} elseif($TemplateName) {
    [string]([datetime]::UtcNow.ToString() + ":`t" + "Calling Get-TemplatePermissions() with TemplateName " + $TemplateName) |Write-Verbose ;
    $TemplateSettings= Get-TemplatePermissions -TemplateName $TemplateName ;
} else {
    throw "Did not find a template name provided" ;
}
 
#New-Object -TypeName pscustomobject -Property $TemplateSettings |Select-Object -Property * |ConvertTo-Json -Depth 3 |Write-Output ;
$TemplateSettings |ConvertTo-Json -Depth 3 |Write-Output ;
 
Remove-PSDrive -Name $ForestShortName ;