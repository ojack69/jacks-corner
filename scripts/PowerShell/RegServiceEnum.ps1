<#
  .SYNOPSIS
  Enumerate possibly misconfigured services' registry entries

  .DESCRIPTION
  This script tries to enumerate services whose registry entries ACLs are misconfigured.

  .OUTPUTS
  Returns the list of vulnerable services.

  .EXAMPLE
  PS> .\RegServiceEnum.ps1

#>

$InterestingPermissions = "FullControl"
$IgnoredIdentityReference = "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES", "CREATOR OWNER", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "NT SERVICE\TrustedInstaller"
$AllServicesRegEntries = Get-ChildItem -Path HKLM:\System\CurrentControlSet\Services | Select Name 


ForEach ($RegEntry in $AllServicesRegEntries){
    $FormattedRegPath = ($RegEntry.Name).Replace('HKEY_LOCAL_MACHINE','HKLM:')
    $acls = (Get-ACL $FormattedRegPath).Access
    ForEach ($acl in $acls){
        if(($InterestingPermissions.Contains($acl.RegistryRights)) -and (!$IgnoredIdentityReference.Contains($acl.IdentityReference.Value))){
            Write-Host "[!] Found: $FormattedRegPath - $($acl.RegistryRights) for $($acl.IdentityReference)"
        }
    }
}
