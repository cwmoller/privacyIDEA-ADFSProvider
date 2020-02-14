# Remove the provider

param (
    [switch]$primary = $true 
)

if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator access required"
    exit 1
}

$location = "C:\Program Files\privacyIDEAProvider"
$provider = "privacyIDEA-ADFSProvider"
$file = "${location}\${provider}.dll"

if ($primary) {
	if ((Get-AdfsGlobalAuthenticationPolicy | Select -ExpandProperty "AdditionalAuthenticationProvider") -contains ${provider}) {
		Write-Host "Remove provider from additional authentication providers list first."
		exit
	}
	Unregister-AdfsAuthenticationProvider -Name ${provider}
}
Set-location ${location}
[System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacRemove("${file}")

Restart-Service adfssrv
