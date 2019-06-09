# Remove the provider

param (
    [switch]$primary = $true 
)

$location = "C:\Program Files\privacyIDEAProvider"
$provider = "privacyIDEA-ADFSProvider"

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
$publish.GacRemove("${location}\privacyIDEA-ADFSProvider.dll")

Restart-Service adfssrv
