# Remove the provider

param (
    [switch]$primary = $true 
)

$location = "C:\Program Files\privacyIDEAProvider"

if ($primary) {
	Unregister-AdfsAuthenticationProvider -Name "privacyIDEA-ADFSProvider"
}
Set-location ${location}
[System.Reflection.Assembly]::Load("System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacRemove("${location}\privacyIDEA-ADFSProvider.dll")

Restart-Service adfssrv
