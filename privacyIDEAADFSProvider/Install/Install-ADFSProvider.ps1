# Install the provider

param (
    [switch]$primary = $true 
)

$location = "C:\Program Files\privacyIDEAProvider"

function Gac-Util
{
    param (
        [parameter(Mandatory = $true)][string] $assembly
    )
    try
    {
        $Error.Clear()

        [Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices") | Out-Null
        [System.EnterpriseServices.Internal.Publish] $publish = New-Object System.EnterpriseServices.Internal.Publish

        if (!(Test-Path $assembly -type Leaf) ) 
            { throw "The assembly $assembly does not exist" }

        if ([System.Reflection.Assembly]::LoadFile($assembly).GetName().GetPublicKey().Length -eq 0 ) 
            { throw "The assembly $assembly must be strongly signed" }

        $publish.GacInstall($assembly)

        Write-Host "`t`t$($MyInvocation.InvocationName): Assembly $assembly gacced"
    }
    catch
    {
        Write-Host "`t`t$($MyInvocation.InvocationName): $_"
    }
}

# check event source
if (!([System.Diagnostics.EventLog]::SourceExists("privacyIDEAProvider")))
{
    New-EventLog -LogName "AD FS/Admin" -Source "privacyIDEAProvider"
    Write-Host "Log source created"
}

Set-location ${location}
Gac-Util "${location}\privacyIDEA-ADFSProvider.dll"

if ($primary) {
	$typeName = "privacyIDEAADFSProvider.Adapter, privacyIDEA-ADFSProvider, Version=1.3.4.1, Culture=neutral, PublicKeyToken=a11686e933c2d195"
	Register-AdfsAuthenticationProvider -TypeName $typeName -Name "privacyIDEA-ADFSProvider" -ConfigurationFilePath "${location}\config.xml" -Verbose
}

Restart-Service adfssrv
