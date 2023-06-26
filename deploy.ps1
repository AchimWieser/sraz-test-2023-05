#Requires -RunAsAdministrator

[CmdletBinding()]
param (
	$DNSName,
	$DownloadUri = 'https://www.scriptrunner.com/hubfs/MGA_Files/ScriptRunnerTrial_6.8.2345.0.zip'
)

$eap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

#region functions
if ($null -eq $env:TEMP) {
	Set-Variable -Name 'tempPath' -Scope 'script' -Value (Join-Path -Path "$($HOME)" -ChildPath 'temp\scriptrunner') #-Visibility Private
}
else {
	Set-Variable -Name 'tempPath' -Scope 'script' -Value (Join-Path -Path "$($env:TEMP)" -ChildPath 'scriptrunner') #-Visibility Private
}
$null = New-Item -ItemType Directory -Path $tempPath -Force
$logFileName = "sr-install-$((Get-Date).ToString('yyyyMMdd-HHmmss')).log"
Set-Variable -Name 'logFilePath' -Scope 'script' -Value (Join-Path -Path $tempPath -ChildPath $logFileName) #-Visibility Private
Write-Output "Writing logoutput to '$($logFilePath)' ..."
function Write-SRLog {
	[CmdletBinding()]
	param (
		[parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
		[object[]]$InputObject,
		[ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')]
		[string]$LogType = 'Info',
		[Alias('PassThrough')]
		[switch]$PassThru
	)

	Begin {
		function Local:WriteSRLog {
			[CmdletBinding()]
			param(
				[string]$Log,
				[switch]$PassThru,
				[ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')]
				[string]$LogType = 'Info',
				[bool]$CanWriteLog
			)

			if ($PassThru.IsPresent) {
				$Log.TrimEnd([System.Environment]::NewLine)
			}
			if ($CanWriteLog) {
				"$((Get-Date).ToString('[yyyy-MM-dd HH:mm:ss,fff] '))" + "$($LogType): " + $Log.TrimEnd([System.Environment]::NewLine) | Out-File -FilePath $script:logFilePath -Encoding utf8 -Append -Force
			}
		}

		$canWriteLog = $false
		$logPath = Split-Path -Path $script:logFilePath -Parent -ErrorAction Continue
		$canWriteLog = (Test-Path -Path $logPath -ErrorAction Continue)
	}

	Process {
		if ($PSBoundParameters.ContainsKey('InputObject')) {
			$InputObject | ForEach-Object {
				$log = ($_ | Out-String)
				WriteSRLog -LogType $LogType -Log $log -PassThru:($PassThru.IsPresent) -CanWriteLog $canWriteLog
			}
		}
		else {
			$log = $_ | Out-String
			WriteSRLog -LogType $LogType -Log $log -PassThru:($PassThru.IsPresent) -CanWriteLog $canWriteLog
		}
	}
}
#endregion functions

trap {
	$ErrorActionPreference = $eap
	$_ | Write-SRLog -LogType Error
	throw $_
}


$PSVersionTable | Write-SRLog -PassThru | Write-Output
whoami.exe | Write-SRLog -PassThru | Write-Output

if (-not $PSBoundParameters.ContainsKey('DNSName')) {
	$DNSName = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
}

# Use TLS1.2 Protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set TLS for later PowerShell module installations
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord

Enable-PSRemoting -Force -SkipNetworkProfileCheck -Verbose

# Create install folder
$installTempPath = 'C:\srinstall\'
$null = New-Item -ItemType Directory -Path $installTempPath -Force
if (-not (Test-Path -Path $installTempPath)) {
	Write-Error "Path '$($installTempPath)' does not exist." -ErrorAction Stop
}

# Create SSL Certifikates
$CertArgs = @{
	'DnsName'           = $DNSName
	'FriendlyName'      = 'Automated ScriptRunner SSL Certificate'
	'Subject'           = "CN=$($DNSName)"
	'CertStoreLocation' = 'Cert:\LocalMachine\My'
	'NotAfter'          = (Get-Date).AddYears(2)
	'KeyAlgorithm'      = 'RSA'
	'KeyExportPolicy'   = 'Exportable'
	'KeySpec'           = 'Signature'
	'KeyLength'         = 2048
	'ErrorAction'       = 'Ignore'
}

$cert = New-SelfSignedCertificate @CertArgs

if ($null -ne $cert) {
	try {
		# Setting the cert paths and the pfx password
		$certPath = $installTempPath
		$pfxCertPath = "$($certPath)scriptrunner.pfx"

		$HashValue = (Get-Date).ToString()
		$HashValueBytes = [System.Text.Encoding]::Unicode.GetBytes($HashValue)
		$EncodedHv = [Convert]::ToBase64String($HashValueBytes)
		$certPassword = $EncodedHv

		# Exporting the certificate as .cer and .pfx
		Export-Certificate -Cert $cert -FilePath "$($certPath)scriptrunner.cer" -Type CERT
		Export-PfxCertificate -Cert $cert -FilePath $pfxCertPath -Password (ConvertTo-SecureString -String $certPassword -Force -AsPlainText)

		$cert01 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$cert01.Import($pfxCertPath, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

		$storeLocation = 'LocalMachine'
		$storeName = 'Root'

		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
		$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$store.Add($cert01)
		$store.Close()
	}
	catch {
		$Error[0]
		Write-Error 'Error occured during creation and exporting the certificate.' -ErrorAction Stop
	}
}

# Allow HTPPS to ScriptRunner Server
$fireWallRuleName = 'ScriptRunner_tcp/443'
# netsh advfirewall firewall add rule name= $fireWallRuleName dir=in action=allow protocol=TCP localport=443
if ($null -eq (Get-NetFirewallRule -DisplayName $fireWallRuleName -ErrorAction SilentlyContinue)) {
	New-NetFirewallRule -Name $fireWallRuleName -DisplayName $fireWallRuleName -Direction Inbound -Action Allow -Protocol 'TCP' -LocalPort '443' -Enabled True
}
Start-Sleep -Seconds 5
$null = Get-NetFirewallRule -DisplayName $fireWallRuleName -ErrorAction Continue

# Why install chrome???
# try {
# 	# Install Chrome
# 	$Installer = "$env:temp\chrome_installer.exe"
# 	$url = 'http://dl.google.com/chrome/install/375.126/chrome_installer.exe'
# 	Invoke-WebRequest -Uri $url -OutFile $Installer -UseBasicParsing
# 	Start-Process -FilePath $Installer -Args '/silent /install' -Wait
# 	Remove-Item -Path $Installer
# }
# catch {
# 	$Error[0]
# 	Write-Error "Error occured while installing Chrome." -ErrorAction SilentlyContinue
# }

# Download ScriptRunner setup ZIP
Invoke-WebRequest -Uri $DownloadUri -OutFile "$($installTempPath)scriptrunnertrial.zip"

# Unpack ScriptRunner setup ZIP
Expand-Archive -Path "$($installTempPath)scriptrunnertrial.zip" -DestinationPath "$($installTempPath)scriptrunner"

# Get name of ScriptRunner setup file
$setupExe = (Get-ChildItem -Path "$($installTempPath)\scriptrunner\" -Filter 'setup*.exe').Name
if ($null -ne $setupExe) {
	# Install ScriptRunner in silent mode
	Start-Process "$($installTempPath)\scriptrunner\$($setupExe)" -ArgumentList @('-S', '-force') -Wait -NoNewWindow
}
else {
	Write-Error "ScriptRunner Setup File '$($installTempPath)\scriptrunner\$($setupExe)' not found." -ErrorAction Stop
}

# Import of the ScriptRunner Module (use complete module path without trailing backslash !!!)
Import-Module -Name "$($env:ProgramFiles)\ScriptRunner\Service\Bin\PsModules\ScriptRunnerSettings"

# Aktiviere HTTPS / -Restart-AsrService not working
Set-AsrSTSOptions -SSLCertThumbprint $cert.Thumbprint -LocalPort 443 -AuthMode WIN
Set-AsrURI -LocalOnly 1

Restart-AsrService
Start-Sleep -Seconds 10
Test-AsrUri -Verbose -ErrorAction Continue

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
Install-Module -Name Az.Accounts, Az.Resources, AzureAD -Scope AllUsers -Force
Get-Module -ListAvailable -Name Az.Accounts, Az.Resources, AzureAD

$ErrorActionPreference = $eap
