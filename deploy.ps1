
hostname

$PSVersionTable

whoami.exe

"Environment Variables:"
Get-ChildItem env:

Get-Module

"Available Modules:"
Get-Module -ListAvailable

try {
	# Use TLS1.2 Protocol
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	try {
		# Set TLS for later PowerShell module installations
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	}
	catch {
		$Error[0]
		Write-Error "Error occured while setting TLS Version." -ErrorAction Stop
	}

	# Create install folder
	$installTempPath = 'C:\srinstall\'
	$null = New-Item -ItemType Directory -Path $installTempPath -Force
	if (-not (Test-Path -Path $installTempPath)) {
		Write-Error "Path '$($installTempPath)' does not exist." -ErrorAction Stop
	}

	# Create SSL Certifikates
	$dnsName = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

	$CertArgs = @{
		'DnsName'           = $dnsName
		'FriendlyName'      = 'ScriptRunner SSL Certificate'
		'Subject'           = "CN=$($dnsName)"
		'CertStoreLocation' = "Cert:\LocalMachine\My"
		'NotAfter'          = (Get-Date).AddYears(2)
		'KeyAlgorithm'      = "RSA"
		'KeyExportPolicy'   = "Exportable"
		'KeySpec'           = "Signature"
		'KeyLength'         = 2048
		'ErrorAction'       = 'Continue'
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

			$storeLocation = "LocalMachine"
			$storeName = "Root"

			$store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
			$store.Add($cert01)
			$store.Close()
		}
		catch {
			$Error[0]
			Write-Error "Error occured during creation and exporting the certificate." -ErrorAction Stop
		}
	}

	# Allow HTPPS to ScriptRunner Server
	$fireWallRuleName = 'ScriptRunner_tcp/443'
	# netsh advfirewall firewall add rule name= $fireWallRuleName dir=in action=allow protocol=TCP localport=443
	if($null -eq (Get-NetFirewallRule -DisplayName $fireWallRuleName -ErrorAction SilentlyContinue)) {
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
	Invoke-WebRequest -Uri "https://www.scriptrunner.com/hubfs/MGA_Files/ScriptRunnerTrial_6.8.2345.0.zip" -OutFile "$($installTempPath)scriptrunnertrial.zip"

	# Unpack ScriptRunner setup ZIP
	Expand-Archive -Path "$($installTempPath)scriptrunnertrial.zip" -DestinationPath "$($installTempPath)scriptrunner"

	# Get name of ScriptRunner setup file
	$setupExe = (Get-ChildItem -Path "$($installTempPath)\scriptrunner\" -Filter 'setup*.exe').Name
	if ($null -ne $setupExe) {
		# Install ScriptRunner in silent mode
		Start-Process "$($installTempPath)\scriptrunner\$($setupExe)" -ArgumentList @("-S", "-force") -Wait -NoNewWindow
	}
	else {
		Write-Error "ScriptRunner Setup File '$($installTempPath)\scriptrunner\$($setupExe)' not found." -ErrorAction Stop
	}

	# Import of the ScriptRunner Module
	Import-Module -Name "$($env:ProgramFiles)\ScriptRunner\Service\Bin\PsModules\ScriptRunnerSettings\ScriptRunnerSettings.psm1" -Global

	# Aktiviere HTTPS / -Restart-AsrService not working
	Set-AsrSTSOptions -SSLCertThumbprint $cert.Thumbprint -LocalPort 443
	Set-AsrURI -LocalOnly

	Restart-AsrService
	Start-Sleep -Seconds 10
	Test-AsrUri -Verbose -ErrorAction Continue
}
catch {
	$Error[0]
	Write-Error "Error occured during deployment" -ErrorAction Stop
}
finally {
}

Get-AzContext
