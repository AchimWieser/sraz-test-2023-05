# Requires -Version 5.1
# Requires -RunAsAdministrator
# CloudShell currently only supports Az 9.7
#Requires -Module @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.12.2' }
#Requires -Module @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.6.1'}
# Requires -Module @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.12.3' } # Az 10.0
# Requires -Module @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.7.0' } # Az 10.0


[CmdletBinding()]
param(
	[Parameter(Mandatory)]
	[string]$DnsName,
	[Parameter(Mandatory)]
	[string]$CertBase64
)

$eap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

# set module variables
Set-Variable -Name 'appNameSPA' -Scope 'script' -Value '[DBG] ScriptRunner Portal' #-Visibility Private -Option ReadOnly -Force
Set-Variable -Name 'appNameAPI' -Scope 'script' -Value '[DBG] ScriptRunner Service' #-Visibility Private -Option ReadOnly -Force
# the URIs SHOULD BE lowercase!
Set-Variable -Name 'appPathAdmin' -Scope 'script' -Value 'admin/' #-Visibility Private -Option ReadOnly -Force
Set-Variable -Name 'appPathDelegate' -Scope 'script' -Value 'delegate/' #-Visibility Private -Option ReadOnly -Force
Set-Variable -Name 'appPathSelfService' -Scope 'script' -Value 'selfservice/' #-Visibility Private -Option ReadOnly -Force
Set-Variable -Name 'appPathSrApp' -Scope 'script' -Value 'portal/' #-Visibility Private -Option ReadOnly -Force

Set-Variable -Name 'configFile' -Scope 'script' -Value 'app.json' #-Visibility Private -Option ReadOnly -Force
Set-Variable -Name 'tenantName' -Scope 'script' -Value $null #-Visibility Private

#region functions
if ($null -eq $env:TEMP) {
	Set-Variable -Name 'tempPath' -Scope 'script' -Value (Join-Path -Path "$($HOME)" -ChildPath 'temp\scriptrunner') #-Visibility Private
}
else {
	Set-Variable -Name 'tempPath' -Scope 'script' -Value (Join-Path -Path "$($env:TEMP)" -ChildPath 'scriptrunner') #-Visibility Private
}
$null = New-Item -ItemType Directory -Path $tempPath -Force
$logFileName = "sr-register-apps-$((Get-Date).ToString('yyyyMMdd-HHmmss')).log"
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


function AddAzureADAppCertCred {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$AppObjectID,
		[Parameter(ParameterSetName = 'Thumbprint', Mandatory)]
		[string]$Thumbprint,
		[Parameter(ParameterSetName = 'Thumbprint')]
		[ValidateSet('LocalMachine', 'CurrentUser')]
		[string]$CertStore = 'LocalMachine',
		[Parameter(ParameterSetName = 'CertData', Mandatory)]
		[byte[]]$CertData,
		[Parameter(ParameterSetName = 'CertBase64', Mandatory)]
		[string]$CertBase64
	)

		"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
		$myCertData = $null
		# TODO: check if cert already exists!
		$appKeyCreds = Get-AzADAppCredential -ObjectId $AppObjectID
		if ($PSBoundParameters.ContainsKey('Thumbprint')) {
			foreach ($keyCred in $appKeyCreds) {
				$CustomKeyIdentifier = $keyCred.CustomKeyIdentifier
				if ($null -ne $CustomKeyIdentifier) {
					# only certificates have a CustomKeyIdentifier
					$tp = [System.Convert]::ToBase64String($CustomKeyIdentifier)
					if ($tp -eq $Thumbprint) {
						Write-SRLog "Thumbprint '$Thumbprint' is already registered with application ObjectId '$AppObjectID'." -PassThru | Write-Output
						return
					}
				}
			}

			Write-SRLog "Add certificate '$($Thumbprint)' as a secret to prove the application's identity when requesting a token." -PassThru | Write-Output
			$certPath = "Cert:\$($CertStore)\My\$($Thumbprint)"
			$cert = Get-Item -Path $certPath -ErrorAction Continue
			if ($null -eq $cert) {
				$e = Write-SRLog "Certificate '$($certPath)' not found." -PassThru
				$e | Write-Error -ErrorAction Stop
			}
			$myCertData = $cert.GetRawCertData()
			#$base64Value = [System.Convert]::ToBase64String($certData)

			# fix timezone issue
			# org expirationDate is not accepted depending on timezone. => Error: Key credential end date is invalid.
			# https://github.com/Azure/azure-powershell/issues/6974#issuecomment-463083366
			# $effectiveDate = [datetime]::Parse($cert.GetEffectiveDateString())
			# $validFrom = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($effectiveDate, [System.TimeZoneInfo]::Local.Id, [System.TimeZoneInfo]::Utc.Id)
			# $expirationDate = [datetime]::Parse($cert.GetExpirationDateString())
			# $validTo = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($expirationDate, [System.TimeZoneInfo]::Local.Id, [System.TimeZoneInfo]::Utc.Id)
		}
		elseif ($PSBoundParameters.ContainsKey('CertData')) {
			$appKeyCreds
			$myCertData = $CertData
		}
		elseif ($PSBoundParameters.ContainsKey('CertBase64')) {
			$myCertData = [System.Convert]::FromBase64String($CertBase64)
		}
		else {
			throw 'Invalid ParameterSet.'
		}

		$kcProperties = @{
			Key   = $myCertData
			Type  = 'AsymmetricX509Cert'
			Usage = 'Verify'
		}
		$keyCredentials = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphKeyCredential' -Property $kcProperties

		$keyCredArgs = @{
			ObjectId       = $AppObjectID
			KeyCredentials = $keyCredentials
		}
		New-AzADAppCredential @keyCredArgs
		Write-SRLog "Add new AppCredential to AppId $($AppObjectID)." -PassThru | Write-Output
}

<#
function RemoveAzureADAppCertCred {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$AppObjectID,
		[Parameter(Mandatory)]
		[string]$Thumbprint
	)

	$appKeyCreds = AzureAD\Get-AzureADApplicationKeyCredential -ObjectId $AppObjectID
	foreach ($keyCred in $appKeyCreds) {
		$CustomKeyIdentifier = $keyCred.CustomKeyIdentifier
		$tp = [System.Convert]::ToBase64String($CustomKeyIdentifier)
		if ($tp -eq $Thumbprint) {
			Write-Verbose "Remove KeyCredential with Thumbprint '$Thumbprint' from application ObjectId '$AppObjectID'." -Verbose
			AzureAD\Remove-AzureADApplicationKeyCredential -ObjectId $AppObjectID -KeyId $keyCred.KeyId
			return
		}
	}
	Write-Warning "No KeyCredential with Thumbprint '$Thumbprint' found for application ObjectId '$AppObjectID'."
}
#>

function AddResourceAccessPermission {
	<#
		.SYNOPSIS
		Adds the requiredAccesses (expressed as a pipe separated string) to the requiredAccess structure
		The exposed permissions are in the $exposedPermissions collection, and the type of permission (Scope | Role) is
		described in $permissionType
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$RequiredAccesses,
		[Parameter(Mandatory)]
		[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphRequiredResourceAccess]
		$RequiredAccess,
		[Parameter(ParameterSetName = 'PermissionScope', Mandatory)]
		[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphPermissionScope[]]
		$PermissionScope,
		[Parameter(ParameterSetName = 'AppRole', Mandatory)]
		[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphAppRole[]]
		$AppRole
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$exposedPermissions = $null
	[string]$PermissionType = $null
	if ($PSCmdlet.ParameterSetName -eq 'PermissionScope') {
		$exposedPermissions = $PermissionScope
		$PermissionType = 'Scope'
	}
	elseif ($PSCmdlet.ParameterSetName -eq 'AppRole') {
		$exposedPermissions = $AppRole
		$PermissionType = 'Role'
	}
	else {
		throw "Invalid ParameterSet '$($PSCmdlet.ParameterSetName)'"
	}

	$myResourceAccesses = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphResourceAccess]'
	foreach ($ra in $RequiredAccess.ResourceAccess) {
		$null = $myResourceAccesses.Add($ra)
	}
	foreach ($permission in $RequiredAccesses.Trim().Split('|')) {
		foreach ($exposedPermission in $exposedPermissions) {
			if ($exposedPermission.Value -eq $permission) {
				$resourceAccess = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphResourceAccess'#'Microsoft.Open.AzureAD.Model.ResourceAccess'
				$resourceAccess.Type = $PermissionType # Scope = Delegated permissions | Role = Application permissions
				$resourceAccess.Id = $exposedPermission.Id # Read directory data
				if (-not $myResourceAccesses.Contains($resourceAccess)) {
					$myResourceAccesses.Add($resourceAccess)
				}
			}
		}
	}
	$RequiredAccess.ResourceAccess = $myResourceAccesses
}

function GetRequiredPermissions {
	<#
		.EXAMPLE
		GetRequiredPermissions "Microsoft Graph" "Graph.Read|User.Read"
		.NOTES
		See also: http://stackoverflow.com/questions/42164581/how-to-configure-a-new-azure-ad-application-through-powershell
		-ApplicationDisplayName 'Microsoft Graph' -RequiredDelegatedPermissions 'User.Read|openid|profile'
	#>
	[CmdletBinding()]
	[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess])]
	param (
		[string]$ApplicationDisplayName = 'Microsoft Graph',
		[string]$RequiredDelegatedPermissions = 'User.Read|openid|profile',
		[string]$RequiredApplicationPermissions,
		$ServicePrincipal
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	# If we are passed the service principal we use it directly, otherwise we find it from the display name (which might not be unique)
	if ($ServicePrincipal) {
		$sp = $ServicePrincipal
	}
	else {
		# $sp = AzureAD\Get-AzureADServicePrincipal -Filter "DisplayName eq '$ApplicationDisplayName'" | Select-Object -First 1
		$sp = Get-AzADServicePrincipal -Filter "DisplayName eq '$ApplicationDisplayName'" | Select-Object -First 1
	}
	$appid = $sp.AppId
	#'Microsoft.Open.AzureAD.Model.RequiredResourceAccess'
	$requiredAccess = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess'
	$requiredAccess.ResourceAppId = $appid
	#'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]'
	$requiredAccess.ResourceAccess = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphResourceAccess]'

	# You can explore the permissions using
	# $servicePrincipal.AppRoles for application permissions and
	# $servicePrincipal.Oauth2Permissions for delegated permissions.
	# To see the list of all the Delegated permissions for the application:
	# $sp.Oauth2Permissions | Select-Object Id, AdminConsentDisplayName, Value
	if ($RequiredDelegatedPermissions) {
		AddResourceAccessPermission -RequiredAccess $requiredAccess -PermissionScope $sp.Oauth2PermissionScope -RequiredAccesses $requiredDelegatedPermissions
	}

	# To see the list of all the Application permissions for the application
	# $sp.AppRoles | Select-Object Id, AdminConsentDisplayName, Value
	if ($RequiredApplicationPermissions) {
		AddResourceAccessPermission -RequiredAccess $requiredAccess -AppRole $sp.AppRole -RequiredAccesses $requiredApplicationPermissions
	}
	return $requiredAccess
}

function NewPermissionScope {
	<#
		.SYNOPSIS
		This function creates a new Azure AD scope (OAuth2Permission) with default and provided values
	#>
	[CmdletBinding()]
	[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPermissionScope])]
	param (
		[Parameter(Mandatory)]
		[string]$Value,
		[string]$UserConsentDisplayName,
		[string]$UserConsentDescription,
		[string]$AdminConsentDisplayName,
		[string]$AdminConsentDescription,
		[string]$Type = 'User'
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$scope = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPermissionScope'
	$scope.Id = New-Guid
	$scope.Value = $Value
	$scope.UserConsentDisplayName = $UserConsentDisplayName
	$scope.UserConsentDescription = $UserConsentDescription
	$scope.AdminConsentDisplayName = $AdminConsentDisplayName
	$scope.AdminConsentDescription = $AdminConsentDescription
	$scope.IsEnabled = $true
	$scope.Type = $Type
	return $scope
}

function GrantConsent {
	param (
		[string]$Scope,
		[string]$ResourceId,
		[string]$ClientId
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$body = @{
		clientId    = $clientID
		consentType = 'AllPrincipals'
		principalId = $null
		resourceId  = $ResourceId
		scope       = $Scope
		# startTime   = "2019-10-19T10:37:00Z"
		# expiryTime  = "2019-10-19T10:37:00Z"
	}
	<#
	POST https://graph.microsoft.com/v1.0/oauth2PermissionGrants
	Content-Type: application/json
	Content-Length: 30
	{
		"clientId": "clientId-value",
		"consentType": "consentType-value",
		"principalId": "principalId-value",
		"resourceId": "resourceId-value",
		"scope": "scope-value"
	}
	#>
	$apiUrl = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'
	$requestArgs = @{
		Uri         = $apiUrl
		Headers     = @{ Authorization = "Bearer $($Tokenresponse.access_token)" }
		Method      = 'POST'
		Body        = $body | ConvertTo-Json
		ContentType = 'application/json'
	}
	Invoke-RestMethod @requestArgs

}

function GrantApiResourceAccess {
	<#
		.EXAMPLE
		GrantApiResourceAccess -AppObjectId $spaAadApplication.Id -ResourceAppId $serviceServicePrincipal.AppId -ResourceAccessType 'Scope' -PermissionScopeId $permission.Id
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$AppObjectId,
		[Parameter(Mandatory)]
		[string]$ResourceAppId,
		[Parameter(Mandatory)]
		[ValidateSet('Scope', 'Role')]
		[string]$ResourceAccessType,
		# The unique identifier for one of the OAuth2Permission or AppRole instances that the resource application exposes.
		[Parameter(Mandatory)]
		[string]$PermissionScopeId
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$aadApp = Get-AzADApplication -ObjectId $AppObjectId
	$reqResourceAccess = $aadApp.RequiredResourceAccess | Where-Object -Property 'ResourceAppId' -EQ -Value $ResourceAppId
	if ($null -ne $reqResourceAccess) {
		$permission = $reqResourceAccess.ResourceAccess | Where-Object -Property Id -EQ $PermissionScopeId
		if ($null -ne $permission) {
			Write-SRLog "Application '$($aadApp.DisplayName)' has already '$PermissionScopeId' access to resource '$ResourceAppId' of type '$ResourceAccessType'" -PassThru | Write-Output
			return
		}
	}

	# Delegated Permissions (scope)
	# Application Permissions (role)
	# https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/api/entity-and-complex-type-reference#resourceaccess-type
	$permission = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphResourceAccess'
	$permission.Id = $PermissionScopeId
	$permission.Type = $ResourceAccessType
	if ($null -eq $reqResourceAccess) {
		Write-SRLog "Add permission '$PermissionScopeId' for resource AppID '$ResourceAppId'." -PassThru | Write-Output
		$reqResourceAccess = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess'
		$reqResourceAccess.ResourceAppId = $ResourceAppId
		$reqResourceAccess.ResourceAccess = $permission
	}
	else {
		Write-SRLog "Add permission '$PermissionScopeId' for existing resource AppID '$ResourceAppId'." -PassThru | Write-Output
		$reqResourceAccess.ResourceAccess.Add($permission)
	}

	$requiredResourceAccesses = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess]'
	foreach ($item in  $aadApp.RequiredResourceAccess) {
		$requiredResourceAccesses.Add($item)
	}
	$requiredResourceAccesses.Add($reqResourceAccess)
	Write-SRLog "Update required resource access for application '$($aadApp.DisplayName)'." -PassThru | Write-Output
	Update-AzADApplication -ObjectId $AppObjectId -RequiredResourceAccess $requiredResourceAccesses
}

function WaitForAppRegistration {
	<#
		.SYNOPSIS
		Get App Registration, but wait for complete deployment of App Registration for 100 seconds before throwing an exception.
	#>
	[CmdletBinding()]
	[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphApplication])]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$appRegistration = $null
	$waitCount = 0
	$waitPeriod = 20
	while ($waitCount -lt $waitPeriod) {
		$reqArgs = @{
			ObjectId = $ObjectId
		}
		if ($waitCount -lt ($waitPeriod - 1)) {
			$reqArgs.Add('ErrorAction', 'SilentlyContinue')
		}
		try {
			$appRegistration = Get-AzADApplication @reqArgs
		}
		catch {
			Write-Debug "$($_)"
			$appRegistration = $null
		}
		finally {
			if ($null -eq $appRegistration) {
				Write-SRLog "Waiting for complete deployment of the app registration with ObjectId '$ObjectId' ($($waitCount + 1)/$($waitPeriod)) ..." -LogType Verbose -PassThru | Write-Verbose
				Start-Sleep -Seconds 5
				$waitCount++
			}
			else {
				$waitCount = $waitPeriod
			}
		}
	}
	return $appRegistration
}

function WaitForServicePrincipal {
	<#
		.SYNOPSIS
		Get ServicePrincipal, but wait for complete deployment of ServicePrincipal for 100 seconds before throwing an exception.
	#>
	[CmdletBinding()]
	[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphServicePrincipal])]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$sp = $null
	$waitCount = 0
	$waitPeriod = 20
	while ($waitCount -lt $waitPeriod) {
		$reqArgs = @{
			ObjectId = $ObjectId
		}
		if ($waitCount -lt ($waitPeriod - 1)) {
			$reqArgs.Add('ErrorAction', 'SilentlyContinue')
		}
		try {
			$sp = Get-AzADServicePrincipal @reqArgs
		}
		catch {
			Write-Debug "$($_)"
			$sp = $null
		}
		finally {
			if ($null -eq $sp) {
				Write-SRLog "Waiting for complete deployment of the ServicePrincipal with ObjectId '$ObjectId' ($($waitCount + 1)/$($waitPeriod)) ..." -LogType Verbose -PassThru | Write-Verbose
				Start-Sleep -Seconds 5
				$waitCount++
			}
			else {
				$waitCount = $waitPeriod
			}
		}
	}
	return $sp
}

function SetPreAuthorizedApp {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId,
		# [Parameter(Mandatory)]
		# [string]$ClientObjectId,
		[Parameter(Mandatory)]
		[string]$ClientAppId,
		[string]$Scope = 'access_as_user',
		[int]$RequestedAccessTokenVersion = $null
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	# Get the application and delegated permission to pre-authorize
	#$null = WaitForAppRegistration -ObjectId $ClientObjectId
	$appRegistration = $null
	$oauth2Permission = $null
	$i = 0
	while (-not (($null -ne $oauth2Permission) -and ($null -ne $oauth2Permission.Id))) {
		$appRegistration = Get-AzADApplication -ObjectId $ObjectId
		$oauth2Permission = $appRegistration.Api.Oauth2PermissionScope | Where-Object { $_.Value -eq $Scope }
		if (($null -eq $oauth2Permission) -or ($null -eq $oauth2Permission.Id)) {
			Write-SRLog "Wait for OAuth2PermissionScope '$($Scope)' of application '$($appRegistration.DisplayName)' with ObjectId '$($ObjectId)'." -PassThru | Write-Output
			if ($i -gt 5) {
				$e = Write-SRLog -LogType Error "Permission Scope '$($Scope)' of application '$($appRegistration.DisplayName)' with ObjectId '$($ObjectId)' not found." -PassThru
				$e | Write-Error -ErrorAction Stop
			}
			$i++
			Start-Sleep -Seconds 5
		}
	}

	# Set accessToken required version
	$appRegistration.Api.RequestedAccessTokenVersion = $RequestedAccessTokenVersion

	$preAuthorizedApps = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPreAuthorizedApplication]'
	foreach ($preAuthorizedApp in $appRegistration.Api.PreAuthorizedApplication) {
		$null = $preAuthorizedApps.Add($preAuthorizedApp)
		if ($preAuthorizedApp.AppId -eq $ClientAppId) {
			if ($preAuthorizedApp.DelegatedPermissionId.Contains($oauth2Permission.Id)) {
				Write-SRLog "Application '$($appRegistration.DisplayName)' with ObjectId '$($appRegistration.Id)' already contains the delegatedPermissionId '$($oauth2Permission.Id)' of preAuthorizedApplication with AppId '$($ClientAppId)'." -PassThru | Write-Output
				return
			}
			else {
				Write-SRLog "Add delegatedPermissionId '$($oauth2Permission.Id)' for preAuthorizedApplication with AppId '$($ClientAppId)' to application '$($appRegistration.DisplayName)' with ObjectId '$($appRegistration.Id)'." -PassThru | Write-Output
				$preAuthorizedApp.DelegatedPermissionId += $oauth2Permission.Id
				Update-AzADApplication -ObjectId $appRegistration.Id -Api $appRegistration.Api
				return
			}
		}
	}

	# Build a PreAuthorizedApplication object
	# Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphApiApplication
	$preAuthorizedApplication = New-Object 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPreAuthorizedApplication'
	$preAuthorizedApplication.AppId = $ClientAppId
	$preAuthorizedApplication.DelegatedPermissionId = @($oauth2Permission.Id)

	$null = $preAuthorizedApps.Add($preAuthorizedApplication)
	$appRegistration.Api.PreAuthorizedApplication = $preAuthorizedApps.ToArray()
	# Update the Application object
	Write-SRLog "Add preAuthorizedApplication with AppId '$($ClientAppId)' and  delegatedPermissionId '$($oauth2Permission.Id)' to application '$($appRegistration.DisplayName)' with ObjectId '$($appRegistration.Id)'." -PassThru | Write-Output
	Update-AzADApplication -ObjectId $appRegistration.Id -Api $appRegistration.Api
}

function SetGroupMembershipClaims {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId,
		[ValidateSet('SecurityGroup', 'ApplicationGroup', 'DirectoryRole', 'All' )]
		[string]$GroupMembershipClaims
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$appRegistration = WaitForAppRegistration -ObjectId $ObjectId
	if ([string]::IsNullOrEmpty($appRegistration.GroupMembershipClaim)) {
		#AzureAD\Set-AzureADMSApplication -ObjectId $appRegistration.Id -GroupMembershipClaims $GroupMembershipClaims
		Update-AzADApplication -ObjectId $appRegistration.Id -GroupMembershipClaim $GroupMembershipClaims
		Write-SRLog "Set group membership claims for app '$($appRegistration.DisplayName)' with ObjectId '$($appRegistration.Id)' to '$GroupMembershipClaims'." -PassThru | Write-Output
	}
	else {
		Write-SRLog "Group membership claims for app '$($appRegistration.DisplayName)' with ObjectId '$($appRegistration.Id)' are already set to '$($appRegistration.GroupMembershipClaim)'." -PassThru | Write-Output
	}
}

function SetApplicationLogo {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ObjectId,
		[ValidateSet('Service', 'WebApp')]
		[string]$AppType
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	$logo = $null
	if ($AppType -eq 'Service') {
		# Logo Service
		$logo = 'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAsSAAALEgHS3X78AAAIZElEQVR4nO1dPW9TVxh+bwhOalFhpUs7kQ5MrYTpxESNRJdmwEwdMfIPaPgFdX9BnR9gkYxMOANMSDhMTMWR2qUMjSe6lBIRuYlJcqvn+Jg6tu+95+M9x9fxfSQrUZR7z8fj9/u95wZhGFKG9GAh4yJdyAhJGTJCUoaMkJRhMe0T7DaCVSIqDn0K8vfLCpfvyJ8tItojona+GrYdT9kKqfOyJAElIirLnyobr4N9SRA+zXw13HO7Ij2kgpBuIyhIAtaJ6Jrn4XeJaBOffDV853nsMUyVkG4jKEoS7k1tEmexJYlpTWsCUyGk2wigimpE9K33wdUA21ObBjFeCZESUU8xEaPwTowXQqSNgET86HwwN4AqW/dhY5wTItUTjOYVpwO5B7yzSr4aNl2O5JSQbiOoz7BURMGptDghRMYSzSm4sL6wK6WFPchkJ0Qa7paDgC5tgAorcxt81lxWtxFUiOjVHJBBco3P5ZrZwEaInNhDzsnNCB5yksJCyByTMQAbKdaEZGR8BAspVkZdGvBXtpPQQXBplRY+XaVgpUjBUmHileHROwrftun0/R6FB96TubdsDL0xIdK1bfsy4EGuQMt32xRc0osvT9/u0tGTEoU9b4lceF8lU5fYSGXJVEjTpzeVu7mpTQawsHJNXOsR2JNNuUf68zWcZ8130Belnlxfa4hrMomqDW1Cuo2gfA7TIS5wT+6VFrQIkWLoVf5nHNqqS1dCanMShXPhsq7qUiZEuriZqtLHPVmCUIKOhBgZKQ4sXq2I+MMUuBb3mCJqqkMrxSGS4ecc61n4rNjf3N47OnkTHT8h7lj8ep0Wv1qnIMejJcPePh3/Xqfj3+qxccmFL0pEuYIIKk//ZsuwKwWMqoS0OOrg+Jbmbv6fZTnpbFPv5fpYNH3hSplyN+pGcYcKwoOOGPekc7b4hy8Kxr1w5c7Hv/Ve3Kfj1yx+zE6+GiaqrkRCuKQDkrFcHs+yDH9rgYs36rR41U9X0PHrLfrwcl38Dmm8eP2nif932LzOJSmJUqJCyKZt35RK2gPfWqgRRNY+gdQKJCNOLWJuh4+LHOmX7Xw1jI1NYgmRPvQ/trNYut08owZmEVCvR8+047xJ+DKufTXJy7J2TWAgZ50MEnbtTt/Y2yOWVeeEeE7sOQXTWmL3NFJlyfT6nzYjj3pVXIDeP33TEl4S9PrA4AqXOlcQXho+Lrw0Jq8rUm3FEWJdCfzkhz3WTTn9a4c+/FqLjV+GARVz8ZsaLXzO17kKA//vI/MgVeJBvhpODLTjVJaVBetH1zxkwDU+enaXDp+UlMkA8L+4BtfiHhzAmhii/khjFEeIlQWDyuAA1NPho9WxIE4HuBb3wL04wLA2PUKk/TDOV8Cv5/CsOMuvuAfuxUEK1maTW8PeymTtGKIkZOI/q4KjQifUFHMtfEAKh/piWKM/QuD1wPjZoPei4qQxAffEva3ucdDhSKVMFDEnhADCAHe2ja6FN2VjM5KAe2MMs2u3xdoYMPEmUYRYyyMyuEg1HD29pa234dq6hu4Ywp49vSXW5LLXK4oQNsdduJ6Pi9R7+UBJd2PhOq6tzbxU1CrmjGAQa2Ce18Q99naSA1Ls6CZMgktVNQqVsTBnpnqIElJ3tMapB+kYwIck6sIrISopDI8tn0q2gDPtooIxQmRQODUw1rAT4XMsVYwRkrazP+YNqbMhSKGfx7FU4ZUQlWAM9QxfUMlHmQaQpkidhHBliZXG4inJssIbIaLhbSVZRXglRGEszBlzd4CJUXIUIWxyim8hWoByN35R6kBEAcjHNxdjqBTQMGfMHdVP5nlNdPGiCLEOBqCf0f6z9P1z7V4rlF1dQ3cMkIe1YE2WtZABJu5xFCHWDvryWsu4SIVgzKXqwr1NAz6sCWtjgJaEWBHSb6i2q6eLZwodeFyif9eynQdrY3CZ/RESvrePLaG7l9ZarKTgXkvfNVm66fHotSXUCZHRunGdE/ko0+LUMGB7uEgRNm2txdI7jNjEsiayH5URiXN7rRQlVxodG7gMD8fCpuBaeHpcjdzHf1in4yP3No4Qqx1FDcG2rj6AUF+3H/cdBQ3XU7jcay1xLdtDPwcdjvpI5N7GnWxt7UqgTMrZSgrPCK4nNgUS2K/67Z1tJUULkmjwdtNKylRejtzbpMcR2rYHBHC3k04TTG2ku/lqGOmiJaVOrGXTtuUmTWBaS+yeOifkRHSp23tc0wbWwFTyNSdEnry5ZTsD0fSWYOBF8xlT760OMKbK3JikYyvpNFOVbK+1lIgWzpjHwT68+lm02aDNEw9i+gLGwpgYG3OIalMSvVg8tf7EZ/2zx6KHMBOPRVN2cADL2KwHBxCjlJgAkoV0uanEQCIQP/hseBuBknSQZsXQSdlMBf2o3zx3hGunSAbp7J0yIfIMwQ3jKc0vNnTOXzQ5L4vnYb35QEfnJCDSJUT60Ocn9HaPiu5bFLS7TuT7MzLVlYwNk/N7bU4l9RpW21ToGKp7ukAC0cgJMiJEimHZpz1RSb9MAmPaQxX7Ns/4Z0eN88LqVGvieKFLdhj/GdzPV0OrgMe6lVRO4L7tfc4BrMkgrt7ejBQeMoiz2XpOSdnnJIOyl4JZwdqATwL74whygkXfcYpnYG3FmXht3gDn4HWrUdgwDfpU4OPVq2VZBp51FdaRuSmnD7c7f4JK5r5WZzz/tSFVlPOTBrLXd8djR7731tsD7dkL7idjPl5wPwpJTMX2KHNGoAep7lMiRjFVQgaQHhmIqUzhDdO70unY9PEC+ySkgpBhyLNWSjKFXXLgne3LwBXORittR4mkjpBRSIKKQ5+Chu3ZkU+7tgeftJ/lknpC5g2pO1pj3pERkjJkhKQMGSFpAhH9B4daLnmI/0EjAAAAAElFTkSuQmCC'
	}
	else {
		# Logo WebApp
		$logo = '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'
	}

	try {
		$logoFilepath = Join-Path -Path $Script:tempPath -ChildPath 'logo.png'
		$null = New-Item -Path $Script:tempPath -ItemType Directory -Force
		$bytes = [System.Convert]::FromBase64String($logo)
		[System.IO.File]::WriteAllBytes($logoFilepath, $bytes)

		# Update-AzADApplication with LogoInputFile fails => use Graph API
		# https://github.com/Azure/azure-powershell/issues/16865
		# Az.Resources\Update-AzADApplication -ObjectId $ObjectId -LogoInputFile $logoFilepath
		$logoUri = "https://graph.microsoft.com/v1.0/applications/$($ObjectId)/logo"
		$graphToken = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').token
		$header = @{ Authorization = "Bearer $($graphToken)" }
		Invoke-RestMethod -Method Put -Uri $logoUri -Headers $header -ContentType 'image/png' -InFile $logoFilePath
		Write-SRLog "Set $($AppType) logo for application '$($ObjectId)'." -PassThru | Write-Verbose
		Remove-Item -Path $logoFilepath -Force
	}
	catch {
		Write-SRLog "Failed to set $($AppType) logo for application '$ObjectId'." -PassThru | Write-Warning
		$_ | Write-SRLog -PassThru | Write-Warning
	}
}

function AddAzADDirectoryRole {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$ServicePrincipalObjectId,
		[Parameter(Mandatory)]
		[string]$RoleDefinitionId
	)
	<#
		https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
		https://learn.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal#microsoft-graph-api

		RoleDefinitionName = 'Directory Readers' -> RoleTemplateId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'

		POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
		Content-type: application/json
		{
			"@odata.type": "#microsoft.graph.unifiedRoleAssignment",
			"roleDefinitionId": "b0f54661-2d74-4c50-afa3-1ec803f12efe",
			"principalId": "f8ca5a85-489a-49a0-b555-0a6d81e56f0d",
			"directoryScopeId": "/"
		}
	#>
	try {
		"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose

		$graphToken = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').token
		$header = @{ Authorization = "Bearer $($graphToken)" }
		$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId+eq+'$($ServicePrincipalObjectId)'"
		$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $header
		if ($null -ne $response -and $null -ne $response.value) {
			foreach ($value in $response.value) {
				if ($RoleDefinitionId -eq $value.roleDefinitionId) {
					Write-SRLog "Directory Role with DefinitionId '$($RoleDefinitionId)' is already assigned to ServicePrincipal with ObjectId '$($ServicePrincipalObjectId)'." -PassThru | Write-Output
					return
				}
			}
		}
		else {
			throw "Get directory RoleAssignments for ServicePrincipal with ObjectId '$($ServicePrincipalObjectId)' failed."
		}

		$data = @{
			'@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
			roleDefinitionId = $RoleDefinitionId
			principalId      = $ServicePrincipalObjectId
			directoryScopeId = '/'
		}
		$uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
		$body = $data | ConvertTo-Json
		Invoke-RestMethod -Method Post -Uri $uri -Headers $header -ContentType 'application/json' -Body $body | Write-SRLog -PassThru | Write-Output
		Write-SRLog "Add directory role with DefinitionId '$($RoleDefinitionId)' to application with ObjectId '$($ServicePrincipalObjectId)' done." -PassThru | Write-Output
	}
	catch {
		Write-SRLog -LogType Error "Add directory role with DefinitionId '$($RoleDefinitionId)' to application with ObjectId '$($ServicePrincipalObjectId)' failed." -PassThru | Write-Error -ErrorAction Continue
		$e = $_ | Write-SRLog -LogType Error -PassThru
		$e | Write-Error -ErrorAction Stop
	}
}

function AddAzRoleAssignment {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ServicePrincipalObjectId,
		[Parameter(ParameterSetName = 'RoleDefinitionName', Mandatory)]
		[string]$RoleDefinitionName,
		[Parameter(ParameterSetName = 'RoleDefinitionId', Mandatory)]
		[string]$RoleDefinitionId,
		[Parameter(ParameterSetName = 'RoleDefinitionId', Mandatory)]
		[string]$Scope
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose

	if ($PSCmdlet.ParameterSetName -eq 'RoleDefinitionId') {
		Az.Resources\Get-AzRoleDefinition -Id $RoleDefinitionId -ErrorAction Continue | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
		if ($null -eq (Az.Resources\Get-AzRoleAssignment -ObjectId $ServicePrincipalObjectId | Where-Object -Property 'RoleDefinitionId' -EQ $RoleDefinitionId)) {
			# ParameterSet with RoleDefinitionId requires mandatory -Scope Parameter
			Az.Resources\New-AzRoleAssignment -ObjectId $ServicePrincipalObjectId -RoleDefinitionId $RoleDefinitionId -Scope $Scope -ErrorAction Continue | Write-SRLog -PassThru | Write-Output
		}
		else {
			Write-SRLog "RoleAssignment with RoleDefinitionId '$($RoleDefinitionId)' already exists for Service Principal with ObjectId '$($ServicePrincipalObjectId)'." -PassThru | Write-Output
		}
	}
	elseif ($PSCmdlet.ParameterSetName -eq 'RoleDefinitionName') {
		Az.Resources\Get-AzRoleDefinition -Name $RoleDefinitionName -ErrorAction Continue | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
		if ($null -eq (Az.Resources\Get-AzRoleAssignment -ObjectId $ServicePrincipalObjectId | Where-Object -Property 'RoleDefinitionName' -EQ $RoleDefinitionName)) {
			Az.Resources\New-AzRoleAssignment -ObjectId $ServicePrincipalObjectId -RoleDefinitionName $RoleDefinitionName -ErrorAction Continue | Write-SRLog -PassThru | Write-Output
		}
		else {
			Write-SRLog "RoleAssignment with RoleDefinitionName '$($RoleDefinitionName)' already exists for Service Principal with ObjectId '$($ServicePrincipalObjectId)'." -PassThru | Write-Output
		}
	}
}

<#
function RemoveAzureADAppRoleAssignment {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$ServicePrincipalObjectId,
		# default RoleTemplateId 'Directory Readers'
		[string]$RoleTemplateId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'
	)

	$role = AzureAD\Get-AzureADDirectoryRole -Filter "RoleTemplateId eq '$RoleTemplateId'"
	if ($null -ne $role) {
		if ($null -ne (AzureAD\Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object -Property ObjectId -eq $ServicePrincipalObjectId)) {
			AzureAD\Remove-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -MemberId $ServicePrincipalObjectId
			Write-Verbose "Removed role assignment of service principal '$ServicePrincipalObjectId' to directory role '$($role.ObjectId)'."
		}
		else {
			Write-Verbose "Role assignment for service principal '$ServicePrincipalObjectId' to directory role '$($role.ObjectId)' not set. Nothing to remove."
		}
	}
	else {
		Write-Error "AzureAD Directory Role with TemplateID '$RoleTemplateId' not found."
	}
}
#>

function ConfigureAADApplications {
	<#
		.Description
		This function creates the Azure AD applications for the sample in the provided Azure AD tenant and updates the
		configuration files in the client and service project of the visual studio solution (App.Config and Web.Config)
		so that they are consistent with the Applications parameters
	#>
	[CmdletBinding()]
	param (
		# [string]$TenantId,
		# the URIs SHOULD BE lowercase!
		[string]$DnsName,
		# [int]$Port,
		[Parameter(ParameterSetName = 'CertThumbprint', Mandatory)]
		[string]$CertThumbprint,
		# [string]$SSLCertThumbprint
		[Parameter(ParameterSetName = 'CertBase64', Mandatory)]
		[string]$CertBase64
	)

	begin {
		"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
		# Get the user running the script to add the user as the app owner
		#$user = AzureAD\Get-AzureADUser -ObjectId $sessionInfo.Account.Id
		# $user = Az.Resources\Get-AzADUser -UserPrincipalName (Az.Accounts\Get-AzContext).Account.Id
		# Write-SRLog "Run register as user$($user | Out-String)" -PassThru | Write-Output
		(Az.Accounts\Get-AzContext).Account | Out-String | Write-SRLog -PassThru | Write-Output

		# the URIs SHOULD BE lowercase!
		Set-Variable -Name 'baseUri' -Option Constant -Visibility Private -Value "https://$($DnsName)/scriptrunner/"
		Set-Variable -Name 'backendUri' -Option Constant -Visibility Private -Value "https://$($DnsName)/scriptrunner/"
		Write-SRLog "BaseUri: '$baseUri'" -PassThru | Write-Output
		Write-SRLog "BackendUri: '$backendUri'" -PassThru | Write-Output
	}

	process {}

	end {
		# $appConfig = @{}
		# $useAppId = $false
		$serviceAadApplication = $null
		if ($null -eq $serviceAadApplication) {
			#$serviceAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
			$serviceAadApplication = Get-AzADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
		}

		if ($null -eq $serviceAadApplication) {
			# Create the service AAD application
			Write-SRLog "Creating the Azure AD application '$($appNameAPI)'..." -PassThru | Write-Output
			# create the application
			$aadAppArgs = @{
				DisplayName = $appNameAPI
				#HomePage                = $backendUri
				#PublicClient            = $False
				#Oauth2AllowImplicitFlow = $False
			}
			#$serviceAadApplication = AzureAD\New-AzureADApplication @aadAppArgs
			$serviceAadApplication = New-AzADApplication @aadAppArgs
			Write-SRLog "Azure AD Application '$($appNameAPI)' with ObjectId '$($serviceAadApplication.Id)' created." -PassThru | Write-Output
			$null = WaitForAppRegistration -ObjectId $serviceAadApplication.Id
		}
		else {
			Write-SRLog "Azure AD Application '$($appNameAPI)' with ObjectId '$($serviceAadApplication.Id)' already exists." -PassThru | Write-Output
		}

		$serviceIdentifierUri = 'api://' + $serviceAadApplication.AppId
		#-Oauth2AllowImplicitFlow $False -Homepage $backendUri
		Update-AzADApplication -ObjectId $serviceAadApplication.Id -IdentifierUris $serviceIdentifierUri | Write-SRLog -PassThru | Write-Output

		$serviceServicePrincipal = $null
		# if ($useAppId) {
		# 	$serviceServicePrincipal = AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIdApi)'"
		# }
		if ($null -eq $serviceServicePrincipal) {
			$serviceServicePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
		}
		if ($null -eq $serviceServicePrincipal) {
			# create the service principal of the newly created application
			Write-SRLog "Creating Azure AD service principal '$($appNameAPI)'..." -PassThru | Write-Output
			#$serviceServicePrincipal = AzureAD\New-AzureADServicePrincipal -AppId $serviceAadApplication.AppId -Tags { WindowsAzureActiveDirectoryIntegratedApp }
			$serviceServicePrincipal = New-AzADServicePrincipal -ApplicationId $serviceAadApplication.AppId -Tag 'WindowsAzureActiveDirectoryIntegratedApp' -ErrorAction Stop
			Write-SRLog "Azure AD service principal '$($appNameAPI)' with ObjectId '$($serviceServicePrincipal.Id)' created." -PassThru | Write-Output
			$null = WaitForServicePrincipal -ObjectId $serviceServicePrincipal.Id
		}
		else {
			Write-SRLog "Azure AD service principal '$($appNameAPI)' with ObjectId '$($serviceServicePrincipal.Id)' already exists." -PassThru | Write-Output
		}

		# add the user running the script as an app owner if needed
		<# TODO: Is Owner required?
		$owner = AzureAD\Get-AzureADApplicationOwner -ObjectId $serviceAadApplication.ObjectId
		if ($null -eq $owner) {
			AzureAD\Add-AzureADApplicationOwner -ObjectId $serviceAadApplication.ObjectId -RefObjectId $user.ObjectId
			Write-Verbose "'$($user.UserPrincipalName)' added as an application owner to app '$($serviceServicePrincipal.DisplayName)'."
		}
		#>
		<#
		Write-Verbose "Grant 'Microsoft Graph' 'Directory.Read.All' permission for '$appNameAPI'."
		$spMsGraph = Get-AzureADServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'"
		$permission = $spMsGraph.AppRoles | Where-Object -Property Value -eq 'Directory.Read.All'
		GrantApiResourceAccess -AppObjectId $serviceAadApplication.ObjectId -ResourceAppId $spMsGraph.AppId -ResourceAccessType 'Role' -PermissionId $permission.Id
		#>

		Write-SRLog "Assign Directory Role 'Directory Reader' to service principal '$appNameAPI' ..." -PassThru | Write-Output
		AddAzADDirectoryRole -ServicePrincipalObjectId $serviceServicePrincipal.Id -RoleDefinitionId '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'
		Write-SRLog "Assign Azure Role 'Reader' to service principal '$appNameAPI' ..." -PassThru | Write-Output
		#AddAzRoleAssignment -ServicePrincipalObjectId $serviceServicePrincipal.Id -RoleDefinitionId 'acdd72a7-3385-48ef-bd42-f606fba81ae7' -Scope 'TODO'
		AddAzRoleAssignment -ServicePrincipalObjectId $serviceServicePrincipal.Id -RoleDefinitionName 'Reader'

		# accessToken claims config
		Write-SRLog "Setting group membership claims for application '$appNameAPI' ..." -PassThru | Write-Output
		SetGroupMembershipClaims -ObjectId $serviceAadApplication.Id -GroupMembershipClaims 'SecurityGroup'

		# upload AAD thumbprint
		if ($PSCmdlet.ParameterSetName -eq 'CertThumbprint') {
			AddAzureADAppCertCred -AppObjectID $serviceAadApplication.Id -Thumbprint $CertThumbprint
		}
		elseif ($PSCmdlet.ParameterSetName -eq 'CertBase64') {
			AddAzureADAppCertCred -AppObjectID $serviceAadApplication.Id -CertBase64 $CertBase64
		}
		else {
			throw "Invalid ParameterSet $($PSCmdlet.ParameterSetName)."
		}

		# upload application logos
		SetApplicationLogo -ObjectId $serviceAadApplication.Id -AppType 'Service'

		# URL of the AAD application in the Azure portal
		# $servicePortalUrl = "https://portal.azure.com/#@$($tenantName)/blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($serviceAadApplication.AppId)/objectId/$($serviceAadApplication.ObjectId)/isMSAApp/"
		Write-SRLog "Done creating the WebAPI service application '$appNameAPI'." -PassThru | Write-Output

		# if (-not $OnlyService.IsPresent) {
		# $useAppId = $false
		# if ($null -ne $appConfig.clientIDApp) {
		# 	$useAppId = $true
		# 	Write-SRLog "Use Portal ClientID '$($appConfig.clientIDApp)'." -PassThru | Write-Output
		# }

		$spaAadApplication = $null
		# if ($useAppId) {
		# 	$spaAadApplication = Az.Resources\Get-AzADApplication -Filter "Id eq '$($appConfig.clientIdApp)'"
		# }
		if ($null -eq $spaAadApplication) {
			# $spaAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameSPA'" | Select-Object -First 1
			$spaAadApplication = Get-AzADApplication -Filter "DisplayName eq '$appNameSPA'" | Select-Object -First 1
		}

		if ($null -eq $spaAadApplication) {
			# Create the spa AAD application
			Write-SRLog "Creating Azure AD application '$($appNameSPA)'..." -PassThru | Write-Output
			# create the application
			$webApp = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphWebApplication'
			$webApp.ImplicitGrantSetting.EnableAccessTokenIssuance = $false
			$webApp.ImplicitGrantSetting.EnableIdTokenIssuance = $false
			$webApp.HomePageUrl = "$($baseUri)$($appPathSrApp)"
			$aadAppArgs = @{
				DisplayName = $appNameSPA
				HomePage    = $webApp.HomePageUrl
				Web         = $webApp
				#IdentifierUri           = [Uri]::EscapeUriString("https://$($tenantName)/$($appNameSPA)")
				#PublicClient            = $False
				#Oauth2AllowImplicitFlow = $False
				#Oauth2Permissions       = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.OAuth2Permission]'
			}
			#$spaAadApplication = AzureAD\New-AzureADApplication @aadAppArgs
			$spaAadApplication = New-AzADApplication @aadAppArgs
			Write-SRLog "Azure AD Application '$($appNameSPA)' with ObjectId '$($spaAadApplication.Id)' created." -PassThru | Write-Output
			$null = WaitForAppRegistration -ObjectId $spaAadApplication.Id
		}
		else {
			Write-SRLog "Azure AD Application '$($appNameSPA)' with ObjectId '$($spaAadApplication.Id)' already exists." -PassThru | Write-Output
		}

		$spaIdentifierUri = 'api://' + $spaAadApplication.AppId
		#-Oauth2AllowImplicitFlow $False -Homepage $backendUri
		Update-AzADApplication -ObjectId $spaAadApplication.Id -IdentifierUris $spaIdentifierUri | Write-SRLog -PassThru | Write-Output

		# force redirect URIs to lowercase
		$redirectUris = @(
			"$($baseUri)$($appPathAdmin)".ToLowerInvariant(),
			"$($baseUri)$($appPathDelegate)".ToLowerInvariant(),
			"$($baseUri)$($appPathSelfService)".ToLowerInvariant(),
			"$($baseUri)$($appPathSrApp)".ToLowerInvariant()
			# "$($backendUri)$($appPathAdmin)".ToLowerInvariant(),
			# "$($backendUri)$($appPathSrApp)".ToLowerInvariant()
		)
		$myRedirectUris = New-Object -TypeName 'System.Collections.Generic.List[String]'
		foreach ($uri in $spaAadApplication.Spa.RedirectUri) {
			$null = $myRedirectUris.Add($uri)
		}
		foreach ($redirectUri in $redirectUris) {
			if (-not $myRedirectUris.Contains($redirectUri)) {
				Write-SRLog "Add '$($spaAadApplication.DisplayName)' SPA redirect Uri '$($redirectUri)'." | Write-Output
				$myRedirectUris.Add($redirectUri)
			}
			else {
				Write-SRLog "'$($spaAadApplication.DisplayName)' SPA redirect Uri '$($redirectUri)' already exists. Skip." -PassThru | Write-Verbose
			}
		}
		Update-AzADApplication -ObjectId $spaAadApplication.Id -SPARedirectUri $myRedirectUris

		$spaServicePrincipal = $null
		# if ($useAppId) {
		# 	$spaServicePrincipal = AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIdApp)'"
		# }
		if ($null -eq $spaServicePrincipal) {
			# $spaServicePrincipal = AzureAD\Get-AzureADServicePrincipal -Filter "DisplayName eq '$appNameSPA'" | Select-Object -First 1
			$spaServicePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '$appNameSPA'" | Select-Object -First 1
		}
		if ($null -eq $spaServicePrincipal) {
			# create the service principal of the newly created application
			Write-SRLog "Creating Azure AD service principal '$($appNameSPA)'..." -PassThru | Write-Output
			# $spaServicePrincipal = AzureAD\New-AzureADServicePrincipal -AppId $spaAadApplication.AppId -Tags { WindowsAzureActiveDirectoryIntegratedApp }
			$spaServicePrincipal = New-AzADServicePrincipal -ApplicationId $spaAadApplication.AppId -Tag { WindowsAzureActiveDirectoryIntegratedApp }
			Write-SRLog "Azure AD service principal '$($appNameSPA)' with ObjectId '$($spaServicePrincipal.Id)' created." -PassThru | Write-Output
			$null = WaitForServicePrincipal -ObjectId $spaServicePrincipal.Id
		}
		else {
			Write-SRLog "Azure AD service principal '$($appNameSPA)' with ObjectId '$($spaServicePrincipal.Id)' already exists." -PassThru | Write-Output
		}

		# add the user running the script as an app owner if needed
		# TODO: Is Owner required?
		<#
			$owner = AzureAD\Get-AzureADApplicationOwner -ObjectId $spaAadApplication.ObjectId
			if ($null -eq $owner) {
				AzureAD\Add-AzureADApplicationOwner -ObjectId $spaAadApplication.ObjectId -RefObjectId $user.ObjectId
				Write-SRLog "'$($user.UserPrincipalName)' added as an application owner to app '$($spaServicePrincipal.DisplayName)'." -PassThru | Write-Output
			}
			#>

		# URL of the AAD application in the Azure portal
		# $spaPortalUrl = "https://portal.azure.com/#@$($tenantName)/blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/$($spaAadApplication.AppId)/objectId/$($spaAadApplication.ObjectId)/isMSAApp/"
		Write-SRLog "Done creating the SPA application '$($appNameSPA)'." -PassThru | Write-Output

		$requiredResourcesAccess = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphRequiredResourceAccess]'

		# Add Required Resources Access (from 'spa' to 'Microsoft Graph')
		Write-SRLog "Grant 'Microsoft Graph' 'user.read', 'openid', 'profile' permission for '$appNameSPA'." -PassThru | Write-Output
		$requiredPermissions = GetRequiredPermissions -ApplicationDisplayName 'Microsoft Graph' -RequiredDelegatedPermissions 'User.Read|openid|profile'
		$requiredResourcesAccess.Add($requiredPermissions)
		# AzureAD\Set-AzureADApplication -ObjectId $spaAadApplication.ObjectId -RequiredResourceAccess $requiredResourcesAccess -Oauth2AllowImplicitFlow $False
		Update-AzADApplication -ObjectId $spaAadApplication.Id -RequiredResourceAccess $requiredResourcesAccess

		SetApplicationLogo -ObjectId $spaAadApplication.Id -AppType 'WebApp'

		# rename the user_impersonation scope if it exists to match the readme steps or add a new scope
		$scopes = New-Object -TypeName 'System.Collections.Generic.List[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPermissionScope]'
		# add all existing scopes first
		$serviceAadApplication.Api.Oauth2PermissionScope | ForEach-Object { $scopes.Add($_) }
		$scope = $serviceAadApplication.Api.Oauth2PermissionScope | Where-Object { ($_.Value -eq 'user_impersonation') -or ($_.Value -eq 'access_as_user') }
		if ($null -ne $scope) {
			# repair user_impersonation scope
			$scope.Value = 'access_as_user'
		}
		else {
			# Add scope
			$scopeArgs = @{
				Value                   = 'access_as_user'
				UserConsentDisplayName  = "Access $appNameAPI"
				UserConsentDescription  = "Allow the application to access $appNameAPI on your behalf."
				AdminConsentDisplayName = "Access $appNameAPI"
				AdminConsentDescription = 'Allows the app to have the same access to information in the directory on behalf of the signed-in user.'
			}
			$scope = NewPermissionScope @scopeArgs
			$scopes.Add($scope)
			Write-SRLog "Add permission scope $($scope.Value)." -PassThru | Write-Output
		}

		$api = New-Object -TypeName 'Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphApiApplication'
		$api.Oauth2PermissionScope = $scopes
		$api.KnownClientApplication = @($spaServicePrincipal.AppId)
		$api.RequestedAccessTokenVersion = 2
		$api.PreAuthorizedApplication


		# add/update scopes & authorize client application
		# AzureAD\Set-AzureADApplication -ObjectId $serviceAadApplication.ObjectId -OAuth2Permission $scopes -KnownClientApplications @($spaServicePrincipal.AppId)
		Update-AzADApplication -ObjectId $serviceAadApplication.Id -Api $api

		# grant permission to service for webapi
		# You can explore the permissions using
		# $servicePrincipal.AppRoles for application permissions and
		# $servicePrincipal.Oauth2Permissions for delegated permissions.
		Write-SRLog "Grant '$appNameAPI' 'access_as_user' permission for '$appNameSPA'." -PassThru | Write-Output
		# refresh service principal
		$serviceServicePrincipal = Get-AzADServicePrincipal -ObjectId $serviceServicePrincipal.Id
		$permissionScope = $serviceServicePrincipal.Oauth2PermissionScope | Where-Object -Property Value -EQ 'access_as_user'
		GrantApiResourceAccess -AppObjectId $spaAadApplication.Id -ResourceAppId $serviceServicePrincipal.AppId -ResourceAccessType 'Scope' -PermissionScopeId $permissionScope.Id

		Write-SRLog "Set '$($spaAadApplication.DisplayName)' as pre authorized client for '$($serviceAadApplication.DisplayName)'..." -PassThru | Write-Output
		#SetPreAuthorizedApp -ObjectId $serviceAadApplication.Id -ClientObjectId $spaAadApplication.Id -ClientAppId $spaAadApplication.AppId -Scope 'access_as_user' -RequestedAccessTokenVersion 2
		SetPreAuthorizedApp -ObjectId $serviceAadApplication.Id -ClientAppId $spaAadApplication.AppId -Scope 'access_as_user' -RequestedAccessTokenVersion 2
		Write-SRLog "Done authorization of '$appNameSPA' for '$appNameAPI'." -PassThru | Write-Output

		# configure WebApp settings
		# ConfigureWebAppSettings -BackendUri $backendUri -TenantId $TenantId -ClientIDApp $spaAadApplication.AppId -ClientIDApi $serviceAadApplication.AppId

		# add firewall rule
		# AddFirewallRule -LocalPort "$Port"

		# configure service settings
		# Stop-AsrService

		# $stsArgs = @{
		# 	AuthMode          = 'AADv2'
		# 	AADTenant         = $TenantId
		# 	AADAudience       = $serviceAadApplication.AppId
		# 	AADThumbprint     = $AADThumbprint
		# 	SSLCertThumbprint = $SSLCertThumbprint
		# 	LocalPort         = $Port
		# }
		# Set-AsrSTSOptions @stsArgs -Restart

		# Write-Warning ""
		# Write-Warning "------------------------------------------------------------------------------------------------"
		# Write-Warning "IMPORTANT"
		# Write-Warning "Please follow the instructions below to complete a few manual steps in the Azure portal."
		# Write-Warning "For app registration '$($appNameSPA)':"
		# Write-Warning "Open $spaPortalUrl"
		# Write-Warning "- Navigate to the Manifest page, find the 'replyUrlsWithType' section and"
		# Write-Warning "  change the type of all redirect URIs to 'Spa'."
		# Write-Warning "  Optional: set the property 'oauth2AllowIdTokenImplicitFlow' to false."
		# Write-Warning "  Please make sure to save the manifest after you have applied the changes."
		# Write-Warning ""
		# Write-Warning "For app registration '$($appNameAPI)':"
		# Write-Warning "Open $servicePortalUrl"
		# Write-Warning "- Navigate to the Manifest page, find the property 'accessTokenAcceptedVersion' and"
		# Write-Warning "  set it to 2."
		# Write-Warning "  Optional: set the property 'oauth2AllowIdTokenImplicitFlow' to false."
		# Write-Warning "  Please make sure to save the manifest after you have applied the changes."
		# Write-Warning "- Navigate to the API permissions page, and"
		# Write-Warning "  grant admin consent for $($tenant.DisplayName)"
		# Write-Warning "  to permission 'Microsoft Graph' - 'Directory.Read.All'."
		# Write-Warning "------------------------------------------------------------------------------------------------"
		# Write-Warning ""
		# }
		# else {
		# -OnlyService
		# configure service settings
		# Stop-AsrService
		# $stsArgs = @{
		# 	AADTenant     = $TenantId
		# 	AADAudience   = $serviceAadApplication.AppId
		# 	AADThumbprint = $AADThumbprint
		# }
		# Set-AsrSTSOptions @stsArgs -Restart
		# }

		$DeploymentScriptOutputs = @{}
		$DeploymentScriptOutputs.ApplicationNameSPA = $appNameSPA
		$DeploymentScriptOutputs.ApplicationNameAPI = $appNameAPI
		$DeploymentScriptOutputs.ApplicationIdAPI = $serviceServicePrincipal.AppId
		$DeploymentScriptOutputs.ApplicationIdSPA = $spaServicePrincipal.AppId
		$DeploymentScriptOutputs.ObjectIdAzAdAppAPI = $serviceAadApplication.Id
		$DeploymentScriptOutputs.ObjectIdAzAdSpAPI = $serviceServicePrincipal.Id
		$DeploymentScriptOutputs.ObjectIdAzAdAppSPA = $spaAadApplication.Id
		$DeploymentScriptOutputs.ObjectIdAzAdSpSPA = $spaServicePrincipal.Id
	}

	<#
	if ($OpenBrowser.IsPresent) {
		if (-not $OnlyService.IsPresent) {
			Start-Process "$spaPortalUrl"
		}
		Start-Process "$servicePortalUrl"
	}
	DisconnectAzureAD
	#>

	# TODO:
	# Remove id token implicit grant flow
	# Set replyUrlType to 'Spa' for the webapp
	# Set 'accessTokenAcceptedVersion': 2 for the service application
}

<#
function GetWebAppInstallPath {
	[OutputType([string])]
	param()

	$installGuid = '{D65A5939-EC3C-41D7-882D-75677AC64A22}'
	[string]$installPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($installGuid)" -ErrorAction SilentlyContinue |
		Select-Object -ExpandProperty 'InstallLocation'
	if($null -eq $installPath) {
		Write-Warning "ScriptRunner WebApps are not installed. Only the integrated WebApps will be available."
	}

	return $installPath
}
#>

<#
function GrantIntegratedConfigFiles {
	param(
		$configPath,
		$linkPath,
		$configFilename,
		$dbgname
		)

	if(-not (Test-Path -Path $configPath -ErrorAction SilentlyContinue)) {
		Write-Verbose "Create new $($configFilename) for integrated $($dbgname)..."
		New-Item -ItemType Directory -Path $configPath -Force
		$configFilepath = Join-Path -Path $configPath -ChildPath $configFilename
		$appConfig = '{ "$schema": "./app.schema.json" }' | ConvertFrom-Json
		$appConfig | ConvertTo-Json | Out-File -FilePath $configFilePath -Encoding utf8 -Force
		New-Item -ItemType SymbolicLink -Path (Join-Path -Path $linkPath -ChildPath $configFilename) -Value $configFilepath -Force
	}
}
#>

<#
function GetIntegratedPortalConfigPath {
	[OutputType([string])]
	param()

	$configPath = Join-Path -Path $env:ProgramData -ChildPath 'scriptrunner\service\portal'
	$linkPath = Join-Path -Path $env:ProgramFiles -ChildPath 'scriptrunner\service\portal'
	$null = GrantIntegratedConfigFiles -dbgname 'Portal' -configPath $configPath -linkPath $linkPath -configFilename $configFile
	return $configPath
}
#>

<#
function GetIntegratedAdminConfigPath {
	[OutputType([string])]
	param()

	$configPath = Join-Path -Path $env:ProgramData -ChildPath 'scriptrunner\service\admin'
	$linkPath = Join-Path -Path $env:ProgramFiles -ChildPath 'scriptrunner\service\admin'
	$null = GrantIntegratedConfigFiles -dbgname 'Admin App' -configPath $configPath -linkPath $linkPath -configFilename $configFile
	return $configPath
}
#>

<#
function SetAppJson {
	[CmdletBinding()]
	param (
		[string]$Path, # = "${env:ProgramFiles}\ScriptRunner\WebApps\Portal\",
		[string]$BackendUri, # = 'http://localhost:8091/ScriptRunner/',
		# [string]$ReportUri,
		[string]$TenantId,
		[string]$ClientIDApp,
		[string]$ClientIDApi,
		[string[]]$Remove
	)

	$templateFile = "_$($configFile)"
	$templateFilePath = Join-Path -Path $Path -ChildPath $templateFile
	$configFilePath = Join-Path -Path $Path -ChildPath $configFile

	$appConfig = $null
	if (Test-Path -Path $configFilePath) {
		Write-Verbose "Reading '$($configFilePath)'..."
		$appConfig = Get-Content -Path $configFilePath -Force -Raw -Encoding UTF8 | ConvertFrom-Json
	}
	elseif (Test-Path -Path $templateFilePath) {
		Write-Verbose "Reading '$($templateFilePath)'..."
		$appConfig = Get-Content -Path $templateFilePath -Force -Raw -Encoding UTF8 | ConvertFrom-Json
	}
	else {
		Write-Warning "'$($Path)' - the '$configFile' file does not exist at the given path. Start with an empty config."
		$appConfig = '{ "$schema": "./app.schema.json" }' | ConvertFrom-Json
	}

	if ($PSBoundParameters.ContainsKey('Remove')) {
		foreach ($prop in $Remove) {
			if ($appConfig | Get-Member -Name $prop) {
				if ($prop -eq 'baseuri') {
					if ($appConfig | Get-Member -Name '_baseuri_') {
						# backup initial baseuri
						Write-Verbose "Restore baseuri: '$($appConfig._baseuri_)'"
						$appConfig | Add-Member -NotePropertyName 'baseuri' -NotePropertyValue $appConfig._baseuri_ -TypeName 'string' -Force
						$appConfig.PSObject.Properties.Remove('_baseuri_')
					}
				}
				else {
					Write-Verbose "Removing '$($prop): $($appConfig.PSObject.Properties[$prop].Value)'..."
					$appConfig.PSObject.Properties.Remove($prop)
				}
			}
		}
	}

	if ($PSBoundParameters.ContainsKey('BackendUri')) {
		Write-Verbose "Update baseuri: '$($BackendUri)'"
		if ($appConfig | Get-Member -Name 'baseuri') {
			if (-not ($appConfig | Get-Member -Name '_baseuri_')) {
				$appConfig | Add-Member -NotePropertyName '_baseuri_' -NotePropertyValue $appConfig.baseuri -TypeName 'string' -Force
			}
		}
		$appConfig | Add-Member -NotePropertyName 'baseuri' -NotePropertyValue $BackendUri -TypeName 'string' -Force
	}
	else {
		Write-Verbose "Keep baseuri: '$($appConfig.baseuri)'"
	}

	# if ($PSBoundParameters.ContainsKey('ReportUri')) {
	# 	Write-Verbose "Update reporturi: '$($ReportUri)'"
	# 	$appConfig | Add-Member -NotePropertyName 'reporturi' -NotePropertyValue $ReportUri -TypeName 'string' -Force
	# }
	# else {
	# 	if ($appConfig | Get-Member -Name 'reporturi') {
	# 		Write-Verbose "Keep reporturi: '$($appConfig.reporturi)'"
	# 	}
	# 	else {
	# 		$appConfig.baseuri
	# 		$temp = $appConfig.baseuri -split ':'
	# 		$ReportUri = "$($temp[0]):$($temp[1])/scriptrunner/reports"
	# 		Write-Verbose "Set reporturi: '$($ReportUri)'"
	# 		$appConfig | Add-Member -NotePropertyName 'reporturi' -NotePropertyValue $ReportUri -TypeName 'string' -Force
	# 	}
	# }

	if ($PSBoundParameters.ContainsKey('TenantId')) {
		Write-Verbose "Update tenantID: '$($TenantId)'"
		$appConfig | Add-Member -NotePropertyName 'tenantID' -NotePropertyValue $TenantId -TypeName 'string' -Force
	}
	else {
		if ($appConfig.tenantID) {
			Write-Verbose "Keep tenantID: '$($appConfig.tenantID)'"
		}
	}

	if ($PSBoundParameters.ContainsKey('ClientIDApp')) {
		Write-Verbose "Update clientIDApp: '$($ClientIDApp)'"
		$appConfig | Add-Member -NotePropertyName 'clientIDApp' -NotePropertyValue $ClientIDApp -TypeName 'string' -Force
	}
	else {
		if ($appConfig.clientIDApp) {
			Write-Verbose "Keep clientIDApp: '$($appConfig.clientIDApp)'"
		}
	}

	if ($PSBoundParameters.ContainsKey('ClientIDApi')) {
		Write-Verbose "Update clientIDApi: '$($ClientIDApi)'"
		$appConfig | Add-Member -NotePropertyName 'clientIDApi' -NotePropertyValue $ClientIDApi -TypeName 'string' -Force
	}
	else {
		if ($appConfig.clientIDApi) {
			Write-Verbose "Keep clientIDApi: '$($appConfig.clientIDApi)'"
		}
	}

	Write-Verbose "Writing '$($configFilePath)'..."
	$appConfig | ConvertTo-Json | Out-File -FilePath $configFilePath -Encoding utf8 -Force

	if (Test-Path -Path $templateFilePath) {
		Write-Verbose "Removing template '$($templateFilePath)'..."
		Remove-Item -Path $templateFilePath -Force
	}
}
#>

<#
function ConfigureWebAppSettings {
	[CmdletBinding()]
	param (
		[string]$BackendUri,
		[string]$TenantId,
		[string]$ClientIDApp,
		[string]$ClientIDApi
	)

	$installPath = GetWebAppInstallPath
	if($null -ne $installPath) {
		$webApps = @('AdminApp', 'DelegateApp', 'SelfServiceApp', 'Portal')

		foreach ($webApp in $webApps) {
			$appInstallPath = Join-Path -Path $installPath -ChildPath $webApp
			if (Test-Path -Path $appInstallPath -ErrorAction SilentlyContinue) {
				SetAppJson -Path $appInstallPath -BackendUri $BackendUri -TenantId $TenantId -ClientIDApp $ClientIDApp -ClientIDApi $ClientIDApi
			}
			else {
				Write-Warning "$webApp not found at '$appInstallPath'. Skip configuration of '$WebApp'."
			}
		}
	}
	SetAppJson -Path (GetIntegratedPortalConfigPath) -TenantId $TenantId -ClientIDApp $ClientIDApp -ClientIDApi $ClientIDApi
	SetAppJson -Path (GetIntegratedAdminConfigPath) -TenantId $TenantId -ClientIDApp $ClientIDApp -ClientIDApi $ClientIDApi
}
#>

function Register-AsrAzureADApp {
	[CmdletBinding()]
	param (
		# [Parameter(Mandatory)]
		# [string]$TenantID,
		[Parameter(Mandatory)]
		[string]$DnsName,
		# [Parameter(Mandatory)]
		# [Alias('IPPort')]
		# [int]$Port,
		# [Parameter(Mandatory)]
		# [string]$SSLCertThumbprint,
		[Parameter(ParameterSetName = 'CertThumbprint', Mandatory)]
		[string]$AADThumbprint,
		[Parameter(ParameterSetName = 'CertBase64', Mandatory)]
		[string]$CertBase64
		# [ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		# [string]$AzureEnvironmentName = 'AzureCloud'
	)

	$eap = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	try {
		# if (-not $PSBoundParameters.ContainsKey('AADThumbprint')) {
		# 	$AADThumbprint = $SSLCertThumbprint
		# }

		if (-not $PSBoundParameters.ContainsKey('DnsName')) {
			$cs = Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$false
			if ($cs.PartOfDomain) {
				$DnsName = "$($cs.DNSHostName).$($cs.Domain)".ToLowerInvariant()
			}
			else {
				$DnsName = "$($cs.DNSHostName)".ToLowerInvariant()
			}
		}
		else {
			# the URIs SHOULD BE lowercase!
			$DnsName = $DnsName.ToLowerInvariant()
		}

		# configure Azure app registrations
		$configArgs = @{
			#Credential           = $Credential
			#TenantId             = $TenantId
			DnsName = $DnsName
			#Port                 = $Port
			#AADThumbprint        = $AADThumbprint
			#SSLCertThumbprint    = $SSLCertThumbprint
			#AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSCmdlet.ParameterSetName -eq 'CertThumbprint') {
			$configArgs.AADThumbprint = $AADThumbprint

		}
		elseif ($PSCmdlet.ParameterSetName -eq 'CertBase64') {
			$configArgs.CertBase64 = $CertBase64
		}
		else {
			throw "Invalid Parameterset $($PSCmdlet.ParameterSetName)."
		}

		ConfigureAADApplications @configArgs
	}
	catch {
		throw $_
	}
	finally {
		$ErrorActionPreference = $eap
	}
}

<#
function RemoveAADApplications {
	[CmdletBinding()]
	param (
		[PSCredential]$Credential,
		[string]$TenantID,
		[string]$AzureEnvironmentName,
		[ValidateSet('All', 'Portal', 'Service')]
		[string]$App = 'All'
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs

		if (!$TenantID) {
			$sessionInfo = AzureAD\Get-AzureADCurrentSessionInfo -Confirm:$false
			$TenantID = $sessionInfo.TenantId
		}
	}

	process {

		$appConfig = GetWebAppSetting

		# Removes the applications
		Write-Verbose "Cleaning-up ScriptRunner applications from tenant '$tenantName'..."

		if (($PSBoundParameters.App -eq 'All') -or ($PSBoundParameters.App -eq 'Portal')) {
			Write-Verbose "Portal  ClientId: $($appConfig.clientIDApp)"
			if ($null -eq $appConfig.clientIDApp) {
				throw "Portal AppID/ClientID not set in $($configFile)."
			}
			Write-Verbose "Removing app registration '$($appConfig.clientIDApp)' if needed..."
			AzureAD\Get-AzureADApplication -Filter "AppId eq '$($appConfig.clientIDApp)'" |
			ForEach-Object -Process {
				AzureAD\Remove-AzureADApplication -ObjectId $_.ObjectId
				Write-Verbose "Removed '$($_.DisplayName)' app registration."
				}

				# also remove service principals of this apps
				Write-Verbose "Removing service principal '$($appConfig.clientIDApp)' if needed..."
				AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIDApp)'" |
				ForEach-Object -Process {
					AzureAD\Remove-AzureADServicePrincipal -ObjectId $_.ObjectId -Confirm:$false
					Write-Verbose "Removed $($_.DisplayName) service principal."
				}
		}

		if (($PSBoundParameters.App -eq 'All') -or ($PSBoundParameters.App -eq 'Service')) {
			if ($null -eq $appConfig.clientIDApi) {
				if($PSBoundParameters.App -eq 'All'){
					Write-Warning "Service AppID/ClientID not set in $($configFile)."
				}
				$clientIDApi = Get-ItemProperty -Path HKLM:\SOFTWARE\ScriptRunner\Service\STS\ -Name 'AADAudience' -ErrorAction SilentlyContinue |
				Select-Object -ExpandProperty 'AADAudience' -ErrorAction SilentlyContinue
				if ($null -ne $clientIDApi) {
					$appConfig | Add-Member -NotePropertyName 'clientIDApi' -NotePropertyValue $clientIDApi -TypeName 'string' -Force
				}
				if ([string]::IsNullOrEmpty($appConfig.clientIDApi)) {
					throw "Service AppID/ClientID not set in STS-Options."
				}
				Write-Verbose "Service ClientId: $($appConfig.clientIDApi)"
			}
			Write-Verbose "Removing app registration '$($appConfig.clientIDApi)' if needed..."
			AzureAD\Get-AzureADApplication -Filter "AppId eq '$($appConfig.clientIDApi)'" |
				ForEach-Object -Process {
					AzureAD\Remove-AzureADApplication -ObjectId $_.ObjectId
					Write-Verbose "Removed '$($_.DisplayName)' app registration."
				}

				Write-Verbose "Removing service principal '$($appConfig.clientIDApi)' if needed..."
				AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIDApi)'" |
				ForEach-Object -Process {
					AzureAD\Remove-AzureADServicePrincipal -ObjectId $_.ObjectId -Confirm:$false
					Write-Verbose "Removed $($_.DisplayName) service principal."
				}
		}
	}

	end {
		DisconnectAzureAD
	}

}
#>

<#
function Unregister-AsrAzureADApp {
	[CmdletBinding()]
	param (
		[ValidateSet('All', 'Portal', 'Service')]
		[string]$App = 'All',
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID
	)

	$eap = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	try {
		Stop-AsrService

		RemoveAADApplications -Credential $Credential -TenantID $TenantID -AzureEnvironmentName $AzureEnvironmentName -App $App -ErrorAction Stop

		# always remove WebApp settings and remove firewall rule
		RemoveWebAppSettings -Settings @('tenantID', 'clientIDApp', 'clientIDApi', 'baseuri')
		RemoveFirewallRule

		# always set secure token service options OFF and restart service
		if ($App -eq 'Portal') {
			Set-AsrSTSOptions -AuthMode OFF -Restart
		}
		else {
			$stsArgs = @{
				AADTenant     = ''
				AADAudience   = ''
				AADThumbprint = ''
			}
			Set-AsrSTSOptions @stsArgs -AuthMode OFF -Restart
		}
	}
	catch {
		throw $_
	}
	finally {
		$ErrorActionPreference = $eap
		DisconnectAzureAD
	}
}
#>

<#
function Get-AsrAzureADApp {
	[CmdletBinding()]
	param (
		[ValidateSet('All', 'Portal', 'Service')]
		[string]$App = 'All',
		[ValidateSet('AzureAD', 'MsGraph', 'ServicePrincipal')]
		[string[]]$AppType,
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs

		Set-Variable -Name 'nameSPA' -Option Constant -Visibility Private -Value 'Portal'
		Set-Variable -Name 'nameAPI' -Option Constant -Visibility Private -Value 'Service'
	}

	process {
		$AppName = @()
		switch ($App) {
			'Portal' { $AppName = @($nameSPA) }
			'Service' { $AppName = @($nameAPI) }
			Default {
				$AppName = @($nameSPA, $nameAPI)
			}
		}

		if (-not $PSBoundParameters.ContainsKey('AppType')) {
			$AppType = @('AzureAD', 'MsGraph', 'ServicePrincipal')
		}

		$appConfig = GetWebAppSetting
		if ($AppName -contains $nameSPA) {
			if ([string]::IsNullOrEmpty($appConfig.clientIDApp)) {
				throw "Portal AppID/ClientID not set in $($configFile)."
			}
			Write-Verbose "Portal  ClientId: $($appConfig.clientIDApp)"
		}
		if ($AppName -contains $nameAPI) {
			if ([string]::IsNullOrEmpty($appConfig.clientIDApi)) {
				Write-Warning "Service AppID/ClientID not set in $($configFile)."
				$clientIDApi = Get-ItemProperty -Path HKLM:\SOFTWARE\ScriptRunner\Service\STS\ -Name 'AADAudience' -ErrorAction SilentlyContinue |
				Select-Object -ExpandProperty 'AADAudience' -ErrorAction SilentlyContinue
				if ($null -ne $clientIDApi) {
					$appConfig | Add-Member -NotePropertyName 'clientIDApi' -NotePropertyValue $clientIDApi -TypeName 'string' -Force
				}
				if ([string]::IsNullOrEmpty($appConfig.clientIDApi)) {
					throw "Service AppID/ClientID not set in STS-Options."
				}
			}
			Write-Verbose "Service ClientId: $($appConfig.clientIDApi)"
		}

		if ($AppType -contains 'AzureAD') {
			if ($AppName -contains $nameSPA) {
				AzureAD\Get-AzureADApplication -Filter "AppId eq '$($appConfig.clientIDApp)'"
			}
			if ($AppName -contains $nameAPI) {
				AzureAD\Get-AzureADApplication -Filter "AppId eq '$($appConfig.clientIDApi)'"
			}
		}

		if ($AppType -contains 'ServicePrincipal') {
			if ($AppName -contains $nameSPA) {
				AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIDApp)'"
			}
			if ($AppName -contains $nameAPI) {
				AzureAD\Get-AzureADServicePrincipal -Filter "AppId eq '$($appConfig.clientIDApi)'"
			}
		}

		if ($AppType -contains 'MsGraph') {
			if ($AppName -contains $nameSPA) {
				AzureAD\Get-AzureADMSApplication -Filter "AppId eq '$($appConfig.clientIDApp)'"
			}
			if ($AppName -contains $nameAPI) {
				AzureAD\Get-AzureADMSApplication -Filter "AppId eq '$($appConfig.clientIDApi)'"
			}
		}
	}

	end {
		DisconnectAzureAD
	}
}
#>

<#
function Get-AsrAzureADAppCertificate {
	[CmdletBinding()]
	param (
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs
	}

	process {
		$eap = $ErrorActionPreference
		$ErrorActionPreference = 'Stop'
		try {
			$serviceAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
			if ($null -eq $serviceAadApplication) {
				throw "No AzureAD Application with Displayname '$appNameAPI' found in this tenant."
			}
			AzureAD\Get-AzureADApplicationKeyCredential -ObjectId $serviceAadApplication.ObjectId |
			Add-Member -MemberType ScriptProperty -Name Thumbprint -Value {
				[System.Convert]::ToBase64String($this.CustomKeyIdentifier)
			} -PassThru
		}
		catch {
			DisconnectAzureAD
			$ErrorActionPreference = $eap
			throw $_
		}
	}

	end {
		DisconnectAzureAD
	}
}
#>

<#
function New-AsrAzureADAppCertificate {
	[CmdletBinding(SupportsShouldProcess)]
	param (
		[Parameter(Mandatory)]
		[string]$Thumbprint,
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID,
		[Alias('UseForServerAuth')]
		[switch]$UseAsSSLCertificate,
		[switch]$Restart
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs
	}

	process {
		$eap = $ErrorActionPreference
		$ErrorActionPreference = 'Stop'
		try {
			$serviceAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
			if ($null -eq $serviceAadApplication) {
				throw "No AzureAD Application with Displayname '$appNameAPI' found in this tenant."
			}
			AddAzureADAppCertCred -AppObjectID $serviceAadApplication.ObjectId -Thumbprint $Thumbprint
			$stsArgs = @{
				AADThumbprint = $Thumbprint
			}
			if ($PSBoundParameters.ContainsKey('UseAsSSLCertificate')) {
				$stsArgs['SSLCertThumbprint'] = $Thumbprint
			}
			Set-AsrSTSOptions @stsArgs -Restart:$Restart.IsPresent
		}
		catch {
			DisconnectAzureAD
			$ErrorActionPreference = $eap
			throw $_
		}
	}

	end {
		DisconnectAzureAD
	}
}
#>

<#
function Remove-AsrAzureADAppCertificate {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$Thumbprint,
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs
	}

	process {
		$eap = $ErrorActionPreference
		$ErrorActionPreference = 'Stop'
		try {
			$serviceAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
			if ($null -eq $serviceAadApplication) {
				throw "No AzureAD Application with Displayname '$appNameAPI' found in this tenant."
			}
			RemoveAzureADAppCertCred -AppObjectID $serviceAadApplication.ObjectId -Thumbprint $Thumbprint
		}
		catch {
			DisconnectAzureAD
			$ErrorActionPreference = $eap
			throw $_
		}
	}

	end {
		DisconnectAzureAD
	}

}
#>

<#
function Update-AsrAzureADAppCertificate {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string]$NewThumbprint,
		[Parameter(Mandatory)]
		[string]$OldThumbprint,
		[ValidateSet('AzureCloud', 'AzureGermanyCloud', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3', 'AzureChinaCloud', 'AzurePPE')]
		[string]$AzureEnvironmentName = 'AzureCloud',
		[PSCredential]$Credential,
		[string]$TenantID,
		[Alias('UseForServerAuth')]
		[switch]$UseAsSSLCertificate,
		[switch]$Restart
	)

	begin {
		$connectArgs = @{
			AzureEnvironmentName = $AzureEnvironmentName
		}
		if ($PSBoundParameters.ContainsKey('TenantId')) {
			$connectArgs['TenantId'] = $TenantId
		}
		if ($PSBoundParameters.ContainsKey('Credential')) {
			$connectArgs['Credential'] = $Credential
		}
		ConnectAzureAD @connectArgs
	}

	process {
		$eap = $ErrorActionPreference
		$ErrorActionPreference = 'Stop'
		try {
			$serviceAadApplication = AzureAD\Get-AzureADApplication -Filter "DisplayName eq '$appNameAPI'" | Select-Object -First 1
			if ($null -eq $serviceAadApplication) {
				throw "No AzureAD Application with Displayname '$appNameAPI' found in this tenant."
			}
			AddAzureADAppCertCred -AppObjectID $serviceAadApplication.ObjectId -Thumbprint $NewThumbprint
			RemoveAzureADAppCertCred -AppObjectID $serviceAadApplication.ObjectId -Thumbprint $OldThumbprint
			$stsArgs = @{
				AADThumbprint = $NewThumbprint
			}
			if ($PSBoundParameters.ContainsKey('UseAsSSLCertificate')) {
				$stsArgs['SSLCertThumbprint'] = $NewThumbprint
			}
			Set-AsrSTSOptions @stsArgs -Restart:$Restart.IsPresent

		}
		catch {
			DisconnectAzureAD
			$ErrorActionPreference = $eap
			throw $_
		}
	}

	end {
		DisconnectAzureAD
	}
}
#>

function NewSelfSignedAppCert {
	[CmdletBinding(DefaultParameterSetName = 'CertName')]
	param (
		[Parameter(ParameterSetName = 'Subject', Mandatory)]
		$Subject,
		[Parameter(ParameterSetName = 'CertName')]
		$CertName = 'ScriptRunnerService',
		[ValidateSet('LocalMachine', 'CurrentUser')]
		$CertStore = 'LocalMachine'
	)

	"Run '$($PSCmdlet.MyInvocation.MyCommand)' with Parameters$($PSBoundParameters | Out-String)" | Write-SRLog -LogType Verbose -PassThru | Write-Verbose
	if ($PSBoundParameters.ContainsKey('Subject')) {
		$mySubject = $Subject
	}
	else {
		$mySubject = "CN=$($CertName)"
		try {
			$domain = (Get-AzTenant -ErrorAction SilentlyContinue | Select-Object -First 1).DefaultDomain
			if ($null -ne $domain) {
				$mySubject = "CN=$($CertName),O=$($domain)"
			}
		}
		catch { $_ }
	}

	$certArgs = @{
		Subject           = $mySubject
		CertStoreLocation = "Cert:\$($CertStore)\My"
		KeyExportPolicy   = 'Exportable'
		KeySpec           = 'Signature'
		KeyLength         = 2048
		KeyAlgorithm      = 'RSA'
		HashAlgorithm     = 'SHA256'
		KeyUsage          = @('DigitalSignature', 'KeyEncipherment')
	}

	New-SelfSignedCertificate @certArgs
	#$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
}
#endregion functions

trap {
	$ErrorActionPreference = $eap
	$_ | Write-SRLog -LogType Error
	throw $_
}

Register-AsrAzureADApp -DnsName $DnsName -CertBase64 $CertBase64

$ErrorActionPreference = $eap
