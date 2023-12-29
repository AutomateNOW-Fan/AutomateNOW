Using Module .\Classes.psm1
$InformationPreference = 'Continue'

#Region - Utilities

Function Compare-ObjectProperty {
    <#
    .SYNOPSIS
        Compares two objects property by property.
    .DESCRIPTION
        Compares two objects property by property. A simple Compare-Object only compares those properties with the same name in the two objects.
    .PARAMETER ReferenceObject
        The first object to compare
    .PARAMETER DifferenceObject
        The second object to compare
    .EXAMPLE
        $a = New-Object psobject -Prop ([ordered] @{ One = 1; Two = 2})
        $b = New-Object psobject -Prop ([ordered] @{ One = 1; Two = 2; Three = 3})

        Compare-Object $a $b

        # would return $null because it only compares the properties that have common names but

        Compare-ObjectProperty $a $b

        # would return below because it compares the two objects property by property

        PropertyName RefValue DiffValue
        ------------ -------- ---------
        Three 3
    .OUTPUTS
        [psobject]
    .LINK
        https://github.com/riedyw/PoshFunctions
    #>

    #region Parameters
    [CmdletBinding(ConfirmImpact = 'None')]
    [outputtype('psobject')]
    Param(
        [Parameter(Mandatory, HelpMessage = 'First object to compare', Position = 0)]
        [PSObject] $ReferenceObject,
    
        [Parameter(Mandatory, HelpMessage = 'Second object to compare', Position = 1)]
        [PSObject] $DifferenceObject
    )
    #endregion Parameters
    
    begin {
        Write-Verbose -Message "Starting [$($MyInvocation.Mycommand)]"
    }
    
    process {
        $objprops = $ReferenceObject | Get-Member -MemberType Property, NoteProperty | ForEach-Object Name
        $objprops += $DifferenceObject | Get-Member -MemberType Property, NoteProperty | ForEach-Object Name
        $objprops = $objprops | Sort-Object | Select-Object -Unique
        $diffs = @()
        foreach ($objprop in $objprops) {
            $diff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -Property $objprop
            if ($diff) {
                $diffprops = @{
                    PropertyName = $objprop
                    RefValue     = ($diff | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object $($objprop))
                    DiffValue    = ($diff | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object $($objprop))
                }
                $diffs += New-Object -TypeName PSObject -Property $diffprops
            }
        }
        if ($diffs) { return ($diffs | Select-Object -Property PropertyName, RefValue, DiffValue) }
    }
    
    end {
        Write-Verbose -Message "Ending [$($MyInvocation.Mycommand)]"
    }
}

Function ConvertTo-QueryString {
    <#
    Credit for this function: https://www.powershellgallery.com/packages/MSIdentityTools
#>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # Value to convert
        [Parameter(Mandatory = $true)]
        $InputObject,
        [Parameter(Mandatory = $false)]
        [string[]] $IncludeProperties,
        # URL encode parameter names
        [Parameter(Mandatory = $false)]
        [switch] $EncodeParameterNames
    )
    process {
        $QueryString = New-Object System.Text.StringBuilder
        if ($InputObject -is [hashtable]) {
            #-or $InputObject -is [System.Collections.Specialized.OrderedDictionary] -or $InputObject.GetType().FullName.StartsWith('System.Collections.Generic.Dictionary')) {
            foreach ($Item in $InputObject.GetEnumerator()) {
                if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                [string] $ParameterName = $Item.Key
                if ($EncodeParameterNames) { $ParameterName = [System.Net.WebUtility]::UrlEncode($ParameterName) }
                [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.Value))
            }
        }            
        ElseIf ($InputObject.GetType().FullName.StartsWith('ANOW')) {
            foreach ($Item in ($InputObject | Get-Member | Where-Object { $_.MemberType -eq 'Property' } | Select-Object -ExpandProperty Name)) {
                If ($item -in $IncludeProperties) {
                    if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                    [string] $ParameterName = $Item
                    if ($EncodeParameterNames) { $ParameterName = [System.Net.WebUtility]::UrlEncode($ParameterName) }
                    If ($InputObject."$Item" -is [boolean]) {
                        If ($InputObject."$Item" -eq $true) {
                            [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('true'))
                        }
                        Else {
                            [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('false'))
                        }
                    }
                    Else {
                        [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($InputObject."$Item"))
                    }
                    
                }
            }
        }
        elseif ($InputObject -is [object] -and $InputObject -isnot [ValueType]) {
            foreach ($Item in ($InputObject | Get-Member -MemberType Property, NoteProperty)) {
                if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                [string] $ParameterName = $Item.Name
                if ($EncodeParameterNames) { $ParameterName = [System.Net.WebUtility]::UrlEncode($ParameterName) }
                [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($InputObject.($Item.Name)))
            }
        }
        else {
            ## Non-Terminating Error
            $Exception = New-Object ArgumentException -ArgumentList ('Cannot convert input of type {0} to query string.' -f $InputObject.GetType())
            Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ParserError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'ConvertQueryStringFailureTypeNotSupported' -TargetObject $InputObject
            continue
        }
        [string]$Result = $QueryString.ToString()
        [string]$Result = $Result -replace '\+', '%20' -replace 'criteria1', 'criteria' -replace 'criteria2', 'criteria' -replace 'criteria3', 'criteria'
        Write-Output $Result
    }
}

#endregion

#Region - API
Function Invoke-AutomateNOWAPI {
    <#
    .SYNOPSIS
    Invokes the API of an AutomateNOW instance
    
    .DESCRIPTION    
    The `Invoke-AutomateNOWAPI` cmdlet sends API commands (in the form of HTTPS requests) to an instance of AutomateNOW. It returns the results in either JSON or PSCustomObject.
    
    .PARAMETER Command
    Specifies the command to invoke with the API call. The value must begin with a forward slash. For example: /secUser/getUserInfo
    
    .PARAMETER Method
    Specifies the method to use with the API call. Valid values are GET and POST.
    
    .PARAMETER Headers
    Optional hashtable to add headers.
    
    .PARAMETER NotSecure
    Switch parameter to accomodate instances using the http protocol. Only use this if the instance is on http and not https.
    
    .PARAMETER Body
    Specifies the body object. The format will depend on what you have for content type. Usually, this is a string or a hashtable.
    
    .PARAMETER ContentType
    Specifies the content type of the body (only needed if a body is included)
    
    .PARAMETER Instance
    Specifies the name of the AutomateNOW instance. For example: s2.infinitedata.com
    
    .PARAMETER JustGiveMeJSON
    Switch parameter to return the results in a JSON string instead of a PSCustomObject
        
    .PARAMETER NotAPICommand
    Rarely used switch parameter that removes the '/api' portion of the API URL. Note: This parameter is slated for removal
        
    .INPUTS
    None. You cannot pipe objects to Invoke-AutomateNOWAPI (yet).
    
    .OUTPUTS
    PSCustomObject or String is returned
    
    .EXAMPLE
    Invoke-AutomateNOWAPI -command '/secUser/getUserInfo' -method GET
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $false)]
        [switch]$NotSecure = $false,
        [Parameter(Mandatory = $false)]
        [string]$Body,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json',
        [Parameter(Mandatory = $false)]
        [string]$Instance,
        [Parameter(Mandatory = $false)]
        [switch]$JustGiveMeJSON,
        [Parameter(Mandatory = $false)]
        [switch]$NotAPICommand = $false
    )
    If ($anow_session.header.values.count -eq 0 -or $anow_session.Instance.Length -eq 0) {
        Write-Warning -Message "Please use Connect-AutomateNOW to establish your access token."
        Break
    }
    ElseIf ($anow_session.header.Authorization -notmatch '^Bearer [a-zA-Z-_:,."0-9]{1,}$') {
        [string]$malformed_token = $anow_session.header.values
        Write-Warning -Message "Somehow the access token is not in the expected format. Please contact the author with this apparently malformed token: $malformed_token"
        Break
    }
    ElseIf ($command -notmatch '^/.{1,}') {
        Write-Warning -Message "Please prefix the command with a forward slash (for example: /secUser/getUserInfo)."
        Break
    }
    If ($Instance.Length -eq 0) {
        [string]$Instance = $anow_session.Instance
    }
    [hashtable]$parameters = @{}
    If ($NotSecure -eq $true) {
        [string]$protocol = 'http'
    }
    Else {
        [string]$protocol = 'https'
    }
    [int64]$ps_version_major = $PSVersionTable.PSVersion.Major
    If ($ps_version_major -eq 5) {
        $parameters.Add('UseBasicParsing', $true)
    }
    ElseIf ($ps_version_major -gt 5) {
        If ($protocol -eq 'http') {
            $parameters.Add('SkipCertificateCheck', $true)
        }        
    }
    Else {
        Write-Warning -Message "Please use either Windows PowerShell 5.x or PowerShell Core. This module is not compatible with PowerShell 4 or below."
        Break
    }
    If ($NotAPICommand -ne $true) {
        [string]$api_url = ($protocol + '://' + $instance + '/automatenow/api' + $command)
    }
    Else {
        [string]$api_url = ($protocol + '://' + $instance + '/automatenow' + $command)
    }
    $parameters.Add('Uri', $api_url)
    If ($Headers -is [hashtable]) {
        $Headers.Add('domain', $anow_session.header.domain)
        $Headers.Add('Authorization', $anow_session.header.Authorization)
    }
    Else {
        $parameters.Add('Headers', $anow_session.header)
    }
    $parameters.Add('Method', $Method)
    $parameters.Add('ContentType', $ContentType)
    If ($Body.Length -gt 0) {
        Write-Verbose -Message "Sending body: $Body"
        If ($Method -eq 'GET') {
            [string]$api_url = $api_url + '?' + $Body
        }
        Else {
            $parameters.Add('Body', $Body)
        }
    }        
    [string]$parameters_display = $parameters | ConvertTo-Json
    Write-Verbose -Message "Sending the following parameters to $api_url -> $parameters_display."
    $ProgressPreference = 'SilentlyContinue'
    $Error.Clear()
    Try {
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$results = Invoke-WebRequest @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        If ($Message -match '(The underlying connection was closed|The SSL connection could not be established)') {
            Write-Warning -Message 'Please try again with the -NotSecure parameter if you are connecting to an insecure instance.'
            Break
        }
        ElseIf ($Message -match 'Response status code does not indicate success:') {
            $Error.Clear()
            Try {
                [int32]$return_code = $Message -split 'success: ' -split ' ' | Select-Object -Last 1 -Skip 1
            }
            Catch {
                [string]$Message2 = $_.Exception.Message
                Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
            }
        }
        ElseIf ($Message -match 'The remote server returned an error: ') {
            $Error.Clear()
            Try {
                [int32]$return_code = $Message -split '\(' -split '\)' | Select-Object -Skip 1 -First 1
            }
            Catch {
                [string]$Message2 = $_.Exception.Message
                Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
            }
        }
        Else {
            [string]$ReturnCodeWarning = "Invoke-WebRequest failed due to [$Message]"
        }
        [string]$ReturnCodeWarning = Switch ($return_code) {
            401 { "You received HTTP Code $return_code (Unauthorized). HAS YOUR TOKEN EXPIRED? DID YOU REFRESH? :-)" }
            403 { "You received HTTP Code $return_code (Forbidden). DO YOU MAYBE NOT HAVE PERMISSION TO THIS? [$command]" }
            404 { "You received HTTP Code $return_code (Page Not Found). ARE YOU SURE THIS ENDPOINT REALLY EXISTS? [$command]" }
            Default { "You received HTTP Code $return_code instead of '200 OK'. Apparently, something is wrong..." }
        }
        Write-Warning -Message $ReturnCodeWarning
        Break
    }
    $ProgressPreference = 'Continue'
    [string]$content = $Results.Content
    If ($content -notmatch '^{.{1,}}$') {
        Write-Warning -Message "The returned results were somehow not a JSON object."
        Break
    }
    If ($JustGiveMeJSON -eq $true) {
        Return $content
    }
    $Error.Clear()
    Try {
        [PSCustomObject]$content_object = $content | ConvertFrom-JSON
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "ConvertFrom-JSON failed to convert the resturned results due to [$Message]."
        Break
    }
    Return $content_object
}
#endregion

#Region - Authentication

Function Confirm-AutomateNOWSession {
    <#
.SYNOPSIS
Confirms that the local session variable created by Connect-AutomateNOW is still apparently valid.

.DESCRIPTION
The `Confirm-AutomateNOWSession` function confirms that the local session variable created by Connect-AutomateNOW is still apparently valid (not expired yet). This function does not make any network connections. It is only reviewing and advising on the currently stored session variable.

.PARAMETER Quiet
Switch parameter to silence the extraneous output that this outputs by default

.PARAMETER IgnoreEmptyDomain
Switch parameter to ignore the lack of configured domain in the session header. This was intended for development purposes and is likely to be removed in the future.

.PARAMETER DoNotRefresh
Switch parameter to ignore MaximumTokenRefreshAge

.PARAMETER MaximumTokenRefreshAge
int32 parameter to specify the minimum age (in seconds) of the refresh token before updating it occurs automatically. Default is 3300 (meaning that the token will not be refreshed if it is less than 300 seconds old)

.INPUTS
None. You cannot pipe objects to Confirm-AutomateNOWSession (yet).

.OUTPUTS
Returns a boolean $True if the local session variable appears to be valid (not expired yet)

.EXAMPLE
Confirm-AutomateNOWSession -Quiet

.NOTES
You must use Connect-AutomateNOW to establish the token before you can confirm it

#>
    [OutputType([boolean])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreEmptyDomain,
        [Parameter(Mandatory = $false)]
        [switch]$DoNotRefresh,
        [Parameter(Mandatory = $false)]
        [int32]$MaximumTokenRefreshAge = 3300
    )
    If ($anow_session.header.values.count -eq 0) {
        Write-Warning -Message "Please use Connect-AutomateNOW to establish your access token or provide your token through the -AccessToken parameter of Connect-AutomateNOW."
        Break
    }
    ElseIf ($anow_session.header.Authorization -notmatch '^Bearer [a-zA-Z-_/=:,."0-9]{1,}$') {
        [string]$malformed_token = $anow_session.header.values
        Write-Warning -Message "Somehow the access token is not in the expected format. Please contact the author with this apparently malformed token: [$malformed_token]"
        Break
    }
    ElseIf ($anow_session.header.domain.Length -eq 0 -and $IgnoreEmptyDomain -ne $true) {
        Write-Warning -Message 'Please use Switch-AutomateNOWDomain to switch your domain. Use Get-AutomateNOWDomains or include the -Domain parameter with Connect-AutomateNOW'
        Break
    }
    ElseIf ($anow_session.RefreshToken -eq 'Not set') {
        Write-Warning -Message 'This connection is without a refresh token! Please use -RefreshToken with Connect-AutomateNOW to include one.'
        Return $true
    }
    ElseIf ($anow_session.ExpirationDate -isnot [datetime]) {
        Write-Warning -Message 'Somehow there is no expiration date available. Are you debugging at this moment? Make sure that you allow Confirm-AutomateNOWSession to complete.'
        Break
    }
    ElseIf ($anow_session.RefreshToken -notmatch '^[a-zA-Z-_/=:,."0-9]{1,}$' -and $anow_session.RefreshToken.Length -gt 0) {
        [string]$malformed_refresh_token = $anow_session.RefreshToken
        Write-Warning -Message "Somehow the refresh token does not appear to be valid. Please contact the author about this apparently malformed token: [$malformed_refresh_token]"
        Break
    }
    If ($null -eq (Get-Command -Name Invoke-AutomateNOWAPI -EA 0)) {
        Write-Warning -Message 'Somehow the Invoke-AutomateNOWAPI function is not available in this session. Did you install -and- import the module?'
        Break
    }
    If ($anow_session.ExpirationDate -gt (Get-Date -Date '1970-01-01 00:00:00')) {
        [datetime]$current_date = Get-Date
        [datetime]$ExpirationDate = $anow_session.ExpirationDate
        [string]$ExpirationDateDisplay = Get-Date -Date $ExpirationDate -Format 'yyyy-MM-dd HH:mm:ss'
        [timespan]$TimeRemaining = ($ExpirationDate - $current_date)
        [int32]$SecondsRemaining = $TimeRemaining.TotalSeconds
        If ($SecondsRemaining -lt 0) {
            If ($SecondsRemaining -lt -86400) {
                [int32]$DaysRemaining = ($SecondsRemaining / -86400)
                Write-Warning -Message "This token expired about [$DaysRemaining] day(s) ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            ElseIf ($SecondsRemaining -lt -3600) {
                [int32]$HoursRemaining = ($SecondsRemaining / -3600)
                Write-Warning -Message "This token expired about [$HoursRemaining] hour(s) ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            ElseIf ($SecondsRemaining -lt -60) {
                [int32]$MinutesRemaining = ($SecondsRemaining / -60)
                Write-Warning -Message "This token expired about [$MinutesRemaining] minute(s) ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            Else {
                Write-Warning -Message "This token expired [$SecondsRemaining] second(s) ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
        }
        ElseIf (($SecondsRemaining -lt $MaximumTokenRefreshAge) -and ($DoNotRefresh -ne $true)) {
            [int32]$minutes_elapsed = ($TimeRemaining.TotalMinutes)
            Write-Verbose -Message "This token will expire in [$minutes_elapsed] minutes. Refreshing your token automatically. Use -DoNotRefresh with Connect-AutomateNOW to stop this behavior."
            Update-AutomateNOWToken
        }
        Else {
            Write-Verbose -Message "Debug: This token still has [$SecondsRemaining] seconds remaining"
        }
    }
    Else {
        Write-Warning -Message "This token has an unknown expiration date because you used -AccessToken without including -RefreshToken :|"
    }
    Return $true
}

Function Connect-AutomateNOW {
    <#
.SYNOPSIS
Connects to the API of an AutomateNOW! instance

.DESCRIPTION
The `Connect-AutomateNow` function authenticates to the API of an AutomateNOW! instance. It then sets the access token globally.

.PARAMETER Instance
Specifies the name of the AutomateNOW! instance. For example: s2.infinitedata.com

.PARAMETER Domain
Optional string to set the AutomateNOW domain manually. If you do not specify, then you will (likely) need to use Switch-AutomateNOWDomain

.PARAMETER AccessToken
Optionally specify the access token manually. This is normally copy/pasted from your web browser. This is intended for use when development testing. For best results, combine with -RefreshToken and -ExpirationDate

.PARAMETER RefreshToken
Optionally specify the refresh token manually. This is normally copy/pasted from your web browser. You don't need to include this if you use -AccessToken but it helps.

.PARAMETER ExpirationDate
Int64 representing the current date in UNIX time milliseconds. You don't need to include this if you use -AccessToken but it helps.

.PARAMETER ReadJSONFromClipboard
Switch parameter that will enable reading the JSON payload from the clipboard. You must have a valid authentication JSON payload in your clipboard for this to work (hint: You can copy it from your web browser after you've logged in). This parameter is useful for one-off usages where entering the password into the PowerShell prompt is undesireable.

.PARAMETER User
Specifies the user connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it.

.PARAMETER Pass
Specifies the password for connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it.

.PARAMETER NotSecure
Switch parameter to accomodate instances that use the http protocol (typically on port 8080)
    
.PARAMETER Quiet
Switch parameter to silence the output of the access token (note that this parameter overrides -SkipMOTD)

.PARAMETER SkipMOTD
Switch parameter to silence the "message of the day". This parameter is ignored if -Quiet is set.

.PARAMETER SkipPreviousSessionCheck
Switch parameter to override the requirement to disconnect from a previous session before starting a new session on a different instance

.PARAMETER Key
Optional 16-byte array for when InfiniteDATA has changed their encryption key. Let's hope we don't need to use this :-)

.INPUTS
None. You cannot pipe objects to Connect-AutomateNOW (yet).

.OUTPUTS
There is no direct output. Rather, a global variable $anow_session.header with the bearer access token is set in the current powershell session.

.EXAMPLE
Example 1 (You will be prompted for credential, just like the UI) *RECOMMENDED*
Connect-AutomateNOW -Instance 's2.infinitedata.com'

Example 2 (You will logon to the AutomateNOW UI and copy the authentication JSON payload into your clipboard)
Connect-AutomateNOW -Instance 's2.infinitedata.com' -ReadJSONFromClipboard

Example 3 (You will provide the access token, refresh token and expiration date typically sourced from your web browser after logging on that way)
Connect-AutomateNOW -Instance 's2.infinitedata.com' -AccessToken 'ey...' -RefreshToken 'ey...' -ExpirationDate 1700000000000

Example 4 (You will provide only the access token without an accompanying refresh or expiration date)
Connect-AutomateNOW -Instance 's2.infinitedata.com' -AccessToken 'ey...'

Example 5 (Shows how to connect to an insecure instance and also how to skip the check if a previous session already exists)
Connect-AutomateNOW -Instance 'blah-blah.azure.com' -NotSecure -Domain 'Test' -SkipPreviousSessionCheck

Example 6 (Shows how to enter an alternate encryption key array)
Connect-AutomateNOW -Instance 's2.infinitedata.com' -Key [byte[]]@(7, 22, 15, 11, 1, 24, 8, 13, 16, 10, 5, 17, 12, 19, 27, 9)

Example 7 (You will supply the user and password on the commandline. This is not secure because your password will be logged in your command line history. This is only here for convenience in a training instance!) *NOT RECOMMENDED*
Connect-AutomateNOW -Instance 's2.infinitedata.com' -User 'user.10' -Pass '********' -Domain 'Test' -Quiet

.NOTES
1. You only need to specify the -Instance parameter. You -should- specify the -Domain parameter as well, otherwise you will need to immediately use Switch-Domain.
1. The -User and -Pass parameters really should be removed as using them would put your credential into your command history. However, they are still available in case that approach is still desireable.
2. If you're going to use -AccessToken then you *should* include -RefreshToken and -ExpirationDate as well (but you don't have to).
3. The -ReadJSONFromClipboard parameter is mainly intended for demonstration purposes to speed things up and not have to worry about typing mistakes.
4. Just like the console does, this module will auto-refresh your token. The difference is that the console will refresh if your token is at least 1 second old whereas this module refreshes after 300 seconds (See Update-AutomateNOWToken for more info)
5. Always use Disconnect-AutomateNOW after you have concluded your session

#>
    [OutputType([string])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Clipboard')]
        [string]$Instance,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [string]$Domain,
        [ValidateScript({ $_ -match '^ey[a-zA-Z0-9_.-]{4,}$' })]
        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,
        [ValidateScript({ $_ -match '^ey[a-zA-Z0-9_.-]{4,}$' })]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [string]$RefreshToken,
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [int64]$ExpirationDate = 0,
        [Parameter(Mandatory = $true, ParameterSetName = 'Clipboard')]
        [switch]$ReadJSONFromClipboard,
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectCredential')]
        [string]$User,
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectCredential')]
        [string]$Pass,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [switch]$NotSecure,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [switch]$Quiet,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [switch]$SkipMOTD,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [switch]$SkipPreviousSessionCheck,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [byte[]]$Key = @(7, 22, 15, 11, 1, 24, 8, 13, 16, 10, 5, 17, 12, 19, 27, 9)
    )
    Function New-ANowAuthenticationPayload {
        [OutputType([string])]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [string]$User,
            [Parameter(Mandatory = $true)]
            [string]$Pass,
            [Parameter(Mandatory = $false)]
            [boolean]$SuperUser = $false,
            [Parameter(Mandatory = $false)]
            [byte[]]$Key = @(7, 22, 15, 11, 1, 24, 8, 13, 16, 10, 5, 17, 12, 19, 27, 9)
        )
        [byte[]]$passwd_array = [System.Text.Encoding]::UTF8.GetBytes($pass)
        [byte[]]$encrytped_array = For ($i = 0; $i -lt ($passwd_array.Length); $i++) {
            [byte]$current_byte = $passwd_array[$i]
            [int32]$first = (-bnot $current_byte -shr 0) -band 0x0f
            [int32]$second = (-bnot $current_byte -shr 4) -band 0x0f
            $Key[$first]
            $Key[$second]
        }
        [string]$encrypted_string = [System.Convert]::ToBase64String($encrytped_array)
        [hashtable]$payload = @{}
        $payload.Add('j_username', $user)
        $payload.Add('j_password', "ENCRYPTED::$encrypted_string")
        $payload.Add('superuser', $superuser)
        [string]$payload_json = $payload | ConvertTo-Json -Compress
        Write-Verbose -Message "Sending payload $payload_json"
        Return $payload_json
    }
    Function New-ANOWAuthenticationProperties {
        [OutputType([hashtable])]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [string]$User,
            [Parameter(Mandatory = $true)]
            [string]$Pass
        )
        [string]$body = New-ANOWAuthenticationPayload -User $User -Pass $Pass
        [string]$login_url = ($protocol + '://' + $instance + '/automatenow/api/login/authenticate')
        [hashtable]$parameters = @{}
        [int32]$ps_version_major = $PSVersionTable.PSVersion.Major
        If ($ps_version_major -eq 5) {
            # The below C# code provides the equivalent of the -SkipCertificateCheck parameter for Windows PowerShell 5.1 Invoke-WebRequest
            If (($null -eq ("TrustAllCertsPolicy" -as [type])) -and ($protocol -eq 'http')) {
                [string]$certificate_policy = @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                $Error.Clear()
                Try {
                    Add-Type -TypeDefinition $certificate_policy
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Add-Type failed due to [$Message]"
                    Break
                }
                $Error.Clear()
                Try {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
                }
                Catch {
                    [string]$Message = $_.Exception.Message                
                    Write-Warning -Message "New-Object failed to create a new 'TrustAllCertsPolicy' CertificatePolicy object due to [$Message]."
                    Break
                }
            }
            $parameters.Add('UseBasicParsing', $true)
        }
        ElseIf ( $ps_version_major -gt 5) {
            $parameters.Add('SkipCertificateCheck', $true)
        }
        Else {
            Write-Warning -Message "Please use either Windows PowerShell 5.1 or PowerShell Core."
            Break
        }
        $parameters.Add('Uri', $login_url)
        $parameters.Add('Method', 'POST')
        $parameters.Add('Body', $body)
        $parameters.Add('ContentType', 'application/json')
        $Error.Clear()
        Try {
            [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$results = Invoke-WebRequest @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            If ($Message -match '(The underlying connection was closed|The SSL connection could not be established)') {
                Write-Warning -Message 'Please try again with the -NotSecure parameter if you are connecting to an insecure instance.'
                Break
            }
            ElseIf ($Message -match 'Response status code does not indicate success:') {
                $Error.Clear()
                Try {
                    [int32]$return_code = $Message -split 'success: ' -split ' ' | Select-Object -Last 1 -Skip 1
                }
                Catch {
                    [string]$Message2 = $_.Exception.Message
                    Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                }
            }
            ElseIf ($Message -match 'The remote server returned an error: ') {
                $Error.Clear()
                Try {
                    [int32]$return_code = $Message -split '\(' -split '\)' | Select-Object -Skip 1 -First 1
                }
                Catch {
                    [string]$Message2 = $_.Exception.Message
                    Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                }
            }
            Else {
                [string]$ReturnCodeWarning = "Invoke-WebRequest failed due to [$Message]"
            }
            [string]$ReturnCodeWarning = Switch ($return_code) {
                401 { "You received HTTP Code $return_code (Unauthorized). DID YOU MAYBE ENTER THE WRONG PASSWORD? :-)" }
                403 { "You received HTTP Code $return_code (Forbidden). DO YOU MAYBE NOT HAVE PERMISSION TO THIS? [$command]" }
                404 { "You received HTTP Code $return_code (Page Not Found). ARE YOU SURE THIS ENDPOINT REALLY EXISTS? [$command]" }
                Default { "You received HTTP Code $return_code instead of '200 OK'. Apparently, something is wrong..." }
            }
            Write-Warning -Message $ReturnCodeWarning
            Break
        }
        [string]$content = $Results.Content
        If ($content -notmatch '^{"token_type":"Bearer","access_token":"[a-zA-Z-_:,."0-9]{1,}"}$') {
            [string]$content = "The returned content does not contain a bearer token. Please check the credential you are using."
        }
        Write-Verbose -Message "`r`nToken properties: $content`r`n"
        $Error.Clear()
        Try {
            [PSCustomObject]$token_properties = $content | ConvertFrom-Json
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "ConvertFrom-Json or Select-Object failed due to [$Message]."
            Break
        }
        Return $token_properties
    }
    If ($NotSecure -eq $true) {
        [string]$protocol = 'http'
    }
    Else {
        [string]$protocol = 'https'
    }
    If (($null -ne $anow_session.ExpirationDate) -and ($Instance -ne $anow_session.Instance) -and ($SkipPreviousSessionCheck -ne $true)) {
        [datetime]$current_date = Get-Date
        [datetime]$expiration_date = $anow_session.ExpirationDate
        [timespan]$TimeRemaining = ($expiration_date - $current_date)
        [int32]$SecondsRemaining = $TimeRemaining.TotalSeconds
        If ($SecondsRemaining -gt 60) {
            [string]$AlreadyConnectedInstance = ($anow_session.Instance)
            Write-Warning -Message "Please use Disconnect-AutomateNOW to terminate your previous connection to $AlreadyConnectedInstance (Use -SkipPreviousSessionCheck to override this)"
            Break
        }
    }
    ElseIf ($null -ne $anow_session) {
        $Error.Clear()
        Try {
            Remove-Variable -Name anow_session -Scope Global -Force
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Remove-Variable failed to remove the `$anow_session variable due to [$Message]."
            Break
        }
    }
    If ($ReadJSONFromClipboard -eq $true) {
        $Error.Clear()
        Try {
            If ($null -eq (Get-Clipboard)) {
                Write-Warning "The clipboard cannot be read. Please use a different parameter set or fill up your clipboard with the authentication JSON payload."
                Break
            }
            Else {
                [string]$Clipboard = Get-Clipboard
                If ($Clipboard -notmatch '[0-9a-zA-Z \n{}":,_.-]{1,}(?:"expires_in")[0-9a-zA-Z \n{}":,_.-]{1,}') {
                    Write-Verbose -Message "The contents of the clipboard are: $Clipboard"
                    Write-Warning "The contents of the clipboard do not appear to be a valid JSON authentication payload"
                    Break
                }
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-Clipboard failed to read the clipboard due to [$Message]."
            Break
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$AuthenticationObject = $Clipboard | ConvertFrom-Json
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "ConvertFrom-Json failed to convert the contents of the clipboard due to [$Message]."
            Break
        }
        If ($AuthenticationObject.token_type -ne 'Bearer') {
            Write-Warning -Message "Somehow the authentication object that was extracted from the clipboard does not include the Token Type. This is fatal."
            Break
        }
        ElseIf ($AuthenticationObject.expires_in -isnot [int32]) {
            Write-Warning -Message "Somehow the authentication object that was extracted from the clipboard does not have a valid expires_in property. This is fatal."
            Break
        }
        ElseIf ($AuthenticationObject.expirationDate -isnot [int64]) {
            Write-Warning -Message "Somehow the authentication object that was extracted from the clipboard does not have a valid expirationDate property. This is fatal."
            Break
        }
        [string]$AccessToken = $AuthenticationObject.access_token
        [string]$RefreshToken = $AuthenticationObject.refresh_token
        [int64]$ExpirationDate = $AuthenticationObject.expirationDate
    }    
    If ($AccessToken.Length -eq 0) {
        If ($User.Length -eq 0 ) {
            $Error.Clear()
            Try {
                [string]$User = Read-Host -Prompt 'Please enter username (e.g. jsmith)'
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Read-Host failed to receive the current username due to [$Message]."
                Break
            }
        }
        If ($Pass.Length -eq 0 ) {        
            If ($ps_version_major -gt 5) {
                $Error.Clear()
                Try {
                    [string]$Pass = Read-Host -Prompt 'Please enter password (e.g. ******)' -MaskInput
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Read-Host failed to receive the current password on PowerShell Core due to [$Message]."
                    Break
                }
            }
            Else {
                $Error.Clear()
                Try {
                    [securestring]$SecurePass = Read-Host -Prompt 'Please enter password (e.g. ******)' -AsSecureString
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Read-Host failed to receive the current password on Windows PowerShell due to [$Message]."
                    Break
                }
                $Error.Clear()
                Try {
                    [string]$Pass = [System.Net.NetworkCredential]::new("", $SecurePass).Password
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "The 'new' constructor of the System.Net.NetworkCredential class failed to convert a secure string to plain text due to [$Message]."
                    Break
                }
                $Error.Clear()
                Try {
                    [PSCustomObject]$token_properties = New-ANOWAuthenticationProperties -User $User -Pass $Pass
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning "New-ANOWAuthenticationProperties failed due to [$Message]."
                    Break
                }
                If ( $token_properties.expirationDate -isnot [int64]) {
                    Write-Warning -Message "How is it that the expiration date value is not a 64-bit integer? Something must be wrong. Are we in a time machine?"
                    Break
                }
                [string]$access_token = $token_properties.access_token
                [string]$refresh_token = $token_properties.refresh_token
            }
        }
    }
    Else {
        [string]$access_token = $AccessToken
        If ($RefreshToken.Length -gt 0) {
            [string]$refresh_token = $RefreshToken
        }
        Else {
            [string]$refresh_token = 'Not set'
        }
    }
    $Error.Clear()
    Try {
        [System.TimeZoneInfo]$timezone = Get-TimeZone
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Get-TimeZone failed due to get the time zone due to [$Message]."
        Break
    }
    [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    If ($refresh_token -ne 'Not set' -and $ExpirationDate -eq 0) {
        $Error.Clear()
        Try {
            [datetime]$expiration_date_utc = (Get-Date -Date '1970-01-01').AddMilliseconds($token_properties.expirationDate)
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Get-Date failed due to process the expiration date from the `$token_properties variable due to [$Message]"
            Break
        }
        [datetime]$expiration_date = ($expiration_date_utc + $utc_offset) # We're adding 2 values here: the current time in UTC and the current machine's UTC offset
    }
    Else {
        If ($ExpirationDate -gt 0) {
            $Error.Clear()
            Try {
                [datetime]$expiration_date_utc = (Get-Date -Date '1970-01-01').AddMilliseconds($ExpirationDate)
            }
            Catch {
                Write-Warning "Get-Date failed due to process the expiration date from the `$ExpirationDate variable due to [$Message]"
                Break
            }
            [datetime]$Current_Date_UTC = (Get-Date).ToUniversalTime()
            [timespan]$Remaining_Time = ($Current_Date_UTC - $expiration_date_utc)
            [datetime]$expiration_date = ($expiration_date_utc + $utc_offset) # We're adding 2 values here: the current time in UTC and the current machine's UTC offset
            If ($Remaining_Time.TotalSeconds -gt 0) {
                [int32]$remaining_minutes = $Remaining_Time.TotalMinutes
                [string]$display_date = $expiration_date.ToString()
                Write-Warning -Message "This token expired about [$remaining_minutes] minute(s) ago at [$display_date]. Please re-authenticate to obtain a new one."
                Break
            }
        }
        Else {
            [datetime]$expiration_date = Get-Date -Date '1970-01-01'
        }        
    }
    [hashtable]$anow_session = @{}
    $anow_session.Add('User', $User)
    $anow_session.Add('Instance', $Instance)
    If ($NotSecure -eq $true) {
        $anow_session.Add('NotSecure', $True)
    }    
    $anow_session.Add('ExpirationDate', $expiration_date)
    $anow_session.Add('AccessToken', $access_token)
    $anow_session.Add('RefreshToken', $refresh_token)
    [hashtable]$Header = @{'Authorization' = "Bearer $access_token"; 'domain' = ''; }
    If ($Domain.Length -gt 0) {
        $Header['domain'] = $Domain
    }
    $anow_session.Add('header', $Header)
    Write-Verbose -Message 'Global variable $anow_session.header has been set. Refer to this as your authentication header.'
    $Error.Clear()
    Try {
        [PSCustomObject]$userInfo = Get-AutomateNOWUser
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Get-AutomateNOWUser failed to get the currently logged in user info due to [$Message]."
        Break
    }
    If ($userInfo.domains.length -eq 0) {
        Write-Warning "Somehow the user info object is malformed."
        Break
    }
    [string]$userName = $userInfo.id
    If ($userName.Length -eq 0) {
        Write-Warning -Message "Somehow the username property is not present from the user object. This is fatal."
        Break
    }
    $anow_session['User'] = $userName
    [array]$domains = $userInfo.domains -split ','
    [int32]$domain_count = $domains.Count
    Write-Verbose -Message "Detected $domain_count domains"
    If ($domain_count -gt 0) {
        $anow_session.Add('domains', $domains)
    }
    Else {
        Write-Warning "Somehow the count of domains is zero."
        Break
    }
    If ($domain_count -eq 1) {
        If ($Domain.Length -eq 0) {
            [string]$Domain = $domains
            If ($null -ne $anow_session.header.Domain) {
                $anow_session.header.Remove('domain')
            }
            $anow_session.header.Add('domain', $Domain)
            Write-Verbose -Message "Automatically choosing the [$Domain] domain as it is the only one available."
        }
        ElseIf ($userInfo.domains -ne $Domain) {
            Write-Warning -Message "The domain you chose with -Domain is not the same as the one on [$instance]. Are you sure you entered the domain correctly?"
            Break
        }
    }    
    Else {
        If ($domains -contains $Domain) {
            If ($Domain.Length -gt 0) {
                $anow_session.header['domain'] = $Domain
            }
            Else {
                Write-Warning -Message "The domain you chose with -Domain is not available on [$instance]. Are you sure you entered the domain correctly?"
                Break
            }
        }
        Else {
            Write-Verbose -Message "Proceeding without a domain selected"
        }
    }
    $anow_session.Add('protocol', $protocol)
    $Error.Clear()
    Try {
        New-Variable -Name 'anow_session' -Scope Global -Value $anow_session
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "New-Variable failed due to create the session properties object due to [$Message]"
        Break
    }
    Write-Verbose -Message 'Global variable $anow_session has been set. Use this for other session properties.'
    If ($Quiet -ne $true) {
        If ($SkipMOTD -ne $true) {
            Import-AutomateNOWTimeZone
            [string]$home_url = ($protocol + '://' + $instance + '/automatenow')
            $Error.Clear()
            Try {
                [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$results = Invoke-WebRequest -UseBasicParsing -Uri $home_url
            }
            Catch {
                [string]$Message = $_.Exception.Message
                If ($Message -match '(The underlying connection was closed|The SSL connection could not be established)') {
                    Write-Warning -Message 'Please try again with the -NotSecure parameter if you are connecting to an insecure instance.'
                    Break
                }
                ElseIf ($Message -match 'Response status code does not indicate success:') {
                    $Error.Clear()
                    Try {
                        [int32]$return_code = $Message -split 'success: ' -split ' ' | Select-Object -Last 1 -Skip 1
                    }
                    Catch {
                        [string]$Message2 = $_.Exception.Message
                        Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                    }
                }
                ElseIf ($Message -match 'The remote server returned an error: ') {
                    $Error.Clear()
                    Try {
                        [int32]$return_code = $Message -split '\(' -split '\)' | Select-Object -Skip 1 -First 1
                    }
                    Catch {
                        [string]$Message2 = $_.Exception.Message
                        Write-Warning -Message "Unable to extract the error code from [$Message] due to [$Message2]"
                    }
                }
                Else {
                    [string]$ReturnCodeWarning = "Invoke-WebRequest failed (on the home page!) due to [$Message]"
                }
                [string]$ReturnCodeWarning = Switch ($return_code) {
                    401 { "You received HTTP Code $return_code (Unauthorized). DID YOU MAYBE ENTER THE WRONG PASSWORD? :-)" }
                    403 { "You received HTTP Code $return_code (Forbidden). DO YOU MAYBE NOT HAVE PERMISSION TO THIS? [$command]" }
                    404 { "You received HTTP Code $return_code (Page Not Found). ARE YOU SURE THIS ENDPOINT REALLY EXISTS? [$command]" }
                    Default { "You received HTTP Code $return_code instead of '200 OK'. Apparently, something is wrong..." }
                }
                Write-Warning -Message $ReturnCodeWarning
                Break
            }
            If ($results.StatusCode -eq 200) {
                $Error.Clear()
                Try {
                    [PSCustomObject]$instance_info = (($results | Select-Object -ExpandProperty content) -split "`n" | Where-Object { $_ -match '^\s{0,8}{"licenseInfo":.{1,}' } | Select-Object -First 1) | ConvertFrom-Json
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning "Failed due to parse the results of the home page details object due to [$Message]"
                    Break
                }
                If ($Null -eq $instance_info.licenseInfo) {
                    Write-Warning -Message "Somehow the response from the instance info request was empty!"
                    Break
                }
                [string]$licenseInfo = $instance_info.licenseInfo
                [array]$timeZones = $instance_info.timeZones
                If ($licenseInfo -notmatch '^@{') {
                    Write-Warning -Message "Somehow the instance information was invalid."
                    Break
                }
                $Error.Clear()
                Try {
                    [PSCustomObject]$instance_info_object = $licenseInfo -replace '@{' -replace '}', ';' -split ';' | ForEach-Object { $_.trim() } | ForEach-Object { [PSCustomobject]@{name = ($_ -split '=' | Select-Object -First 1); value = ($_ -split '=' | Select-Object -First 1 -Skip 1) } } | Where-Object { $_.name.length -gt 0 }
                    [hashtable]$instance_info_table = @{}
                    ForEach ($info in $instance_info_object) {
                        $instance_info_table.Add(($info.name), ($info.value))
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the instance information into a valid object due to [$Message]. We were so close! Did something change in InfiniteDATA's code? :-)"
                    Break
                }
                $Error.Clear()
                [string[]]$timezones_split = $timeZones -split ','
                Try {
                    [ANOWTimeZone[]]$available_timezones = ForEach ($zone in $timezones_split) {
                        $anow_session.supported_timezones | Where-Object { $_.id -eq $zone }
                    } 
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the available time zones from [$Instance] into an array of valid ANOWTimeZone class objects due to [$Message]. We were so close! Did something change in InfiniteDATA's code? :-)"
                    Break
                }
                [int32]$available_timezones_count = $available_timezones.count
                If ($available_timezones_count -gt 0) {
                    Write-Verbose -Message "[$Instance] has [$available_timezones_count] available timezones to choose from"
                }
                Else {
                    Write-Warning -Message "Somehow there are no timezones available from this instance. Something must be wrong."
                    Break
                }
                $anow_session.Add('available_timezones', $available_timezones)
                $anow_session.Add('instance_info', $instance_info_table)
                [string]$applicationVersion = $anow_session.instance_info.applicationVersion
                [string]$application = $anow_session.instance_info.application
                [string]$motd_message = "`r`nWelcome to $application version $applicationVersion"
                Write-Information -MessageData $motd_message
            }
            Else {
                If ($null -eq $results.StatusCode) {
                    Write-Warning -Message "The results were empty. There must be a bigger problem..."
                    Break
                }
                Else {
                    [int32]$status_code = $results.StatusCode
                    Write-Warning -Message "Received HTTP status code [$status_code] instead of 200. Please look into it. You can try suppressing this attempt to retrieve instance info by including the -SkipMOTD parameter."
                    Break
                }
            }
            [PSCustomObject]$anow_session_display = [PSCustomObject]@{ protocol = $protocol; instance = $instance; token_expires = $expiration_date; user = $userName; domain = $Domain; access_token = ($access_token.SubString(0, 5) + '...' + $access_token.SubString(($access_token.Length - 5), 5)) }
            Format-Table -InputObject $anow_session_display -AutoSize -Wrap    
        }
    }
    If ($Domain.Length -eq 0) {
        [string]$domains_display = $domains -join ', '
        Write-Warning -Message "You did not include the domain. Please use Switch-AutomateNOWDomain to select one of the available domains: $domains_display"
    }
}

Function Disconnect-AutomateNOW {
    <#
.SYNOPSIS
Disconnects from the API of an AutomateNOW! instance

.DESCRIPTION
The `Disconnect-AutomateNOW` function logs out of the API of an AutomateNOW! instance. It then removes the global session variable object.

.INPUTS
None. You cannot pipe objects to Disconnect-AutomateNOW.

.OUTPUTS
A string indicating the results of the disconnection attempt.

.EXAMPLE
Disconnect-AutomateNOW

.NOTES
Although it is a good practice to disconnect your session, do be aware that the initial auth token is not revoked or terminated on the server side after logging out. This is the nature of JWT tokens.

#>
    [CmdletBinding()]
    Param(
    
    )
    If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/logoutEvent'
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    [PSCustomObject]$response = $results.response
    If ($response.status -eq 0) {
        [string]$Instance = $anow_session.Instance
        $Error.Clear()
        Try {
            Remove-Variable -Name anow_session -Scope Global -Force
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Remove-Variable failed to remove the `$anow_session variable due to [$Message]."
            Break
        }
        Write-Information -MessageData "Successfully disconnected from [$Instance]."
    }
}

Function Set-AutomateNOWPassword {
    <#
    .SYNOPSIS
    Sets the password of the local authenticated user of an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Set-AutomateNOWPassword` sets the password of the local authenticated user of an AutomateNOW! instance. This is not intended for ldap integrated instances.
    
    .PARAMETER OldPasswd
    String representing the current password of the authenticated user (use -Secure for masked input)

    .PARAMETER NewPasswd
    String representing the new password of the authenticated user (use -Secure for masked input)

    .PARAMETER Secure
    Prompts for current and new passwords using Read-Host with the -MaskInput parameter to hide the input

    .INPUTS
    None. You cannot pipe objects to Set-AutomateNOWPassword.
    
    .OUTPUTS
    None except for confirmation from Write-Information
    
    .EXAMPLE
    Set-AutomateNOWPassword -OldPasswd 'MyCoolPassword1!' -NewPasswd 'MyCoolPassword4#'

    .EXAMPLE
    Set-AutomateNOWPassword -Secure
    
    .NOTES
    This function should ONLY be used in a development environment. This function is not ready for production use as it needs to be updated to receive a (pipelined) credential object.
    
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'PlainText')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'PlainText')]
        [string]$OldPasswd,
        [Parameter(Mandatory = $true, ParameterSetName = 'PlainText')]    
        [string]$NewPasswd,
        [Parameter(Mandatory = $true, ParameterSetName = 'Secure')]
        [switch]$Secure
    )
    If ($Secure -eq $true) {
        $Error.Clear()
        Try {
            [string]$OldPasswd = Read-Host -Prompt 'Enter current password' -MaskInput
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Read-Host failed to receive the current password due to [$Message]."
            Break
        }
        If ($OldPasswd.Length -eq 0) {
            Write-Warning -Message "You must provide the current password. Please try again."
            Break
        }
        $Error.Clear()
        Try {
            [string]$NewPasswd = Read-Host -Prompt 'Enter new password' -MaskInput
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Read-Host failed to receive the new password due to [$Message]."
            Break
        }
        If ($NewPasswd.Length -eq 0) {
            Write-Warning -Message "You must provide the new password. Please try again."
            Break
        }
    }
    [string]$regex_passwd_reqs = '.{8,}'
    If ($OldPasswd -notmatch $regex_passwd_reqs) {
        Write-Warning -Message "Somehow the current password does not meet complexity requirements (minimum 8 chars, 1 upper, 1 lower, 1 number, 1 special character). Please check the password that you supplied here."
        Break
    }
    If ($NewPasswd -notmatch $regex_passwd_reqs) {
        Write-Warning -Message "Somehow the new password did not meet complexity requirements (minimum 8 chars, 1 upper, 1 lower, 1 number, 1 special character). Please check the password that you supplied here."
        Break
    }
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$User = ($anow_session.User)
    Try {
        [string]$OldPasswordEncoded = [System.Net.WebUtility]::UrlEncode($OldPasswd)
        [string]$NewPasswordEncoded = [System.Net.WebUtility]::UrlEncode($NewPasswd)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Somehow the UrlEncode method of the [System.Net.WebUtility] class failed due to [$Message]"
        Break
    }
    [string]$Body = ('id=' + $User + '&oldPassword=' + $OldPasswordEncoded + '&newPassword=' + $NewPasswordEncoded + '&repeatPassword=' + $NewPasswordEncoded)    
    [string]$command = '/secUser/updatePassword'
    [hashtable]$parameters = @{}
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    Write-Verbose -Message $parameters_display
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
        Break
    }
    If ($results.response.status -eq 0) {
        Write-Information -MessageData "Password successfully changed for $User"
        [string]$response_display = $results.response | ConvertTo-Json
        Write-Verbose -Message $response_display
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Somehow there was no response data. Please look into this."
        Break
    }
    Else {
        [string]$response_display = $results.response | ConvertTo-Json
        Write-Warning -Message "The attempt to change the password failed. Please see the returned data: $response_display"
        Break
    }
}

Function Switch-AutomateNOWDomain {
    <#
.SYNOPSIS
Switches the currently selected domain for the logged on user of an AutomateNOW! instance

.DESCRIPTION    
The `Switch-AutomateNOWDomain` cmdlet does not actually communicate with the AutomateNOW! instance. It modifies the $anow_session global variable.

.PARAMETER Domain
Required string representing the name of the domain to switch to.

.INPUTS
None. You cannot pipe objects to Switch-AutomateNOWDomain.

.OUTPUTS
None except for Write-Information messages.

.EXAMPLE
Switch-AutomateNOWDomain -Domain 'Sandbox'

.NOTES
You must use Connect-AutomateNOW to establish the token by way of global variable.

This function is considered part of the Authentication functions. In the future, this function should support receiving a [ANOWDomain] object to switch to.

#>
    [CmdletBinding()]
    Param(
        [string]$Domain
    )
    If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$Instance = $anow_session.Instance
    If ($anow_session.domains -cnotcontains $Domain) {
        [string]$available_domains = $anow_session.domains -join ', '
        If ($anow_session.domains -contains $Domain) {
            Write-Warning -Message "The domains are case-sensitive. Please choose from [$available_domains]."
            Break
        }
        Write-Warning -Message "The domain [$Domain] is not on [$Instance]. Please choose from [$available_domains]."
        Break
    }
    $Error.Clear()
    Try {
        $anow_session.header.Remove('domain')
        $anow_session.header.Add('domain', $Domain)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "The Add/Remove method failed on `$anow_session.header` due to [$Message]."
        Break
    }
    Write-Information -MessageData "The [$Domain] domain has been selected for [$Instance]."
}

Function Update-AutomateNOWToken {
    <#
    .SYNOPSIS
    Updates the session token used to connect to an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Update-AutomateNOWToken` function updates the existing session token that is being used to connect to an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Update-AutomateNOWToken (yet).
    
    .OUTPUTS
    
    
    .EXAMPLE
    Invoke-AutomateNOWAPI -command '/secUser/getUserInfo' -method GET
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function has no parameters. It assumes you already have a global session variable ($anow_session)
    
    #>
    If ($anow_session.RefreshToken.Length -eq 0) {
        Write-Warning -Message "Somehow there is no refresh token."
        Break
    }
    ElseIf ( $anow_session.RefreshToken -eq 'Not set' ) {
        Write-Warning -Message "It is not possible to refresh the token if you used -AccessToken without also including -RefreshToken"
    }
    [string]$command = '/oauth/access_token'
    [string]$ContentType = 'application/x-www-form-urlencoded; charset=UTF-8'
    [string]$RefreshToken = $anow_session.RefreshToken
    [string]$Body = 'grant_type=refresh_token&refresh_token=' + $RefreshToken    
    [hashtable]$parameters = @{}
    $parameters.Add('Method', 'POST')
    $parameters.Add('Command', $command)
    $parameters.Add('ContentType', $ContentType)
    $parameters.Add('NotAPICommand', $true)
    $parameters.Add('Body', $Body)
    If (($anow_session.NotSecure) -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    $Error.Clear()
    Try {
        [PSCustomObject]$token_properties = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Invoke-AutomateNOWAPI failed to access the [$command] endpoint due to [$Message]."
        Break
    }
    [string]$access_token = $token_properties.access_token
    [string]$refresh_token = $token_properties.refresh_token
    $Error.Clear()
    Try {
        [System.TimeZoneInfo]$timezone = Get-TimeZone
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Get-TimeZone failed due to get the time zone due to [$Message]."
        Break
    }
    [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    $Error.Clear()
    Try {
        [datetime]$expiration_date_utc = (Get-Date -Date '1970-01-01').AddMilliseconds($token_properties.expirationDate)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Get-Date failed due to process the authentication properties due to [$Message]"
        Break
    }
    [datetime]$expiration_date = ($expiration_date_utc + $utc_offset) # We're adding 2 values here: the current time in UTC and the current machine's UTC offset
    $anow_session.'ExpirationDate' = $expiration_date
    $anow_session.'AccessToken' = $access_token
    $anow_session.'RefreshToken' = $refresh_token
    [string]$expiration_date_display = Get-Date -Date $expiration_date -Format 'yyyy-MM-dd HH:mm:ss'
    $anow_session.header.'Authorization' = "Bearer $access_token"
    Write-Verbose -Message 'Global variable $anow_session.header has been set. Use this as your authentication header.'
    Write-Information -MessageData "Your token has been refreshed. The new expiration date is [$expiration_date_display]"
}

#endregion

#Region - Domains

Function Get-AutomateNOWDomain {
    <#
    .SYNOPSIS
    Gets the domains from an instance of AutomateNOW!
    
    .DESCRIPTION    
    `Get-AutomateNOWDomain` gets the domains from an instance of AutomateNOW!

    .PARAMETER Id
    Optional string array to specify the name(s) of the domain to retrieve. To retrieve all domains, do not use this optional parameter.

    .INPUTS
    `Get-AutomateNOWDomain` accepts strings representing the simpleId (name) of the domain from the pipeline
    
    .OUTPUTS
    An array of [ANOWDomain] class objects
    
    .EXAMPLE
    Get-AutomateNOWDomain

    .EXAMPLE
    Get-AutomateNOWDomain -Id 'Training'

    .EXAMPLE
    Get-AutomateNOWDomain -Id 'Training', 'Production'

    .EXAMPLE
    @('Training', 'Production', 'Test') | Get-AutomateNOWDomain
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    
    #>
    [OutputType([ANOWDomain[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
        [string]$command = '/domain/read'
        $parameters.Add('Command', $command)
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        If ($results.response.status -ne 0) {
            If ($null -eq $results.response.status) {
                Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                Break
            }
            Else {
                [int32]$status_code = $results.response.status
                [string]$results_response = $results.response
                Write-Warning -Message "Received status code [$status_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWDomain[]]$Domains = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the set of [ANOWDomain] objects due to [$Message]."
            Break
        }
    }
    Process {
        If (($_.Length -gt 0) -or ($Id.Count -gt 0)) {
            If ($_.Length -gt 0) {
                [string]$current_domain_name = $_
                [ANOWDomain]$Domain = $results.response.data | Where-Object { $_.Id -eq $current_domain_name } | Select-Object -First 1
                Return $Domain
            }
            Else {
                [ANOWDomain[]]$Domains = ($Domains | Where-Object { $_.Id -in $Id })
                Return $Domains
            } 
        }
        Return $Domains
    }
    End {

    }
}

Function Export-AutomateNOWDomain {
    <#
    .SYNOPSIS
    Exports the domains from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the domains from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWDomain] object (Use Get-AutomateNOWDomain to retrieve them)
    
    .INPUTS
    ONLY [ANOWDomain] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWDomain] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWDomain | Export-AutomateNOWDomain

    .EXAMPLE
    Get-AutomateNOWDomain -Id 'Training' | Export-AutomateNOWDomain

    .EXAMPLE
    @( 'Training', 'Test', 'Prod' ) | Get-AutomateNOWDomain | Export-AutomateNOWDomain

    .EXAMPLE
    Get-AutomateNOWDomain | Where-Object { $_.id -like '*Test*' } | Export-AutomateNOWDomain

    .NOTES
	You must present [ANOWDomain] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWDomain]$Domain
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Domains-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWDomain]$Domain = $_
        }
        $Error.Clear()
        Try {
            $Domain | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWDomain] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

#endregion

#Region - Folders

Function Get-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Gets the folders from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the folders from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the folder to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .INPUTS
    Accepts a string representing the simple id of the folder from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWFolder] class objects
    
    .EXAMPLE
    Get-AutomateNOWFolder

    .EXAMPLE
    Get-AutomateNOWFolder -Id 'Folder1'

    .EXAMPLE
    @( 'Folder1', 'Folder2' ) | Get-AutomateNOWFolder

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the folders.

    #>
    [OutputType([ANOWFolder[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
    }
    Process {
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            If ($_.Length -gt 0 ) {
                [string]$Foldername = $_
            }
            Else {
                [string]$Foldername = $Id
            }
            [string]$command = ('/folder/read?id=' + $Foldername)
        }
        Else {
            [string]$command = '/folder/read'
        }
        If ($null -eq $parameters["Command"]) {
            $parameters.Add('Command', $command)
        }
        Else {
            $parameters.Command = $command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        If ($results.response.status -ne 0) {
            [string]$Message = $results.response | ConvertTo-Json -Compress
            Write-Warning "$Message"
        }
        If ($results.response.status -ne 0) {
            If ($null -eq $results.response.status) {
                Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                Break
            }
            Else {
                [int32]$status_code = $results.response.status
                [string]$results_response = $results.response
                Write-Warning -Message "Received status code [$status_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWFolder[]]$Folders = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWFolder] objects due to [$Message]."
            Break
        }
        If ($folders.Count -gt 0) {
            Return $Folders
        }
    }
    End {

    }
}

Function Export-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Exports the folders from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the folders from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWFolder] object (Use Get-AutomateNOWFolder to retrieve them)
    
    .INPUTS
    ONLY [ANOWFolder] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWFolder] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWFolder | Export-AutomateNOWFolder

    .EXAMPLE
    Get-AutomateNOWFolder -Id 'Folder01' | Export-AutomateNOWFolder

    .EXAMPLE
    @( 'Folder01', 'Folder02' ) | Get-AutomateNOWFolder | Export-AutomateNOWFolder

    .EXAMPLE
    Get-AutomateNOWFolder | Where-Object { $_.simpleId -eq 'Folder01' } | Export-AutomateNOWFolder

    .NOTES
	You must present [ANOWFolder] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWFolder]$Folder
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Folders-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWFolder]$Folder = $_
        }
        $Error.Clear()
        Try {
            $Folder | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWFolder] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function New-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Creates a Folder within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a Folder within an AutomateNOW! instance and returns back the newly created [ANOWFolder] object

    .PARAMETER Id
    The intended name of the Folder. For example: 'LinuxFolder1'. This value may not contain the domain in brackets.

    .PARAMETER Description
    Optional description of the Folder.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Folder into.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWFolder.
    
    .OUTPUTS
    An [ANOWFolder] object representing the newly created Folder
    
    .EXAMPLE
    New-AutomateNOWFolder -Id 'MyFolder' -Description 'Folder description' -codeRepository 'MyRepository'
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the folder must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWFolder])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$Folder_exists = ($null -ne (Get-AutomateNOWFolder -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWFolder failed to check if the Folder [$Id] already existed due to [$Message]."
        Break
    }
    If ($Folder_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Folder named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWFolder]$ANOWFolder = New-Object -TypeName ANOWFolder
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed due to create the object of type [ANOWFolder] due to [$Message]."
        Break
    }

    $ANOWFolder.'id' = $Id
    $ANOWFolder.'description' = $Description
    $ANOWFolder.'codeRepository' = $codeRepository
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWFolder -IncludeProperties id, description, codeRepository
    [hashtable]$BodyMetaData = @{}
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_oldValues' = '{}'
    $BodyMetaData.'_componentId' = 'FolderCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'FolderDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat ' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/folder/create'
    [hashtable]$parameters = @{}
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create folder [$Id] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create folder [$Id] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWFolder]$Folder = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWFolder] object due to [$Message]."
        Break
    }        
    If ($Folder.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWFolder] object is empty!"
        Break
    }
    Return $Folder
}

Function Remove-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Removes a folder from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a folder from an AutomateNOW! instance
    
    .PARAMETER Folder
    An [ANOWFolder] object representing the Folder to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWFolder] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWFolder -Id 'Folder01' | Remove-AutomateNOWFolder

    .EXAMPLE
    @( 'Folder1', 'Folder2', 'Folder3') | Remove-AutomateNOWFolder

    .EXAMPLE
    Get-AutomateNOWFolder | ? { $_.simpleId -like 'test*' } | Remove-AutomateNOWFolder
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWFolder]$Folder,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
            Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
            Break
        }
        ElseIf ($Id -Match '[.{1,}].{1,}') {
            Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually required the 'simple id':-)"
            Break
        }
        [string]$command = '/folder/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Folder.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Folder_id = $_.id
                
            }
            ElseIf ($Folder.id.Length -gt 0) {
                [string]$Folder_id = $Folder.id
            }
            Else {
                [string]$Folder_id = $Id
            }
            [string]$Body = 'id=' + $Folder_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$Folder_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Folder $Folder_id successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - Icons

Function Export-AutomateNOWIcon {
    If ($anow_assets.icon_library.Count -eq 0) {
        Write-Warning -Message "Please use Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon to import the icon names into your session."
        Break
    }
    [PSCustomObject[]]$ExportTableFatCow = ForEach ($Icon in $anow_assets.icon_library['FAT_COW']) { [PSCustomObject]@{Library = 'FAT_COW'; Icon = $Icon; } }
    [PSCustomObject[]]$ExportTableFugue = ForEach ($Icon in $anow_assets.icon_library['FUGUE']) { [PSCustomObject]@{Library = 'FUGUE'; Icon = $Icon; } }
    [PSCustomObject[]]$ExportTableFontAwesome = ForEach ($Icon in $anow_assets.icon_library['FONT_AWESOME']) { [PSCustomObject]@{Library = 'FONT_AWESOME'; Icon = $Icon; } }
    [PSCustomObject[]]$DataToExport = ($ExportTableFatCow + $ExportTableFugue + $ExportTableFontAwesome)
    [int32]$DataToExportCount = $DataToExport.Count
    If ($DataToExportCount -eq 0) {
        Write-Warning -Message "Somehow there are zero icons to export. Please look into this."
        Break
    }
    [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
    [string]$ExportFileName = 'Export-AutomateNOW-Icons-' + $current_time + '.csv'
    [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
    [hashtable]$parameters = @{}
    $parameters.Add('Path', $ExportFilePath)
    If ($PSVersionTable.PSVersion.Major -eq 5) {
        $parameters.Add('NoTypeInformation', $true)
    }
    $Error.Clear()
    Try {
        $DataToExport | Export-CSV @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Export-CSV failed to export the icon asset data due to [$Message]"
        Break
    }
    $Error.Clear()
    [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
    [int32]$filelength = $fileinfo.Length
    [string]$filelength_display = "{0:N0}" -f $filelength
    Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
}

Function Import-AutomateNOWIcon {
    <#
    .SYNOPSIS
    Imports the icon asset information from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Import-AutomateNOWIcon` function imports the icon asset information from an AutomateNOW! instance and makes it available for other functions (e.g. Format-AutomateNOWIconList)
    
    .INPUTS
    None. You cannot pipe objects to Import-AutomateNOWIcon.
    
    .OUTPUTS
    The output is set into the global variable anow_assets. A .csv file may optionally be created to capture the output.
    
    .PARAMETER Instance
    Specifies the name of the AutomateNOW! instance. For example: s2.infinitedata.com

    .EXAMPLE
    Import-AutomateNOWIcon -Instance 'z4.infinitedata.com'
    
    .NOTES
    You DO NOT need to authenticate to the instance to execute this function.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Instance
    )
    Function Format-AutomateNOWIconList {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [ValidateSet('FatCow', 'Fugue', 'FontAwesome', IgnoreCase = $false)]
            [string]$Library,
            [Parameter(Mandatory = $true)]
            [array]$assets_content,
            [Parameter(Mandatory = $true)]
            [string]$first_icon_name,
            [Parameter(Mandatory = $true)]
            [string]$last_icon_name
        )
        [int32]$assets_content_count = $assets_content.Count
        If ($assets_content_count -eq 0) {
            Write-Warning -Message "Somehow there was no content..."
            Break
        }
        [string]$icon_index_first_string_id = ('"ID": "' + $Library + 'DataSource",')
        [string]$icon_index_first_string_name = ("{name: '$first_icon_name'")
        [string]$icon_index_last_string_name = ("{name: '$last_icon_name'")
        $Error.Clear()
        Try {
            [int32]$icon_index_first_number1 = $assets_content.IndexOf($($assets_content -match $icon_index_first_string_id | Select-Object -First 1))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to extract the first index position of the first icon from the [$Library] icon library due to [$Message]"
            Break
        }
        $Error.Clear()
        Try {
            [int32]$icon_index_first_number2 = $assets_content[$icon_index_first_number1..$assets_content_count].IndexOf($($assets_content[$icon_index_first_number1..$assets_content_count] -match $icon_index_first_string_name | Select-Object -First 1))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to extract the second index position of the first icon from the [$Library] icon library due to [$Message]"
            Break
        }
        [int32]$icon_index_first_number = ($icon_index_first_number1 + $icon_index_first_number2)
        Write-Verbose "Extracted first index of [$icon_index_first_number] from the [$Library] icon library"
        $Error.Clear()
        Try {
            [int32]$icon_index_last_number = $assets_content[$icon_index_first_number..$assets_content_count].IndexOf($($assets_content[$icon_index_first_number..$assets_content_count] -match $icon_index_last_string_name | Select-Object -First 1))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to extract the index position of the last icon from the [$Library] icon library due to [$Message]"
            Break
        }
        [int32]$icon_index_last_number = ($icon_index_last_number + $icon_index_first_number)
        Write-Verbose "Extracted last index of [$icon_index_last_number] for [$Library]"
        $Error.Clear()
        Try {
            [array]$icon_raw_array = $assets_content[$icon_index_first_number..$icon_index_last_number]
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to extract the icon data from the assets library from position [$icon_index_first_number] to [$icon_index_last_number] from the [$Library] icon library due to [$Message]"
            Break
        }
        [int32]$icon_raw_array_count = $icon_raw_array.Count
        Write-Verbose -Message "Found [$icon_raw_array_count] icons from the [$Library] library"
        [array]$icon_list = $icon_raw_array | ForEach-Object { $_ -replace '\s' -replace 'name:' -replace "{'" -replace "'}," -replace "'}" }
        Return $icon_list
    }
    If ($Instance.Length -eq 0) {
        [string]$Instance = $anow_session.Instance
        If ($Instance.Length -eq 0) {
            Write-Warning -Message 'You need to either supply the instance via -Instance or use Connect-AutomateNOW to define it for you'
            Break            
        }
    }
    If ($Instance -match '/' -or $Instance -match 'http') {
        Write-Warning -Message 'Please do not include http or any slashes in the instance name. Following are 2 valid examples: a2.InfiniteData.com, contoso-sbox-anow.region.cloudapp.azure.com:8080'
        Break
    }
    [string]$url_homepage = ('https://' + $Instance + '/automatenow/') # Note the backslash at the end. This is required!
    Write-Verbose -Message "The instance url is set to [$url_homepage]"
    [int32]$ps_version_major = $PSVersionTable.PSVersion.Major
    If ($ps_version_major -gt 5) {
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$request_homepage = Invoke-WebRequest -uri $url_homepage
    }
    ElseIf ($ps_version_major -eq 5) {
        [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$request_homepage = Invoke-WebRequest -uri $url_homepage
    }
    Else {
        Write-Warning -Message "Only Windows PowerShell 5.1 and PowerShell Core (7+) are supported."
    }
    [int32]$request_statuscode = $request_homepage.StatusCode
    If ($request_statuscode -ne 200) {
        Write-Warning -Message "Somehow the response code was [$request_statuscode] instead of 200. Please look into this."
        Break
    }
    [array]$homepage_content = $request_homepage.Content -split "`n"
    [int32]$homepage_content_line_count = $homepage_content.Count
    Write-Verbose -Message "The homepage content from [$Instance] has [$homepage_content_line_count] lines"
    [string]$asset_url = ($url_homepage + ($homepage_content -match 'assets/application/automateNow-[0-9a-z]{32}.js' -replace '"></script>' -replace '<script type="text/javascript" src="/automatenow/' | Select-Object -First 1))
    Write-Verbose -Message "Fetching assets from [$asset_url]"    
    If ($ps_version_major -gt 5) {
        [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$request_assets = Invoke-WebRequest -Uri $asset_url
    }
    ElseIf ($ps_version_major -eq 5) {
        [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$request_assets = Invoke-WebRequest -Uri $asset_url
    }
    Else {
        Write-Warning -Message "Only Windows PowerShell 5.1 and PowerShell Core (7+) are supported."
    }
    [int32]$request_statuscode = $request_assets.StatusCode
    If ($request_statuscode -ne 200) {
        Write-Warning -Message "Somehow the response code was [$request_statuscode] instead of 200. Please look into this."
        Break
    }
    [array]$assets_content = $request_assets.Content -split "`r" -split "`n"
    [int32]$assets_content_line_count = $assets_content.Count
    Write-Verbose -Message "The assets content from [$Instance] has [$assets_content_line_count] lines"
    $Error.Clear()
    Try {
        [array]$IconNames_FatCow = Format-AutomateNOWIconList -assets_content $assets_content -Library 'FatCow' -first_icon_name '32_bit' -last_icon_name 'zootool'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Format-AutomateNOWIconList failed to extract the FatCow icons due to [$Message]"
        Break
    }
    $Error.Clear()
    Try {
        [array]$IconNames_Fugue = Format-AutomateNOWIconList -assets_content $assets_content -Library 'Fugue' -first_icon_name 'abacus' -last_icon_name 'zootool'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Format-AutomateNOWIconList failed to extract the Fugue icons due to [$Message]"
        Break
    }
    $Error.Clear()
    Try {
        [array]$IconNames_FontAwesome = Format-AutomateNOWIconList -assets_content $assets_content -Library 'FontAwesome' -first_icon_name '500px' -last_icon_name 'youtube-square'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Format-AutomateNOWIconList failed to extract the FontAwesome icons due to [$Message]"
        Break
    }
    [int32]$IconCount_FatCow = ($IconNames_FatCow.Count)
    [int32]$IconCount_Fugue = ($IconNames_Fugue.Count)
    [int32]$IconCount_FontAwesome = ($IconNames_FontAwesome.Count)
    If ( $IconCount_FatCow -eq 0 -or $IconCount_Fugue -eq 0 -or $IconCount_FontAwesome -eq 0) {
        Write-Warning -Message "Somehow one or more of the icon counts summed to zero. Please look into this. [FatCow = $IconCount_FatCow; Fugue = $IconCount_Fugue; FontAwesome = $IconCount_FontAwesome;]"
        Break
    }
    [int32]$IconCount = ($IconCount_FatCow + $IconCount_Fugue + $IconCount_FontAwesome)
    [hashtable]$icon_sets = @{ 'FAT_COW' = $IconNames_FatCow; 'FUGUE' = $IconNames_Fugue; 'FONT_AWESOME' = $IconNames_FontAwesome; 'FAT_COW_COUNT' = $IconCount_FatCow; 'FUGUE_COUNT' = $IconCount_Fugue; 'FONT_AWESOME_COUNT' = $IconCount_FatCow; 'TOTAL_COUNT' = $iconCount; }
    If ($null -eq $anow_assets) {
        [hashtable]$global:anow_assets = @{}
    }
    If ($null -eq $anow_assets.icon_library) {
        $anow_assets.Add('icon_library', $icon_sets)
    }
    Else {
        $anow_assets.icon_library = $icon_sets
    }
    Write-Verbose "Added $IconCount icons to the assets library of this session"
}

Function Import-AutomateNOWLocalIcon {
    <#
    .SYNOPSIS
    Loads the icon assets from a local file Icons.ps1 instead of from a live AutomateNOW! instance
    
    #>
    [string]$LocalIconScript = ($PSScriptRoot + '\Icons.ps1')
    If ((Test-Path -Path "$LocalIconScript") -eq $true) {
        $Error.Clear()
        Try {
            . "$LocalIconScript"
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to load the local icon script [$LocalIconScript] due to [$Message]"
            Break
        }
        [int32]$fat_cow_icon_count = $anow_assets.icon_library["FAT_COW"].Count
        [int32]$fugue_icon_count = $anow_assets.icon_library["FUGUE"].Count
        [int32]$font_awesome_icon_count = $anow_assets.icon_library["FONT_AWESOME"].Count
        Write-Verbose -Message "Imported icons:"
        Write-Verbose -Message "Fat Cow [$fat_cow_icon_count]"
        Write-Verbose -Message "Fugue [$fugue_icon_count]"
        Write-Verbose -Message "Font Awesome [$font_awesome_icon_count]"
    }
    Else {
        Write-Warning -Message "The Icons.ps1 file is not available!"
    }
}

Function Read-AutomateNOWIcon {
    <#
    .SYNOPSIS
    Reads the icon assets from the local cache.

    .DESCRIPTION
    Reads the icon assets from the local cache. You must first import the icons with either Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon.

    .PARAMETER iconSet
    Mandatory string representing a choice between three icon sets. Valid choices are: FAT_COW, FUGUE, FONT_AWESOME

    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWIconSet]$iconSet
    )
    If ($anow_assets.icon_library.Count -eq 0) {
        Write-Warning -Message "Please use Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon to import the icon names into your session."
        Break
    }
    Return $anow_assets.icon_library."$iconSet"
}

Function Write-AutomateNOWIconData {
    <#
    
    This is experimental

    Write-AutomateNOWIconDate -iconSet 'FUGUE' -filepath 'c:\temp\icons'

    #>
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWIconSet]$iconSet,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ (Test-Path -Path "$_") -eq $true })]
        [string]$filepath,
        [Parameter(Mandatory = $false)]
        [string]$Instance,
        [Parameter(Mandatory = $false)]
        [int32]$pause_delay = 50
    )
    Begin {
        If ($Instance.Length -eq 0) {
            [string]$Instance = $anow_session.Instance
            If ($Instance.Length -eq 0) {
                Write-Warning -Message "You needed to either specify the instance with -Instance or use Connect-AutomateNOW to establish a session."
                Break
            }
        }
        If ($anow_assets.icon_library.Count -eq 0) {
            Write-Warning -Message "Please use Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon to import the icon names into your session."
            Break
        }
    }
    Process {
        If ($_.Length -gt 0) {
            [string]$Set = $_
        }
        Else {
            [string]$Set = $iconSet
        }
        If ($Set -eq 'FONT_AWESOME') {
            Write-Warning -Message "The Font Awesome icon set is a font and not a series of images, therefore they cannot be written to disk as imagefiles."
        }
        Else {
            [string]$current_path = "$filepath\$Set"
            If ((Test-Path -Path $current_path) -eq $false) {
                $Error.Clear()
                Try {
                    New-Item -ItemType Directory -Path "$current_path" -Force | Out-Null
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "New-Item failed to create $current_path due to [$Message]"
                    Break
                }
                Write-Verbose -Message "Created the [$Set] directory in [$filepath]"
            }
            [int32]$current_path_file_count = Get-ChildItem -Path "$current_path\*.png" | Measure-Object | Select-Object -ExpandProperty Count
            If ($current_path_file_count -gt 0) {
                Throw "There are $current_path_file_count .png files in the [$current_path] directory."
            }
            [array]$icon_names = $anow_assets.icon_library["$iconSet"]
            [int32]$current_icons_count = $icon_names.Count
            If ($current_icons_count -eq 0) {
                Write-Warning -Message "Somehow there are 0 icons available for the [$iconSet] icon set. Please look into this."
                Break
            }
            [string]$icon_directory_name = ($iconSet -replace '_').ToLower()
            [string]$base_icon_uri = 'https' + '://' + $instance + "/automatenow/img/$icon_directory_name/"
            [int32]$total_bytes_downloaded = 0
            [int32]$icons_downloaded = 0
            [int32]$current_loop = 1
            $Error.Clear()
            Try {
                [System.Diagnostics.Stopwatch]$stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
                $stopwatch.Start()
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "A System.Diagnostics.Stopwatch couldn't be started due to [$Message]"
                Break
            }
            ForEach ($current_icon_name in $icon_names) {
                [string]$current_icon_download_url = ($base_icon_uri + $current_icon_name + '.png')
                [string]$current_icon_file_path = "$filepath\$iconSet\$current_icon_name.png"
                $Error.Clear()
                Try {
                    $ProgressPreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $current_icon_download_url -PassThru -OutFile $current_icon_file_path | Out-Null
                    $ProgressPreference = 'Continue'
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Invoke-WebRequest failed to download the icon file [$current_icon_download_url] due to [$Message]"
                    Break
                }        
                $Error.Clear()
                Try {
                    [System.IO.FileSystemInfo]$current_icon_file_info = Get-Item -Path "$current_icon_file_path"
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-Item failed to read the recently downloaded icon file [$current_icon_file_path] due to [$Message]"
                    Break
                }
                [int32]$current_bytes_downloaded = $current_icon_file_info.Length
                [int32]$total_bytes_downloaded = ($total_bytes_downloaded + $current_bytes_downloaded)
                $icons_downloaded++
                [string]$total_bytes_downloaded_display = "{0:N0}" -f $total_bytes_downloaded
                [int32]$elapsed_ms = $stopwatch.ElapsedMilliseconds
                [decimal]$bytes_per_ms = ($total_bytes_downloaded / $elapsed_ms)
                [string]$kbyte_sec_display = [math]::Round(($bytes_per_ms * 1000 / 1024), 2).ToString("0.00")
                [int32]$avg_file_size = ($total_bytes_downloaded / $current_loop)
                [string]$avg_file_size_display = "{0:N0}" -f $avg_file_size
                Write-Progress -PercentComplete ($current_loop / $current_icons_count * 100) -Activity "   Downloading the '$iconSet' icon library (throttle: $pause_delay ms)" -Status "Image $current_loop of $current_icons_count - Average filesize: $avg_file_size_display bytes - Total Downloaded: $total_bytes_downloaded_display bytes" -CurrentOperation "Speed: $kbyte_sec_display KByte/sec - Downloaded $current_icon_name.png"
                Start-Sleep -Milliseconds $pause_delay
                $current_loop++
            }    
        }
    }
    End {
        [int32]$current_path_file_count = Get-ChildItem -Path "$current_path\*.png" | Measure-Object | Select-Object -ExpandProperty Count
        If ($current_path_file_count -gt 0) {
            Write-Information "Successfully downloaded $current_path_file_count to the $current_path directory"
        }
        Else {
            Throw "There are $current_path_file_count .png files in the [$current_path] directory."
        }
    }
}

#endregion

#Region - Nodes

Function Get-AutomateNOWNode {
    <#
    .SYNOPSIS
    Gets the nodes from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the nodes from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the node to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .INPUTS
    Accepts a string representing the simple id of the node from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWNode] class objects
    
    .EXAMPLE
    Get-AutomateNOWNode

    .EXAMPLE
    Get-AutomateNOWNode -Id 'my_node_01'

    .EXAMPLE
    @( 'my_node_01', 'my_node_02' ) | Get-AutomateNOWNode

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the nodes.

    #>
    [OutputType([ANOWNode[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
    }
    Process {
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            [hashtable]$Body = @{}
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            $Body.'_operationType' = 'fetch'
            $Body.'_operationId' = 'read'
            $Body.'_textMatchStyle' = 'exactCase'
            $Body.'_dataSource' = 'ServerNodeDataSource'
            $Body.'isc_metaDataPrefix' = '_'
            $Body.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $Body
            [string]$command = ('/serverNode/read?' + $Body)
        }
        Else {
            [string]$command = '/serverNode'
        }
        If ($null -eq $parameters["Command"]) {
            $parameters.Add('Command', $command)
        }
        Else {
            $parameters.Command = $command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        If ($results.response.status -ne 0) {
            [string]$Message = $results.response | ConvertTo-Json -Compress
            Write-Warning "$Message"
        }
        If ($results.response.status -ne 0) {
            If ($null -eq $results.response.status) {
                Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                Break
            }
            Else {
                [int32]$status_code = $results.response.status
                [string]$results_response = $results.response
                Write-Warning -Message "Received status code [$status_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWNode[]]$nodes = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWNode] objects due to [$Message]."
            Break
        }
        If ($nodes.Count -gt 0) {
            Return $nodes
        }
    }
    End {

    }
}

Function Export-AutomateNOWNode {
    <#
    .SYNOPSIS
    Exports the nodes from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the nodes from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWNode] object (Use Get-AutomateNOWNode to retrieve them)
    
    .INPUTS
    ONLY [ANOWNode] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWNode] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWNode | Export-AutomateNOWNode

    .EXAMPLE
    Get-AutomateNOWNode -Id 'Node01' | Export-AutomateNOWNode

    .EXAMPLE
    @( 'Node01', 'Node02' ) | Get-AutomateNOWNode | Export-AutomateNOWNode

    .EXAMPLE
    Get-AutomateNOWNode | Where-Object { $_.serverNodeType -eq 'LINUX' } | Export-AutomateNOWNode

    .NOTES
	You must present [ANOWNode] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWNode]$Node
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Nodes-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWNode]$Node = $_
        }
        $Error.Clear()
        Try {
            $Node | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWNode] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function New-AutomateNOWNode {
    <#
    .SYNOPSIS
    Creates a node within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a node within an AutomateNOW! instance and returns back the newly created [ANOWNode] object

    .PARAMETER Id
    The intended name of the node. For example: 'LinuxNode1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the node.

    .PARAMETER Description
    Optional description of the node.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new node. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the node into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the node into.

    .PARAMETER WeightCapacity
    Optional integer to specify the total weight capacity of the node. Defaults to 50.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWNode.
    
    .OUTPUTS
    An [ANOWNode] object representing the newly created node
    
    .EXAMPLE
    New-AutomateNOWNode
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the node must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWNode])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWserverNode_type]$Type,
        [Parameter(Mandatory = $false)]
        [int32]$WeightCapacity = 50,
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$node_exists = ($null -ne (Get-AutomateNOWNode -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWNode failed to check if the node [$Id] already existed due to [$Message]."
        Break
    }
    If ($node_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a node named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWNode]$ANOWNode = New-Object -TypeName ANOWNode
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed due to create the object of type [ANOWNode] due to [$Message]."
        Break
    }
    $ANOWNode.'id' = $Id
    $ANOWNode.'serverNodeType' = $Type
    $ANOWNode.'loadBalancer' = $alse
    $ANOWNode.'totalWeightCapacity' = $WeightCapacity
    $ANOWNode.'description' = $Description
    $ANOWNode.'tags' = $Tags
    $ANOWNode.'folder' = $Folder
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWNode -IncludeProperties id, serverNodeType, loadBalancer, totalWeightCapacity, description, tags, folder, codeRepository
    [hashtable]$BodyMetaData = @{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = ('{"serverNodeType":"' + $Type + '","loadBalancer":' + $LoadBalancer + ',"totalWeightCapacity":' + $WeightCapacity + '}')
    $BodyMetaData.'_componentId' = 'ServerNodeCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'ServerNodeDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/serverNode/create'
    [hashtable]$parameters = @{}
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create node [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create node [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWNode]$node = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWNode] object due to [$Message]."
        Break
    }        
    If ($node.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWNode] node is empty!"
        Break
    }
    Return $node
}

Function Remove-AutomateNOWNode {
    <#
    .SYNOPSIS
    Removes a node from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Remove-AutomateNOWNode` function removes a node from an AutomateNOW! instance
    
    .PARAMETER Node
    An [ANOWNode] object representing the node to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWNode] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWNode -Id 'Node01' | Remove-AutomateNOWNode

    .EXAMPLE
    Get-AutomateNOWNode -Id 'Node01', 'Node02' | Remove-AutomateNOWNode
    
    .EXAMPLE
    @( 'Node1', 'Node2', 'Node3') | Remove-AutomateNOWNode

    .EXAMPLE
    Get-AutomateNOWNode | ? { $_.serverNodeType -eq 'LINUX' } | Remove-AutomateNOWNode
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWNode]$Node,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
            Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
            Break
        }
        ElseIf ($Id -Match '[.{1,}].{1,}') {
            Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually required the 'simple id':-)"
            Break
        }
        [string]$command = '/serverNode/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Node.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$node_id = $_.id
                
            }
            ElseIf ($Node.id.Length -gt 0) {
                [string]$node_id = $Node.id
            }
            Else {
                [string]$node_id = $Id
            }
            [string]$Body = 'id=' + $node_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$node_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Node $node_id successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - Tags
Function Get-AutomateNOWTag {
    <#
    .SYNOPSIS
    Gets the tags from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Get-AutomateNOWTag` function gets the tags from an instance of AutomateNOW!
    
    .INPUTS
    `Get-AutomateNOWTag` accepts tag id strings from the pipeline
    
    .OUTPUTS
    An array of [ANOWTag] objects
    
    .PARAMETER Id
    Optional string array containing the simple id's of the tags (that means without the brackets [])
    
    .EXAMPLE
    Get-AutomateNOWTag

    .EXAMPLE
    Get-AtuomateNOWTag -Id 'Tag1'

    .Example
    Get-AutomateNOWTag -Id 'Tag1', 'Tag2','Tag3'
    
    .EXAMPLE
    '('Tag1', 'Tag2', 'Tag3') | Get-AutomateNOWTag

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Despite the name of the endpoint, only the tags for the current domain are sent.
    #>
    [OutputType([ANOWTag[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string[]]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/tag/readAllDomains'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        $Error.Clear()
        Try {
            [ANOWTag[]]$Tags = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create array of [ANOWTag] objects due to [$Message]."
            Break
        }
        [int32]$Tags_count = $Tags.Count
        If ($Tags_count -eq 0) {
            Write-Warning -Message "Somehow there are no tags available. Was this instance just created 5 minutes ago?"
            Break
        }
    }
    Process {
        If (($_.Length -gt 0) -or ($Id.Count -gt 0)) {
            If ($_.Length -gt 0) {
                $Error.Clear()
                Try {
                    [string]$current_tag_name = $_
                    [ANOWTag]$Tag = $Tags | Where-Object { $_.simpleId -eq $current_tag_name } | Select-Object -First 1
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Unable to create a [ANOWTag] object (for $_) due to [$Message]."
                    Break
                }
                Return $Tag
            }
            Else {
                $Error.Clear()
                Try {
                    [ANOWTag[]]$Tags = ($Tags | Where-Object { $_.simpleId -in $Id })
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Unable to form an array of [ANOWTag] objects based on the provided Tag Id's due to [$Message]."
                    Break
                }
                Return $Tags
            } 
        }
        Return $Tags
    }
    End {
            
    }
}

Function Export-AutomateNOWTag {
    <#
    .SYNOPSIS
    Exports the tags from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the tags from an instance of AutomateNOW! to a local .csv file
    
    .INPUTS
    ONLY [ANOWTag] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWTag] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWTag | Export-AutomateNOWTag

    .EXAMPLE
    Get-AutomateNOWTag -Id 'Tag01' | Export-AutomateNOWTag

    .EXAMPLE
    @( 'Tag01', 'Tag02', 'Tag03' ) | Get-AutomateNOWTag | Export-AutomateNOWTag

    .EXAMPLE
    Get-AutomateNOWTag | Where-Object { $_.simpleid -like 'Test-*' } | Export-AutomateNOWTag

    .NOTES
    You must present [ANOWTag] objects to the pipeline to use this function.
    #>
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWTag]$Tag
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Tags-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWTag]$Tag = $_
        }
        $Error.Clear()
        Try {
            $Tag | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWTag] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function New-AutomateNOWTag {
    <#
    .SYNOPSIS
    Creates a new tag on an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a new tag on an AutomateNOW! instance and returns back the created [ANOWTag] object
    
    .PARAMETER Id
    The intended name of the tag. For example: 'MyCoolTag'. This value may not contain the domain in brackets.

    .PARAMETER description
    The description of the tag. This parameter is not required. For example: 'My cool tag description'

    .PARAMETER iconSet
    The name of the icon library (if you choose to use one). Possible choices are: FAT_COW, FUGUE and FONT_AWESOME.

    .PARAMETER iconCode
    The name of the icon which matches the chosen library.

    .PARAMETER textColor
    The RGB in hex of the tag's foreground (text) color. You must include the # character and it is case sensitive. Example: #FF00FF

    .PARAMETER backgroundColor
    The RGB in hex of the tag's background color. You must include the # character and it is case sensitive. Example: #00FF00

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWTag.
    
    .OUTPUTS
    An [ANOWTag] object representing the newly created tag
    
    .EXAMPLE
    New-AutomateNOWTag -id 'MyCoolTag123' -description 'My tags description' -iconSet 'FUGUE' -IconCode 'abacus' -textColor '#0A0A0A' -backgroundColor 'transparent'
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Note that transparent is an available option for either background or foreground color.

    The name (id) of the tag must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWTag])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [string]$description = '',
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ANOWIconSet]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [string]$iconCode,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateScript( { $_ -cmatch '^#[0-9A-F]{6}$' -or $_ -cmatch '^transparent$' } ) ]
        [string]$textColor = '#FFFFFF',
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateScript( { $_ -cmatch '^#[0-9A-F]{6}$' -or $_ -cmatch '^transparent$' } ) ]
        [string]$backgroundColor = '#FF0000'
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is no global session token"
            Break
        }
        If ($Id.Length -eq 0) {
            Write-Warning -Message "The Id must be at least 1 character in length. Please try again."
            Break
        }
        If (($iconSet.Length -gt 0) -and ($iconCode.Length -eq 0)) {
            Write-Warning -Message "If you specify an icon library then you must also specify an icon"
            Break
        }
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
        $Error.Clear()
        Try {
            [boolean]$tag_exists = ($null -ne (Get-AutomateNOWTag -Id $Id))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTag failed to check if the tag [$Id] already existed due to [$Message]."
            Break
        }
        If ($tag_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a tag named [$Id] in [$current_domain]. Please check into this."
            Break
        }
        ## End warning ##
    }
    Process {
        $Error.Clear()
        Try {
            [ANOWTag]$ANOWTag = New-Object -TypeName ANOWTag
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-Object failed due to create the [ANOWTag] object type due to [$Message]."
            Break
        }
        $ANOWTag.'Id' = $Id
        If ($null -ne $textColor) {
            $ANOWTag.'textColor' = $textColor
        }
        If ($null -ne $backgroundColor) {
            $ANOWTag.'backgroundColor' = $backgroundColor
        }
        If ($null -ne $description) {
            $ANOWTag.'description' = $description
        }
        If ($null -ne $iconSet) {
            $ANOWTag.'iconSet' = $iconSet
        }
        If ($null -ne $iconCode) {
            $ANOWTag.'iconCode' = $iconCode
        }
        [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWTag -IncludeProperties textColor, backgroundColor, id, description, iconSet, iconCode
        [hashtable]$BodyMetaData = @{}
        $BodyMetaData.'_textMatchStyle' = 'exact'
        $BodyMetaData.'_operationType' = 'add'
        $BodyMetaData.'_oldValues' = '{"textColor":"#FFFFFF","backgroundColor":"#FF0000"}'
        $BodyMetaData.'_componentId' = 'TagCreateWindow_form'
        $BodyMetaData.'_dataSource' = 'TagDataSource'
        $BodyMetaData.'isc_metaDataPrefix' = '_'
        $BodyMetaData.'isc_dataFormat' = 'json'
        [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
        [string]$command = '/tag/create'
        [string]$ContentType = 'application/x-www-form-urlencoded; charset=UTF-8'
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', $ContentType)
        $parameters.Add('Command', $command)
        $parameters.Add('Body', $Body)
        If ($Verbose -eq $true) {
            $parameters.Add('Verbose', $true)
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to [$Message]"
            Break
        }
        If ($results.response.status -ne 0) {
            [string]$parameters_display = $parameters | ConvertTo-Json -Compress
            If ($results.response.status -gt 0) {
                [string]$results_display = $results | ConvertTo-Json -Compress
                Write-Warning -Message "Executing [$command] returned the error $results_display. Parameters: $parameters_display"
                Break
            }
            ElseIf ($null -eq $results.response.status) {
                Write-Warning -Message "Executing [$command] returned an empty response. Parameters: $parameters_display"
                Break
            }
            Else {
                Write-Warning -Message "Unknown error when executing [$command]. Parameters: $parameters_display"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWTag[]]$tag_data = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the class object [ANOWTag] with the response due to [$message]"
            Break
        }
        [string]$domain = $anow_session.header.domain
        [string]$tag_string = $tag_data.ToString()
        Write-Verbose -Message "The tag [$tag_string] was created in the [$domain] domain"
        If ($Quiet -ne $true) {
            Return $tag_data
        }
    }
    End {
    }
}

Function Remove-AutomateNOWTag {
    <#
    .SYNOPSIS
    Removes a tag from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a tag from an AutomateNOW! instance
    
    .PARAMETER Id
    A string array of simple Id's of the tags to delete. Do not include the domain. For example: 'Tag1' is valid, whereas '[Domain]Tag1' is not valid.

    .PARAMETER Tag
    An [ANOWTag] object representing the tag to be deleted.
    
    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    `Remove-AutomateNOWTag` accepts pipeline input on the Tag parameter or the Id by way of -Id
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Remove-AutomateNOWTag -Id 'Tag1'

    .EXAMPLE
    Remove-AutomateNOWTag -Id 'Tag1', 'Tag2'
    
    .EXAMPLE
    @( 'Tag1', 'Tag2', 'Tag3') | Remove-AutomateNOWTag

    .EXAMPLE
    Get-AutomateNOWTag | ? { $_.simpleid -like '*my_tag*' } | Remove-AutomateNOWTag
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Id')]
        [string[]]$Id,
        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ParameterSetName = 'Pipeline')]
        [ANOWTag]$Tag,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
            Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
            Break
        }
        ElseIf ($Id -Match '[.{1,}].{1,}') {
            Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually required the 'simple id':-)"
            Break
        }
        [string]$command = '/tag/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$(If($Tag.id.Length -gt 0) {$Tag.id} Else {$_.id})")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$tag_id = $_.id
                
            }
            ElseIf ($Tag.id.Length -gt 0) {
                [string]$tag_id = $Tag.id
            }
            Else {
                [string]$tag_id = $Id
            }
            [string]$Body = 'id=' + $tag_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$Id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Tag $Id successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - Tasks

Function Get-AutomateNOWTask {
    <#
    .SYNOPSIS
    Gets the Tasks from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the Tasks from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the Task to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER taskType
    Optional string representing the type of task to return. For example, a shell task is SH. This parameter cannot be combined with -monitorType or -sensorType.
    
    .PARAMETER monitorType
    Optional string representing the type of monitor to return. For example, a python monitor is PYTHON_MONITOR. This parameter cannot be combined with -taskType or -sensorType.
    
    .PARAMETER sensorType
    Optional string representing the type of sensor to return. For example, a file sensor is FILE_SENSOR. This parameter cannot be combined with -monitorType or -taskType.
    
    .PARAMETER sortBy
    Optional string parameter to sort the results by. Valid choices are: id, processingType, simpleId, dateCreated, node, outOfSync, keepResourcesOnFailure, onHold, lastUpdated, highRisk, weight, taskType, userIp, createdBy, lazyLoad, passBy, lastUpdatedBy, durationSum, serverNodeType, eagerScriptExecution, passResourceDependenciesToChildren, owner, checkedOut, estimatedDuration, passActionsToChildren. Defaults to id.
    
    .PARAMETER Descending
    Optional switch parameter to sort in descending order

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the Task from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWTask] class objects
    
    .EXAMPLE
    Get-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task_01'

    .EXAMPLE
    @( 'Task_01', 'Task_02' ) | Get-AutomateNOWTask

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Tasks (not recommended)

    Please be aware that tasks are actually divided into 3 types which is not directly illustrated in the console. The three types are Tasks, Monitors and Sensors. That is why there are three separate exclusive parameters for the task type.

    #>
    [OutputType([ANOWTask[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default' )]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ParameterSetName = 'Default')]
        [string]$Id,
        [Parameter(Mandatory = $True, ParameterSetName = 'taskType')]
        [ANOWTask_taskType]$taskType,
        [Parameter(Mandatory = $True, ParameterSetName = 'monitorType')]
        [ANOWTask_monitorType]$monitorType,
        [Parameter(Mandatory = $True, ParameterSetName = 'sensorType')]
        [ANOWTask_sensorType]$sensorType,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'taskType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'monitorType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'sensorType')]
        [ValidateSet('id', 'processingType', 'simpleId', 'dateCreated', 'node', 'outOfSync', 'keepResourcesOnFailure', 'onHold', 'lastUpdated', 'highRisk', 'weight', 'taskType', 'userIp', 'createdBy', 'lazyLoad', 'passBy', 'lastUpdatedBy', 'durationSum', 'serverNodeType', 'eagerScriptExecution', 'passResourceDependenciesToChildren', 'owner', 'checkedOut', 'estimatedDuration', 'passActionsToChildren')]
        [string]$sortBy = 'id',
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'taskType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'monitorType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'sensorType')]
        [switch]$Descending,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'taskType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'monitorType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'sensorType')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'taskType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'monitorType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'sensorType')]
        [int32]$endRow = 2000
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
    }
    Process {
        [hashtable]$Body = @{}
        $Body.'_constructor' = 'AdvancedCriteria'
        $Body.'operator' = 'and'
        $Body.'_operationType' = 'fetch'
        $Body.'startRow' = $startRow
        $Body.'endRow' = $endRow
        $Body.'_textMatchStyle' = 'substring'
        $Body.'_componentId' = 'ProcessingTemplateList'
        $Body.'_dataSource' = 'ProcessingTemplateDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        If ($Descending -eq $true) {
            $Body.'_sortBy' = '-' + $sortBy
        }
        Else {
            $Body.'_sortBy' = $sortBy
        }        
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
        }
        ElseIf ($null -ne $taskType) {
            $Body.'criteria' = '{"fieldName":"taskType","operator":"equals","value":"' + $taskType + '"}'

        }
        ElseIf ($null -ne $monitorType) {
            $Body.'criteria' = '{"fieldName":"monitorType","operator":"equals","value":"' + $monitorType + '"}'

        }
        ElseIf ($null -ne $sensorType) {
            $Body.'criteria' = '{"fieldName":"sensorType","operator":"equals","value":"' + $sensorType + '"}'

        }
        Else {
            $Body.'criteria1' = '{"_constructor":"AdvancedCriteria","operator":"or","criteria":[{"fieldName":"processingType","operator":"equals","value":"TASK"},{"fieldName":"serviceType","operator":"equals","value":"SENSOR"},{"fieldName":"serviceType","operator":"equals","value":"MONITOR"}]}'
            $Body.'criteria2' = '{"fieldName":"serverNodeType","operator":"notNull"}'
        }
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/processingTemplate/read?' + $Body)
        If ($null -eq $parameters["Command"]) {
            $parameters.Add('Command', $command)
        }
        Else {
            $parameters.Command = $command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        If ($results.response.status -ne 0) {
            [string]$Message = $results.response | ConvertTo-Json -Compress
            Write-Warning "$Message"
        }
        If ($results.response.status -ne 0) {
            If ($null -eq $results.response.status) {
                Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                Break
            }
            Else {
                [int32]$status_code = $results.response.status
                [string]$results_response = $results.response
                Write-Warning -Message "Received status code [$status_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWTask[]]$Tasks = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWTask] objects due to [$Message]."
            Break
        }
        If ($Tasks.Count -gt 0) {
            Return $Tasks
        }
    }
    End {

    }
}

Function Export-AutomateNOWTask {
    <#
    .SYNOPSIS
    Exports the Tasks from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the Tasks from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWTask] object (Use Get-AutomateNOWTask to retrieve them)
    
    .INPUTS
    ONLY [ANOWTask] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWTask] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWTask | Export-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01' | Export-AutomateNOWTask

    .EXAMPLE
    @( 'Task01', 'Task02' ) | Get-AutomateNOWTask | Export-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask | Where-Object { $_.taskType -eq 'PYTHON' } | Export-AutomateNOWTask

    .NOTES
	You must present [ANOWTask] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWTask]$Task
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Tasks-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWTask]$Task = $_
        }
        $Error.Clear()
        Try {
            $Task | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWTask] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function New-AutomateNOWTask {
    <#
    .SYNOPSIS
    Creates a Task within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a Task within an AutomateNOW! instance and returns back the newly created [ANOWTask] object

    .PARAMETER Id
    The intended name of the Task. For example: 'LinuxTask1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the Task.

    .PARAMETER Description
    Optional description of the Task.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Task. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the Task into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Task into.

    .PARAMETER WeightCapacity
    Optional integer to specify the total weight capacity of the Task. Defaults to 50.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWTask.
    
    .OUTPUTS
    An [ANOWTask] object representing the newly created Task
    
    .EXAMPLE
    New-AutomateNOWTask
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the task must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWTask])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWserverTask_type]$Type,
        [Parameter(Mandatory = $false)]
        [int32]$WeightCapacity = 50,
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$Task_exists = ($null -ne (Get-AutomateNOWTask -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWTask failed to check if the Task [$Id] already existed due to [$Message]."
        Break
    }
    If ($Task_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Task named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWTask]$ANOWTask = New-Object -TypeName ANOWTask
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed due to create the object of type [ANOWTask] due to [$Message]."
        Break
    }
    $ANOWTask.'id' = $Id
    $ANOWTask.'serverTaskType' = $Type
    $ANOWTask.'loadBalancer' = $alse
    $ANOWTask.'totalWeightCapacity' = $WeightCapacity
    $ANOWTask.'description' = $Description
    $ANOWTask.'tags' = $Tags
    $ANOWTask.'folder' = $Folder
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWTask -IncludeProperties id, serverTaskType, loadBalancer, totalWeightCapacity, description, tags, folder, codeRepository
    [hashtable]$BodyMetaData = @{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = ('{"serverTaskType":"' + $Type + '","loadBalancer":' + $LoadBalancer + ',"totalWeightCapacity":' + $WeightCapacity + '}')
    $BodyMetaData.'_componentId' = 'ServerTaskCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'ServerTaskDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/serverTask/create'
    [hashtable]$parameters = @{}
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Task [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Task [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWTask]$Task = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWTask] object due to [$Message]."
        Break
    }        
    If ($Task.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWTask] Task is empty!"
        Break
    }
    Return $Task
}

Function Remove-AutomateNOWTask {
    <#
    .SYNOPSIS
    Removes a Task from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Remove-AutomateNOWTask` function removes a Task from an AutomateNOW! instance
    
    .PARAMETER Task
    An [ANOWTask] object representing the Task to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01' | Remove-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01', 'Task02' | Remove-AutomateNOWTask
    
    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Remove-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask | ? { $_.serverTaskType -eq 'LINUX' } | Remove-AutomateNOWTask
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
            Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
            Break
        }
        ElseIf ($Id -Match '[.{1,}].{1,}') {
            Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually required the 'simple id':-)"
            Break
        }
        [string]$command = '/serverTask/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Task.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Task_id = $_.id
                
            }
            ElseIf ($Task.id.Length -gt 0) {
                [string]$Task_id = $Task.id
            }
            Else {
                [string]$Task_id = $Id
            }
            [string]$Body = 'id=' + $Task_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$Task_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Task $Task_id successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - TimeZones

Function Get-AutomateNOWTimeZone {
    <#
    .SYNOPSIS
    Gets all of the supported time zones from the global session variable
    
    .DESCRIPTION    
    The `Get-AutomateNOWTimeZone` gets all of the supported time zones from the global session variable
    
    .INPUTS
    `Get-AutomateNOWTimeZone` accepts a timezone ID's from the pipeline
    
    .OUTPUTS
    An array of [ANOWTimeZone] objects
    
    .EXAMPLE
    Get-AutomateNOWTimeZone

    .EXAMPLE
    Get-AutomateNOWTimeZone -Id 'Pacific/Honolulu'

    .EXAMPLE
    @( 'Pacific/Honolulu', 'Pacific/Midway' ) | Get-AutomateNOWTimeZone

    .EXAMPLE
    Get-AutomateNOWTimeZone | Where-Object {$_.name -match 'Greenwich' }
    
    .NOTES
    You must use Import-AutomateNOWTimeZone to fill up the global session variable with the supported timezones.

    #>
    [OutputType([ANOWTimeZone[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z/+-]{1,}$' })]
        [string]$Id
    )
    Begin {
        [int32]$supported_timezone_count = $anow_session.supported_timezones.count
        If ($supported_timezone_count -eq 0) {
            Write-Warning -Message "Please use Import-AutomateNOWTimeZone to import the supported timezones into your global session variable"
            Break
        }
        Else {
            Write-Verbose -Message "returning $supported_timezone_count timezone objects."
        }
    }
    Process {
        If ($Id.Length -eq 0) {
            [ANOWTimeZone[]]$Result = $anow_session.supported_timezones
        }
        Else {
            [ANOWTimeZone]$Result = $anow_session.supported_timezones | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
        }
        Return $Result
    }
}

Function Export-AutomateNOWTimeZone {
    <#
    .SYNOPSIS
    Exports the timezones from the global session variable
    
    .DESCRIPTION    
    Exports the timezones from the global session variable to a local .csv file
    
    .PARAMETER Timezone
    Optional [ANOWTimezone] object (Use Get-AutomateNOWTimezone to retrieve them)
    
    .PARAMETER Id
    Optional string representing the Id of the timezone (e.g. Americas/New York)
    
    .INPUTS
    [ANOWTimeZone] objects from the pipeline are accepted or you can specify the name (id) of the timezone (see Examples below).
    
    .OUTPUTS
    The [ANOWTimeZone] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWTimeZone | Export-AutomateNOWTimeZone

    .EXAMPLE
    Get-AutomateNOWTimeZone -Id 'Pacific/Honolulu' | Export-AutomateNOWtimeZone
    
    .EXAMPLE
    @( 'Pacific/Honolulu', 'Pacific/Midway' ) | Get-AutomateNOWTimeZone | Export-AutomateNOWTimeZone

    .EXAMPLE
    Get-AutomateNOWTimeZone | Where-Object {$_.name -match 'Greenwich' } | Export-AutomateNOWTimeZone

    .NOTES
    You may present [ANOWTimezone] objects to the pipeline or specify the -Id manually.

    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWTimeZone]$TimeZone,
        [ValidateScript({ $_ -match '^[0-9a-zA-z/+-]{1,}$' })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Individual')]
        [string]$Id
    )
    Begin {
        [int32]$supported_timezone_count = $anow_session.supported_timezones.count
        If ($supported_timezone_count -eq 0) {
            Write-Warning -Message "Please use Import-AutomateNOWTimeZone to import the supported timezones into your global session variable"
            Break
        }
        Else {
            Write-Verbose -Message "Exporting $supported_timezone_count timezone objects."
        }
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-TimeZones-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($All -eq $true) {
            $Error.Clear()
            Try {
                [ANOWTimeZone[]]$ANOWTimeZones = $anow_session.supported_timezones
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to extract the [ANOWTimeZone] objects due to [$Message]"
                Break
            }
            $Error.Clear()
            Try {
                $ANOWTimeZones | Export-CSV @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Export-CSV failed to export the [ANOWTimeZone] objects due to [$Message]"
                Break
            }
        }
        ElseIf ($_.id.Length -gt 0) {
            If ($null -eq $parameters.'Append') {
                $parameters.Add('Append', $true)
            }
            [string]$current_timezone_id = $_.id
            [ANOWTimeZone]$ANOWTimeZone = $anow_session.supported_timezones | Where-Object { $_.id -eq $current_timezone_id } | Select-Object -First 1
            $Error.Clear()
            Try {
                $ANOWTimeZone | Export-CSV @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Export-CSV failed to export the [ANOWTimeZone] object on the pipeline due to [$Message]"
                Break
            }
        }
        ElseIf ($Id.length -gt 0) {
            $Error.Clear()
            Try {
                [ANOWTimeZone]$ANOWTimeZone = $anow_session.supported_timezones | Where-Object { $_.Id -eq $Id }
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to extracted the named timezone due to [$Message]. Did you enter a valid Id?"
                Break
            }            
            $Error.Clear()
            Try {
                $ANOWTimeZone | Export-CSV @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Export-CSV failed to export the [ANOWTimeZone] objects due to [$Message]"
                Break
            }
        }
        Else {
            Write-Warning -Message "Export-AutomateNOWTimeZone was somehow unable to process the input"
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function Import-AutomateNOWTimeZone {
    <#
    .SYNOPSIS
    Imports all of the supported time zones from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Import-AutomateNOWTimeZone` imports all of the supported time zones from an instance of AutomateNOW! into the existing global session variable.
    
    .INPUTS
    None. You cannot pipe objects to Import-AutomateNOWTimeZone.
    
    .OUTPUTS
    There is no direct output as the timezone objects are loaded into the existing global session variable.
    
    .EXAMPLE
    Import-AutomateNOWTimeZone
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters for Import-AutomateNOWTimeZone.

    #>
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/home/readTimeZones'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_textMatchStyle', 'exact')
    $BodyObject.Add('_componentId', 'cacheAllData')
    $BodyObject.Add('_dataSource', 'TimeZoneDataSource')
    $BodyObject.Add('_operationId', 'TimeZoneDataSource_fetch')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    [string]$Body = ConvertTo-QueryString -InputObject $BodyObject    
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'GET')
    $parameters.Add('Body', $Body)
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Instance', $Instance)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    [ANOWTimezone[]]$TimeZones = $results.response.data
    [int32]$TimeZones_count = $TimeZones.Count
    If ($TimeZones_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 time zones..."
        Break
    }
    If ($null -eq $anow_session.supported_timezones) {
        $anow_session.Add('supported_timezones', $TimeZones)
    }
    Else {
        $anow_session.supported_timezones = $TimeZones
    }
    Write-Verbose -Message "Imported [$TimeZones_count] time zones into the current session"
}

#endregion

#Region - Users

Function Get-AutomateNOWUser {
    <#
    .SYNOPSIS
    Gets the details of the currently authenticated user
    
    .DESCRIPTION    
    Gets the details of the currently authenticated user from an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWUser.
    
    .OUTPUTS
    A single [ANOWUser] object
    
    .EXAMPLE
    Get-AutomateNOWUser
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.

    Get-AutomateNOWUser DOES NOT refresh the token automatically. This is because it is used during the authentication process.
    #>
    [OutputType([ANOWUser])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet -DoNotRefresh) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/secUser/getUserInfo'
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'GET')
    $parameters.Add('Instance', $Instance)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    $Error.Clear()
    Try {
        [ANOWUser]$current_user = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    Return $current_user
}

Function Export-AutomateNOWUser {
    <#
    .SYNOPSIS
    Exports the users from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the users from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER User
    Mandatory [ANOWUser] object (Use Get-AutomateNOWUser to retrieve them)
    
    .INPUTS
    ONLY [ANOWUser] objects from the pipeline are accepted. Strings are not accepted.
    
    .OUTPUTS
    The [ANOWUser] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWUser | Export-AutomateNOWUser

    .NOTES
	You must present [ANOWUser] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWUser]$User
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Users-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWUser]$User = $_
        }
        $Error.Clear()
        Try {
            $User | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWUser] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

#endregion

#Region - Workflows

Function Get-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Gets the workflows from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the workflows from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the workflow to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .INPUTS
    Accepts a string representing the simple id of the workflow from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWWorkflow] class objects
    
    .EXAMPLE
    Get-AutomateNOWWorkflow

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'workflow_01'

    .EXAMPLE
    @( 'workflow_01', 'workflow_02' ) | Get-AutomateNOWWorkflow

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the workflows.

    #>
    [OutputType([ANOWWorkflow[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
    }
    Process {
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            [hashtable]$Body = @{}
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            $Body.'_operationType' = 'fetch'
            $Body.'_operationId' = 'read'
            $Body.'_textMatchStyle' = 'exactCase'
            $Body.'_dataSource' = 'ProcessingTemplateDataSource'
            $Body.'isc_metaDataPrefix' = '_'
            $Body.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $Body
            [string]$command = ('/processingTemplate/read?' + $Body)
        }
        Else {
            [string]$command = '/processingTemplate/read'
        }
        If ($null -eq $parameters["Command"]) {
            $parameters.Add('Command', $command)
        }
        Else {
            $parameters.Command = $command
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
            Break
        }
        If ($results.response.status -ne 0) {
            [string]$Message = $results.response | ConvertTo-Json -Compress
            Write-Warning "$Message"
        }
        If ($results.response.status -ne 0) {
            If ($null -eq $results.response.status) {
                Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                Break
            }
            Else {
                [int32]$status_code = $results.response.status
                [string]$results_response = $results.response
                Write-Warning -Message "Received status code [$status_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                Break
            }
        }
        $Error.Clear()
        Try {
            [ANOWWorkflow[]]$workflows = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWWorkflow] objects due to [$Message]."
            Break
        }
        If ($workflows.Count -gt 0) {
            Return $workflows
        }
    }
    End {

    }
}

Function Export-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Exports the workflows from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the workflows from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWWorkflow] object (Use Get-AutomateNOWWorkflow to retrieve them)
    
    .INPUTS
    ONLY [ANOWWorkflow] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWWorkflow] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWWorkflow | Export-AutomateNOWWorkflow

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01' | Export-AutomateNOWWorkflow

    .EXAMPLE
    @( 'Workflow01', 'Workflow02', 'Workflow03' ) | Get-AutomateNOWWorkflow | Export-AutomateNOWWorkflow

    .EXAMPLE
    Get-AutomateNOWWorkflow | Where-Object { $_.id -like '*MyWorkflow*' } | Export-AutomateNOWWorkflow

    .NOTES
	You must present [ANOWWorkflow] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWWorkflow]$Workflow
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Workflows-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWWorkflow]$workflow = $_
        }
        $Error.Clear()
        Try {
            $workflow | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWWorkflow] object on the pipeline due to [$Message]"
            Break
        }
    }
    End {
        $Error.Clear()
        If ((Test-Path -Path $ExportFilePath) -eq $true) {
            [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
            [int32]$filelength = $fileinfo.Length
            [string]$filelength_display = "{0:N0}" -f $filelength
            Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
        }
    }
}

Function New-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Creates a Workflow within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a Workflow within an AutomateNOW! instance and returns back the newly created [ANOWWorkflow] object

    .PARAMETER Id
    The intended name of the workflow. For example: 'MyWorkflow1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the Workflow.

    .PARAMETER Description
    Optional description of the Workflow.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Workflow. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the Workflow into.

    .PARAMETER WorkSpace
    Optional name of the code workspace to place the Workflow into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Workflow into.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWWorkflow.
    
    .OUTPUTS
    An [ANOWWorkflow] object representing the newly created workflow
    
    .EXAMPLE
    New-AutomateNOWWorkflow -Id 'Workflow01' -Type STANDARD

    .EXAMPLE
    New-AutomateNOWWorkflow -Id 'Workflow01' -Type STANDARD -Description 'description' -Tags 'Tag1', 'Tag2' -Folder 'Folder1' -CodeRepository 'MyCodeRepository' -Workspace 'MyWorkspace'
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the workflow must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWWorkflow])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWWorkflow_workflowType]$Type,
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$Workspace,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$Workflow_exists = ($null -ne (Get-AutomateNOWWorkflow -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWWorkflow failed to check if the workflow [$Id] already existed due to [$Message]."
        Break                
    }
    If ($Workflow_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a workflow named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWWorkflow]$ANOWWorkflow = New-Object -TypeName ANOWWorkflow
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed due to create the object of type [ANOWWorkflow] due to [$Message]."
        Break
    }
    $ANOWWorkflow.'processingType' = 'WORKFLOW'
    $ANOWWorkflow.'workflowType' = $Type
    $ANOWWorkflow.'id' = $Id
    $ANOWWorkflow.'description' = $Description
    $ANOWWorkflow.'tags' = $Tags
    $ANOWWorkflow.'folder' = $Folder
    $ANOWWorkflow.'codeRepository' = $CodeRepository
    $ANOWWorkflow.'workspace' = $Workspace
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWWorkflow -IncludeProperties id, processingType, workflowType, description, tags, folder, codeRepository, workspace
    [hashtable]$BodyMetaData = @{}
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_oldValues' = ('{"processingType":"' + 'WORKFLOW' + '","workflowType":' + $Type + ',"workspace":' + $null + '}')
    $BodyMetaData.'_componentId' = 'ProcessingTemplateCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'ProcessingTemplateDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/processingTemplate/create'
    [hashtable]$parameters = @{}
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Workflow [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Workflow [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWWorkflow]$Workflow = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWWorkflow] object due to [$Message]."
        Break
    }        
    If ($Workflow.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWWorkflow] object is empty!"
        Break
    }
    Return $Workflow
}

Function Remove-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Removes a Workflow from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a Workflow from an AutomateNOW! instance
    
    .PARAMETER Workflow
    An [ANOWworkflow] object representing the workflow to be deleted.
    
    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01' | Remove-AutomateNOWWorkflow

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01', 'Workflow02' | Remove-AutomateNOWWorkflow
    
    .EXAMPLE
    @( 'Workflow1', 'Workflow2', 'Workflow3') | Remove-AutomateNOWWorkflow

    .EXAMPLE
    Get-AutomateNOWWorkflow | ? { $_.workflowType -eq 'STANDARD' } | Remove-AutomateNOWWorkflow
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
            Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
            Break
        }
        ElseIf ($Id -Match '[.{1,}].{1,}') {
            Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually required the 'simple id':-)"
            Break
        }
        [string]$command = '/processingTemplate/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Workflow.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Workflow_id = $_.id
                
            }
            ElseIf ($Workflow.id.Length -gt 0) {
                [string]$Workflow_id = $Workflow.id
            }
            Else {
                [string]$Workflow_id = $Id
            }
            [string]$Body = 'id=' + $Workflow_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$workflow_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Workflow $workflow_id successfully removed"
        }
    }
    End {

    }
}

#endregion
