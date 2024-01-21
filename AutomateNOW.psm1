Using Module .\Classes.psm1
$InformationPreference = 'Continue'

#Region - Utility Functions

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
                
                [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.Value))
            }
        }            
        ElseIf ($InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
            foreach ($Item in $InputObject.GetEnumerator()) {
                if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                [string]$ParameterName = $Item.Key
                If ($Item.value -is [boolean]) {
                    If ($Item.value -eq $true) {
                        [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('true'))
                    }
                    Else {
                        [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('false'))
                    }
                }
                Else {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.value))
                }
            }
        }
        ElseIf ($InputObject.GetType().FullName.StartsWith('ANOW')) {
            foreach ($Item in ($InputObject | Get-Member | Where-Object { $_.MemberType -eq 'Property' } | Select-Object -ExpandProperty Name)) {
                If ($item -in $IncludeProperties) {
                    if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                    [string] $ParameterName = $Item
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

Function New-WebkitBoundaryString {
    [string]$webkit_boundary = (((65..90) | Sort-Object { Get-Random } | Select-Object -First 5 | ForEach-Object { [char]$_ }) + ((48..57) | Sort-Object { Get-Random } | Select-Object -First 5 | ForEach-Object { [char]$_ }) + ((97..122) | Sort-Object { Get-Random } | Select-Object -First 6 | ForEach-Object { [char]$_ }) | Sort-Object { Get-Random }) -join ''
    Return $webkit_boundary
}

#endregion

#Region - API Functions
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
    
    .PARAMETER BinaryBody
    Specifies a byte array for the body. This is used for uploading files.
    
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
    The corresponding ANOW Data Source Item type is returned (e.g. a local dictionary store item)
    
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
        [byte[]]$BinaryBody,
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
    If ($Body.Length -gt 0 -and $BinaryBody.Count -gt 0) {
        Write-Warning -Message "You cannot specify a binary body and a text body. Please choose one or the other."
        Break
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
        $parameters.Add('Headers', $Headers)
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
    ElseIf ($BinaryBody.Count -gt 0) {
        $parameters.Add('Body', $BinaryBody)
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
    If ($content -notmatch '^{.{1,}}$' -and $BinaryBody.Count -eq 0) {
        Write-Warning -Message "The returned results were somehow not a JSON object."
        Break
    }
    If ($JustGiveMeJSON -eq $true) {
        Return $content
    }
    $Error.Clear()
    If ($BinaryBody.Count -eq 0) {
        Try {
            [PSCustomObject]$content_object = $content | ConvertFrom-JSON
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "ConvertFrom-JSON failed to convert the returned results due to [$Message]."
            Break
        }
    }
    Else {
        [array]$split_content = $content -split "`n"
        [int32]$split_content_count = $split_content.Count
        If ($split_content_count -eq 0) {
            Write-Warning "Failed to interpret the response after posting a binary payload. Please look into this."
            Break
        }
        [string]$data = $split_content -cmatch 'messageType'
        If ($data.Length -eq 0) {
            Write-Warning -Message "Failed to extract the messageType after posting a binary payload. Please look into this."
            Break
        }
        Else {
            [string]$data = $data.Trim()
        }
        $Error.Clear()
        Try {
            [PSCustomObject]$content_object = $data | ConvertFrom-Json
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "ConvertFrom-JSON failed to convert the returned results after posting a binary payload due to [$Message]."
            Break
        }
        [string]$messageType = $content_object.messageType
        If ($messageType.Length -eq 0) {
            Write-Warning "Failed to extract the messageType (from the response JSON) after posting a binary payload. Please look into this."
            Break
        }
        [int32]$response_code = $content_object.response.status        
        If ($response_code -eq 0) {
            $Error.Clear()
            Try {
                $content_object.response.data.masterDataSource = $DataSource                
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning "Failed to convert the returned results into a [ANOWLocalFileStoreRecord] object after successfully posting a binary payload due to [$Message]."
                Break
            }            
        }
        ElseIf ($response_code -eq -1) {
            [string]$error_message = $data_object.response.data
            Write-Warning -Message "Error: [$messageType] $error_message"
            Break
        }
    }
    Return $content_object
}
#endregion

#Region - Authentication Functions

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
        Write-Warning "Get-TimeZone failed to get the time zone due to [$Message]."
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
            Write-Warning "Get-Date failed to process the expiration date from the `$token_properties variable due to [$Message]"
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
                Write-Warning "Get-Date failed to process the expiration date from the `$ExpirationDate variable due to [$Message]"
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
        Write-Warning "New-Variable failed to create the session properties object due to [$Message]"
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
                    Write-Warning "Failed to parse the results of the home page details object due to [$Message]"
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] while running Disconnect-AutomateNOW due to [$Message]."
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] while running Set-AutomateNOWPassword due to [$Message]."
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
        Write-Warning "Get-TimeZone failed to get the time zone due to [$Message]."
        Break
    }
    [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    $Error.Clear()
    Try {
        [datetime]$expiration_date_utc = (Get-Date -Date '1970-01-01').AddMilliseconds($token_properties.expirationDate)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "Get-Date failed to process the authentication properties due to [$Message]"
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

#Region - Object Functions

#Region - DataSources

Function Get-AutomateNOWDataSource {
    <#
    .SYNOPSIS
    Gets the DataSources from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the DataSources from an AutomateNOW! instance
    
    .PARAMETER Type
    String identifying the type of DataSource. Valid options are: LOCAL_DICTIONARY, LOCAL_KEY_VALUE_STORE, LOCAL_FILE_STORE, LOCAL_TEXT_FILE_STORE

    .PARAMETER Id
    String containing the simple id of the DataSource to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the DataSource from the pipeline or individually (but not an array) or you can specify by start and end rows.
    
    .OUTPUTS
    An array of one or more [ANOWDataSource] class objects
    
    .EXAMPLE
    Get-AutomateNOWDataSource

    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'my_DataSource_01'

    .EXAMPLE
    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY

    .EXAMPLE
    Get-AutomateNOWDataSource -startRow 0 -endRow 500

    .EXAMPLE
    @( 'my_DataSource_01', 'my_DataSource_02' ) | Get-AutomateNOWDataSource

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the DataSources.

    #>
    [OutputType([ANOWDataSource[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$endRow = 2000,
        [Parameter(Mandatory = $False, ParameterSetName = 'Id', ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False, ParameterSetName = 'Type')]
        [ANOWDataSource_dataSourceType]$Type
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($startRow -gt $endRow) {
            Write-Warning -Message "The start row must not exceed the end row."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }    
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {            
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
        }
        Else {
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = 'exact'
        $Body.'_componentId' = 'DataSourceList'
        $Body.'_dataSource' = 'DataSourceDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/dataSource/read?' + $Body)
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] while running Get-AutomateNOWDataSource due to [$Message]."
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
            [ANOWDataSource[]]$DataSources = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWDataSource] objects due to [$Message]."
            Break
        }
        If ($Type.Length -gt 0) {
            $DataSources = $DataSources | Where-Object { $_.datasourceType -eq $Type }
        }
        If ($DataSources.Count -gt 0) {
            Return $DataSources
        }
    }
    End {

    }
}

Function Export-AutomateNOWDataSource {
    <#
    .SYNOPSIS
    Exports the DataSources from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the DataSources from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWDataSource] object (Use Get-AutomateNOWDataSource to retrieve them)
    
    .INPUTS
    ONLY [ANOWDataSource] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWDataSource] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWDataSource | Export-AutomateNOWDataSource

    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01' | Export-AutomateNOWDataSource

    .EXAMPLE
    @( 'DataSource01', 'DataSource02' ) | Get-AutomateNOWDataSource | Export-AutomateNOWDataSource

    .EXAMPLE
    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY | Export-AutomateNOWDataSource

    .NOTES
	You must present [ANOWDataSource] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWDataSource]$DataSource
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-DataSources-' + $current_time + '.csv'
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
            [ANOWDataSource]$DataSource = $_
        }
        $Error.Clear()
        Try {
            $DataSource | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWDataSource] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWDataSource {
    <#
    .SYNOPSIS
    Creates a DataSource within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a DataSource within an AutomateNOW! instance and returns back the newly created [ANOWDataSource] object

    .PARAMETER Id
    The intended name of the DataSource. For example: 'LinuxDataSource1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the DataSource. Valid options are: LOCAL_DICTIONARY, LOCAL_KEY_VALUE_STORE, LOCAL_FILE_STORE, LOCAL_TEXT_FILE_STORE

    .PARAMETER Description
    Optional description of the DataSource (may not exceed 255 characters).

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new DataSource. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the DataSource into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the DataSource into.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWDataSource.
    
    .OUTPUTS
    An [ANOWDataSource] object representing the newly created DataSource
    
    .EXAMPLE
    New-AutomateNOWDataSource
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the DataSource must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWDataSource])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWDataSource_dataSourceType]$Type,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
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
        [boolean]$DataSource_exists = ($null -ne (Get-AutomateNOWDataSource -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWDataSource failed to check if the DataSource [$Id] already existed due to [$Message]."
        Break
    }
    If ($DataSource_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a DataSource named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWDataSource]$ANOWDataSource = New-Object -TypeName ANOWDataSource
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed to create the object of type [ANOWDataSource] due to [$Message]."
        Break
    }
    $ANOWDataSource.'id' = $Id
    $ANOWDataSource.'dataSourceType' = $Type
    $ANOWDataSource.'description' = $Description
    $ANOWDataSource.'tags' = $Tags
    $ANOWDataSource.'folder' = $Folder
    $ANOWDataSource.'codeRepository' = $codeRepository
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWDataSource -IncludeProperties id, dataSourceType, description, tags, folder, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = ('{"dataSourceType":"' + $Type + '"}')
    $BodyMetaData.'_componentId' = 'DataSourceCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'DataSourceDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/dataSource/create'
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create DataSource [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create DataSource [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWDataSource]$DataSource = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWDataSource] object due to [$Message]."
        Break
    }        
    If ($DataSource.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWDataSource] DataSource is empty!"
        Break
    }
    Return $DataSource
}

Function Remove-AutomateNOWDataSource {
    <#
    .SYNOPSIS
    Removes a DataSource from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Remove-AutomateNOWDataSource` function removes a DataSource from an AutomateNOW! instance
    
    .PARAMETER DataSource
    An [ANOWDataSource] object representing the DataSource to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWDataSource] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01' | Remove-AutomateNOWDataSource

    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01', 'DataSource02' | Remove-AutomateNOWDataSource
    
    .EXAMPLE
    @( 'DataSource1', 'DataSource2', 'DataSource3') | Remove-AutomateNOWDataSource

    .EXAMPLE
    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY | Remove-AutomateNOWDataSource
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWDataSource]$DataSource,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/dataSource/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($DataSource.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$DataSource_id = $_.id
                
            }
            ElseIf ($DataSource.id.Length -gt 0) {
                [string]$DataSource_id = $DataSource.id
            }
            Else {
                [string]$DataSource_id = $Id
            }
            [string]$Body = 'id=' + $DataSource_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$DataSource_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "DataSource $DataSource_id successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - DataSourceItems

Function Get-AutomateNOWDataSourceItem {
    <#
    .SYNOPSIS
    Gets the DataSourceItems from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the DataSourceItems from an AutomateNOW! instance
    
    .PARAMETER DataSource
    Mandatory [ANOWDataSource] object. Use Get-AutomateNOWDataSource to get this object.

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts [ANOWDataSource] objects either individually or from the pipeline.
    
    .OUTPUTS
    An array of one or more [ANOWDataSourceItem] class objects that are linked to the provided [ANOWDataSource] object
    
    .EXAMPLE
    Get-AutomateNOWDataSource | Get-AutomateNOWDataSourceItem

    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01' | Get-AutomateNOWDataSourceItem

    .EXAMPLE
    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY | Get-AutomateNOWDataSourceItem

    .EXAMPLE
    @( 'DataSource01', 'DataSource02' ) | Get-AutomateNOWDataSource | Get-AutomateNOWDataSourceItem -startRow 0 -endRow 5

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the DataSourceItems.

    #>
    [OutputType([ANOWDataSourceItem[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ANOWDataSource]$DataSource,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$endRow = 2000
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($startRow -gt $endRow) {
            Write-Warning -Message "The start row must not exceed the end row."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.Id.Length -gt 0) {
            $DataSource = $_
        }
        [string]$Type = $DataSource.dataSourceType
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        [string]$DataSource_id = $DataSource.id
        $Body.Add('masterDataSource', $DataSource_id)
        $Body.Add('_operationType', 'fetch')
        $Body.Add('_startRow', $startRow)
        $Body.Add('_endRow', $endRow)
        $Body.Add('_textMatchStyle', 'substring')
        If ($Type -eq 'LOCAL_DICTIONARY') {
            [string]$command = '/localDictionaryRecord/read?'
            $Body.Add('_sortBy', 'value')
            $Body.Add('_componentId', 'LocalDictionaryRecordList')
            $Body.Add('_dataSource', 'LocalDictionaryRecordDataSource')        
        }
        ElseIf ($Type -eq 'LOCAL_KEY_VALUE_STORE') {
            [string]$command = '/localKeyValueStoreRecord/read?'
            $Body.Add('_sortBy', 'value')
            $Body.Add('_componentId', 'LocalKeyValueStoreRecordList')
            $Body.Add('_dataSource', 'LocalKeyValueStoreRecordDataSource')        
        }
        ElseIf ($Type -eq 'LOCAL_FILE_STORE') {
            [string]$command = '/localFileStoreRecord/read?'
            $Body.Add('_componentId', 'LocalFileStoreRecordList')
            $Body.Add('_dataSource', 'LocalFileStoreRecordDataSource')        
        }
        ElseIf ($Type -eq 'LOCAL_TEXT_FILE_STORE') {
            [string]$command = '/localTextFileStoreRecord/read?'
            $Body.Add('_componentId', 'LocalTextFileStoreRecordList')
            $Body.Add('_dataSource', 'LocalTextFileStoreRecordDataSource')        
        }
        Else {
            Write-Warning -Message "Failed to determine DataSourceItem type!"
            Break
        }
        $Body.Add('isc_metaDataPrefix', '_')
        $Body.Add('isc_dataFormat', 'json')
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ($command + $Body)
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
        [int32]$DataSourceItemsCount = $results.response.data.count
        If ($DataSourceItemsCount -gt 0) {
            If ($Type -eq 'LOCAL_DICTIONARY') {
                $Error.Clear()
                Try {
                    [ANOWLocalDictionaryRecord[]]$DataSourceItems = ForEach ($result in $results.response.data) {
                        $result.masterDataSource = $DataSource
                        $result
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the response into a series of [ANOWLocalDictionaryRecord] objects due to [$Message]."
                    Break
                }
            }
            ElseIf ($Type -eq 'LOCAL_KEY_VALUE_STORE') {
                $Error.Clear()
                Try {
                    [ANOWLocalKeyValueStoreRecord[]]$DataSourceItems = ForEach ($result in $results.response.data) {
                        $result.masterDataSource = $DataSource
                        $result
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the response into a series of [ANOWLocalKeyValueStoreRecord] objects due to [$Message]."
                    Break
                }
                If ($DataSourceItems.Count -gt 0) {
                    Return $DataSourceItems
                }
            }
            ElseIf ($Type -eq 'LOCAL_FILE_STORE') {
                $Error.Clear()
                Try {
                    [ANOWLocalFileStoreRecord[]]$DataSourceItems = ForEach ($result in $results.response.data) {
                        $result.masterDataSource = $DataSource
                        $result
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the response into a series of [ANOWLocalFileStoreRecord] objects due to [$Message]."
                    Break
                }
                If ($DataSourceItems.Count -gt 0) {
                    Return $DataSourceItems
                }
            }
            ElseIf ($Type -eq 'LOCAL_TEXT_FILE_STORE') {
                $Error.Clear()
                Try {
                    [ANOWLocalTextFileStoreRecord[]]$DataSourceItems = ForEach ($result in $results.response.data) {
                        $result.masterDataSource = $DataSource
                        $result
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to parse the response into a series of [ANOWLocalTextFileStoreRecord] objects due to [$Message]."
                    Break
                }
                If ($DataSourceItems.Count -gt 0) {
                    Return $DataSourceItems
                }
            }
            Else {
                Write-Warning -Message "Failed to determine DataSourceItem type!"
                Break
            }            
        }
        Else {
            Write-Verbose -Message "There no items in DataSource ($DataSource_id)"
        }
    }
    End {

    }
}

Function Export-AutomateNOWDataSourceItem {
    <#
    .SYNOPSIS
    Exports the DataSourceItems from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the DataSourceItems from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER DataSourceItem
    Mandatory [ANOWDataSourceItem] object (Use Get-AutomateNOWDataSourceItem to retrieve them)
    
    .PARAMETER Type
    Mandatory string indicating the type of DataSourceItem to be exported. Valid choices are: LOCAL_DICTIONARY, LOCAL_KEY_VALUE_STORE, LOCAL_FILE_STORE, LOCAL_TEXT_FILE_STORE
    
    .INPUTS
    ONLY [ANOWDataSourceItem] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWDataSourceItem] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY | Get-AutomateNOWDataSourceItem | Export-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY

    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01' | Get-AutomateNOWDataSourceItem | Export-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY

    .EXAMPLE
    @( 'DataSource01', 'DataSource02' ) | Get-AutomateNOWDataSource | Get-AutomateNOWDataSourceItem -startRow 0 -endRow 5 | Export-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY

    .NOTES
	You must present [ANOWDataSourceItem] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWDataSourceItem]$DataSourceItem,
        [Parameter(Mandatory = $true)]
        [ANOWDataSource_dataSourceType]$Type
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = "Export-AutomateNOW-DataSourceItems-$Type-" + $current_time + '.csv'
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
            $DataSourceItem = $_ # do not hard type this variable
        }
        If ($DataSourceItem.masterDataSource.dataSourceType -ne $Type) {
            [string]$dataSourceType = $DataSourceItem.masterDataSource.dataSourceType
            Write-Warning -Message "You specified [$Type] as the DataSource Type but a DataSource of type [$dataSourceType] was sent instead. Exiting."
            Break
        }
        $Error.Clear()
        Try {
            $DataSourceItem | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWDataSourceItem] object on the pipeline due to [$Message]"
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

Function Add-AutomateNOWDataSourceItem {
    <#
    .SYNOPSIS
    Adds a DataSourceItem to a DataSource within an AutomateNOW! instance
    
    .DESCRIPTION    
    Adds a DataSourceItem to a DataSource within an AutomateNOW! instance and returns back the newly created [ANOWDataSourceItem]

    .PARAMETER DataSource
    Mandatory [ANOWDataSource] object. Use Get-AutomateNOWDataSource to get this object.

    .PARAMETER Type
    Required type of the DataSourceItem. Valid options are: LOCAL_DICTIONARY, LOCAL_KEY_VALUE_STORE, LOCAL_FILE_STORE, LOCAL_TEXT_FILE_STORE

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .PARAMETER key
    [LOCAL_KEY_VALUE_STORE] ONLY - The unique key of the item (must be unique within the datasource)

    .PARAMETER value
    [LOCAL_DICTIONARY] OR [LOCAL_KEY_VALUE_STORE] Either the key of the dictionary item (must be unique within the datasource) OR the value of your key/value pair and does NOT need to be unique.

    .PARAMETER displayValue
    [LOCAL_DICTIONARY] ONLY - The value of the dictionary item. This does not need to be unique within the dictionary data store.

    .PARAMETER file_id
    [LOCAL_FILE_STORE] OR [LOCAL_TEXT_FILE_STORE] This is the unique id of the file which you must supply. This is -not the same- as the name of the file. This property serves the same purpose as the key in a key/value pair.

    .PARAMETER text_file
    [LOCAL_TEXT_FILE_STORE] ONLY - Use Get-Item or Get-ChildItem to get the text file first as a [System.IO.FileSystemInfo] object. See examples below.

    .PARAMETER binary_file
    [LOCAL_FILE_STORE] ONLY - Use Get-Item or Get-ChildItem to get the binary file first as a [System.IO.FileSystemInfo] object. See examples below.

    .PARAMETER mime_type
    [LOCAL_FILE_STORE] ONLY - Mandatory string to specify the mime type. If you're not sure, you can use 'application/octet-stream'. However, it would be good of you to more precisely define the mime type of the file that you are uploading. For now, this needs to be supplied by you, the end-user. For now, you will have to use the console to determine the mime type :( : Examples: .wav = 'audio/wav', .exe = 'application/x-msdownload', .pptx = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'. You could check the registry and go by file extension alone. The console -is- inspecting the file.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWDataSourceItem.
    
    .OUTPUTS
    An [ANOWDataSourceItem] object representing the newly created DataSourceItem
    
    .EXAMPLE
    How to upload an entry to a local dictionary store data source

    $data_source = Get-AutomateNOWDataSource -Id 'data_source_dictionary'
    Add-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY -DataSource $data_source -value '2' -displayValue 'two'

    .EXAMPLE
    How to upload a key/value pair to a local key value store data source

    $data_source = Get-AutomateNOWDataSource -Id 'local_key_value_store'
    Add-AutomateNOWDataSourceItem -Type LOCAL_KEY_VALUE_STORE -DataSource $data_source -key '3' -value 'three'

    .EXAMPLE
    A three-line code that uploads a binary file to a local store data source.

    $data_source = Get-AutomateNOWDataSource -Id 'local_file_store'
    $local_binary_file = Get-Item -Path 'c:\temp\file.exe'
    Add-AutomateNOWDataSourceItem -DataSource $data_source -Type LOCAL_FILE_STORE -file_id 'binary_file_01-file.exe' -local_binary_file $local_binary_file -mime_type 'application/x-msdownload'
    
    .EXAMPLE
    Same as above example except as a one-liner

    Add-AutomateNOWDataSourceItem -DataSource (Get-AutomateNOWDataSource -Id 'local_file_store') -Type LOCAL_FILE_STORE -file_id 'binary_file_01-file.exe' -binary_file (Get-Item -Path 'c:\temp\file.exe') -mime_type 'application/x-msdownload'

    .EXAMPLE
    Reads all of the text files from your 7-Zip installation and uploads them to a local text file store data source. ASCII or UTF-8 files will be differentiated automatically.

    $data_source = Get-AutomateNOWDataSource -Id 'local_text_file_store'
    ForEach($local_file in (Get-ChildItem -File -Recurse -Path 'C:\Program Files (x86)\7-Zip\*.txt')){
        [string]$file_name = $local_file.name
        Add-AutomateNOWDataSourceItem -DataSource $data_source -Type LOCAL_TEXT_FILE_STORE -file_id $file_name -text_file $local_file -Quiet
    }

    .EXAMPLE
    Reads all of the .wav files from your local Windows installation and uploads them to a local file store data source. The mime type is supplied manually.

    $data_source = Get-AutomateNOWDataSource -Id 'local_file_store'
    ForEach($local_file in (Get-ChildItem -File -Path 'C:\windows\media\*.wav')){
        [string]$file_name = $local_file.name
        Add-AutomateNOWDataSourceItem -DataSource $data_source -Type LOCAL_FILE_STORE -file_id $file_name -binary_file $local_file -Quiet -mime_type 'audio/wav'
    }

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    MimeType does not need to be specified on a text file upload. It is either text/plain or text/plain;charset=UTF-8.

    #>
    [OutputType([ANOWDataSourceItem])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_DICTIONARY')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_KEY_VALUE_STORE')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_FILE_STORE')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_TEXT_FILE_STORE')]
        [ANOWDataSource]$DataSource,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_DICTIONARY')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_KEY_VALUE_STORE')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_FILE_STORE')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_TEXT_FILE_STORE')]
        [ANOWDataSource_dataSourceType]$Type,
        [Parameter(Mandatory = $false, ParameterSetName = 'LOCAL_DICTIONARY')]
        [Parameter(Mandatory = $false, ParameterSetName = 'LOCAL_KEY_VALUE_STORE')]
        [Parameter(Mandatory = $false, ParameterSetName = 'LOCAL_FILE_STORE')]
        [Parameter(Mandatory = $false, ParameterSetName = 'LOCAL_TEXT_FILE_STORE')]
        [switch]$Quiet,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_KEY_VALUE_STORE')]
        [string]$key,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_DICTIONARY')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_KEY_VALUE_STORE')]
        [string]$value,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_DICTIONARY')]
        [string]$displayValue,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_FILE_STORE')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_TEXT_FILE_STORE')]
        [string]$file_id,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_TEXT_FILE_STORE')]
        [System.IO.FileSystemInfo]$text_file,
        [ValidateScript({ (Test-Path -Path $_.FullName) -eq $true })]
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_FILE_STORE')]
        [System.IO.FileSystemInfo]$binary_file,
        [Parameter(Mandatory = $true, ParameterSetName = 'LOCAL_FILE_STORE')]
        [string]$mime_type
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$cr = "`r`n"
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    [string]$DataSource_Id = $DataSource.Id
    [hashtable]$parameters = @{}
    $parameters.Add('Method', 'POST')
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    If ($Type -eq 'LOCAL_DICTIONARY') {        
        If ($value.length -eq 0) {
            Write-Warning -Message "Please include the -value parameter with LOCAL_DICTIONARY type"
            Break
        }
        ElseIf ($displayValue.length -eq 0) {
            Write-Warning -Message "Please include the -displayValue parameter with LOCAL_DICTIONARY type"
            Break
        }
        [ANOWLocalDictionaryRecord[]]$current_items = Get-AutomateNOWDataSourceItem -DataSource $DataSource
        If ($value -in $current_items.value) {
            Write-Warning -Message "An item with the value of [$value] already exists in this dictionary. Please note that every value in the dictionary must be unique (the displayValue does not need to be unique)"
            Break
        }
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        [string]$command = '/localDictionaryRecord/create'
        $Error.Clear()
        Try {
            [ANOWLocalDictionaryRecord]$ANOWDataSourceItem = New-Object -TypeName ANOWLocalDictionaryRecord
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-Object failed to create the object of type [ANOWLocalDictionaryRecord] due to [$Message]."
            Break
        }
        $ANOWDataSourceItem.value = $value
        $ANOWDataSourceItem.displayValue = $displayValue
        [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWDataSourceItem -IncludeProperties value, displayValue
        $BodyMetaData.'masterDataSource' = "$DataSource_Id"
        $BodyMetaData.'_componentId' = 'LocalDictionaryRecordEditForm'
        $BodyMetaData.'_dataSource' = 'LocalDictionaryRecordDataSource'
        $BodyMetaData.'_textMatchStyle' = 'exact'
        $BodyMetaData.'_operationType' = 'add'
        $BodyMetaData.'_oldValues' = '{}'
        $BodyMetaData.'isc_metaDataPrefix' = '_'
        $BodyMetaData.'isc_dataFormat' = 'json'
        [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
        $parameters.Add('Body', $Body)
    }
    ElseIf ($Type -eq 'LOCAL_KEY_VALUE_STORE') {
        If ($key.length -eq 0) {
            Write-Warning -Message "Please include the -key parameter with LOCAL_KEY_VALUE_STORE type"
            Break
        }
        ElseIf ($value.length -eq 0) {
            Write-Warning -Message "Please include the -value parameter with LOCAL_KEY_VALUE_STORE type"
            Break
        }
        [ANOWLocalKeyValueStoreRecord[]]$current_items = Get-AutomateNOWDataSourceItem -DataSource $DataSource
        If ($value -in $current_items.value) {
            Write-Warning -Message "An item with the value of [$value] already exists in this dictionary. Please note that every value in the dictionary must be unique (the displayValue does not need to be unique)"
            Break
        }
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        [string]$command = '/localKeyValueStoreRecord/create'
        $Error.Clear()
        Try {
            [ANOWLocalKeyValueStoreRecord]$ANOWDataSourceItem = New-Object -TypeName ANOWLocalKeyValueStoreRecord
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-Object failed to create the object of type [ANOWLocalKeyValueStoreRecord] due to [$Message]."
            Break
        }
        $ANOWDataSourceItem.key = $key
        $ANOWDataSourceItem.value = $value
        [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWDataSourceItem -IncludeProperties key, value
        $BodyMetaData.'masterDataSource' = "$DataSource_Id"
        $BodyMetaData.'_componentId' = 'LocalKeyValueStoreRecordEditForm'
        $BodyMetaData.'_dataSource' = 'LocalKeyValueStoreRecordDataSource'
        $BodyMetaData.'_textMatchStyle' = 'exact'
        $BodyMetaData.'_operationType' = 'add'
        $BodyMetaData.'_oldValues' = '{}'
        $BodyMetaData.'isc_metaDataPrefix' = '_'
        $BodyMetaData.'isc_dataFormat' = 'json'
        [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
        $parameters.Add('Body', $Body)
    }
    ElseIf ($Type -eq 'LOCAL_FILE_STORE') {
        If ($file_id.length -eq 0) {
            Write-Warning -Message "Please include the -file_id parameter with LOCAL_KEY_VALUE_STORE type"
            Break
        }
        [ANOWLocalFileStoreRecord[]]$current_items = Get-AutomateNOWDataSourceItem -DataSource $DataSource
        If ($file_id -in $current_items.key) {
            Write-Warning -Message "A file with the [$file_id] already exists in this local file store. Please note that every file_id in a local file store must be unique (the contents do not need to be unique)"
            Break
        }
        [hashtable]$get_file_parameters = @{}
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $get_file_parameters.Add('Encoding', 'Byte')
            $get_file_parameters.Add('Raw', $true)
        }
        Else {
            $get_file_parameters.Add('AsByteStream', $true)
        }
        [string]$binary_file_fullname = $binary_file.fullname
        $get_file_parameters.Add('Path', "$binary_file_fullname")
        $Error.Clear()
        Try {
            [byte[]]$file_bytes = Get-Content @get_file_parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-Content failed to create the object of type [ANOWLocalKeyValueStoreRecord] due to [$Message]."
            Break
        }
        [string]$object_id = $DataSource.id
        [string]$uploaded_filename = $binary_file.name
        [string]$boundary_string = New-WebkitBoundaryString
        [System.Collections.ArrayList]$form_prefix = New-Object -TypeName System.Collections.ArrayList
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"id`"" + $cr + $cr)
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"key`"" + $cr)
        [void]$form_prefix.Add($file_id)
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"masterDataSource`"" + $cr)
        [void]$form_prefix.Add($object_id)
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"uploadWindow`"" + $cr)
        [void]$form_prefix.Add("isc_InfiniteWindow_0")
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"access_token`"" + $cr)
        [void]$form_prefix.Add($anow_session.AccessToken)
        [void]$form_prefix.Add("------WebKitFormBoundary$boundary_string")
        [void]$form_prefix.Add("Content-Disposition: form-data; name=`"file`"; filename=`"$uploaded_filename`"")
        [void]$form_prefix.Add("Content-Type: $mime_type" + $cr + $cr)
        [System.Collections.ArrayList]$form_suffix = New-Object -TypeName System.Collections.ArrayList
        [void]$form_suffix.Add($cr + "------WebKitFormBoundary$boundary_string--" + $cr)
        [string]$body_prefix = $form_prefix -join $cr
        [string]$body_suffix = $form_suffix -join ''
        [byte[]]$body_prefix_bytes = [System.Text.Encoding]::UTF8.GetBytes($body_prefix)
        [byte[]]$body_suffix_bytes = [System.Text.Encoding]::UTF8.GetBytes($body_suffix)
        [byte[]]$body = $body_prefix_bytes + $file_bytes + $body_suffix_bytes
        [int32]$content_length = $body.count
        [string]$domain = $anow_session.header.domain
        [string]$command = "/localFileStoreRecord/uploadFile?domain=$domain"
        $parameters.Add('ContentType', "multipart/form-data; boundary=----WebKitFormBoundary$boundary_string")
        $Error.Clear()
        Try {
            [ANOWLocalFileStoreRecord]$ANOWDataSourceItem = New-Object -TypeName ANOWLocalFileStoreRecord
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-Object failed to create the object of type [ANOWLocalFileStoreRecord] due to [$Message]."
            Break
        }
        $ANOWDataSourceItem.key = $file_id
        [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWDataSourceItem -IncludeProperties key
        $parameters.Add('BinaryBody', $Body)
        $parameters.Add('Headers', [hashtable]@{"Content-Length" = $content_length; "Upgrade-Insecure-Requests" = 1; }) # is this header really needed?
    }
    ElseIf ($Type -eq 'LOCAL_TEXT_FILE_STORE') {
        If ($file_id.length -eq 0) {
            Write-Warning -Message "Please include the -file_id parameter with LOCAL_TEXT_FILE_STORE type"
            Break
        }
        If ($mime_type -notmatch '^[a-z-]{1,}\/[a-z0-9-.+]{1,}$') {
            Write-Warning -Message "[$mime_type] does not appear to be a valid mime type. Please, check the mime type or contact the author of this script if there is a mistake."
            Break
        }
        [ANOWLocalTextFileStoreRecord[]]$current_items = Get-AutomateNOWDataSourceItem -DataSource $DataSource
        If ($file_id -in $current_items.key) {
            Write-Warning -Message "A file with the id [$file_id] already exists in this local file store. Please note that every file_id in a local file store must be unique (the contents do not need to be unique)"
            Break
        }
        [hashtable]$get_file_parameters = @{}
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $get_file_parameters.Add('Encoding', 'Byte')
            $get_file_parameters.Add('Raw', $true)
        }
        Else {
            $get_file_parameters.Add('AsByteStream', $true)
        }
        [string]$text_file_fullname = $text_file.fullname
        $get_file_parameters.Add('Path', "$text_file_fullname")
        $Error.Clear()
        Try {
            [byte[]]$file_bytes = Get-Content @get_file_parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-Content failed to create the object of type [ANOWLocalTextFileStoreRecord] due to [$Message]."
            Break
        }
        [string]$object_id = $DataSource.id
        [string]$uploaded_filename = $text_file.name
        If ((($file_bytes | Sort-Object -Unique) | ForEach-Object { $_ -eq 10 -or $_ -eq 13 -or ( $_ -ge 32 -and $_ -le 126) }) -contains $false) {
            [string]$mime_type = 'text/plain;charset=UTF-8'
        }
        Else {
            [string]$mime_type = 'text/plain'
        }        
        [int32]$content_length = $file_bytes.count
        [string]$domain = $anow_session.header.domain
        [string]$command = "/localTextFileStoreRecord/create"
        $parameters.Add('ContentType', "application/x-www-form-urlencoded; charset=UTF-8")
        $Error.Clear()
        Try {
            [ANOWLocalTextFileStoreRecord]$ANOWDataSourceItem = New-Object -TypeName ANOWLocalTextFileStoreRecord
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "New-Object failed to create the object of type [ANOWLocalTextFileStoreRecord] due to [$Message]."
            Break
        }
        $ANOWDataSourceItem.key = $file_id
        $ANOWDataSourceItem.fileName = $uploaded_filename
        $ANOWDataSourceItem.mimeType = $mime_type
        $ANOWDataSourceItem.size = $content_length
        [string]$content = [char[]]$file_bytes -join ''
        [string]$formatted_content = [System.Uri]::UnescapeDataString($content)
        $ANOWDataSourceItem.content = $formatted_content
        [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWDataSourceItem -IncludeProperties key, fileName, mimeType, size, content
        $BodyMetaData.'masterDataSource' = "$DataSource_Id"
        $BodyMetaData.'_componentId' = 'LocalTextFileStoreRecordEditForm'
        $BodyMetaData.'_dataSource' = 'LocalTextFileStoreRecordDataSource'
        $BodyMetaData.'_textMatchStyle' = 'exact'
        $BodyMetaData.'_operationType' = 'add'
        $BodyMetaData.'_oldValues' = '{}'
        $BodyMetaData.'isc_metaDataPrefix' = '_'
        $BodyMetaData.'isc_dataFormat' = 'json'
        [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
        $parameters.Add('Body', $Body)
    }
    Else {
        Write-Warning -Message "Failed to determine DataSourceItem type!"
        Break
    }
    $parameters.Add('Command', $command)
    [string]$parameters_display = $parameters | ConvertTo-Json -Compress
    $Error.Clear()
    Try {
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    [string]$DataSourceItem_Id = $results.id
    If ($DataSourceItem_Id -match '[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}') {        
        Write-Information -Message "Item $file_id was successfully added to $DataSource_Id."
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "After trying to add item $file_id was to Data Source [$DataSource_Id], an empty response was received. Please look into this."
        Break
    }
    $Error.Clear()
    Try {
        Switch ($Type) {
            LOCAL_DICTIONARY {
                [PSCustomObject]$current_result = $results.response.data[0]
                $current_result.masterDataSource = $DataSource
                [ANOWLocalDictionaryRecord]$DataSourceItem = $current_result
                Break
            }
            LOCAL_KEY_VALUE_STORE {
                [PSCustomObject]$current_result = $results.response.data[0]
                $current_result.masterDataSource = $DataSource
                [ANOWLocalKeyValueStoreRecord]$DataSourceItem = $current_result
                Break
            }
            LOCAL_FILE_STORE {
                [PSCustomObject]$current_result = $results.response.data[0]
                $current_result.masterDataSource = $DataSource
                [ANOWLocalFileStoreRecord]$DataSourceItem = $current_result
                Break
            }
            LOCAL_TEXT_FILE_STORE {
                [PSCustomObject]$current_result = $results.response.data[0]
                $current_result.masterDataSource = $DataSource
                [ANOWLocalTextFileStoreRecord]$DataSourceItem = $current_result
                Break
            }
        }
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWDataSourceItem] object due to [$Message]."
        Break
    }        
    If ($DataSourceItem.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWDataSourceItem] DataSourceItem is empty!"
        Break
    }
    If ($Quiet -ne $true) {
        Return $DataSourceItem
    }    
}

Function Remove-AutomateNOWDataSourceItem {
    <#
    .SYNOPSIS
    Removes a DataSourceItem from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a DataSourceItem from an AutomateNOW! instance
    
    .PARAMETER DataSourceItem
    An [ANOWDataSourceItem] object representing the DataSourceItem to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWDataSourceItem] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWDataSource -Id 'DataSource01' | Get-AutomateNOWDataSourceItem | Remove-AutomateNOWDataSourceItem

    .EXAMPLE
    @( 'DataSource01', 'DataSource02' ) | Get-AutomateNOWDataSource | Get-AutomateNOWDataSourceItem | Remove-AutomateNOWDataSourceItem -Force

    .EXAMPLE
    Get-AutomateNOWDataSource | Where-Object { $_.createdBy -eq 'me'} | Get-AutomateNOWDataSourceItem | Remove-AutomateNOWDataSourceItem

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWDataSourceItem]$DataSourceItem,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($DataSourceItem.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$DataSourceItem_id = $_.id
                
            }
            ElseIf ($DataSourceItem.id.Length -gt 0) {
                [string]$DataSourceItem_id = $DataSourceItem.id
            }
            Else {
                [string]$DataSourceItem_id = $Id
            }
            [string]$Body = 'id=' + $DataSourceItem_id
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            If ($DataSourceItem -is [ANOWLocalDictionaryRecord]) {
                [string]$command = '/localDictionaryRecord/delete'
            }
            ElseIf ($DataSourceItem -is [ANOWLocalKeyValueStoreRecord]) {
                [string]$command = '/localKeyValueStoreRecord/delete'
            }
            ElseIf ($DataSourceItem -is [ANOWLocalFileStoreRecord]) {
                [string]$command = '/localFileStoreRecord/delete'
            }
            ElseIf ($DataSourceItem -is [ANOWLocalTextFileStoreRecord]) {
                [string]$command = '/localTextFileStoreRecord/delete'
            }
            Else {
                Write-Warning -Message "Unable to determine DataSourceItem type"
                Break
            }
            If ($null -ne $parameters.Command) {
                $parameters.Remove('Command')
            }
            $parameters.Add('Command', $command)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$DataSourceItem_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "DataSourceItem $DataSourceItem_id successfully removed"
        }
    }
    End {

    }
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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

Function Set-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Changes the settings of a Folder from an AutomateNOW! instance
    
    .DESCRIPTION    
    Changes the settings of a Folder from an AutomateNOW! instance
    
    .PARAMETER Folder
    An [ANOWFolder] object representing the Folder to be changed.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWFolder] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    The modified [ANOWFolder] object will be returned
    
    .EXAMPLE
    Get-AutomateNOWFolder -Id 'Folder01' | Set-AutomateNOWFolder -Description 'New Description'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The only property which the console allows to be changed is the description.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWFolder]$Folder,
        [Parameter(Mandatory = $true, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [AllowEmptyString()]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/folder/update'
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
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$Folder_exists = ($null -eq (Get-AutomateNOWFolder -Id $Folder_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWFolder failed to check if the Folder [$Folder_id] already existed due to [$Message]."
                Break
            }
            If ($Folder_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Folder named [$Folder_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Folder.id
            $BodyMetaData.'parent' = $Folder.parent
            $BodyMetaData.'codeRepository' = $Folder.codeRepository
            $BodyMetaData.'_oldValues' = $Folder.CreateOldValues()
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_componentId' = 'FolderEditForm'
            $BodyMetaData.'_dataSource' = 'FolderDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat ' = 'json'
            $BodyMetaData.description = $Description
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Folder_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Folder $Folder_id was successfully updated"
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
    Optional description of the Folder (may not exceed 255 characters).

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
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
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
        Write-Warning -Message "New-Object failed to create the object of type [ANOWFolder] due to [$Message]."
        Break
    }

    $ANOWFolder.'id' = $Id
    $ANOWFolder.'description' = $Description
    $ANOWFolder.'codeRepository' = $codeRepository
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWFolder -IncludeProperties id, description, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Folder_id] due to [$Message]."
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
            [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
    Optional description of the node (may not exceed 255 characters).

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
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
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
        Write-Warning -Message "New-Object failed to create the object of type [ANOWNode] due to [$Message]."
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
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$node_id] due to [$Message]."
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

#Region - Referrals

Function Find-AutomateNOWObjectReferral {
    <#
    .SYNOPSIS
    Gets the referrals for an object from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the referrals for an object from an AutomateNOW! instance
    
    .PARAMETER Count
    Optional switch to return only the count of total referrals. Returns 0 when no results are found.

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .PARAMETER TaskTemplate
    [ANOWTaskTemplate] object to find referrals to. Use Get-AutomateNOWTaskTemplate to obtain these objects.
    
    .PARAMETER WorkflowTemplate
    [ANOWWorkflowTemplate] object to find referrals to. Use Get-AutomateNOWWorkflowTemplate to obtain these objects.
    
    .PARAMETER Node
    [ANOWNode] object to find referrals to. Use Get-AutomateNOWNode to obtain these objects.
    
    .INPUTS
    Accepts many types of [ANOW] objects including TaskTemplate, WorkflowTemplate and Node
    
    .OUTPUTS
    Raw results by default or a summary with the -Count parameter
    
    .EXAMPLE
    $server_node = Get-AutomateNOWNode -Id 'server_node_01'
    Find-AutomateNOWObjectReferral -Node $server_node

    .EXAMPLE
    $workflow_template = Get-AutomateNOWWorkflowTemplate -Id 'workflow_template_01'
    Find-AutomateNOWObjectReferral -WorkflowTemplate $workflow_template -Count

    .EXAMPLE
    Get-AutomateNOWNode -Id 'Server_Node_01' | Find-AutomateNOWObjectReferral

    .EXAMPLE
    @('Workflow_01', 'Workflow_02') | Get-AutomateNOWWorkflowTemplate | Find-AutomateNOWObjectReferral

    .EXAMPLE
    Get-AutomateNOWTaskTemplate | Find-AutomateNOWObjectReferral

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Type PYTHON | Find-AutomateNOWObjectReferral -Count

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function is very far from complete as there are other object types which need to be added.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [switch]$Count,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 2000,
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, ParameterSetName = 'TaskTemplate')]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, ParameterSetName = 'WorkflowTemplate')]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, ParameterSetName = 'Node')]
        [ANOWNode]$Node
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($startRow -gt $endRow) {
            Write-Warning -Message "The start row must not exceed the end row."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_ -is [ANOWTaskTemplate] -or $TaskTemplate.Id.Length -gt 0) {
            [string]$domainClass = 'ProcessingTemplate'
            If ($TaskTemplate.Id.Length -gt 0) {
                $Body.'id' = $TaskTemplate.Id
            }
            Else {
                $Body.'id' = $_.'id'
            }
        }
        ElseIf ($_ -is [ANOWWorkflowTemplate] -or $WorkflowTemplate.Id.Length -gt 0) {
            [string]$domainClass = 'ProcessingTemplate'
            If ($WorkflowTemplate.Id.Length -gt 0) {
                $Body.'id' = $WorkflowTemplate.Id
            }
            Else {
                $Body.'id' = $_.'id'
            }            
        }
        ElseIf ($_ -is [ANOWNode] -or $Node.Id.Length -gt 0) {
            [string]$domainClass = 'ServerNode'
            If ($Node.id.Length -gt 0) {
                $Body.'id' = $Node.id
            }
            Else {
                $Body.'id' = $_.'id'
            }
        }
        Else {
            Write-Warning -Message "Unable to determine input object. Please specify an object of [ANOW] base class type."
            Break
        }
        [string]$object_id = $Body.'id'
        $Body.'domainClass' = $domainclass
        $Body.'_operationType' = 'fetch'
        $Body.'_startRow' = $startRow
        $Body.'_endRow' = $endRow
        $Body.'_textMatchStyle' = 'exact'
        $Body.'_componentId' = 'ReferenceListWindow_list'
        $Body.'_dataSource' = 'ReferrersDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/findReferrers/read?' + $Body)
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] while running Find-AutomateNOWObjectReferral due to [$Message]."
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
        $data = $results.response.data # it's less lines of code if this variable is not hard typed
        If ($Count -eq $true) {
            [int32]$results_count = $data.count
            [PSCustomObject]$results_summary = [PSCustomObject]@{ object = $object_id; object_class = $domainClass; referrals = $results_count; }
            Return $results_summary
        }
        Else {
            Return $data
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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

Function Set-AutomateNOWTag {
    <#
    .SYNOPSIS
    Changes the settings of a Tag from an AutomateNOW! instance
    
    .DESCRIPTION    
    Changes the settings of a Tag from an AutomateNOW! instance
    
    .PARAMETER Tag
    An [ANOWWorkspace] object representing the Tag to be changed.

    .PARAMETER description
    Optional description of the tag (may not exceed 255 characters).

    .PARAMETER iconSet
    The name of the icon library (if you choose to use one). Possible choices are: FAT_COW, FUGUE and FONT_AWESOME.

    .PARAMETER iconCode
    The name of the icon which matches the chosen library.

    .PARAMETER textColor
    The RGB in hex of the tag's foreground (text) color. You must include the # character and it is case sensitive. Example: #FF00FF

    .PARAMETER backgroundColor
    The RGB in hex of the tag's background color. You must include the # character and it is case sensitive. Example: #00FF00

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWTag] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    The modified [ANOWTag] object will be returned
    
    .EXAMPLE
    Get-AutomateNOWTag -Id 'Tag01' | Set-AutomateNOWTag -Description 'New Description'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The only property which the console allows to be changed is the description.

    #>
    [Cmdletbinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default', ValueFromPipeline = $True)]
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon', ValueFromPipeline = $True)]
        [ANOWTag]$Tag,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [Parameter(Mandatory = $false, ParameterSetName = 'WithIcon', HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ANOWIconSet]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [string]$iconCode,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', HelpMessage = "Enter a hexadecimal RGB (#FF0000) or the word transparent in lower case")]
        [Parameter(Mandatory = $false, ParameterSetName = 'WithIcon', HelpMessage = "Enter a hexadecimal RGB (#FF0000) or the word transparent in lower case")]
        [ValidateScript( { $_ -cmatch '^#[0-9A-F]{6}$' -or $_ -cmatch '^transparent$' } ) ]
        [string]$textColor = '#FFFFFF',
        [Parameter(Mandatory = $false, ParameterSetName = 'Default', HelpMessage = "Enter a hexadecimal RGB (#FF0000) or the word transparent in lower case")]
        [Parameter(Mandatory = $false, ParameterSetName = 'WithIcon', HelpMessage = "Enter a hexadecimal RGB (#FF0000) or the word transparent in lower case")]
        [ValidateScript( { $_ -cmatch '^#[0-9A-F]{6}$' -or $_ -cmatch '^transparent$' } ) ]
        [string]$backgroundColor = '#FF0000',
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'WithIcon')]
        [switch]$Force,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [switch]$RemoveIcon
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Description.Length -eq 0 -and $textColor.Length -eq 0) {
            Write-Warning -Message "It appears that you are not changing anything in this tag. We should not continue to engage the API. Please, review your objective and try again."
            Break
        }
        [string]$command = '/tag/update'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Tag.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Tag_id = $_.simpleId
            }
            Else {
                [string]$Tag_id = $Tag.simpleId
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$Tag_exists = ($null -eq (Get-AutomateNOWTag -Id $Tag_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag failed to check if the Tag [$Tag_id] already existed due to [$Message]."
                Break
            }
            If ($Tag_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Tag named [$Tag_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Tag.id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            Else {
                $BodyMetaData.'description' = $Tag.description
            }
            If ($codeRepository.Length -gt 0) {
                $BodyMetaData.'codeRepository' = $codeRepository
            }
            Else {
                $BodyMetaData.'codeRepository' = $Tag.codeRepository
            }
            If ($textColor.Length -gt 0) {
                $BodyMetaData.'textColor' = $textColor
            }
            Else {
                $BodyMetaData.'textColor' = $Tag.textColor
            }
            If ($backgroundColor.Length -gt 0) {
                $BodyMetaData.'backgroundColor' = $backgroundColor
            }
            Else {
                $BodyMetaData.'backgroundColor' = $Tag.backgroundColor
            }
            If ($RemoveIcon -eq $true) {
                $BodyMetaData.'iconCode' = $null
                $BodyMetaData.'iconSet' = $null
            }
            Else {
                If ($iconCode.Length -gt 0) {
                    $BodyMetaData.'iconCode' = $iconCode
                }
                Else {
                    $BodyMetaData.'iconCode' = $Tag.iconCode
                }
                If ($iconSet.Length -gt 0) {
                    $BodyMetaData.'iconSet' = $iconSet
                }
                Else {
                    $BodyMetaData.'iconSet' = $Tag.iconSet
                }
            }
            $BodyMetaData.'version' = $null # Note: This appears to be an unneeded property leftover by the vendor
            $BodyMetaData.'_oldValues' = $Tag.CreateOldValues()
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_componentId' = 'TagEditForm'
            $BodyMetaData.'_dataSource' = 'TagDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat ' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties textColor, backgroundColor, id, description, iconSet, iconCode, codeRepository
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Tag_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Tag $Tag_id was successfully updated"
        }
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
    Optional description of the tag (may not exceed 255 characters).

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
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ANOWIconSet]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [string]$iconCode,
        [Parameter(Mandatory = $false)]
        [ValidateScript( { $_ -cmatch '^#[0-9A-F]{6}$' -or $_ -cmatch '^transparent$' } ) ]
        [string]$textColor = '#FFFFFF',
        [Parameter(Mandatory = $false)]
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
            Write-Warning -Message "New-Object failed to create the [ANOWTag] object type due to [$Message]."
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
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
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
        ForEach ($current_id in $Id) {
            If ($current_id -match '^(\s.{1,}|.{1,}\s)$') {
                Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
                Break
            }
            ElseIf ($curent_id -Match '[.{1,}].{1,}') {
                Write-Warning -Message "Do not include the Domain surrounded by brackets []. The -Id parameter actually requires the 'simple id':-)"
                Break
            }
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Id] due to [$Message]."
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

Function Get-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Gets the task templates from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the task templates from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the task template to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER taskType
    Optional string representing the type of task template to return. For example, a Shell Task template is SH. This parameter cannot be combined with -monitorType or -sensorType.
    
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
    Accepts a string representing the simple id of the task template from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWtaskTemplate] class objects
    
    .EXAMPLE
    Get-AutomateNOWTaskTemplate

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'task_template_01'

    .EXAMPLE
    @( 'task_template_01', 'task_template_02' ) | Get-AutomateNOWTaskTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the task templates (not recommended)

    Please be aware that task templates are actually divided into 3 types which is not directly illustrated in the console. The three types are task templates, Monitors and Sensors. That is why there are three separate exclusive parameters for the task template type.

    #>
    [OutputType([ANOWTaskTemplate[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default' )]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ParameterSetName = 'Default')]
        [string]$Id,
        [Parameter(Mandatory = $True, ParameterSetName = 'taskType')]
        [ANOWTaskTemplate_taskType]$taskType,
        [Parameter(Mandatory = $True, ParameterSetName = 'monitorType')]
        [ANOWTaskTemplate_monitorType]$monitorType,
        [Parameter(Mandatory = $True, ParameterSetName = 'sensorType')]
        [ANOWTaskTemplate_sensorType]$sensorType,
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
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
            [ANOWTaskTemplate[]]$TaskTemplates = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWTaskTemplate] objects due to [$Message]."
            Break
        }
        If ($TaskTemplates.Count -gt 0) {
            Return $TaskTemplates
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
    Mandatory [ANOWTaskTemplate] object (Use Get-AutomateNOWTask to retrieve them)
    
    .INPUTS
    ONLY [ANOWTaskTemplate] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWTaskTemplate] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWTask | Export-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01' | Export-AutomateNOWTask

    .EXAMPLE
    @( 'Task01', 'Task02' ) | Get-AutomateNOWTask | Export-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask | Where-Object { $_.taskType -eq 'PYTHON' } | Export-AutomateNOWTask

    .NOTES
	You must present [ANOWTaskTemplate] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWTaskTemplate]$Task
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
            [ANOWTaskTemplate]$Task = $_
        }
        $Error.Clear()
        Try {
            $Task | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWTaskTemplate] object on the pipeline due to [$Message]"
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
    Creates a Task within an AutomateNOW! instance and returns back the newly created [ANOWTaskTemplate] object

    .PARAMETER Id
    The intended name of the Task. For example: 'LinuxTask1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the Task.

    .PARAMETER Description
    Optional description of the task (may not exceed 255 characters).

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
    An [ANOWTaskTemplate] object representing the newly created Task
    
    .EXAMPLE
    New-AutomateNOWTask
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the task must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWTaskTemplate])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWserverTask_type]$Type,
        [Parameter(Mandatory = $false)]
        [int32]$WeightCapacity = 50,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
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
        [ANOWTaskTemplate]$ANOWTask = New-Object -TypeName ANOWTask
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed to create the object of type [ANOWTaskTemplate] due to [$Message]."
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
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
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
        [ANOWTaskTemplate]$Task = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWTaskTemplate] object due to [$Message]."
        Break
    }        
    If ($Task.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWTaskTemplate] Task is empty!"
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
    An [ANOWTaskTemplate] object representing the Task to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)
    
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
        [ANOWTaskTemplate]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Task_id] due to [$Message]."
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

Function Show-AutomateNOWTaskType {
    <#
    .SYNOPSIS
    Shows all of the available task types for AutomateNOW! in human readable format
    
    .DESCRIPTION    
    Shows all of the available task types for AutomateNOW! in human readable format (this was statically coded and will become outdated!)
    
    .INPUTS
    None. You cannot pipe objects to Show-AutomateNOWTaskType.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Show-AutomateNOWTaskType | Select-String -Pattern "PowerShell"
    
    .NOTES
    This is a stand-alone function which does not require connectivity to the AutomateNOW! console

    There are no parameters yet for this function
    #>
    [PSCustomObject]$TaskTypesJson = '[{"processingType":"TASK","id":"TASK","name":"Task","icon":"skin/service.png","folder":true},{"folder":true,"id":"CODE","icon":"skin/terminal.gif","name":"Code","parent":"TASK"},{"id":"FILE_PROCESSING","name":"File Processing","icon":"skin/drive-network.png","folder":true,"processingType":"TASK","parent":"TASK"},{"folder":true,"id":"SQL","icon":"skin/database-sql.png","name":"SQL Database","parent":"TASK"},{"folder":true,"id":"NO_SQL","icon":"skin/database-gear.png","name":"NoSQL Database","parent":"TASK"},{"folder":true,"id":"MESSAGE_QUEUE","icon":"skin/queue.png","name":"Message Queue","parent":"TASK"},{"processingType":"TASK","taskType":"SH","id":"SH","icon":"skin/terminal.gif","name":"Shell Task","parent":"CODE"},{"processingType":"TASK","taskType":"AE_SHELL_SCRIPT","id":"AE_SHELL_SCRIPT","icon":"skin/terminal.gif","name":"AE Shell Task","parent":"CODE"},{"processingType":"TASK","taskType":"PYTHON","id":"PYTHON","icon":"skin/python.png","name":"Python Task","parent":"CODE"},{"processingType":"TASK","taskType":"PERL","id":"PERL","icon":"skin/perl.png","name":"Perl Task","parent":"CODE"},{"processingType":"TASK","taskType":"RUBY","id":"RUBY","icon":"skin/ruby.png","name":"Ruby Task","parent":"CODE"},{"processingType":"TASK","taskType":"GROOVY","id":"GROOVY","icon":"skin/groovy.png","name":"Groovy Task","parent":"CODE"},{"processingType":"TASK","taskType":"POWERSHELL","id":"POWERSHELL","icon":"skin/powershell.png","name":"PowerShell Task","parent":"CODE"},{"processingType":"TASK","id":"JAVA","taskType":"JAVA","name":"Java Task","icon":"skin/java.png","parent":"CODE"},{"processingType":"TASK","id":"SCALA","taskType":"SCALA","name":"Scala Task","icon":"skin/scala.png","parent":"CODE"},{"folder":true,"id":"Z_OS","icon":"skin/zos.png","name":"z/OS","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"Z_OS_DYNAMIC_JCL","id":"Z_OS_DYNAMIC_JCL","icon":"skin/zos.png","name":"z/OS Dynamic JCL","parent":"Z_OS"},{"processingType":"TASK","taskType":"Z_OS_STORED_JCL","id":"Z_OS_STORED_JCL","icon":"skin/zos.png","name":"z/OS Stored JCL","parent":"Z_OS"},{"processingType":"TASK","taskType":"Z_OS_COMMAND","id":"Z_OS_COMMAND","icon":"skin/zos.png","name":"z/OS Command","parent":"Z_OS"},{"folder":true,"id":"AS_400","icon":"skin/ibm_as400.gif","name":"AS/400","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"AS400_BATCH_JOB","id":"AS400_BATCH_JOB","icon":"skin/ibm_as400.gif","name":"AS/400 Batch Job","parent":"AS_400"},{"processingType":"TASK","taskType":"AS400_PROGRAM_CALL","id":"AS400_PROGRAM_CALL","icon":"skin/ibm_as400.gif","name":"AS/400 Program Call","parent":"AS_400"},{"folder":true,"id":"RAINCODE_JCL","icon":"skin/raincode.ico","name":"Raincode JCL","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"RAINCODE_DYNAMIC_JCL","id":"RAINCODE_DYNAMIC_JCL","icon":"skin/raincode.ico","name":"Raincode Dynamic JCL","parent":"RAINCODE_JCL"},{"processingType":"TASK","taskType":"RAINCODE_STORED_JCL","id":"RAINCODE_STORED_JCL","icon":"skin/raincode.ico","name":"Raincode Stored JCL","parent":"RAINCODE_JCL"},{"folder":true,"id":"OPENTEXT","icon":"skin/microfocus.png","name":"OpenText JCL","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"OPENTEXT_DYNAMIC_JCL","id":"OPENTEXT_DYNAMIC_JCL","icon":"skin/microfocus.png","name":"OpenText Dynamic JCL","parent":"OPENTEXT"},{"processingType":"TASK","taskType":"OPENTEXT_STORED_JCL","id":"OPENTEXT_STORED_JCL","icon":"skin/microfocus.png","name":"OpenText Stored JCL","parent":"OPENTEXT"},{"processingType":"TASK","taskType":"RDBMS_STORED_PROCEDURE","id":"RDBMS_STORED_PROCEDURE","icon":"skin/database-gear.png","name":"Stored Procedure Call","parent":"SQL"},{"processingType":"TASK","taskType":"RDBMS_SQL_STATEMENT","id":"RDBMS_SQL_STATEMENT","icon":"skin/database_search.png","name":"RDBMS SQL Statement","parent":"SQL"},{"processingType":"TASK","taskType":"RDBMS_SQL","id":"RDBMS_SQL","icon":"skin/database-sql.png","name":"SQL Script","parent":"SQL"},{"folder":true,"id":"BIG_DATA","icon":"skin/database-gear.png","name":"Big Data","parent":"TASK"},{"folder":true,"id":"REDIS","icon":"skin/redis.png","name":"Redis","parent":"NO_SQL"},{"processingType":"TASK","taskType":"REDIS_SET","id":"REDIS_SET","icon":"skin/redis.png","name":"Redis Set","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_GET","id":"REDIS_GET","icon":"skin/redis.png","name":"Redis Get","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_DELETE","id":"REDIS_DELETE","icon":"skin/redis.png","name":"Redis Delete","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_CLI","id":"REDIS_CLI","icon":"skin/redis.png","name":"Redis Command","parent":"REDIS"},{"processingType":"TASK","id":"HDFS","name":"HDFS","icon":"skin/hadoop.png","parent":"BIG_DATA","folder":true},{"processingType":"TASK","id":"HDFS_UPLOAD_FILE","taskType":"HDFS_UPLOAD_FILE","name":"HDFS Upload File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_APPEND_FILE","taskType":"HDFS_APPEND_FILE","name":"HDFS Append File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DOWNLOAD_FILE","taskType":"HDFS_DOWNLOAD_FILE","name":"HDFS Download File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DELETE_FILE","taskType":"HDFS_DELETE_FILE","name":"HDFS Delete File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_CREATE_DIRECTORY","taskType":"HDFS_CREATE_DIRECTORY","name":"HDFS Create Directory","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DELETE_DIRECTORY","taskType":"HDFS_DELETE_DIRECTORY","name":"HDFS Delete Directory","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_RENAME","taskType":"HDFS_RENAME","name":"HDFS Rename","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HIVE","name":"Hive","icon":"skin/hive.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"IMPALA","name":"Impala","icon":"skin/impala.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SQOOP","name":"Sqoop","icon":"skin/sqoop.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"YARN","name":"Yarn","icon":"skin/hadoop.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SPARK","name":"Spark","icon":"skin/spark.png","parent":"BIG_DATA","folder":"hideInactiveFeatures"},{"id":"SPARK_JAVA","taskType":"SPARK_JAVA","name":"Spark Java Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_SCALA","taskType":"SPARK_SCALA","name":"Spark Scala Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_PYTHON","taskType":"SPARK_PYTHON","name":"Spark Python Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_R","taskType":"SPARK_R","name":"Spark R Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_SQL","taskType":"SPARK_SQL","name":"Spark SQL Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"processingType":"TASK","id":"FLUME","name":"Flume","icon":"skin/flume.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"FLINK","name":"Flink","icon":"skin/flink.jpg ","parent":"BIG_DATA","folder":"hideInactiveFeatures"},{"processingType":"TASK","id":"FLINK_RUN_JOB","taskType":"FLINK_RUN_JOB","name":"Flink Run Job","icon":"skin/flink.jpg","parent":"FLINK"},{"processingType":"TASK","id":"FLINK_JAR_UPLOAD","taskType":"FLINK_JAR_UPLOAD","name":"Flink Upload Jar","icon":"skin/flink.jpg","parent":"FLINK"},{"processingType":"TASK","id":"FLINK_JAR_DELETE","taskType":"FLINK_JAR_DELETE","name":"Flink Delete Jar","icon":"skin/flink.jpg","parent":"FLINK"},{"id":"STORM","name":"Storm","icon":"skin/storm.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"OOZIE","name":"Oozie","icon":"skin/oozie.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"AMBARI","name":"Ambari","icon":"skin/ambari.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"MONGO_DB","name":"Mongo DB","icon":"skin/mongodb.gif","parent":"NO_SQL","folder":true},{"id":"MONGO_DB_INSERT","name":"Mongo DB Insert Document","icon":"skin/mongodb.gif","parent":"MONGO_DB","processingType":"TASK","taskType":"MONGO_DB_INSERT"},{"id":"IBM_MQ","icon":"skin/ibm_mq.png","name":"IBM MQ","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"IBM_MQ_SEND","id":"IBM_MQ_SEND","icon":"skin/ibm_mq.png","name":"Send IBM MQ Message","parent":"IBM_MQ"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"IBM_MQ_SENSOR","id":"IBM_MQ_SENSOR","icon":"skin/ibm_mq.png","name":"IBM MQ Sensor","parent":"IBM_MQ"},{"id":"RABBIT_MQ","name":"RabbitMQ","icon":"skin/rabbitmq.png","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"RABBIT_MQ_SEND","id":"RABBIT_MQ_SEND","name":"Send RabbitMQ Message","icon":"skin/rabbitmq.png","parent":"RABBIT_MQ"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"RABBIT_MQ_SENSOR","id":"RABBIT_MQ_SENSOR","icon":"skin/rabbitmq.png","name":"RabbitMQ Message Sensor","parent":"RABBIT_MQ"},{"id":"KAFKA","name":"Kafka","icon":"skin/kafka.png","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"KAFKA_SEND","id":"KAFKA_SEND","name":"Send Kafka Message","icon":"skin/kafka.png","parent":"KAFKA"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"KAFKA_SENSOR","id":"KAFKA_SENSOR","icon":"skin/kafka.png","name":"Kafka Message Sensor","parent":"KAFKA"},{"processingType":"TASK","taskType":"JMS","id":"JMS","icon":"skin/java.png","name":"JMS","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"JMS_SEND","id":"JMS_SEND","icon":"skin/java.png","name":"Send JMS Message","parent":"JMS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"JMS_SENSOR","id":"JMS_SENSOR","icon":"skin/java.png","name":"JMS Sensor","parent":"JMS"},{"processingType":"TASK","id":"AMQP","icon":"skin/amqp.ico","name":"AMQP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"AMQP_SEND","id":"AMQP_SEND","icon":"skin/amqp.ico","name":"Send AMQP Message","parent":"AMQP"},{"processingType":"TASK","id":"MQTT","icon":"skin/mqtt.png","name":"MQTT","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"MQTT_SEND","id":"MQTT_SEND","icon":"skin/mqtt.png","name":"Send MQTT Message","parent":"MQTT"},{"id":"XMPP","icon":"skin/xmpp.png","name":"XMPP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"XMPP_SEND","id":"XMPP_SEND","icon":"skin/xmpp.png","name":"Send XMPP Message","parent":"XMPP"},{"id":"STOMP","icon":"skin/shoe.png","name":"STOMP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"STOMP_SEND","id":"STOMP_SEND","icon":"skin/shoe.png","name":"Send STOMP Message","parent":"STOMP"},{"processingType":"TASK","taskType":"FILE_TRANSFER","id":"FILE_TRANSFER","icon":"skin/drive-network.png","name":"File Transfer","parent":"FILE_PROCESSING"},{"processingType":"TASK","taskType":"XFTP_COMMAND","id":"XFTP_COMMAND","icon":"skin/drive-network.png","name":"XFTP Command","parent":"FILE_PROCESSING"},{"id":"DATASOURCE_FILE","name":"Data Source","icon":"skin/drive-network.png","folder":true,"parent":"FILE_PROCESSING"},{"id":"DATASOURCE_UPLOAD_FILE","processingType":"TASK","taskType":"DATASOURCE_UPLOAD_FILE","name":"Upload File to Data Source","icon":"skin/drive-upload.png","parent":"DATASOURCE_FILE"},{"id":"DATASOURCE_DOWNLOAD_FILE","processingType":"TASK","taskType":"DATASOURCE_DOWNLOAD_FILE","name":"Download File from Data Source","icon":"skin/drive-download.png","parent":"DATASOURCE_FILE"},{"id":"DATASOURCE_DELETE_FILE","processingType":"TASK","taskType":"DATASOURCE_DELETE_FILE","name":"Delete File from Data Source","icon":"skin/drive_delete.png","parent":"DATASOURCE_FILE"},{"folder":true,"id":"WEB","icon":"skin/world.png","name":"Web","parent":"TASK"},{"folder":true,"id":"EMAIL","icon":"skin/mail.png","name":"Email","parent":"TASK"},{"folder":true,"id":"IBM_SERIES","icon":"skin/ibm.png","name":"IBM Series","parent":"TASK"},{"processingType":"TASK","taskType":"HTTP_REQUEST","id":"HTTP_REQUEST","icon":"skin/http.png","name":"HTTP Request","parent":"WEB"},{"processingType":"TASK","taskType":"REST_WEB_SERVICE_CALL","id":"REST_WEB_SERVICE_CALL","icon":"skin/rest.png","name":"REST Web Service Call","parent":"WEB"},{"processingType":"TASK","taskType":"SOAP_WEB_SERVICE_CALL","id":"SOAP_WEB_SERVICE_CALL","icon":"skin/soap.png","name":"SOAP Web Service Call","parent":"WEB"},{"processingType":"TASK","taskType":"EMAIL_SEND","id":"EMAIL_SEND","icon":"skin/mail.png","name":"Send Email","parent":"EMAIL"},{"processingType":"TASK","taskType":"EMAIL_CONFIRMATION","id":"EMAIL_CONFIRMATION","icon":"skin/mail--pencil.png","name":"Email Confirmation","parent":"EMAIL"},{"processingType":"TASK","taskType":"EMAIL_INPUT","id":"EMAIL_INPUT","icon":"skin/mail-open-table.png","name":"Email Input","parent":"EMAIL"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"EMAIL_SENSOR","id":"EMAIL_SENSOR","icon":"skin/mail.png","name":"Email Sensor","parent":"EMAIL"},{"id":"CLOUD_SERVICES","name":"Cloud Services","icon":"skin/cloud.png","folder":true,"parent":"TASK"},{"id":"AWS","name":"Amazon Web Services","icon":"skin/aws.png","parent":"CLOUD_SERVICES","folder":true},{"id":"AWS_GLUE","name":"Amazon Glue","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_GLUE_WORKFLOW","processingType":"TASK","taskType":"AWS_GLUE_WORKFLOW","name":"AWS Glue Workflow","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_TRIGGER","processingType":"TASK","taskType":"AWS_GLUE_TRIGGER","name":"AWS Glue Trigger","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_CRAWLER","processingType":"TASK","taskType":"AWS_GLUE_CRAWLER","name":"AWS Glue Crawler","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_JOB","processingType":"TASK","taskType":"AWS_GLUE_JOB","name":"AWS Glue Job","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_EMR","name":"Amazon EMR","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_EMR_WORKFLOW","processingType":"TASK","taskType":"AWS_EMR_WORKFLOW","name":"AWS EMR Workflow","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_ADD_STEPS","processingType":"TASK","taskType":"AWS_EMR_ADD_STEPS","name":"AWS EMR Add Steps","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_CANCEL_STEPS","processingType":"TASK","taskType":"AWS_EMR_CANCEL_STEPS","name":"AWS EMR Cancel Steps","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_TERMINATE_JOB_FLOW","processingType":"TASK","taskType":"AWS_EMR_TERMINATE_JOB_FLOW","name":"AWS EMR Terminate Job Flow","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_CONTAINER_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_CONTAINER_MONITOR","name":"AWS EMR Container Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_JOB_FLOW_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_JOB_FLOW_MONITOR","name":"AWS EMR Job Flow Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_STEP_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_STEP_MONITOR","name":"AWS EMR Step Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_NOTEBOOK_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_NOTEBOOK_MONITOR","name":"AWS EMR Notebook Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_PUT","processingType":"TASK","taskType":"AWS_EMR_PUT","name":"AWS EMR Put","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_GET","processingType":"TASK","taskType":"AWS_EMR_GET","name":"AWS EMR Get","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_START_NOTEBOOK_EXECUTION","processingType":"TASK","taskType":"AWS_EMR_START_NOTEBOOK_EXECUTION","name":"AWS EMR Start Notebook Execution","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_STOP_NOTEBOOK_EXECUTION","processingType":"TASK","taskType":"AWS_EMR_STOP_NOTEBOOK_EXECUTION","name":"AWS EMR Stop Notebook Execution","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_API_COMMAND","processingType":"TASK","taskType":"AWS_EMR_API_COMMAND","name":"AWS EMR API Command","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_SAGE_MAKER","name":"Amazon SageMaker","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_SAGE_MAKER_ADD_MODEL","processingType":"TASK","taskType":"AWS_SAGE_MAKER_ADD_MODEL","name":"AWS SageMaker Add Model","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_DELETE_MODEL","processingType":"TASK","taskType":"AWS_SAGE_MAKER_DELETE_MODEL","name":"AWS SageMaker Delete Model","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_PROCESSING","processingType":"TASK","taskType":"AWS_SAGE_MAKER_PROCESSING","name":"AWS SageMaker Processing","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_TRAINING","processingType":"TASK","taskType":"AWS_SAGE_MAKER_TRAINING","name":"AWS SageMaker Training","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_TRANSFORM","processingType":"TASK","taskType":"AWS_SAGE_MAKER_TRANSFORM","name":"AWS SageMaker Transform","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_API_COMMAND","processingType":"TASK","taskType":"AWS_SAGE_MAKER_API_COMMAND","name":"AWS SageMaker API Command","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_LAMBDA","name":"AWS Lambda","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_LAMBDA_INVOKE","name":"AWS Lambda Invoke","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_INVOKE"},{"id":"AWS_LAMBDA_CREATE_FUNCTION","name":"AWS Lambda Create Function","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_CREATE_FUNCTION"},{"id":"AWS_LAMBDA_DELETE_FUNCTION","name":"AWS Lambda Delete Function","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_DELETE_FUNCTION"},{"id":"AWS_EC2","name":"AWS EC2","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_EC2_START_INSTANCE","name":"AWS EC2 Start   Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_START_INSTANCE"},{"id":"AWS_EC2_STOP_INSTANCE","name":"AWS EC2 Stop Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_STOP_INSTANCE"},{"id":"AWS_EC2_TERMINATE_INSTANCE","name":"AWS EC2 Terminate Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_TERMINATE_INSTANCE"},{"id":"AWS_EC2_DELETE_VOLUME","name":"AWS EC2 Delete Volume","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_DELETE_VOLUME"},{"id":"AWS_S3","name":"AWS S3","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_S3_DELETE_OBJECT","name":"AWS S3 Delete Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_DELETE_OBJECT"},{"id":"AWS_S3_COPY_OBJECT","name":"AWS S3 Copy Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_COPY_OBJECT"},{"id":"AWS_S3_MOVE_OBJECT","name":"AWS S3 Move Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_MOVE_OBJECT"},{"id":"AWS_S3_RENAME_OBJECT","name":"AWS S3 Rename Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_RENAME_OBJECT"},{"id":"AWS_BATCH","name":"AWS Batch","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_BATCH_JOB","name":"AWS Batch Job","icon":"skin/aws.png","parent":"AWS_BATCH","processingType":"TASK","taskType":"AWS_BATCH_JOB"},{"id":"AWS_STEP_FUNCTIONS","name":"AWS Step Functions","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_START_STEP_FUNCTION_STATE_MACHINE","name":"AWS Start Step Function State Machine","icon":"skin/aws.png","parent":"AWS_STEP_FUNCTIONS","processingType":"TASK","taskType":"AWS_START_STEP_FUNCTION_STATE_MACHINE"},{"id":"AZURE","name":"Azure","icon":"skin/azure.png","parent":"CLOUD_SERVICES","folder":true,"processingType":"TASK"},{"id":"AZURE_DATA_FACTORY","name":"Azure Data Factory","icon":"skin/azure.png","parent":"AZURE","folder":true,"processingType":"TASK"},{"id":"AZURE_DATA_FACTORY_TRIGGER","processingType":"TASK","taskType":"AZURE_DATA_FACTORY_TRIGGER","name":"Azure Data Factory Trigger","icon":"skin/azure.png","parent":"AZURE_DATA_FACTORY"},{"id":"AZURE_DATA_FACTORY_PIPELINE","processingType":"TASK","taskType":"AZURE_DATA_FACTORY_PIPELINE","name":"Azure Data Factory Pipeline","icon":"skin/azure.png","parent":"AZURE_DATA_FACTORY"},{"id":"AZURE_DATA_LAKE_JOB","processingType":"TASK","taskType":"AZURE_DATA_LAKE_JOB","name":"Azure Data Lake Job","icon":"skin/azure.png","parent":"AZURE"},{"id":"AZURE_DATABRICKS","name":"Azure DataBricks","icon":"skin/azure.png","parent":"AZURE","folder":true},{"id":"AZURE_DATABRICKS_JOB","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Run Job","processingType":"TASK","taskType":"AZURE_DATABRICKS_JOB"},{"id":"AZURE_DATABRICKS_TERMINATE_CLUSTER","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Terminate Cluster","processingType":"TASK","taskType":"AZURE_DATABRICKS_TERMINATE_CLUSTER"},{"id":"AZURE_DATABRICKS_START_CLUSTER","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Start Cluster","processingType":"TASK","taskType":"AZURE_DATABRICKS_START_CLUSTER"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AZURE_DATABRICKS_CLUSTER_MONITOR","id":"AZURE_DATABRICKS_CLUSTER_MONITOR","icon":"skin/azure.png","name":"Azure DataBricks Cluster Monitor","parent":"AZURE_DATABRICKS"},{"processingType":"TASK","taskType":"AZURE_DATABRICKS_LIST_CLUSTERS","id":"AZURE_DATABRICKS_LIST_CLUSTERS","icon":"skin/azure.png","name":"Azure DataBricks List Clusters","parent":"AZURE_DATABRICKS"},{"processingType":"TASK","taskType":"AZURE_DATABRICKS_DELETE_CLUSTER","id":"AZURE_DATABRICKS_DELETE_CLUSTER","icon":"skin/azure.png","name":"Azure DataBricks Delete Cluster Permanently","parent":"AZURE_DATABRICKS"},{"id":"INFORMATICA_CLOUD","name":"Informatica Cloud","icon":"skin/informatica.ico","parent":"CLOUD_SERVICES","folder":true},{"processingType":"TASK","taskType":"INFORMATICA_CLOUD_TASKFLOW","id":"INFORMATICA_CLOUD_TASKFLOW","icon":"skin/informatica.ico","name":"Informatica Cloud Taskflow","parent":"INFORMATICA_CLOUD"},{"folder":true,"id":"ETL","icon":"skin/etl.png","name":"ETL","parent":"TASK"},{"processingType":"TASK","taskType":"INFORMATICA_WORKFLOW","id":"INFORMATICA_WORKFLOW","icon":"skin/informatica.ico","name":"Informatica Power Center Workflow","parent":"ETL"},{"processingType":"TASK","taskType":"INFORMATICA_WS_WORKFLOW","id":"INFORMATICA_WS_WORKFLOW","icon":"skin/informatica.ico","name":"Informatica Power Center Web Service Workflow","parent":"ETL"},{"processingType":"TASK","taskType":"IBM_DATASTAGE","id":"IBM_DATASTAGE","icon":"skin/ibminfosphere.png","name":"IBM Infosphere DataStage","parent":"ETL"},{"processingType":"TASK","taskType":"MS_SSIS","id":"MS_SSIS","icon":"skin/ssis.png","name":"MS SQL Server Integration Services","parent":"ETL"},{"folder":true,"id":"ORACLE_DATA_INTEGRATOR","icon":"skin/odi.png","name":"Oracle Data Integrator","parent":"ETL"},{"processingType":"TASK","taskType":"ODI_SESSION","id":"ODI_SESSION","icon":"skin/odi.png","name":"ODI Session","parent":"ORACLE_DATA_INTEGRATOR"},{"processingType":"TASK","taskType":"ODI_LOAD_PLAN","id":"ODI_LOAD_PLAN","icon":"skin/odi.png","name":"ODI Load Plan","parent":"ORACLE_DATA_INTEGRATOR"},{"folder":true,"id":"SAS","icon":"skin/sas.png","name":"SAS","parent":"ETL"},{"processingType":"TASK","taskType":"SAS_4GL","id":"SAS_4GL","icon":"skin/sas.png","name":"SAS Dynamic Code","parent":"SAS"},{"processingType":"TASK","taskType":"SAS_DI","id":"SAS_DI","icon":"skin/sas.png","name":"SAS Stored Code","parent":"SAS"},{"processingType":"TASK","taskType":"SAS_JOB","id":"SAS_JOB","icon":"skin/sas.png","name":"SAS Job","parent":"SAS"},{"folder":true,"id":"SAS_VIYA","icon":"skin/sas_viya.png","name":"SAS Viya","parent":"ETL"},{"processingType":"TASK","taskType":"SAS_VIYA_JOB","id":"SAS_VIYA_JOB","icon":"skin/sas_viya.png","name":"SAS Viya Job","parent":"SAS_VIYA"},{"id":"TALEND","parent":"ETL","icon":"[SKINIMG]/skin/talend.png","name":"Talend"},{"processingType":"TASK","taskType":"TALEND_JOB","id":"TALEND_JOB","icon":"[SKINIMG]/skin/talend.png","name":"Talend Job","parent":"TALEND"},{"id":"DBT","parent":"ETL","icon":"[SKINIMG]/skin/dbt.ico","name":"dbt"},{"processingType":"TASK","taskType":"DBT_JOB","id":"DBT_JOB","icon":"[SKINIMG]/skin/dbt.ico","name":"dbt Job","parent":"DBT"},{"folder":true,"id":"ERP","icon":"skin/erp.png","name":"ERP","parent":"TASK"},{"folder":true,"id":"SAP_R3","icon":"skin/sap.png","name":"SAP R/3","parent":"ERP"},{"folder":true,"id":"SAP_R3_JOBS","icon":"skin/sap.png","name":"SAP R/3 Job","parent":"SAP_R3"},{"folder":true,"id":"SAP_R3_OTHER","icon":"skin/sap.png","name":"SAP R/3 Other","parent":"SAP_R3"},{"folder":true,"id":"SAP_4H","icon":"skin/sap.png","name":"SAP S/4HANA","parent":"ERP"},{"folder":true,"id":"SAP_4H_JOBS","icon":"skin/sap.png","name":"SAP 4/HANA Job","parent":"SAP_4H"},{"folder":true,"id":"SAP_4H_OTHER","icon":"skin/sap.png","name":"SAP 4/HANA Other","parent":"SAP_4H"},{"folder":true,"id":"SAP_4HC","icon":"skin/sap.png","name":"SAP S/4HANA Cloud","parent":"ERP"},{"processingType":"TASK","taskType":"SAP_R3_JOB","id":"SAP_R3_JOB","icon":"skin/sap.png","name":"SAP R/3 Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_CREATE","id":"SAP_R3_VARIANT_CREATE","icon":"skin/sap.png","name":"SAP R/3 Create Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_COPY","id":"SAP_R3_VARIANT_COPY","icon":"skin/sap.png","name":"SAP R/3 Copy Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_UPDATE","id":"SAP_R3_VARIANT_UPDATE","icon":"skin/sap.png","name":"SAP R/3 Update Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_DELETE","id":"SAP_R3_VARIANT_DELETE","icon":"skin/sap.png","name":"SAP R/3 Delete Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_RAISE_EVENT","id":"SAP_R3_RAISE_EVENT","icon":"skin/sap.png","name":"SAP R/3 Raise Event","parent":"SAP_R3_OTHER"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_R3_EVENT_SENSOR","id":"SAP_R3_EVENT_SENSOR","icon":"skin/sap.png","name":"SAP R/3 Event Sensor","parent":"SAP_R3_OTHER"},{"processingType":"TASK","taskType":"SAP_R3_COPY_EXISTING_JOB","id":"SAP_R3_COPY_EXISTING_JOB","icon":"skin/sap.png","name":"SAP R/3 Copy Existing Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_START_SCHEDULED_JOB","id":"SAP_R3_START_SCHEDULED_JOB","icon":"skin/sap.png","name":"SAP R/3 Start Scheduled Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_JOB_INTERCEPTOR","id":"SAP_R3_JOB_INTERCEPTOR","icon":"skin/sap.png","name":"SAP R/3 Job Interceptor","parent":"SAP_R3_JOBS"},{"processingType":"TASK","id":"SAP_BW_PROCESS_CHAIN","taskType":"SAP_BW_PROCESS_CHAIN","name":"SAP BW Process Chain","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_ARCHIVE","taskType":"SAP_ARCHIVE","name":"SAP Data Archive","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_FUNCTION_MODULE_CALL","taskType":"SAP_FUNCTION_MODULE_CALL","name":"SAP Function Module Call","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_READ_TABLE","taskType":"SAP_READ_TABLE","name":"SAP Read Table","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_CM_PROFILE_ACTIVATE","taskType":"SAP_CM_PROFILE_ACTIVATE","name":"SAP Activate CM Profile","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_CM_PROFILE_DEACTIVATE","taskType":"SAP_CM_PROFILE_DEACTIVATE","name":"SAP Deactivate CM Profile","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_EXPORT_CALENDAR","taskType":"SAP_EXPORT_CALENDAR","name":"SAP Export Calendar","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_EXPORT_JOB","taskType":"SAP_EXPORT_JOB","name":"SAP Export Job","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_MODIFY_INTERCEPTION_CRITERIA","taskType":"SAP_MODIFY_INTERCEPTION_CRITERIA","name":"SAP R/3 Modify Interception Criteria","icon":"skin/sap.png","parent":"SAP_R3_JOBS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_R3_INTERCEPTED_JOB_SENSOR","id":"SAP_R3_INTERCEPTED_JOB_SENSOR","icon":"skin/sap.png","name":"SAP R/3 Intercepted Job Sensor","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_JOB","id":"SAP_4H_JOB","icon":"skin/sap.png","name":"SAP 4/H Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_CREATE","id":"SAP_4H_VARIANT_CREATE","icon":"skin/sap.png","name":"SAP 4/H Create Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_COPY","id":"SAP_4H_VARIANT_COPY","icon":"skin/sap.png","name":"SAP 4/H Copy Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_UPDATE","id":"SAP_4H_VARIANT_UPDATE","icon":"skin/sap.png","name":"SAP 4/H Update Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_DELETE","id":"SAP_4H_VARIANT_DELETE","icon":"skin/sap.png","name":"SAP 4/H Delete Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_RAISE_EVENT","id":"SAP_4H_RAISE_EVENT","icon":"skin/sap.png","name":"SAP 4/H Raise Event","parent":"SAP_4H_OTHER"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_4H_EVENT_SENSOR","id":"SAP_4H_EVENT_SENSOR","icon":"skin/sap.png","name":"SAP 4/H Event Sensor","parent":"SAP_4H_OTHER"},{"processingType":"TASK","taskType":"SAP_4H_COPY_EXISTING_JOB","id":"SAP_4H_COPY_EXISTING_JOB","icon":"skin/sap.png","name":"SAP 4/H Copy Existing Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_START_SCHEDULED_JOB","id":"SAP_4H_START_SCHEDULED_JOB","icon":"skin/sap.png","name":"SAP 4/H Start Scheduled Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_JOB_INTERCEPTOR","id":"SAP_4H_JOB_INTERCEPTOR","icon":"skin/sap.png","name":"SAP 4/H Job Interceptor","parent":"SAP_4H_JOBS"},{"processingType":"TASK","id":"SAP_4H_BW_PROCESS_CHAIN","taskType":"SAP_4H_BW_PROCESS_CHAIN","name":"SAP 4/H BW Process Chain","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_ARCHIVE","taskType":"SAP_4H_ARCHIVE","name":"SAP 4/H Data Archive","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_FUNCTION_MODULE_CALL","taskType":"SAP_4H_FUNCTION_MODULE_CALL","name":"SAP 4/H Function Module Call","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_READ_TABLE","taskType":"SAP_4H_READ_TABLE","name":"SAP 4/H Read Table","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_CM_PROFILE_ACTIVATE","taskType":"SAP_4H_CM_PROFILE_ACTIVATE","name":"SAP 4/H Activate CM Profile","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_CM_PROFILE_DEACTIVATE","taskType":"SAP_4H_CM_PROFILE_DEACTIVATE","name":"SAP 4/H Deactivate CM Profile","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_EXPORT_CALENDAR","taskType":"SAP_4H_EXPORT_CALENDAR","name":"SAP 4/H Export Calendar","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_EXPORT_JOB","taskType":"SAP_4H_EXPORT_JOB","name":"SAP 4/H Export Job","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_MODIFY_INTERCEPTION_CRITERIA","taskType":"SAP_4H_MODIFY_INTERCEPTION_CRITERIA","name":"SAP 4/H Modify Interception Criteria","icon":"skin/sap.png","parent":"SAP_4H_JOBS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_4H_INTERCEPTED_JOB_SENSOR","id":"SAP_4H_INTERCEPTED_JOB_SENSOR","icon":"skin/sap.png","name":"SAP 4/H Intercepted Job Sensor","parent":"SAP_4H_JOBS"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SAP_4H_JOB_MONITOR","id":"SAP_4H_JOB_MONITOR","icon":"skin/sap.png","name":"SAP 4/H Job Monitor","parent":"SAP_4H_JOBS"},{"processingType":"TASK","id":"SAP_ODATA_API_CALL","taskType":"SAP_ODATA_API_CALL","name":"SAP ODATA API Call","icon":"skin/sap.png","parent":"SAP_4HC"},{"processingType":"TASK","id":"SAP_IBP_JOB","taskType":"SAP_IBP_JOB","name":"SAP IBP Job","icon":"skin/sap.png","parent":"SAP_4HC"},{"processingType":"TASK","id":"SAP_IBP_CREATE_PROCESS","taskType":"SAP_IBP_CREATE_PROCESS","name":"SAP IBP Create Process","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SAP_IBP_DELETE_PROCESS","taskType":"SAP_IBP_DELETE_PROCESS","name":"SAP IBP Delete Process","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SAP_IBP_SET_PROCESS_STEP_STATUS","taskType":"SAP_IBP_SET_PROCESS_STEP_STATUS","name":"SAP IBP Set Process Job Status","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"folder":true,"id":"ORACLE_EBS","icon":"skin/oracle.png","name":"Oracle EBS","parent":"ERP"},{"processingType":"TASK","taskType":"ORACLE_EBS_PROGRAM","id":"ORACLE_EBS_PROGRAM","icon":"skin/oracle.png","name":"Oracle EBS Program","parent":"ORACLE_EBS"},{"processingType":"TASK","taskType":"ORACLE_EBS_REQUEST_SET","id":"ORACLE_EBS_REQUEST_SET","icon":"skin/oracle.png","name":"Oracle EBS Request Set","parent":"ORACLE_EBS"},{"id":"ITSM","folder":true,"icon":"skin/compress_repair.png","name":"ITSM","parent":"TASK"},{"id":"JIRA","parent":"ITSM","icon":"skin/jira.png","name":"Jira","folder":true},{"processingType":"TASK","taskType":"ORACLE_EBS_EXECUTE_PROGRAM","id":"ORACLE_EBS_EXECUTE_PROGRAM","icon":"skin/oracle.png","name":"Oracle EBS Execute Program","parent":"ORACLE_EBS"},{"processingType":"TASK","taskType":"ORACLE_EBS_EXECUTE_REQUEST_SET","id":"ORACLE_EBS_EXECUTE_REQUEST_SET","icon":"skin/oracle.png","name":"Oracle EBS Execute Request Set","parent":"ORACLE_EBS"},{"id":"SERVICE_NOW","parent":"ITSM","icon":"skin/servicenow.png","name":"ServiceNow","folder":true},{"id":"SERVICE_NOW_CREATE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_CREATE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Create Incident"},{"id":"SERVICE_NOW_RESOLVE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_RESOLVE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Resolve Incident"},{"id":"SERVICE_NOW_CLOSE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_CLOSE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Close Incident"},{"id":"SERVICE_NOW_UPDATE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_UPDATE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Update Incident"},{"id":"SERVICE_NOW_INCIDENT_STATUS_SENSOR","parent":"SERVICE_NOW","processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SERVICE_NOW_INCIDENT_STATUS_SENSOR","icon":"skin/servicenow.png","name":"ServiceNow Incident Status Sensor"},{"id":"BMC_REMEDY","parent":"ITSM","icon":"skin/bmc.ico","name":"BMC Remedy","folder":true},{"id":"BMC_REMEDY_INCIDENT","parent":"BMC_REMEDY","icon":"skin/bmc.ico","processingType":"TASK","name":"BMC Remedy Incident","taskType":"BMC_REMEDY_INCIDENT"},{"id":"PEOPLESOFT","name":"Peoplesoft","icon":"skin/oracle.png","parent":"ERP","folder":true},{"id":"PEOPLESOFT_APPLICATION_ENGINE_TASK","taskType":"PEOPLESOFT_APPLICATION_ENGINE_TASK","name":"Peoplesoft Application Engine","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_COBOL_SQL_TASK","name":"Peoplesoft COBOL SQL","icon":"skin/oracle.png","parent":"PEOPLESOFT"},{"id":"PEOPLESOFT_CRW_ONLINE_TASK","taskType":"PEOPLESOFT_CRW_ONLINE_TASK","name":"Peoplesoft CRW Online","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_CRYSTAL_REPORTS_TASK","taskType":"PEOPLESOFT_CRYSTAL_REPORTS_TASK","name":"Peoplesoft Crystal Reports","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_CUBE_BUILDER_TASK","taskType":"PEOPLESOFT_CUBE_BUILDER_TASK","name":"Peoplesoft Cube Builder","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_NVISION_TASK","taskType":"PEOPLESOFT_NVISION_TASK","name":"Peoplesoft nVision","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_SQR_PROCESS_TASK","taskType":"PEOPLESOFT_SQR_PROCESS_TASK","name":"Peoplesoft SQR Process","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_SQR_REPORT_TASK","taskType":"PEOPLESOFT_SQR_REPORT_TASK","name":"Peoplesoft SQR Report","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_WINWORD_TASK","taskType":"PEOPLESOFT_WINWORD_TASK","name":"Peoplesoft Winword","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_JOB_TASK","taskType":"PEOPLESOFT_JOB_TASK","name":"Peoplesoft Job","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"WLA","folder":true,"icon":"skin/gears.png","name":"Workload Automation","parent":"TASK"},{"id":"AUTOMATE_NOW_TRIGGER_EVENT","parent":"WLA","icon":"skin/favicon.png","name":"AutomateNOW! Trigger Event","processingType":"TASK","taskType":"AUTOMATE_NOW_TRIGGER_EVENT"},{"id":"APACHE_AIRFLOW_RUN_DAG","parent":"WLA","icon":"skin/airflow.png","name":"Run Apache Airflow DAG","processingType":"TASK","taskType":"APACHE_AIRFLOW_RUN_DAG"},{"id":"ANSIBLE_PLAYBOOK","parent":"WLA","icon":"skin/ansible.png","name":"Ansible playbook","processingType":"TASK","taskType":"ANSIBLE_PLAYBOOK"},{"id":"ANSIBLE_PLAYBOOK_PATH","parent":"WLA","icon":"skin/ansible.png","name":"Ansible script","processingType":"TASK","taskType":"ANSIBLE_PLAYBOOK_PATH"},{"folder":true,"id":"CTRL_M","icon":"skin/bmc.png","name":"Ctrl-M","parent":"WLA"},{"id":"CTRLM_ADD_CONDITION","parent":"CTRL_M","icon":"skin/bmc.png","name":"Add Condition","processingType":"TASK","taskType":"CTRLM_ADD_CONDITION"},{"id":"CTRLM_DELETE_CONDITION","parent":"CTRL_M","icon":"skin/bmc.png","name":"Delete Condition","processingType":"TASK","taskType":"CTRLM_DELETE_CONDITION"},{"id":"CTRLM_ORDER_JOB","parent":"CTRL_M","icon":"skin/bmc.png","name":"Order Job","processingType":"TASK","taskType":"CTRLM_ORDER_JOB"},{"id":"CTRLM_CREATE_JOB","parent":"CTRL_M","icon":"skin/bmc.png","name":"Create Job","processingType":"TASK","taskType":"CTRLM_CREATE_JOB"},{"folder":true,"id":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Ctrl-M Resource","parent":"CTRL_M"},{"id":"CTRLM_RESOURCE_TABLE_ADD","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Add resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_ADD"},{"id":"CTRLM_RESOURCE_TABLE_UPDATE","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Update resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_UPDATE"},{"id":"CTRLM_RESOURCE_TABLE_DELETE","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Update resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_DELETE"},{"folder":true,"id":"INTERNAL","icon":"skin/milestone.png","name":"Internal Task"},{"folder":true,"id":"PROCESSING","icon":"skin/gear.png","name":"Processing","parent":"INTERNAL"},{"processingType":"TASK","taskType":"RESTART","id":"RESTART","icon":"skin/restart.png","name":"Restart","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_COMPLETED","id":"FORCE_COMPLETED","icon":"skin/accept.png","name":"Force Completed","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_FAILED","id":"FORCE_FAILED","icon":"skin/forceFailed.png","name":"Force Failed","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_READY","id":"FORCE_READY","icon":"skin/exe.png","name":"Force Launch","parent":"PROCESSING"},{"processingType":"TASK","taskType":"HOLD","id":"HOLD","icon":"skin/hold.png","name":"Hold","parent":"PROCESSING"},{"processingType":"TASK","taskType":"RESUME","id":"RESUME","icon":"skin/resume.png","name":"Resume","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ABORT","id":"ABORT","icon":"skin/kill.png","name":"Abort","parent":"PROCESSING"},{"processingType":"TASK","taskType":"KILL","id":"KILL","icon":"skin/kill.png","name":"Kill","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SKIP_ON","id":"SKIP_ON","icon":"skin/passByOn.png","name":"Skip On","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SKIP_OFF","id":"SKIP_OFF","icon":"skin/passByOff.png","name":"Skip Off","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_ACTION_SKIP_ON","id":"PROCESSING_ACTION_SKIP_ON","icon":"skin/passByOn.png","name":"Skip On Action","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_ACTION_SKIP_OFF","id":"PROCESSING_ACTION_SKIP_OFF","icon":"skin/passByOff.png","name":"Skip Off Action","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ARCHIVE","id":"ARCHIVE","icon":"skin/archive.png","name":"Archive","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_PRIORITY","id":"SET_PRIORITY","icon":"skin/numeric_stepper.png","name":"Set Priority","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_STATUS_CODE","id":"SET_STATUS_CODE","icon":"skin/sort_number.png","name":"Set Status Code","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_CONTEXT_VARIABLE_VALUE","id":"SET_CONTEXT_VARIABLE_VALUE","icon":"skin/pi_math--pencil.png","name":"Set context variable","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_CONTEXT_VARIABLE_VALUES","id":"SET_CONTEXT_VARIABLE_VALUES","icon":"skin/pi_math--pencil.png","name":"Set multiple context variables","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_RUN_NOW","id":"PROCESSING_RUN_NOW","icon":"skin/gear.png","name":"Add processing from template","parent":"PROCESSING"},{"processingType":"TASK","taskType":"CHECK_PROCESSING_STATE","id":"CHECK_PROCESSING_STATE","icon":"skin/system-monitor.png","name":"Check processing state","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ADD_TAG","id":"ADD_TAG","icon":"skin/price_tag_plus.png","name":"Add Tag","parent":"PROCESSING"},{"processingType":"TASK","taskType":"REMOVE_TAG","id":"REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Remove Tag","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_FOLDER","id":"SET_FOLDER","icon":"skin/folder.png","name":"Set Folder","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_REGISTER_STATE","id":"PROCESSING_REGISTER_STATE","icon":"skin/system-monitor.png","name":"Register Processing State","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_UNREGISTER_STATE","id":"PROCESSING_UNREGISTER_STATE","icon":"skin/system-monitor.png","name":"Unregister Processing State","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_CLEAR_STATE_REGISTRY","id":"PROCESSING_CLEAR_STATE_REGISTRY","icon":"skin/system-monitor.png","name":"Clear Processing Registry","parent":"PROCESSING"},{"folder":true,"id":"RESOURCE","icon":"skin/traffic-light.png","name":"Resource","parent":"INTERNAL"},{"folder":true,"id":"SET_RESOURCE","icon":"skin/traffic-light--pencil.png","name":"Set Resource","parent":"RESOURCE"},{"processingType":"TASK","id":"SET_SEMAPHORE_STATE","name":"Set semaphore state","icon":"skin/traffic-light--pencil.png","parent":"SET_RESOURCE","taskType":"SET_SEMAPHORE_STATE"},{"processingType":"TASK","id":"SET_TIME_WINDOW_STATE","name":"Set time window state","icon":"skin/clock--pencil.png","parent":"SET_RESOURCE","taskType":"SET_TIME_WINDOW_STATE"},{"processingType":"TASK","id":"SET_STOCK_TOTAL_PERMITS","name":"Set stock total permits","icon":"skin/stock--pencil.png","parent":"SET_RESOURCE","taskType":"SET_STOCK_TOTAL_PERMITS"},{"processingType":"TASK","id":"SET_VARIABLE_VALUE","name":"Set variable","icon":"skin/pi_math--pencil.png","parent":"SET_RESOURCE","taskType":"SET_VARIABLE_VALUE"},{"processingType":"TASK","id":"SET_PHYSICAL_RESOURCE","name":"Set physical resource","icon":"skin/memory.png","parent":"SET_RESOURCE","taskType":"SET_PHYSICAL_RESOURCE"},{"processingType":"TASK","id":"SET_METRIC","name":"Set metric","icon":"skin/gauge.png","parent":"SET_RESOURCE","taskType":"SET_METRIC"},{"processingType":"TASK","id":"TRIGGER_EVENT","name":"Trigger Event","icon":"skin/arrow-out.png","parent":"SET_RESOURCE","taskType":"TRIGGER_EVENT"},{"folder":true,"id":"CHECK_RESOURCE","icon":"skin/traffic-light--check.png","name":"Check Resource","parent":"RESOURCE"},{"processingType":"TASK","id":"CHECK_SEMAPHORE_STATE","name":"Check semaphore state","icon":"skin/traffic-light--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_SEMAPHORE_STATE"},{"processingType":"TASK","id":"CHECK_TIME_WINDOW_STATE","name":"Check time window state","icon":"skin/clock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_TIME_WINDOW_STATE"},{"processingType":"TASK","id":"CHECK_STOCK_AVAILABLE_PERMITS","name":"Check stock available permits","icon":"skin/stock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_STOCK_AVAILABLE_PERMITS"},{"processingType":"TASK","id":"CHECK_CALENDAR","name":"Check calendar","icon":"skin/date_control.png","parent":"CHECK_RESOURCE","taskType":"CHECK_CALENDAR"},{"processingType":"TASK","id":"CHECK_STOCK_TOTAL_PERMITS","name":"Check stock total permits","icon":"skin/stock-total--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_STOCK_TOTAL_PERMITS"},{"processingType":"TASK","id":"CHECK_LOCK_STATE","name":"Check lock state","icon":"skin/lock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_LOCK_STATE"},{"processingType":"TASK","id":"CHECK_VARIABLE_VALUE","name":"Check variable value","icon":"skin/pi_math--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_VARIABLE_VALUE"},{"processingType":"TASK","id":"CHECK_PHYSICAL_RESOURCE","name":"Check physical resource","icon":"skin/memory.png","parent":"CHECK_RESOURCE","taskType":"CHECK_PHYSICAL_RESOURCE"},{"processingType":"TASK","id":"CHECK_METRIC","name":"Check metric","icon":"skin/gauge.png","parent":"CHECK_RESOURCE","taskType":"CHECK_METRIC"},{"processingType":"TASK","taskType":"RESOURCE_ADD_TAG","id":"RESOURCE_ADD_TAG","icon":"skin/price_tag_plus.png","name":"Resource Add Tag","parent":"RESOURCE"},{"processingType":"TASK","taskType":"RESOURCE_REMOVE_TAG","id":"RESOURCE_REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Resource Remove Tag","parent":"RESOURCE"},{"processingType":"TASK","taskType":"RESOURCE_SET_FOLDER","id":"RESOURCE_SET_FOLDER","icon":"skin/folder.png","name":"Set Resource Folder","parent":"RESOURCE"},{"folder":true,"id":"SERVER_NODE","icon":"skin/servers.png","name":"Server Node","parent":"INTERNAL"},{"processingType":"TASK","taskType":"SERVER_NODE_HOLD","id":"SERVER_NODE_HOLD","icon":"skin/hold.png","name":"Server Node Hold","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_RESUME","id":"SERVER_NODE_RESUME","icon":"skin/resume.png","name":"Server Node Resume","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SKIP_ON","id":"SERVER_NODE_SKIP_ON","icon":"skin/passByOn.png","name":"Server Node Skip On","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SKIP_OFF","id":"SERVER_NODE_SKIP_OFF","icon":"skin/passByOff.png","name":"Server Node Skip Off","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_ABORT_ALL","id":"SERVER_NODE_ABORT_ALL","icon":"skin/kill.png","name":"Server Node Abort All","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_KILL_ALL","id":"SERVER_NODE_KILL_ALL","icon":"skin/kill.png","name":"Server Node Kill All","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_STOP","id":"SERVER_NODE_STOP","icon":"skin/stop.png","name":"Server Node Stop","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_ADD_TAG","id":"SERVER_NODE_ADD_TAG","icon":"skin/price_tag_plus.png","name":"Server Node Add Tag","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_REMOVE_TAG","id":"SERVER_NODE_REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Server Node Remove Tag","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SET_FOLDER","id":"SERVER_NODE_SET_FOLDER","icon":"skin/folder.png","name":"Server Node Set Folder","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SET_TOTAL_WEIGHT_CAPACITY","id":"SERVER_NODE_SET_TOTAL_WEIGHT_CAPACITY","icon":"skin/folder.png","name":"Server Node Set Capacity","parent":"SERVER_NODE"},{"folder":true,"id":"PROCESSING_TEMPLATE","icon":"skin/clock.png","name":"Processing Template","parent":"INTERNAL"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_HOLD","id":"PROCESSING_TEMPLATE_HOLD","icon":"skin/hold.png","name":"Processing Template Hold","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_RESUME","id":"PROCESSING_TEMPLATE_RESUME","icon":"skin/resume.png","name":"Processing Template Resume","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_SKIP_ON","id":"PROCESSING_TEMPLATE_SKIP_ON","icon":"skin/passByOn.png","name":"Processing Template Skip On","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_SKIP_OFF","id":"PROCESSING_TEMPLATE_SKIP_OFF","icon":"skin/passByOff.png","name":"Processing Template Skip Off","parent":"PROCESSING_TEMPLATE"},{"folder":true,"id":"MAINTENANCE","icon":"skin/gear.png","name":"Maintenance","parent":"INTERNAL"},{"processingType":"TASK","taskType":"ARCHIVE_INTERVAL","id":"ARCHIVE_INTERVAL","icon":"skin/archive.png","name":"Archive old processing items","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"ARCHIVE_CLEANUP","id":"ARCHIVE_CLEANUP","icon":"skin/archive.png","name":"Archive cleanup","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"RECALCULATE_STATISTICS","id":"RECALCULATE_STATISTICS","icon":"skin/calculator.png","name":"Recalculate Statistic","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"DESIGN_BACKUP","id":"DESIGN_BACKUP","icon":"skin/drive-download.png","name":"Design Backup","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"DESIGN_IMPORT","id":"DESIGN_IMPORT","icon":"skin/drive-download.png","name":"Design Import","parent":"MAINTENANCE"},{"folder":true,"id":"OTHER","icon":"skin/alarm.png","name":"Other","parent":"INTERNAL"},{"processingType":"TASK","taskType":"WAIT","id":"WAIT","icon":"skin/alarm.png","name":"Wait","parent":"OTHER"},{"processingType":"TASK","taskType":"CHECK_TIME","id":"CHECK_TIME","icon":"skin/clock.png","name":"Check Time","parent":"OTHER"},{"id":"USER_TASKS","name":"User","icon":"skin/user.png","parent":"INTERNAL","folder":true},{"processingType":"TASK","taskType":"USER_CONFIRM","id":"USER_CONFIRM","icon":"skin/thumbUp.png","name":"User confirmation","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"USER_INPUT","id":"USER_INPUT","icon":"skin/pencil.png","name":"User input","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_GROUP","id":"NOTIFY_GROUP","icon":"skin/users.png","name":"Notify Group","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_CHANNEL","id":"NOTIFY_CHANNEL","icon":"skin/mail_server_exim.png","name":"Notify Channel","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_EMAIL","id":"NOTIFY_EMAIL","icon":"skin/mail.png","name":"Notify Email","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"ADHOC_REPORT_SEND","id":"ADHOC_REPORT_SEND","icon":"skin/table.png","name":"Adhoc Report Send","parent":"USER_TASKS"},{"processingType":"TASK","id":"AE","icon":"skin/terminal.gif","name":"AE","parent":"INTERNAL","folder":true},{"processingType":"TASK","taskType":"AE_SCRIPT","id":"AE_SCRIPT","icon":"skin/terminal.gif","name":"AE Script","parent":"AE"},{"processingType":"WORKFLOW","id":"WORKFLOW","name":"Workflow","icon":"skin/diagram.png","folder":true},{"processingType":"WORKFLOW","workflowType":"STANDARD","id":"STANDARD","icon":"skin/diagram.png","name":"Workflow","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"BROADCAST","id":"BROADCAST","icon":"skin/rss.png","name":"Broadcast","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"FOR_EACH","id":"FOR_EACH","icon":"skin/ordered_list.png","name":"For Each","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"SWITCH","id":"SWITCH","icon":"skin/switch.png","name":"Switch","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"CYCLE","id":"CYCLE","icon":"skin/cycle.png","name":"Cycle","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"TIME_SERIES","id":"TIME_SERIES","icon":"skin/ui-paginator.png","name":"Time Series","parent":"WORKFLOW"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"FILE_SENSOR","id":"FILE_SENSOR","icon":"skin/fileWatcher.png","name":"File Sensor","parent":"FILE_PROCESSING"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"JIRA_ISSUE_SENSOR","id":"JIRA_ISSUE_SENSOR","icon":"skin/jira.png","name":"Jira Issue Sensor","parent":"JIRA"},{"processingType":"TASK","id":"JIRA_ADD_ISSUE","parent":"JIRA","icon":"skin/jira.png","name":"Jira Add Issue","taskType":"JIRA_ADD_ISSUE"},{"id":"RPA","icon":"skin/robot.png","name":"Robotic Process Automation","parent":"TASK","folder":true},{"processingType":"TASK","id":"UI_PATH","icon":"skin/uipath.ico","name":"UiPath","parent":"RPA","taskType":"UI_PATH"},{"processingType":"TASK","id":"BLUE_PRISM","icon":"skin/blueprism.ico","name":"Blue Prism","parent":"RPA","taskType":"BLUE_PRISM"},{"processingType":"TASK","id":"ROBOT_FRAMEWORK_START_ROBOT","icon":"skin/robotFramework.png","name":"Robot Framework Start Robot","parent":"RPA","taskType":"ROBOT_FRAMEWORK_START_ROBOT"},{"id":"BI","icon":"skin/table_chart.png","name":"Business Intelligence","parent":"TASK","folder":true},{"id":"MICROSOFT_POWER_BI","icon":"skin/table_chart.png","name":"Microsoft Power BI","parent":"BI","folder":true},{"processingType":"TASK","id":"MICROSOFT_POWER_BI_DATASET_REFRESH","icon":"skin/powerBi.ico","name":"Microsoft Power BI Refresh Data Set","parent":"MICROSOFT_POWER_BI","taskType":"MICROSOFT_POWER_BI_DATASET_REFRESH"},{"processingType":"TASK","id":"MICROSOFT_POWER_BI_DATAFLOW_REFRESH","icon":"skin/powerBi.ico","name":"Microsoft Power BI Refresh Data Flow","parent":"MICROSOFT_POWER_BI","taskType":"MICROSOFT_POWER_BI_DATAFLOW_REFRESH"},{"id":"INSTANT_MESSAGING","name":"Instant Messaging","icon":"skin/comment_edit.png","parent":"TASK","folder":true},{"processingType":"TASK","id":"TELEGRAM_MESSAGE","icon":"skin/telegram.png","name":"Telegram Message","parent":"INSTANT_MESSAGING","taskType":"TELEGRAM_MESSAGE"},{"processingType":"TASK","id":"WHATSAPP_MESSAGE","icon":"skin/whatsapp.png","name":"WhatsApp Message","parent":"INSTANT_MESSAGING","taskType":"WHATSAPP_MESSAGE"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SQL_SENSOR","id":"SQL_SENSOR","icon":"skin/database-sql.png","name":"SQL Sensor","parent":"SQL"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"Z_OS_JES_JOB_SENSOR","id":"Z_OS_JES_JOB_SENSOR","icon":"skin/zos.png","name":"z/OS JES Job Sensor","parent":"Z_OS"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SH_MONITOR","id":"SH_MONITOR","icon":"skin/terminal.gif","name":"Shell Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PYTHON_MONITOR","id":"PYTHON_MONITOR","icon":"skin/python.png","name":"Python Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PERL_MONITOR","id":"PERL_MONITOR","icon":"skin/perl.png","name":"Perl Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"RUBY_MONITOR","id":"RUBY_MONITOR","icon":"skin/ruby.png","name":"Ruby Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"GROOVY_MONITOR","id":"GROOVY_MONITOR","icon":"skin/groovy.png","name":"Groovy Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"POWERSHELL_MONITOR","id":"POWERSHELL_MONITOR","icon":"skin/powershell.png","name":"PowerShell Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"HTTP_MONITOR","id":"HTTP_MONITOR","icon":"skin/http.png","name":"HTTP Monitor","parent":"WEB"},{"folder":true,"id":"OPERATING_SYSTEM_MONITOR","icon":"skin/system-monitor.png","name":"OS Monitors","parent":"TASK"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SYSTEM_MONITOR","id":"SYSTEM_MONITOR","icon":"skin/memory.png","name":"System Monitor","parent":"OPERATING_SYSTEM_MONITOR"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SYSTEM_PROCESS_MONITOR","id":"SYSTEM_PROCESS_MONITOR","icon":"skin/system-monitor.png","name":"System Process Monitor","parent":"OPERATING_SYSTEM_MONITOR"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SAP_R3_JOB_MONITOR","id":"SAP_R3_JOB_MONITOR","icon":"skin/sap.png","name":"SAP R/3 Job Monitor","parent":"SAP_R3_JOBS"},{"id":"SLA","title":"Service Manager","name":"Service Manager","icon":"skin/traffic-light.png","folder":true},{"id":"BUSINESS_VIEW","title":"Business View","icon":"skin/chart_organisation.png","processingType":"SERVICE","serviceType":"SERVICE_MANAGER","serviceManagerType":"BUSINESS_VIEW","name":"Business View"},{"id":"SLA_SERVICE_MANAGER","title":"Service Level Agreement","icon":"skin/traffic-light.png","processingType":"SERVICE","serviceType":"SERVICE_MANAGER","serviceManagerType":"SLA_SERVICE_MANAGER","name":"Service Level Agreement","parent":"SLA"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PROCESSING_BASELINE_DEVIATION_MONITOR","id":"PROCESSING_BASELINE_DEVIATION_MONITOR","icon":"skin/chart_down_color.png","name":"Baseline Deviation Monitor","parent":"PROCESSING"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PROCESSING_DEADLINE_MONITOR","id":"PROCESSING_DEADLINE_MONITOR","icon":"skin/chart_stock.png","name":"Processing Deadline Monitor","parent":"SLA"},{"processingType":"TRIGGER","id":"TRIGGER","name":"Trigger","icon":"skin/arrow-out.png","folder":true},{"processingType":"TRIGGER","triggerType":"SCHEDULE","id":"SCHEDULE","icon":"skin/clock.png","name":"Time Schedule","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"USER","id":"USER","icon":"skin/user.png","name":"User","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"EVENT","id":"EVENT","icon":"skin/arrow-out.png","name":"Event Schedule","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"SELF_SERVICE","id":"SELF_SERVICE","icon":"skin/user.png","name":"Self Service","parent":"TRIGGER"},{"parent":"NONEXISTING_ITEM_TO_HIDE_FROM_VIEW","processingType":"TASK","taskType":"TRIGGER_ITEM","id":"TRIGGER_ITEM","name":"Trigger Item","icon":"skin/exe.png","inactive":true},{"processingType":"TASK","taskType":"PROCESSING_OBSERVER","id":"PROCESSING_OBSERVER","icon":"skin/emotion_eye.png","name":"Processing Observer","parent":"NONEXISTING_ITEM_TO_HIDE_FROM_VIEW","inactive":true}]' | ConvertFrom-Json
    [array]$TaskTypesArray = $TaskTypesJson | ForEach-Object { [PSCustomObject]@{ Parent = $_.parent; Id = $_.id; Name = $_.name; } }
    Return $TaskTypesArray
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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

#Region - WorkflowTemplates

Function Get-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Gets the workflow templates from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the workflow templates from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the workflow to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER Type
    Optional string containing the type of workflow. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the workflow from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWWorkflowTemplate] class objects
    
    .EXAMPLE
    Get-AutomateNOWWorkflowTempate

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'workflow_01'

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Type TRIGGER

    .EXAMPLE
    @( 'workflow_01', 'workflow_02' ) | Get-AutomateNOWWorkflowTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the workflows.

    #>
    [OutputType([ANOWWorkflowTemplate[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflow_workflowType]$Type,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 2000,
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'processingType'
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
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            $Body.'_textMatchStyle' = 'exact'
        }
        Else {
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'operator' = 'and'
            If ( $Type.length -eq 0) {
                [string]$fieldName = 'processingType'
                [string]$value = 'WORKFLOW'
            }
            Else {
                [string]$fieldName = 'workflowType'
                [string]$value = $Type
            }
            $Body.'criteria' = ('{"fieldName":"' + $fieldName + '","operator":"equals","value":"' + $value + '"}')
            $Body.'_operationType' = 'fetch'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            $Body.'_sortBy' = $sortBy            
        }
        $Body.'_componentId' = 'ProcessingTemplateList'
        $Body.'_dataSource' = 'ProcessingTemplateDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
            [ANOWWorkflowTemplate[]]$workflow_templates = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWWorkflowTemplate] objects due to [$Message]."
            Break
        }
        If ($workflow_templates.Count -gt 0) {
            Return $workflow_templates
        }
    
    }
    End {

    }
}

Function Export-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Exports the workflow templates from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the workflow templates from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER WorkflowTemplate
    Mandatory [ANOWWorkflowTemplate] object (Use Get-AutomateNOWWorkflowTemplate to retrieve them)
    
    .PARAMETER Type
    Mandatory string containing the type of workflow. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWWorkflowTemplate] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | Export-AutomateNOWWorkflowTemplate -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Type STANDARD | Export-AutomateNOWWorkflowTemplate -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'Workflow01' | Export-AutomateNOWWorkflowTemplate -Type FOR_EACH

    .EXAMPLE
    @( 'Workflow01', 'Workflow02', 'Workflow03' ) | Get-AutomateNOWWorkflowTemplate | Export-AutomateNOWWorkflowTemplate -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | Where-Object { $_.id -like '*MyWorkflow*' } | Export-AutomateNOWWorkflowTemplate -Type STANDARD

    .NOTES
	You must present [ANOWWorkflowTemplate] objects to the pipeline to use this function.

    The -Type parameter is mandatory here!
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflow_workflowType]$Type
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-WorkflowTemplates-' + $current_time + '.csv'
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
            [ANOWWorkflowTemplate]$workflow_template = $_
        }
        $Error.Clear()
        Try {
            $workflow_template | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWWorkflowTemplate] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Creates a workflow template within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a workflow template within an AutomateNOW! instance and returns back the newly created [ANOWWorkflowTemplate] object

    .PARAMETER Id
    The intended name of the workflow template. For example: 'MyWorkflow1'. This value may not contain the domain in brackets.

    .PARAMETER Type
    Required type of the workflow template.

    .PARAMETER Description
    Optional description of the workflow template (may not exceed 255 characters).

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

    The name (id) of the workflow template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWWorkflowTemplate])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWWorkflow_workflowType]$Type,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
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
        [boolean]$Workflow_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the workflow template [$Id] already existed due to [$Message]."
        Break                
    }
    If ($Workflow_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a workflow template named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWWorkflowTemplate]$ANOWWorkflowTemplate = New-Object -TypeName ANOWWorkflowTemplate
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed to create the object of type [ANOWWorkflow] due to [$Message]."
        Break
    }
    $ANOWWorkflowTemplate.'processingType' = 'WORKFLOW'
    $ANOWWorkFlowTemplate.'workflowType' = $Type
    $ANOWWorkFlowTemplate.'id' = $Id
    $ANOWWorkFlowTemplate.'description' = $Description
    $ANOWWorkFlowTemplate.'tags' = $Tags
    $ANOWWorkFlowTemplate.'folder' = $Folder
    $ANOWWorkFlowTemplate.'codeRepository' = $CodeRepository
    $ANOWWorkFlowTemplate.'workspace' = $Workspace
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWWorkFlowTemplate -IncludeProperties id, processingType, workflowType, description, tags, folder, codeRepository, workspace
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create workflow template [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create workflow template [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWWorkflowTemplate]$WorkflowTemplate = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWWorkflowTemplate] object due to [$Message]."
        Break
    }        
    If ($WorkflowTemplate.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWWorkflowTemplate] object is empty!"
        Break
    }
    Return $WorkflowTemplate
}

Function Remove-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Removes a workflow template from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a workflow template  from an AutomateNOW! instance
    
    .PARAMETER WorkflowTemplate
    An [ANOWworkflowTemplate] object representing the workflow template to be deleted.
    
    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'Workflow01' | Remove-AutomateNOWWorkflowTemplate

    .EXAMPLE
    Get-AutomateNOWWorkTemplate  -Id 'Workflow01', 'Workflow02' | Remove-AutomateNOWWorkflowTemplate
    
    .EXAMPLE
    @( 'Workflow1', 'Workflow2', 'Workflow3') | Remove-AutomateNOWWorkflowTemplate

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | ? { $_.workflowType -eq 'BROADCAST' } | Remove-AutomateNOWWorkflowTemplate
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
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
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($WorkflowTemplate.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$WorkflowTemplate_id = $_.id
            }
            ElseIf ($WorkflowTemplate.id.Length -gt 0) {
                [string]$WorkflowTemplate_id = $WorkflowTemplate.id
            }
            Else {
                [string]$WorkflowTemplate_id = $Id
            }
            [string]$Body = 'id=' + $WorkflowTemplate_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$WorkflowTemplate_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$error_message = $results.response.data
                If ($error_message -match 'Object may still be in use') {
                    [string]$WorkflowTemplate_id_formatted = $WorkflowTemplate_id -split '\]' | Select-Object -Last 1
                    Write-Warning -Message "This object $WorkflowTemplate_id_formatted is still in use somewhere therefore it cannot be removed! Please use 'Find-AutomateNOWObjectReferral -Object $WorkflowTemplate_id_formatted' to list the references for this object and then remove them."
                }
                Else {
                    [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                    Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
                }
            }
            Write-Verbose -Message "Workflow $WorkflowTemplate_id successfully removed"
        }
    }
    End {

    }
}

Function Copy-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Copies a workflow template from an AutomateNOW! instance
    
    .DESCRIPTION    
    Copies a workflow template from an AutomateNOW! instance. AutomateNOW object id can never be changed, but we can copy the object to a new id and it will include all of the items therein.
    
    .PARAMETER WorkflowTemplate
    Mandatory [ANOWworkflowTemplate] object to be copied.

    .PARAMETER NewId
    Mandatory string indicating the new id or name of the workflow. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

    .PARAMETER RemoveOldTags
    Optional switch that will purposely omit the previously existing tags on the new copy of the workflow. You can still specify new tags with -Tags but the old previous ones will not be carried over. In the UI, this is accomplished by clicking the existing tags off.
    
    .PARAMETER NoFolder
    Optional switch that will ensure that the newly created workflow template will not be placed in a folder. In the UI, this is accomplished by clicking the folder off.
    
    .PARAMETER NoDescription
    Optional switch that will ensure that the newly created workflow template will not carry over its previous description.
    
    .PARAMETER Description
    Optional description of the workflow template (may not exceed 255 characters). You may send an empty string here to ensure that the description is blanked out. Do not use this parameter if your intention is to keep the description from the previous workflow template.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new workflow template. Be sure to pass strings here and now [ANOWTag] objects. The RemoveOldTags DOES NOT impacting this parameter.

    .PARAMETER Folder
    Optional name of the folder to place the workflow template into. The NoFolder parameter overrides this setting.
    
    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted. Pipeline support is intentionally unavailable.
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    This is a safe standard example that is recommended
    
    $workflow01 = Get-AutomateNOWWorkflowTemplate -Id 'old_name_Workflow01'
    Copy-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow01 -NewId 'new_name_Workflow02'
    
    .EXAMPLE
    This is a one-liner approach

    Copy-AutomateNOWWorkflowTemplate -WorkflowTemplate (Get-AutomateNOWWorkflowTemplate -Id 'old_name_Workflow01') -NewId 'new_name_Workflow02'

    .EXAMPLE
    This approach users a For Each loop to iterate through a standard renaming pattern. This approach is not recommended.

    @( 'Workflow1', 'Workflow2', 'Workflow3') | Get-AutomateNOWWorkflowTemplate | ForEachObject { Copy-AutomateNOWWorkflowTemplate -WorkflowTemplate $_ -NewId ($_.simpleId -replace 'Workflow[0-9]', ()'Workflow-' + $_.simpleId[-1]))}

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The new id (name) of the workflow template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.
    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,1024}$' })]
        [string]$NewId,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [switch]$RemoveOldTags,
        [Parameter(Mandatory = $false)]
        [switch]$NoDescription,
        [Parameter(Mandatory = $false)]
        [switch]$NoFolder,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. Technically, the console will not allow a duplicate object to be created. However, it would be cleaner to use the Get function first to ensure we are not trying to create a duplicate here.
        $Error.Clear()
        Try {
            [boolean]$Workflow_template_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the workflow template [$NewId] already existed due to [$Message]."
            Break                
        }
        If ($Workflow_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a workflow template named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        ## End warning ##
        [string]$command = '/processingTemplate/copy'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($PermissionToProceed -ne $false) {
            [string]$WorkflowTemplate_oldId = $WorkflowTemplate.id
            If ($WorkflowTemplate_oldId -eq $NewId) {
                Write-Warning -Message "The new id cannot be the same as the old id."
                Break           
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'oldId' = $WorkflowTemplate_oldId
            $BodyMetaData.'domain' = $WorkflowTemplate.domain
            $BodyMetaData.'id' = $NewId
            If ($NoDescription -ne $true) {
                If ($Description.Length -gt 0) {
                    $BodyMetaData.'description' = $Description
                }
                Else {
                    $BodyMetaData.'description' = $WorkflowTemplate.description
                }
            }
            If ($NoFolder -ne $True) {
                If ($Folder.Length -gt 0) {
                    $BodyMetaData.'folder' = $Folder
                }
                Else {
                    $BodyMetaData.'folder' = $WorkflowTemplate.folder
                }
            }
            [int32]$tag_count = 1
            If ($Tags.Count -gt 0) {
                ForEach ($tag in $Tags) {
                    $BodyMetaData.('tags' + $tag_count ) = $tag
                    $tag_count++
                }
            }
            If ($RemoveOldTags -ne $true) {
                If ($WorkflowTemplate.tags -gt 0) {
                    ForEach ($tag in $WorkflowTemplate.tags) {
                        $BodyMetaData.('tags' + $tag_count ) = $tag
                        $tag_count++
                    }
                }
            }
            $BodyMetaData.'_operationType' = 'add'
            $BodyMetaData.'_operationId' = 'copy'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'ProcessingTemplateDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            $Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties oldId, domain, NewId, description, folder
            $Body = $Body -replace '&tags[0-9]{1,}', '&tags'
            $parameters.Body = $Body
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$WorkflowTemplate_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWWorkflowTemplate]$WorkflowTemplate = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create copied [ANOWWorkflowTemplate] object due to [$Message]."
                Break
            }        
            If ($WorkflowTemplate.id.Length -eq 0) {
                Write-Warning -Message "Somehow the newly created (copied) [ANOWWorkflowTemplate] object is empty!"
                Break
            }
            Return $WorkflowTemplate
        }
    }
    End {

    }
}

Function Rename-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Renames a workflow template from an AutomateNOW! instance
    
    .DESCRIPTION    
    Performs a psuedo-rename operations of a workflow template from an AutomateNOW! instance by copying it first and then deleting the source. This function merely combines Copy-AutomateNOWWorkflowTemplate and Remove-AutomateNOWWorkflowTemplate therefore it is to be considered destructive.
    
    .PARAMETER WorkflowTemplate
    An [ANOWworkflowTemplate] object representing the workflow template to be renamed.
    
    .PARAMETER NewId
    Mandatory string indicating the new id or name of the workflow. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

    .PARAMETER Force
    Force the renaming without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted. There is inventionally no support for the pipeline.
    
    .OUTPUTS
    The newly renamed [ANOWWorkflowTemplate] object will be returned.
    
    .EXAMPLE
    $workflow_template = Get-AutomateNOWWorkflowTemplate -Id 'Workflow01'
    Rename-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -NewId 'WORKFLOW_TEMPLATE_01'

    .EXAMPLE
    Rename-AutomateNOWWorkflowTemplate -WorkflowTemplate (Get-AutomateNOWWorkflowTemplate -Id 'Workflow01') -NewId 'WORKFLOW_TEMPLATE_01'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    When renaming, you may only change the Id of the object.

    This action will be blocked if any existing referrals are found on the object.
    #>
    [OutputType([ANOWWorkflowTemplate])]
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,1024}$' })]
        [string]$NewId,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        ## Begin standard warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. Technically, the console will not allow a duplicate object to be created. However, it would be cleaner to use the Get function first to ensure we are not trying to create a duplicate here.
        $Error.Clear()
        Try {
            [boolean]$new_Workflow_template_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the workflow template [$NewId] already existed due to [$Message]."
            Break                
        }
        If ($new_Workflow_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a workflow template named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        [string]$WorkflowTemplate_id = $WorkflowTemplate.id
        $Error.Clear()
        Try {
            [boolean]$old_Workflow_template_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $WorkflowTemplate_id))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the workflow template [$WorkflowTemplate_id] already existed due to [$Message]."
            Break                
        }
        If ($old_Workflow_template_exists -eq $false) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is not a workflow template named [$WorkflowTemplate_id] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        ## End standard warning ##
        ## Begin referrals warning ##
        ## Do not tamper with this below code which makes sure the object does not have referrals. The old object is removed but this can't happen if referrals exist. The API will prevent this from happening but it is checked here to stop any invalid requests from being sent to the API in the first place.
        $Error.Clear()
        Try {
            [int32]$referrals_count = Find-AutomateNOWObjectReferral -WorkflowTemplate $WorkflowTemplate -Count | Select-Object -Expandproperty referrals
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Find-AutomateNOWObjectReferral failed to extract the referrals on workflow template [$WorkflowTemplate_id] due to [$Message]."
            Break
        }
        If ($referrals_count -gt 0) {
            Write-Warning -Message "Unfortunately, you cannot rename a workflow template that has referrals. This is because the rename is not actually renaming but copying anew and deleting the old. Please, use the Find-AutomateNOWObjectReferral function to identify referrals and remove them."
            Break
        }
        Else {
            Write-Verbose -Message "The workflow template [$WorkflowTemplate_id] does not have any referrals. It is safe to proceed."
        }
    }
    Process {
        If ($PermissionToProceed -ne $false) {
            If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($WorkflowTemplate_id)")) -eq $true) {
                $Error.Clear()
                Try {
                    [ANOWWorkflowTemplate]$new_workflow_template = Copy-AutomateNOWWorkflowTemplate -WorkflowTemplate $WorkflowTemplate -NewId $NewId
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Copy-AutomateNOWWorkflowTemplate failed to create a new workflow template [$NewId] as Part 1 of the renaming process due to [$Message]."
                    Break                
                }            
                If ($new_workflow_template.simpleId -eq $NewId) {
                    Write-Verbose -Message "Part 1: Workflow template [$WorkflowTemplate_id] successfully copied to [$NewId]"
                }
                $Error.Clear()
                Try {
                    [ANOWWorkflowTemplate]$new_workflow_template = Remove-AutomateNOWWorkflowTemplate -WorkflowTemplate $WorkflowTemplate -confirm:$false # Note that confirmation was already provided a few lines above
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Remove-AutomateNOWWorkflowTemplate failed to remove [$WorkflowTemplate_id] as Part 2 of the renaming process due to [$Message]."
                    Break                
                }            
                If ($new_workflow_template.simpleId -eq $NewId) {
                    Write-Verbose -Message "Part 2: Workflow template [$WorkflowTemplate_id] removed"
                }
                Write-Verbose -Message "Workflow [$WorkflowTemplate_id] successfully renamed to [$NewId]"
            }
        }
        Else {
            Write-Warning "No action was taken because either the source object didn't exist or the new object already existed"
        }
    }
    End {
    }
}

#endregion

#Region - Workspaces

Function Get-AutomateNOWWorkspace {
    <#
    .SYNOPSIS
    Gets the Workspaces from an AutomateNOW! instance
    
    .DESCRIPTION    
    Gets the Workspaces from an AutomateNOW! instance
    
    .PARAMETER Id
    Optional string containing the simple id of the Workspace to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .INPUTS
    Accepts a string representing the simple id of the Workspace from the pipeline or individually (but not an array).
    
    .OUTPUTS
    An array of one or more [ANOWWorkspace] class objects
    
    .EXAMPLE
    Get-AutomateNOWWorkspace

    .EXAMPLE
    Get-AutomateNOWWorkspace -Id 'Workspace1'

    .EXAMPLE
    @( 'Workspace1', 'Workspace2' ) | Get-AutomateNOWWorkspace

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Workspaces.

    #>
    [OutputType([ANOWWorkspace[]])]
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
                [string]$Workspacename = $_
            }
            Else {
                [string]$Workspacename = $Id
            }
            [string]$command = ('/workspace/read?id=' + $Workspacename)
        }
        Else {
            [string]$command = '/workspace/read'
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] due to [$Message]."
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
            [ANOWWorkspace[]]$Workspaces = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWWorkspace] objects due to [$Message]."
            Break
        }
        If ($Workspaces.Count -gt 0) {
            Return $Workspaces
        }
    }
    End {

    }
}

Function Set-AutomateNOWWorkspace {
    <#
    .SYNOPSIS
    Changes the settings of a Workspace from an AutomateNOW! instance
    
    .DESCRIPTION    
    Changes the settings of a Workspace from an AutomateNOW! instance
    
    .PARAMETER Workspace
    An [ANOWWorkspace] object representing the Workspace to be changed.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWWorkspace] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    The modified [ANOWWorkspace] object will be returned
    
    .EXAMPLE
    Get-AutomateNOWWorkspace -Id 'Workspace01' | Set-AutomateNOWWorkspace -Description 'New Description'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The only property which the console allows to be changed is the description.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkspace]$Workspace,
        [Parameter(Mandatory = $true, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [AllowEmptyString()]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/workspace/update'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Workspace.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Workspace_id = $_.id                
            }
            ElseIf ($Workspace.id.Length -gt 0) {
                [string]$Workspace_id = $Workspace.id
            }
            Else {
                [string]$Workspace_id = $Id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$Workspace_exists = ($null -eq (Get-AutomateNOWWorkspace -Id $Workspace_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkspace failed to check if the Workspace [$Workspace_id] already existed due to [$Message]."
                Break
            }
            If ($Workspace_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Workspace named [$Workspace_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id', $Workspace.id
            $BodyMetaData.'parent' = $Workspace.parent
            $BodyMetaData.'codeRepository' = $Workspace.codeRepository
            $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_componentId' = 'WorkspaceEditForm'
            $BodyMetaData.'_dataSource' = 'WorkspaceDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat ' = 'json'
            $BodyMetaData.description = $Description
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workspace_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Workspace $Workspace_id was successfully updated"
        }
    }
    End {
        
    }
}

Function Export-AutomateNOWWorkspace {
    <#
    .SYNOPSIS
    Exports the Workspaces from an instance of AutomateNOW!
    
    .DESCRIPTION    
    Exports the Workspaces from an instance of AutomateNOW! to a local .csv file
    
    .PARAMETER Domain
    Mandatory [ANOWWorkspace] object (Use Get-AutomateNOWWorkspace to retrieve them)
    
    .INPUTS
    ONLY [ANOWWorkspace] objects from the pipeline are accepted
    
    .OUTPUTS
    The [ANOWWorkspace] objects are exported to the local disk in CSV format
    
    .EXAMPLE
    Get-AutomateNOWWorkspace | Export-AutomateNOWWorkspace

    .EXAMPLE
    Get-AutomateNOWWorkspace -Id 'Workspace01' | Export-AutomateNOWWorkspace

    .EXAMPLE
    @( 'Workspace01', 'Workspace02' ) | Get-AutomateNOWWorkspace | Export-AutomateNOWWorkspace

    .EXAMPLE
    Get-AutomateNOWWorkspace | Where-Object { $_.simpleId -eq 'Workspace01' } | Export-AutomateNOWWorkspace

    .NOTES
	You must present [ANOWWorkspace] objects to the pipeline to use this function.
    #>
    
    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWWorkspace]$Workspace
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Workspaces-' + $current_time + '.csv'
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
            [ANOWWorkspace]$Workspace = $_
        }
        $Error.Clear()
        Try {
            $Workspace | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWWorkspace] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWWorkspace {
    <#
    .SYNOPSIS
    Creates a Workspace within an AutomateNOW! instance
    
    .DESCRIPTION    
    Creates a Workspace within an AutomateNOW! instance and returns back the newly created [ANOWWorkspace] object

    .PARAMETER Id
    The intended name of the Workspace. For example: 'LinuxWorkspace1'. This value may not contain the domain in brackets.

    .PARAMETER Description
    Optional description of the Workspace (may not exceed 255 characters).

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Workspace into.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWWorkspace.
    
    .OUTPUTS
    An [ANOWWorkspace] object representing the newly created Workspace
    
    .EXAMPLE
    New-AutomateNOWWorkspace -Id 'Workspace1' -Description 'Workspace1 description' -Tags 'Tag1', 'Tag2' -Folder 'Folder1' -iconSet 'FAT_COW' -iconCode 'paper_airplane' -codeRepository 'Repository1'
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Workspace must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    Adding the icon set is missing

    #>

    [OutputType([ANOWWorkspace])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'iconSet')]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [string]$Id,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet', HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet')]
        [string[]]$Tags,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet')]
        [string]$Folder,
        [Parameter(Mandatory = $true, ParameterSetName = 'iconSet')]
        [ANOWiconSetIconsOnly]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'iconSet')]
        [string]$iconCode,
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet')]
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
        [boolean]$Workspace_exists = ($null -ne (Get-AutomateNOWWorkspace -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWWorkspace failed to check if the Workspace [$Id] already existed due to [$Message]."
        Break
    }
    If ($Workspace_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Workspace named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    $Error.Clear()
    Try {
        [ANOWWorkspace]$ANOWWorkspace = New-Object -TypeName ANOWWorkspace
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "New-Object failed to create the object of type [ANOWWorkspace] due to [$Message]."
        Break
    }
    $ANOWWorkspace.'id' = $Id
    If ($Description.Length -gt 0) {
        $ANOWWorkspace.'description' = $Description
    }
    If ($tags.Count -gt 0) {
        $ANOWWorkspace.'tags' = $tags -join ','
    }
    If ($Folder.Length -gt 0) {
        $ANOWWorkspace.'folder' = $Folder
    }
    If ($codeRepository.Length -gt 0) {
        $ANOWWorkspace.'codeRepository' = $codeRepository
    }
    If ($iconSet.Length -gt 0) {
        $ANOWWorkspace.'iconSet' = $iconSet
    }
    If ($iconCode.Length -gt 0) {
        $ANOWWorkspace.'iconCode' = $iconCode
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWWorkspace -IncludeProperties id, description, tags, folder, codeRepository, iconSet, iconCode
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_oldValues' = '{}'
    $BodyMetaData.'_componentId' = 'WorkspaceCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'WorkspaceDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat ' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/workspace/create'
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
        Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] with parameters $parameters_display due to [$Message]."
        Break
    }
    If ($results.response.status -gt 0) {
        [string]$results_display = $response | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Workspace [$Id] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Workspace [$Id] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWWorkspace]$Workspace = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWWorkspace] object due to [$Message]."
        Break
    }        
    If ($Workspace.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWWorkspace] object is empty!"
        Break
    }
    Return $Workspace
}

Function Remove-AutomateNOWWorkspace {
    <#
    .SYNOPSIS
    Removes a Workspace from an AutomateNOW! instance
    
    .DESCRIPTION    
    Removes a Workspace from an AutomateNOW! instance
    
    .PARAMETER Workspace
    An [ANOWWorkspace] object representing the Workspace to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false
    
    .INPUTS
    ONLY [ANOWWorkspace] objects are accepted (including from the pipeline)
    
    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.
    
    .EXAMPLE
    Get-AutomateNOWWorkspace -Id 'Workspace01' | Remove-AutomateNOWWorkspace

    .EXAMPLE
    @( 'Workspace1', 'Workspace2', 'Workspace3') | Remove-AutomateNOWWorkspace

    .EXAMPLE
    Get-AutomateNOWWorkspace | ? { $_.simpleId -like 'test*' } | Remove-AutomateNOWWorkspace
        
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkspace]$Workspace,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/workspace/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Workspace.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Workspace_id = $_.id
                
            }
            ElseIf ($Workspace.id.Length -gt 0) {
                [string]$Workspace_id = $Workspace.id
            }
            Else {
                [string]$Workspace_id = $Id
            }
            [string]$Body = 'id=' + $Workspace_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workspace_id] due to [$Message]."
                Break
            }    
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Workspace $Workspace_id successfully removed"
        }
    }
    End {

    }
}

#endregion

#EndRegion