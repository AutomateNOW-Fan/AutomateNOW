$InformationPreference = 'Continue'

#Region Classes
Class ANOWAuditLogEntry {
    [Parameter(Mandatory = $true)]
    [string]$actionTimestamp
    [ValidateSet('UPDATE', 'INSERT', 'DELETE')]
    [Parameter(Mandatory = $true)]
    [string]$actionType
    [Parameter(Mandatory = $true)]
    [int64]$id
    [Parameter(Mandatory = $true)]
    [string]$objectId
    [Parameter(Mandatory = $true)]
    [string]$tableName
    [Parameter(Mandatory = $false)]
    [string]$userIp
    [Parameter(Mandatory = $false)]
    [string]$createdBy
    [Parameter(Mandatory = $false)]
    [string]$Domain
}

Class ANOWAuditLogEntry_Update : ANOWAuditLogEntry {
    [ValidateSet('UPDATE')]
    [Parameter(Mandatory = $true)]
    [string]$actionType
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$newValues
    [Parameter(Mandatory = $true)]
    [string]$newValuesText
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$oldValues
    [Parameter(Mandatory = $true)]
    [string]$oldValuesText
    ANOWAuditLogEntry_Update() { $this.Init(@{}) }
    ANOWAuditLogEntry_Update([hashtable]$Properties) { $this.Init($Properties) }
    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
    [string] ToString() {
        [string]$ConvertedAuditLogEntry = $this | ConvertTo-Json -Compress
        Return $ConvertedAuditLogEntry
    }
    [PSCustomObject[]] CompareOldNewValues() {
        [PSCustomObject]$ReferenceObject = $this.oldValues
        [PSCustomObject]$DifferenceObject = $this.newValues
        [PSCustomObject[]]$ComparisonObjects = Compare-ObjectProperty -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject | ForEach-Object { [PSCustomObject]@{PropertyName=$_.PropertyName; PreviousValue=$_.RefValue; NewValue=$_.DiffValue } }
        If ($ComparisonObjects.Count -gt 0) {
            Return $ComparisonObjects
        }
        Else {
            Throw "Compare-Object somehow failed to compare the old values against the new values in log entry [$($this.id)]"
        }
    }
}

Class ANOWAuditLogEntry_Delete : ANOWAuditLogEntry {
    [ValidateSet('DELETE')]
    [Parameter(Mandatory = $true)]
    [string]$actionType
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$oldValues
    [Parameter(Mandatory = $true)]
    [string]$oldValuesText

    # Default constructor
    ANOWAuditLogEntry_Update() { $this.Init(@{}) }
    # Convenience constructor from hashtable
    ANOWAuditLogEntry_Update([hashtable]$Properties) { $this.Init($Properties) }
    # Shared initializer method
    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

Class ANOWAuditLogEntry_Insert : ANOWAuditLogEntry {
    [ValidateSet('INSERT')]
    [Parameter(Mandatory = $true)]
    [string]$actionType
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$newValues
    [Parameter(Mandatory = $true)]
    [string]$newValuesText

    # Default constructor
    ANOWAuditLogEntry_Update() { $this.Init(@{}) }
    # Convenience constructor from hashtable
    ANOWAuditLogEntry_Update([hashtable]$Properties) { $this.Init($Properties) }
    # Shared initializer method
    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }        
}

Class AutomateNOWTimeZone {
    [string]$displayName
    [string]$id
    [int32]$rawOffset
    [int32]$dstsavings

    AutomateNOWTimeZone() { $this.Init(@{}) }
    
    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}

#EndRegion

#Region - Utilities
function Compare-ObjectProperty {
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
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object] $InputObjects,
        # URL encode parameter names
        [Parameter(Mandatory = $false)]
        [switch] $EncodeParameterNames
    )
    process {
        foreach ($InputObject in $InputObjects) {
            $QueryString = New-Object System.Text.StringBuilder
            if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.Specialized.OrderedDictionary] -or $InputObject.GetType().FullName.StartsWith('System.Collections.Generic.Dictionary')) {
                foreach ($Item in $InputObject.GetEnumerator()) {
                    if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                    [string] $ParameterName = $Item.Key
                    if ($EncodeParameterNames) { $ParameterName = [System.Net.WebUtility]::UrlEncode($ParameterName) }
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.Value))
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
}

#endregion

#Region - AdHoc Reports

Function Get-AutomateNOWAdhocReport {
    <#
    .SYNOPSIS
    Gets the Adhoc Report objects from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWAdhocReport` cmdlet gets the Adhoc Report objects from an instance of AutomateNOW!
    
    .PARAMETER startRow
    An optional int32 representing what row to start the download from. This is intended for multi-page transfers.

    .PARAMETER endRow
    An optional int32 representing how many rows of data to receive. The default is 2000. This is ideal for testing when you only want a few items.

    .PARAMETER sortBy
    Optional string parameter which defines the sorting order (default is by 'id'). Valid choices are: 'createdBy', 'dateCreated', 'description', 'domain', 'folder', 'id', 'lastUpdated', 'lastUpdatedBy', 'reportType', 'simpleId', 'tags'

    .PARAMETER Descending
    Optional switch parameter which changes the sort order from the default ascending to descending
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWAdhocReport.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWAdhocReport
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 2000,
        [ValidateSet('createdBy', 'dateCreated', 'description', 'domain', 'folder', 'id', 'lastUpdated', 'lastUpdatedBy', 'reportType', 'simpleId', 'tags', IgnoreCase = $false)]
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'id',
        [Parameter(Mandatory = $False)]
        [switch]$Descending
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/adhocReport/read'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    If ($Descending -eq $true) {
        [string]$sortBy = ('-' + $sortBy)
    }
    $BodyObject.Add('_sortBy', $sortBy)
    $BodyObject.Add('_textMatchStyle', 'exact')
    $BodyObject.Add('_componentId', 'AdhocReportList')
    $BodyObject.Add('_dataSource', 'AdhocReportDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject    
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
    [array]$AdhocReports = $results.response.data
    [int32]$AdhocReports_count = $AdhocReports.Count
    If ($AdhocReports_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 Adhoc reports..."
        Break
    }
    Return $AdhocReports
}

#EndRegion

#Region - AuditLog

Function Get-AutomateNOWAuditLog {
    <#
    .SYNOPSIS
    Gets the Audit log from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWAuditLog` cmdlet gets the Audit log from an instance of AutomateNOW!

    .PARAMETER startRow
    An optional int32 representing what row to start the download from. This is intended for multi-page transfers.

    .PARAMETER endRow
    An optional int32 representing how many rows of data to receive. The default is 2000. This is ideal for testing when you only want a few items.

    .PARAMETER Ascending
    Optional switch parameter which changes the sort order (of the actionTimestamp property) from the default descending to ascending

    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWAuditLog.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWAuditLog
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 200,
        [Parameter(Mandatory = $False)]
        [switch]$Ascending
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }    
    If ($endRow -lt $startRow) {
        Write-Warning -Message "The end row must be higher then the start row"
        Break
    }
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    If ($Ascending -ne $true) {
        $BodyObject.Add('_sortBy', '-actionTimestamp')
    }
    Else {
        $BodyObject.Add('_sortBy', 'actionTimestamp')
    }
    $BodyObject.Add('_textMatchStyle', 'substring')
    $BodyObject.Add('_componentId', 'AuditLogEventList')
    $BodyObject.Add('_dataSource', 'AuditLogDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject
    [string]$command = '/auditLog/read' + '?' + $Body # Note these parameters must be passed on the URL directly
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'GET')
    If ($Verbose -eq $true) {
        $parameters.Add('Verbose', $True)
    }
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
    $Error.Clear()
    Try {
        [array]$AuditLogs = ForEach($entry in $results.response.data)  { 
            Switch ($entry.actionType) {
                "UPDATE" { [ANOWAuditLogEntry_Update]$entry; Break }
                "INSERT" { [ANOWAuditLogEntry_Insert]$entry; Break }
                "DELETE" { [ANOWAuditLogEntry_Delete]$entry }
            }
        }
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "ForEach-Object failed due to parse the AuditLog entry due to [$Message]."
        Break
    }
    [int32]$AuditLogs_count = $AuditLogs.Count
    If ($AuditLogs_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 AuditLog entries. This can't be correct."
        Break
    }
    Return $AuditLogs
}

#EndRegion

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
    If ($anow_header.values.count -eq 0) {
        Write-Warning -Message "Please use Connect-AutomateNOW to establish your access token or provide your token through the -AccessToken parameter of Connect-AutomateNOW."
        Break
    }
    ElseIf ($anow_header.Authorization -notmatch '^Bearer [a-zA-Z-_/=:,."0-9]{1,}$') {
        [string]$malformed_token = $anow_header.values
        Write-Warning -Message "Somehow the access token is not in the expected format. Please contact the author with this apparently malformed token: [$malformed_token]"
        Break
    }
    ElseIf ($anow_header.domain.Length -eq 0 -and $IgnoreEmptyDomain -ne $true) {
        Write-Warning -Message 'Please use Switch-AutomateNOWDomain to switch your domain. Use Get-AutomateNOWDomains or include the -Domain parameter with Connect-AutomateNOW'
        Break
    }
    ElseIf ($anow_session.RefreshToken -eq 'Not set') {
        Write-Warning -Message 'This connection is without a refresh token! Please use -RefreshToken with Connect-AutomateNOW to include one.'
        Return $true
    }
    ElseIf ($anow_session.ExpirationDate -isnot [datetime]) {
        Write-Warning -Message 'Somehow there is no expiration date available. Please use Connect-AutomateNOW to establish your session properties.'
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
                Write-Warning -Message "This token expired [$DaysRemaining] days ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            ElseIf ($SecondsRemaining -lt -3600) {
                [int32]$HoursRemaining = ($SecondsRemaining / -3600)
                Write-Warning -Message "This token expired [$HoursRemaining] hours ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            ElseIf ($SecondsRemaining -lt -60) {
                [int32]$MinutesRemaining = ($SecondsRemaining / -60)
                Write-Warning -Message "This token expired [$MinutesRemaining] minutes ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
                Break    
            }
            Else {
                Write-Warning -Message "This token expired [$SecondsRemaining] seconds ago at [$ExpirationDateDisplay]. You can request a new token using Connect-AutomateNOW."
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

.PARAMETER User
Specifies the user connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it.

.PARAMETER Pass
Specifies the password for connecting to the API only if you want to enter it on the command line manually. If you do not specify this, you will be prompted for it.

.PARAMETER AccessToken
Specifies an access token manually. This is normally copy/pasted from your web browser. THIS IS OPTIONAL!

.PARAMETER RefreshToken
Specifies the refresh token manually. This is normally copy/pasted from your web browser. THIS IS OPTIONAL! You can use -AccessToken without this but it is better to include the refresh token as well for a fully functioning session without warnings.

.PARAMETER ExpirationDate
Int64 representing the current date in UNIX time milliseconds. THIS IS OPTIONAL! You can only use this in conjunction with -AccessToken. Hint: If the Unix timestamp is 13 digits in length, it has milliseconds. If it is 10 digits in length, it does not.

.PARAMETER ReadJSONFromClipboard
Switch parameter that read the Access Token, Refresh Token and Expiration Date from your clipboard. Normally, you would copy this from the response to your authentication request in your web browser. This is STRICTLY for your convenience. See notes below.

.PARAMETER Domain
Optional string to set the AutomateNOW domain manually. If you do not specify, then you will (likely) need to use Switch-AutomateNOWDomain

.PARAMETER NotSecure
Switch parameter to accomodate instances that use the http protocol (typically on port 8080)
    
.PARAMETER Quiet
Switch parameter to silence the extraneous output that this outputs by default

.PARAMETER SkipPreviousSessionCheck
Switch parameter to override the requirement to disconnect from a previous session before starting a new session on a different instance

.PARAMETER Key
Optional 16-byte array for when InfiniteDATA has changed their encryption key. Let's hope we don't need to use this :-)

.INPUTS
None. You cannot pipe objects to Connect-AutomateNOW (yet).

.OUTPUTS
There is no direct output. Rather, a global variable $anow_header with the bearer access token is set in the current powershell session.

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
1. The -User and -Pass parameters are NOT NEEDED. They do work but they are not recommended because your credential would be in the command line history. These 2 parameters were intended for convenience on InfiniteDATA training instances with generic logons. Simply do not include them to be prompted for the user/password. You may also skip the entering of passwords entirely by utilizing the -AccessToken and related parameters.
2. The -AccessToken does not require the -RefreshToken and -ExpirationDate values to function but you will not be able to refresh your token and you will not know when it expires.
3. Only use the -ReadJSONFromClipboard parameter if you are fully understanding and comfortable with this script reading a JSON payload from your clipboard.
4. This module will take care of refreshing the token automatically based on the -MaximumTokenRefreshAge parameter of Confirm-AutomateNOWSession (defaults to 3300 seconds meaning that the refresh happens if your token is older than 300 seconds but not eXpired yet)
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
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectCredential')]
        [string]$User,
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectCredential')]
        [string]$Pass,
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
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DirectCredential')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AccessToken')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Clipboard')]
        [string]$Domain,
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
        If ($NotSecure -eq $true) {
            [string]$protocol = 'http'
        }
        Else {
            [string]$protocol = 'https'
        }
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
    If ($null -ne $anow_header) {
        $Error.Clear()
        Try {
            Remove-Variable -Name anow_header -Scope Global -Force
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Remove-Variable failed to remove the `$anow_header variable due to [$Message]."
            Break
        }
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
                [string]$User = Read-Host -Prompt 'Please enter ldap username (e.g. jsmith1)'
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
                    [string]$Pass = Read-Host -Prompt 'Please enter the password (e.g. ********)' -MaskInput
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
                    [securestring]$SecurePass = Read-Host -Prompt 'Please enter the password (e.g. ********)' -AsSecureString
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
    [hashtable]$authorization_header = @{'Authorization' = "Bearer $access_token"; 'domain' = ''; }
    If ($Domain.Length -gt 0) {
        $authorization_header['domain'] = $Domain
    }
    $Error.Clear()
    Try {
        New-Variable -Name 'anow_header' -Scope Global -Value $authorization_header
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "New-Variable failed due to create the header globally due to [$Message]."
        Break
    }
    Write-Verbose -Message 'Global variable $anow_header has been set. Use this as your authentication header.'
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
            If ($Remaining_Time.TotalSeconds -le 1) {
                [datetime]$expiration_date = ($expiration_date_utc + $utc_offset) # We're adding 2 values here: the current time in UTC and the current machine's UTC offset
            }
            Else {
                Write-Warning -Message "Your token has expired. Please obtain a new one."
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
    If ($Domain.Length -gt 0) {
        $anow_session.Add('current_domain', $Domain)
    }
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
            If ($null -ne $anow_header.Domain) {
                $anow_header.Remove('domain')
            }
            If ($null -ne $anow_session.current_domain) {
                $anow_session.Remove('current_domain')
            }
            If ($null -ne $anow_session.domain) {
                $anow_session.Remove('domain')
            }
            $anow_header.Add('domain', $Domain)
            $anow_session.Add('current_domain', $Domain)
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
                $anow_header['domain'] = $Domain
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
        [PSCustomObject]$anow_session_display = [PSCustomObject]@{ instance = $instance; token_expires = $expiration_date; user = $userName; domain = $Domain; access_token = ($access_token.SubString(0, 5) + '...' + $access_token.SubString(($access_token.Length - 5), 5)) }
        Format-Table -InputObject $anow_session_display -AutoSize -Wrap
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
You should do this whenever you are finished with your session. This prevents your token (a.k.a. cookie) from being stolen.
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
            Remove-Variable -Name anow_header -Scope Global -Force
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Remove-Variable failed to remove the `$anow_header variable due to [$Message]."
            Break
        }
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
    Sets the password of the authenticated user of an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Set-AutomateNOWPassword` sets the password of the authenticated user of an AutomateNOW! instance
    
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

    Set-AutomateNOWPassword -Secure
    
    .NOTES
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
    $anow_header.'Authorization' = "Bearer $access_token"
    Write-Verbose -Message 'Global variable $anow_header has been set. Use this as your authentication header.'
    Write-Information -MessageData "Your token has been refreshed. The new expiration date is [$expiration_date_display]"
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
    If ($anow_header.values.count -eq 0 -or $anow_session.Instance.Length -eq 0) {
        Write-Warning -Message "Please use Connect-AutomateNOW to establish your access token."
        Break
    }
    ElseIf ($anow_header.Authorization -notmatch '^Bearer [a-zA-Z-_:,."0-9]{1,}$') {
        [string]$malformed_token = $anow_header.values
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
        $Headers.Add('domain', $anow_header.domain)
        $Headers.Add('Authorization', $anow_header.Authorization)
    }
    Else {
        $parameters.Add('Headers', $anow_header)
        <#
        If($anow_header.domain.Length -gt 0)
        {
            $Headers.Add('domain', $anow_header.domain)
        }
        #>
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
    #$ProgressPreference = 'SilentlyContinue'
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

#EndRegion

#Region - Calendars

Function Get-AutomateNOWCalendar {
    <#
    .SYNOPSIS
    Gets the calendar objects from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWCalendar` cmdlet gets the calendar objects from an instance of AutomateNOW!
    
    .PARAMETER startRow
    An optional int32 representing what row to start the download from. This is intended for multi-page transfers.

    .PARAMETER endRow
    An optional int32 representing how many rows of data to receive. The default is 2000. This is ideal for testing when you only want a few items.

    .PARAMETER sortBy
    Optional string parameter which defines the sorting order (default is by 'id'). Valid choices are: 'createdBy', 'dateCreated', 'id', 'lastUpdated', 'lastUpdatedBy', 'nextCloseDate', 'nextOpenDate', 'simpleId'

    .PARAMETER Descending
    Optional switch parameter which changes the sort order from the default ascending to descending
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWCalendar.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWCalendar
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'SortBy')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'SortBy')]
        [int32]$endRow = 2000,
        [ValidateSet('createdBy', 'dateCreated', 'id', 'lastUpdated', 'lastUpdatedBy', 'nextCloseDate', 'nextOpenDate', 'simpleId', IgnoreCase = $false)]
        [Parameter(Mandatory = $True, ParameterSetName = 'SortBy')]
        [string]$sortBy = 'id',
        [Parameter(Mandatory = $False, ParameterSetName = 'SortBy')]
        [switch]$Descending
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    
    [string]$command = '/resource/read'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_constructor', 'AdvancedCriteria')
    $BodyObject.Add('operator', 'and')
    $BodyObject.Add('_textMatchStyle', 'substring')
    $BodyObject.Add('_componentId', 'ResourceList')
    $BodyObject.Add('_dataSource', 'ResourceDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    $BodyObject.Add('criteria', '{"fieldName":"resourceType","operator":"equals","value":"CALENDAR"}')
    If ($Descending -eq $true) {
        [string]$sortBy = ('-' + $sortBy)
    }
    $BodyObject.Add('_sortBy', $sortBy)
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject    
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
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
    [array]$Calendars = $results.response.data
    [int32]$Calendars_count = $Calendars.Count
    If ($Calendars_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 calendars. Is there something else wrong? Was this instance recently built?"
        Break
    }
    Return $Calendars
}

#EndRegion

#Region - Domains

Function Get-AutomateNOWDomain {
    <#
    .SYNOPSIS
    Gets the details of the available domains from an AutomateNOW instance
    
    .DESCRIPTION    
    The `Get-AutomateNOWDomain` cmdlet invokes the /domain/read endpoint to retrieve information about the available domains on the instance of AutomateNOW that you are connected to
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWUser.
    
    .OUTPUTS
    An array of PSCustomObjects (1 for each available domain)
    
    .EXAMPLE
    Get-AutomateNOWDomain
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([array])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/domain/read'
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
    [PSCustomObject[]]$domains = $results.response.data
    [int32]$domain_count = $domains.Count
    If ($domain_count -eq 0) {
        Write-Warning -Message "Somehow there are no domains available. Please look into this..."
        Break
    }
    Return $domains
}

Function Show-AutomateNOWDomain {
    <#
    .SYNOPSIS
    Shows the details of the available domains from an AutomateNOW instance
    
    .DESCRIPTION    
    The `Show-AutomateNOWDomain` cmdlet invokes the Get-AutomateNOWDomain function to retrieve information about the available domains on the instance of AutomateNOW that you are connected to and to show them
    
    .INPUTS
    None. You cannot pipe objects to Show-AutomateNOWDomain.
    
    .OUTPUTS
    None except for Write-Information messages.
    
    .EXAMPLE
    Show-AutomateNOWDomain
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [PSCustomObject[]]$available_domains = Get-AutomateNOWDomain
    [string]$Instance = $anow_session.Instance
    [int32]$domain_count = $available_domains.Count
    If ($domain_count -gt 1) {
        [string]$available_domains_display = $available_domains.id -join ', '
        Write-Information -MessageData "The [$available_domains_display] domains are available on [$Instance]. Use Switch-AutomateNOWDomain to switch domains."
    }
    Else {
        [string]$available_domains_display = $available_domains.id
        Write-Information -MessageData "The [$available_domains_display] domain is available on [$Instance]."
    }
}

Function Switch-AutomateNOWDomain {
    <#
.SYNOPSIS
Switches the currently selected domain for the logged on user of an AutomateNOW! instance

.DESCRIPTION    
The `Switch-AutomateNOWDomain` cmdlet does not actually communicate with the AutomateNOW! instance. It modifies the $anow_session and $anow_header global variables.

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
        $anow_session.Remove('current_domain')
        $anow_session.Add('current_domain', $Domain)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "The Add/Remove method failed on `$anow_session` due to [$Message]."
        Break
    }
    $Error.Clear()
    Try {
        $anow_header.Remove('domain')
        $anow_header.Add('domain', $Domain)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "The Add/Remove method failed on `$anow_header` due to [$Message]."
        Break
    }
    Write-Information -MessageData "The [$Domain] domain has been selected for [$Instance]."
}

#EndRegion

#Region - Folders

Function Get-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Gets the folder objects from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWFolder` cmdlet gets the folder objects from an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWFolder.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWFolder
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/folder/read'
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
        [PSCustomObject]$response = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    If ($response.response.status -isnot [int64] -and $response.response.status -isnot [int32]) {
        # Yes, the API really does return back an int64
        [string]$parameters_display = $parameters | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow there was not a valid response to the [$command] command. Please look into this. Parameters: $parameters_display"
        Break
    }
    [int32]$response_code = $response.response.status
    If ($response_code -ne 0) {
        [string]$full_response_display = $response.response | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
    }
    [array]$folders = $response.response.data
    [int32]$folders_count = $folders.Count
    If ($folders_count -eq 0) {
        Write-Warning -Message "It appears there are zero folders created yet. Did you create this instance recently?"
    }
    If ($Quiet -ne $true) {
        Write-Information -MessageData "Returned the properties of all [$folders_count] folders"
    }
    Return $folders
}

Function New-AutomateNOWFolder {
    <#
    .SYNOPSIS
    Creates a new folder object in an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `New-AutomateNOWFolder` cmdlet creates a new folder object in an instance of AutomateNOW!
    
    .PARAMETER Id
    The name of the folder. For example: 'MyCoolFolder'

    .PARAMETER Description
    The description of the folder (may contain unicode characters). For example: 'My folder description'

    .PARAMETER Repository
    This parameter appears to be an error from the vendor, hence it is disabled here but included for reference.

    .PARAMETER Quiet
    Switch parameter that suppresses the output (which is the newly created folder object)
    
    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWFolder.
    
    .OUTPUTS
    A PSCustomObject representing the properties of the newly created folder
    
    .EXAMPLE
    New-AutomateNOWFolder
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$Repository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    If ($Repository.Length -gt 0) {
        Write-Warning -Message 'Unfortunately, it seems that associating a folder with a repository is broken. Hence, this parameter is disabled.'
        Break
    }
    If ($Id -notmatch '^[a-zA-Z0-9-._]{1,}$') {
        Write-Warning -Message 'The name of the folder may only consist of letters, numbers, underscores, periods (dot) and hyphens (dash). Please try again'
    }
    [string]$command = '/folder/create'
    [string]$Instance = $anow_session.Instance

    [string]$Id_Encoded = [System.Net.WebUtility]::UrlEncode($Id)

    [string]$Body = 'id=' + $Id_Encoded
    If ($Description.Length -gt 0) {
        [string]$Description_Encoded = [System.Net.WebUtility]::UrlEncode($Description)
        $Body = $Body + '&description=' + $Description_Encoded
    }
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Instance', $Instance)
    $parameters.Add('Body', $Body)
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    $Error.Clear()
    Try {
        [PSCustomObject]$response = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    If ($response.response.status -isnot [int64] -and $response.response.status -isnot [int32]) {
        # Yes, the API really does return back an int64
        [string]$parameters_display = $parameters | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow there was not a valid response to the [$command] command. Please look into this. Parameters: $parameters_display"
        Break
    }
    [int32]$response_code = $response.response.status
    If ($response_code -ne 0) {
        [string]$full_response_display = $response.response | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
    }
    [PSCustomObject[]]$folders = $response.response.data
    [int32]$folders_count = $folders.Count
    If ($folders_count -ne 1) {
        Write-Warning -Message "Somehow there was an error and folder [$id] was not created"
    }
    If ($Quiet -ne $true) {
        Write-Information -MessageData "Folder [$id] was created"
    }
    [PSCustomObject]$folder = $folders | Select-Object -First 1
    Return $folder
}

#endregion

#Region - Icons
Function Import-AutomateNOWIcon {
    <#
    .SYNOPSIS
    Imports the icon asset information from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Import-AutomateNOWIcon` function imports the icon asset information from an AutomateNOW! instance and makes it available for other functions (e.g. Export-AutomateNOWIcon)
    
    .INPUTS
    None. You cannot pipe objects to Import-AutomateNOWIcon.
    
    .OUTPUTS
    The output is set into the global variable anow_assets. A .csv file may optionally be created to capture the output.
    
    .PARAMETER Instance
    Specifies the name of the AutomateNOW! instance. For example: s2.infinitedata.com

    .PARAMETER ExportToFile
    Switch parameter which enables file export. The name of the file will be chosen automatically (e.g. Export-AutomateNOW-Icons-20251103121511.csv)

    .EXAMPLE
    Import-AutomateNOWIcon -Instance 'z4.infinitedata.com' -ExportToFile
    
    .NOTES
    You DO NOT need to authenticate to the instance to execute this function.

    This function is very much a work in progress. The output .csv does not open cleanly in Excel. To workaround this, open the file in Excel as a Text file as this will force the delimiter wizard. Choose tab as the delimiter and enable that the data has a header row and it will import cleanly into Excel.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [string]$Instance,
        [Parameter(Mandatory = $false)]
        [switch]$ExportToFile
    )
    Function Export-AutomateNOWIcon {
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
        [array]$IconNames_FatCow = Export-AutomateNOWIcon -assets_content $assets_content -Library 'FatCow' -first_icon_name '32_bit' -last_icon_name 'zootool'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Export-AutomateNOWIcon failed to extract the FatCow icons due to [$Message]"
        Break
    }
    $Error.Clear()
    Try {
        [array]$IconNames_Fugue = Export-AutomateNOWIcon -assets_content $assets_content -Library 'Fugue' -first_icon_name 'abacus' -last_icon_name 'zootool'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Export-AutomateNOWIcon failed to extract the Fugue icons due to [$Message]"
        Break
    }
    $Error.Clear()
    Try {
        [array]$IconNames_FontAwesome = Export-AutomateNOWIcon -assets_content $assets_content -Library 'FontAwesome' -first_icon_name '500px' -last_icon_name 'youtube-square'
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Export-AutomateNOWIcon failed to extract the FontAwesome icons due to [$Message]"
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
    [PSCustomObject]$icon_library = [PSCustomObject]@{ 'FatCow' = $IconNames_FatCow; 'FatCowCount' = $IconCount_FatCow; 'Fugue' = $IconNames_Fugue; 'FugueCount' = $IconCount_Fugue; 'FontAwesome' = $IconNames_FontAwesome; 'FontAwesomeCount' = $IconCount_FontAwesome; 'TotalCount' = $IconCount; }
    If ($null -ne $anow_assets.icon_library) {
        Remove-Variable -Name anow_assets -Force -Scope Global
    }
    $Error.Clear()
    Try {
        New-Variable -Name anow_assets -Scope Global -Value ([PSCustomObject]@{ icon_library = $icon_library; })
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "New-Variable failed due to create the header globally due to [$Message]."
        Break
    }
    Write-Verbose -Message 'Global variable $anow_assets has been set. Use this for asset resources.'
    If ($ExportToFile -eq $true) {
        [PSCustomObject[]]$ExportTableFatCow = ForEach ($Icon in $IconNames_FatCow) { [PSCustomObject]@{Library = 'FatCow'; Icon = $Icon; } }
        [PSCustomObject[]]$ExportTableFugue = ForEach ($Icon in $IconNames_Fugue) { [PSCustomObject]@{Library = 'Fugue'; Icon = $Icon; } }
        [PSCustomObject[]]$ExportTableFontAwesome = ForEach ($Icon in $IconNames_FontAwesome) { [PSCustomObject]@{Library = 'FontAwesome'; Icon = $Icon; } }
        [PSCustomObject[]]$DataToExport = ($ExportTableFatCow + $ExportTableFugue + $ExportTableFontAwesome)
        [int32]$DataToExportCount = $DataToExport.Count
        If ($DataToExportCount -eq 0) {
            Write-Warning -Message "Somehow there are zero icons to export. Please look into this."
            Break
        }
        $Error.Clear()
        Try {
            [array]$ConvertedData = $DataToExport | ConvertTo-CSV -Delimiter "`t" -NoTypeInformation
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "ConvertTo-CSV failed to convert the icon objects due to [$Message]"
            Break
        }
        [array]$FormattedData = $ConvertedData | ForEach-Object { $_ -replace '"' }
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Icons-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('FilePath', $ExportFilePath)
        [int32]$ps_version_major = $PSVersionTable.PSVersion.Major
        If ($ps_version_major -gt 5) {
            $parameters.Add('Encoding', 'utf8BOM')
        }
        Else {
            $parameters.Add('Encoding', 'UTF8')

        }
        $Error.Clear()
        Try {
            $FormattedData | Out-File @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Out-File failed to convert the icon objects due to [$Message]"
            Break
        }
        $Error.Clear()
        [System.IO.FileInfo]$fileinfo = Get-Item -Path "$ExportFilePath"
        [int32]$filelength = $fileinfo.Length
        [string]$filelength_display = "{0:N0}" -f $filelength
        Write-Information -MessageData "Created file $ExportFileName ($filelength_display bytes)"
    }
}

#EndRegion

#Region - Nodes
Function Get-AutomateNOWNode {
    <#
    .SYNOPSIS
    Gets the nodes of all domains from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Get-AutomateNOWNode` retrieves all of the nodes from the connected AutomateNOW! instance
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWNode.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWNode
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([array])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/serverNode'
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
    [PSCustomObject[]]$nodes = $results.response.data
    [int32]$nodes_count = $nodes.Count
    If ($nodes_count -eq 0) {
        Write-Warning -Message "Somehow there are no nodes available. Is this a newly installed instance which has not been configured yet?"
        Break
    }
    Return $nodes
}

#Endregion

#Region - Overview

Function Get-AutomateNOWOverview {
    <#
    .SYNOPSIS
    Gets the ?? objects from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWOverview` cmdlet gets the ?? objects from an instance of AutomateNOW!
    
    .PARAMETER startRow
    An optional int32 representing what row to start the download from. This is intended for multi-page transfers.

    .PARAMETER endRow
    An optional int32 representing how many rows of data to receive. The default is 2000. This is ideal for testing when you only want a few items.

    .PARAMETER sortBy
    Optional string parameter which defines the sorting order (default is by 'id'). Valid choices are: 'createdBy', 'dateCreated', 'id', 'lastUpdated', 'lastUpdatedBy', 'nextCloseDate', 'nextOpenDate', 'simpleId'

    .PARAMETER Descending
    Optional switch parameter which changes the sort order from the default ascending to descending
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWOverview.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWOverview
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 2000,
        [ValidateSet('agent', 'approvalPending', 'createdBy', 'critical', 'dateCreated', 'highRisk', 'id', 'lazyload', 'name', 'node', 'processingStatus', 'startTime', 'taskType', 'weight', IgnoreCase = $false)]
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'dateCreated',
        [Parameter(Mandatory = $False, ParameterSetName = 'SortBy')]
        [switch]$Descending
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/processing/read'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_constructor', 'AdvancedCriteria')
    $BodyObject.Add('operator', 'and')
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_operationId', 'ProcessingDataSource_fetch')
    $BodyObject.Add('_textMatchStyle', 'exact')
    $BodyObject.Add('_componentId', 'ProcessingTreeGrid')
    $BodyObject.Add('_dataSource', 'ProcessingDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    $BodyObject.Add('criteria1', '{"_constructor":"AdvancedCriteria","operator":"and","criteria":[{"fieldName":"archived","operator":"equals","value":false},{"fieldName":"isProcessing","operator":"equals","value":true},{"fieldName":"isRoot","operator":"equals","value":true}]}')
    $BodyObject.Add('criteria2', '{"fieldName":"parent","value":null,"operator":"equals"}')
    If ($Descending -eq $true) {
        [string]$sortBy = ('-' + $sortBy)
    }
    $BodyObject.Add('_sortBy', $sortBy)
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject    
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
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
    [array]$Items = $results.response.data
    [int32]$Items_count = $Items.Count
    If ($Items_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 items in the Processing Overview. Is there something else wrong? Was this instance recently built?"
        Break
    }
    Return $Items
}

#EndRegion

#Region - Tags
Function New-AutomateNOWTag {
    <#
    .SYNOPSIS
    Creates a new tag on an AutomateNOW! instance
    
    .DESCRIPTION    
    The `New-AutomateNOWTag` function creates a new tag on an AutomateNOW! instance.
    
    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWTag.
    
    .OUTPUTS
    A PSCustomObject representing the newly created tag
    
    .PARAMETER id
    The intended name of the tag. For example: 'MyCoolTag'

    .PARAMETER description
    The description of the tag. This parameter is not required. For example: 'My cool tag description'

    .PARAMETER iconSet
    The name of the icon library (if you choose to use one). Possible choices are: FatCow, Fugue, FontAwesome

    .PARAMETER iconCode
    The name of the icon which matches the chosen library.

    .PARAMETER textColor
    The RGB in hex of the tag's foreground (text) color. For example: FFFFFF (note there is no # symbol) or the word 'transparent'

    .PARAMETER backgroundColor
    The RGB in hex of the tag's background color. For example: A0A0A0 (note there is no # symbol)

    .EXAMPLE
    New-AutomateNOWTag -id 'MyCoolTag123' -description 'My tags description' -iconSet 'Fugue' -IconCode 'abacus' -textColor '0A0A0A' -backgroundColor 'F0F0F0' or the word 'transparent'
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$id,
        [Parameter(Mandatory = $false)]
        [string]$description = '',
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateSet('FatCow', 'Fugue', 'FontAwesome')]
        [string]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [string]$iconCode,
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateScript( { $_ -match '[0-9A-F]{6}' -or $_ -eq 'transparent' } ) ]
        [string]$textColor = 'FFFFFF',
        [Parameter(Mandatory = $true, ParameterSetName = 'WithIcon')]
        [ValidateScript( { $_ -match '[0-9A-F]{6}' -or $_ -eq 'transparent' } ) ]
        [string]$backgroundColor = 'FF0000'

    )
    If ($id.Length -eq 0) {
        Write-Warning -Message "The Id must be at least 1 character in length. Please try again."
        Break
    }
    If (($iconSet.Length -gt 0) -and ($iconCode.Length -eq 0)) {
        Write-Warning -Message "If you specify an icon library then you must also specify an icon"
        Break
    }
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is no global session token"
        Break
    }
    [string]$iconSet = Switch ($iconSet) {
        'FatCow' { 'FAT_COW'; Break }
        'Fegue' { 'FEGUE'; Break }
        'FontAwesome' { 'FONT_AWESOME'; Break }
        'Default' { '' }
    }
    [string]$command = '/tag/create'
    
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    If ($textColor -ne 'transparent') {
        $textColor = ('#' + $textColor)
    }
    If ($backgroundColor -ne 'transparent') {
        $backgroundColor = ('#' + $backgroundColor)
    }
    $BodyObject.Add('textColor', $textColor)
    $BodyObject.Add('backgroundColor', $backgroundColor)
    $BodyObject.Add('id', $id)
    $BodyObject.Add('description', $description)
    $BodyObject.Add('iconSet', $iconSet)
    $BodyObject.Add('iconCode', $iconCode)
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject
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
        [PSCustomObject]$response = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to [$Message]"
    }
    If ($response.response.status -isnot [int64] -and $response.response.status -isnot [int32]) {
        # Yes, the API really does return back an int64
        [string]$parameters_display = $parameters | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow there was not a valid response to the [$command] command. Please look into this. Parameters: $parameters_display"
        Break
    }
    [int32]$response_code = $response.response.status
    If ($response_code -ne 0) {
        [string]$full_response_display = $response.response | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow the response code was not 0 but was $response_code. Please look into this. Body: $full_response_display"
    }
    [PSCustomObject]$tag_data = $response.response.data
    [string]$tag_display = $tag_data | ConvertTo-Json -Compress
    Write-Verbose -Message "Created tag: $tag_display"
    Return $tag_data
}

Function Get-AutomateNOWTag {
    <#
    .SYNOPSIS
    Gets the tags of all domains from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Get-AutomateNOWTag` function retrieves all of the tags from the connected AutomateNOW! instance
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWTag.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWTag
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([array])]
    [Cmdletbinding()]
    Param(
    )
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
    [PSCustomObject[]]$Tags = $results.response.data
    [int32]$Tags_count = $Tags.Count
    If ($Tags_count -eq 0) {
        Write-Warning -Message "Somehow there are no tags available. Was this instance just created 5 minutes ago?"
        Break
    }
    Return $Tags
}

Function Remove-AutomateNOWTag {
    <#
    .SYNOPSIS
    Removes one tag from an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Remove-AutomateNOWTag` function removes one tag from an AutomateNOW! instance
    
    .PARAMETER Id
    The Id of the tag to delete. You can specify like this: -Id 'MyCoolTag' -Domain 'Training' or omit the -Domain parameter and format the Id yourself with -Id '[Training]MyCoolTag'
    
    .PARAMETER Domain
    The domain of the instance you are removing the tag from. If you do not include the domain here then you must include it with the -Id parameter in the excepted format.

    .PARAMETER Quiet
    Use this switch to silently remove the tag without any confirmation that it was successful. This is ideal for batch operations.

    .INPUTS
    `Remove-AutomateNOWTag` accepts pipeline input on the Id parameter
    
    .OUTPUTS
    None. The status will be written to the console with Write-Information.
    
    .EXAMPLE
    Remove-AutomateNOWTag -Id @('[Training]MyCoolTag123', '[Training]MyCoolTag456')
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([array])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$Id,
        [Parameter(Mandatory = $false)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    If ($Id -match '^(\s.{1,}|.{1,}\s)$') {
        Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Id]. Please fix this."
        Break
    }
    ElseIf ($Domain -match '^(\s.{1,}|.{1,}\s)$') {
        Write-Warning -Message "You seem to have whitespace characters in the beginning or end of [$Domain]. Please fix this."
        Break
    }
    If ($Id -notmatch '[.{1,}].{1,}') {
        If ($Domain.Length -eq 0) {
            Write-Warning -Message "You must include the domain either in the Id (e.g. -Id '[Training]MyCoolTag') or with the -Domain parameter (e.g. -Domain 'Training' -Id 'MyCoolTag'). Please try again."
            Break
        }
        Else {
            [string]$Id = ('[' + $Domain + "]$Id")
        }
    }
    [string]$command = '/tag/delete'
    [string]$Body = 'id=' + $id
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
    $parameters.Add('Body', $Body)
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
    If ($anow_session.NotSecure -eq $true) {
        $parameters.Add('NotSecure', $true)
    }    
    $Error.Clear()
    Try {
        [PSCustomObject]$response = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] on [$Id] due to [$Message]."
        Break
    }
    
    If ($response.response.status -isnot [int64] -and $response.response.status -isnot [int32]) {
        # Yes, the API really does return back an int64
        [string]$parameters_display = $parameters | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow there was not a valid response to the [$command] command. Please look into this. Parameters: $parameters_display"
        Break
    }
    [int32]$response_code = $response.response.status
    If ($response_code -ne 0) {
        [string]$full_response_display = $response.response | ConvertTo-Json -Compress
        Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
    }
    If ($Quiet -ne $true) {
        Write-Information -MessageData "Tag $Id successfully deleted"
    }
    
}

#EndRegion

#Region - Tasks

Function Show-AutomateNOWTaskType {
    <#
    .SYNOPSIS
    Shows the available task types from an instance of AutomateNOW! (this was statically coded!)
    
    .DESCRIPTION    
    The `Show-AutomateNOWTaskType` cmdlet gets the tasks from an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Show-AutomateNOWTaskType.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Show-AutomateNOWTaskType | Select-String -Pattern "PowerShell"
    
    .NOTES
    This is a stand-alone function which does not require connectivity to the AutomateNOW! console

    There are no parameters yet for this function (yet)
    #>
    [PSCustomObject]$TaskTypesJson = '[{"processingType":"TASK","id":"TASK","name":"Task","icon":"skin/service.png","folder":true},{"folder":true,"id":"CODE","icon":"skin/terminal.gif","name":"Code","parent":"TASK"},{"id":"FILE_PROCESSING","name":"File Processing","icon":"skin/drive-network.png","folder":true,"processingType":"TASK","parent":"TASK"},{"folder":true,"id":"SQL","icon":"skin/database-sql.png","name":"SQL Database","parent":"TASK"},{"folder":true,"id":"NO_SQL","icon":"skin/database-gear.png","name":"NoSQL Database","parent":"TASK"},{"folder":true,"id":"MESSAGE_QUEUE","icon":"skin/queue.png","name":"Message Queue","parent":"TASK"},{"processingType":"TASK","taskType":"SH","id":"SH","icon":"skin/terminal.gif","name":"Shell Task","parent":"CODE"},{"processingType":"TASK","taskType":"AE_SHELL_SCRIPT","id":"AE_SHELL_SCRIPT","icon":"skin/terminal.gif","name":"AE Shell Task","parent":"CODE"},{"processingType":"TASK","taskType":"PYTHON","id":"PYTHON","icon":"skin/python.png","name":"Python Task","parent":"CODE"},{"processingType":"TASK","taskType":"PERL","id":"PERL","icon":"skin/perl.png","name":"Perl Task","parent":"CODE"},{"processingType":"TASK","taskType":"RUBY","id":"RUBY","icon":"skin/ruby.png","name":"Ruby Task","parent":"CODE"},{"processingType":"TASK","taskType":"GROOVY","id":"GROOVY","icon":"skin/groovy.png","name":"Groovy Task","parent":"CODE"},{"processingType":"TASK","taskType":"POWERSHELL","id":"POWERSHELL","icon":"skin/powershell.png","name":"PowerShell Task","parent":"CODE"},{"processingType":"TASK","id":"JAVA","taskType":"JAVA","name":"Java Task","icon":"skin/java.png","parent":"CODE"},{"processingType":"TASK","id":"SCALA","taskType":"SCALA","name":"Scala Task","icon":"skin/scala.png","parent":"CODE"},{"folder":true,"id":"Z_OS","icon":"skin/zos.png","name":"z/OS","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"Z_OS_DYNAMIC_JCL","id":"Z_OS_DYNAMIC_JCL","icon":"skin/zos.png","name":"z/OS Dynamic JCL","parent":"Z_OS"},{"processingType":"TASK","taskType":"Z_OS_STORED_JCL","id":"Z_OS_STORED_JCL","icon":"skin/zos.png","name":"z/OS Stored JCL","parent":"Z_OS"},{"processingType":"TASK","taskType":"Z_OS_COMMAND","id":"Z_OS_COMMAND","icon":"skin/zos.png","name":"z/OS Command","parent":"Z_OS"},{"folder":true,"id":"AS_400","icon":"skin/ibm_as400.gif","name":"AS/400","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"AS400_BATCH_JOB","id":"AS400_BATCH_JOB","icon":"skin/ibm_as400.gif","name":"AS/400 Batch Job","parent":"AS_400"},{"processingType":"TASK","taskType":"AS400_PROGRAM_CALL","id":"AS400_PROGRAM_CALL","icon":"skin/ibm_as400.gif","name":"AS/400 Program Call","parent":"AS_400"},{"folder":true,"id":"RAINCODE_JCL","icon":"skin/raincode.ico","name":"Raincode JCL","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"RAINCODE_DYNAMIC_JCL","id":"RAINCODE_DYNAMIC_JCL","icon":"skin/raincode.ico","name":"Raincode Dynamic JCL","parent":"RAINCODE_JCL"},{"processingType":"TASK","taskType":"RAINCODE_STORED_JCL","id":"RAINCODE_STORED_JCL","icon":"skin/raincode.ico","name":"Raincode Stored JCL","parent":"RAINCODE_JCL"},{"folder":true,"id":"OPENTEXT","icon":"skin/microfocus.png","name":"OpenText JCL","parent":"IBM_SERIES"},{"processingType":"TASK","taskType":"OPENTEXT_DYNAMIC_JCL","id":"OPENTEXT_DYNAMIC_JCL","icon":"skin/microfocus.png","name":"OpenText Dynamic JCL","parent":"OPENTEXT"},{"processingType":"TASK","taskType":"OPENTEXT_STORED_JCL","id":"OPENTEXT_STORED_JCL","icon":"skin/microfocus.png","name":"OpenText Stored JCL","parent":"OPENTEXT"},{"processingType":"TASK","taskType":"RDBMS_STORED_PROCEDURE","id":"RDBMS_STORED_PROCEDURE","icon":"skin/database-gear.png","name":"Stored Procedure Call","parent":"SQL"},{"processingType":"TASK","taskType":"RDBMS_SQL_STATEMENT","id":"RDBMS_SQL_STATEMENT","icon":"skin/database_search.png","name":"RDBMS SQL Statement","parent":"SQL"},{"processingType":"TASK","taskType":"RDBMS_SQL","id":"RDBMS_SQL","icon":"skin/database-sql.png","name":"SQL Script","parent":"SQL"},{"folder":true,"id":"BIG_DATA","icon":"skin/database-gear.png","name":"Big Data","parent":"TASK"},{"folder":true,"id":"REDIS","icon":"skin/redis.png","name":"Redis","parent":"NO_SQL"},{"processingType":"TASK","taskType":"REDIS_SET","id":"REDIS_SET","icon":"skin/redis.png","name":"Redis Set","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_GET","id":"REDIS_GET","icon":"skin/redis.png","name":"Redis Get","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_DELETE","id":"REDIS_DELETE","icon":"skin/redis.png","name":"Redis Delete","parent":"REDIS"},{"processingType":"TASK","taskType":"REDIS_CLI","id":"REDIS_CLI","icon":"skin/redis.png","name":"Redis Command","parent":"REDIS"},{"processingType":"TASK","id":"HDFS","name":"HDFS","icon":"skin/hadoop.png","parent":"BIG_DATA","folder":true},{"processingType":"TASK","id":"HDFS_UPLOAD_FILE","taskType":"HDFS_UPLOAD_FILE","name":"HDFS Upload File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_APPEND_FILE","taskType":"HDFS_APPEND_FILE","name":"HDFS Append File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DOWNLOAD_FILE","taskType":"HDFS_DOWNLOAD_FILE","name":"HDFS Download File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DELETE_FILE","taskType":"HDFS_DELETE_FILE","name":"HDFS Delete File","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_CREATE_DIRECTORY","taskType":"HDFS_CREATE_DIRECTORY","name":"HDFS Create Directory","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_DELETE_DIRECTORY","taskType":"HDFS_DELETE_DIRECTORY","name":"HDFS Delete Directory","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HDFS_RENAME","taskType":"HDFS_RENAME","name":"HDFS Rename","icon":"skin/hadoop.png","parent":"HDFS"},{"processingType":"TASK","id":"HIVE","name":"Hive","icon":"skin/hive.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"IMPALA","name":"Impala","icon":"skin/impala.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SQOOP","name":"Sqoop","icon":"skin/sqoop.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"YARN","name":"Yarn","icon":"skin/hadoop.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SPARK","name":"Spark","icon":"skin/spark.png","parent":"BIG_DATA","folder":"hideInactiveFeatures"},{"id":"SPARK_JAVA","taskType":"SPARK_JAVA","name":"Spark Java Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_SCALA","taskType":"SPARK_SCALA","name":"Spark Scala Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_PYTHON","taskType":"SPARK_PYTHON","name":"Spark Python Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_R","taskType":"SPARK_R","name":"Spark R Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"id":"SPARK_SQL","taskType":"SPARK_SQL","name":"Spark SQL Job","icon":"skin/spark.png","parent":"SPARK","processingType":"TASK"},{"processingType":"TASK","id":"FLUME","name":"Flume","icon":"skin/flume.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"FLINK","name":"Flink","icon":"skin/flink.jpg ","parent":"BIG_DATA","folder":"hideInactiveFeatures"},{"processingType":"TASK","id":"FLINK_RUN_JOB","taskType":"FLINK_RUN_JOB","name":"Flink Run Job","icon":"skin/flink.jpg","parent":"FLINK"},{"processingType":"TASK","id":"FLINK_JAR_UPLOAD","taskType":"FLINK_JAR_UPLOAD","name":"Flink Upload Jar","icon":"skin/flink.jpg","parent":"FLINK"},{"processingType":"TASK","id":"FLINK_JAR_DELETE","taskType":"FLINK_JAR_DELETE","name":"Flink Delete Jar","icon":"skin/flink.jpg","parent":"FLINK"},{"id":"STORM","name":"Storm","icon":"skin/storm.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"OOZIE","name":"Oozie","icon":"skin/oozie.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"AMBARI","name":"Ambari","icon":"skin/ambari.png","parent":"BIG_DATA","inactive":"hideInactiveFeatures"},{"id":"MONGO_DB","name":"Mongo DB","icon":"skin/mongodb.gif","parent":"NO_SQL","folder":true},{"id":"MONGO_DB_INSERT","name":"Mongo DB Insert Document","icon":"skin/mongodb.gif","parent":"MONGO_DB","processingType":"TASK","taskType":"MONGO_DB_INSERT"},{"id":"IBM_MQ","icon":"skin/ibm_mq.png","name":"IBM MQ","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"IBM_MQ_SEND","id":"IBM_MQ_SEND","icon":"skin/ibm_mq.png","name":"Send IBM MQ Message","parent":"IBM_MQ"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"IBM_MQ_SENSOR","id":"IBM_MQ_SENSOR","icon":"skin/ibm_mq.png","name":"IBM MQ Sensor","parent":"IBM_MQ"},{"id":"RABBIT_MQ","name":"RabbitMQ","icon":"skin/rabbitmq.png","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"RABBIT_MQ_SEND","id":"RABBIT_MQ_SEND","name":"Send RabbitMQ Message","icon":"skin/rabbitmq.png","parent":"RABBIT_MQ"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"RABBIT_MQ_SENSOR","id":"RABBIT_MQ_SENSOR","icon":"skin/rabbitmq.png","name":"RabbitMQ Message Sensor","parent":"RABBIT_MQ"},{"id":"KAFKA","name":"Kafka","icon":"skin/kafka.png","parent":"MESSAGE_QUEUE"},{"processingType":"TASK","taskType":"KAFKA_SEND","id":"KAFKA_SEND","name":"Send Kafka Message","icon":"skin/kafka.png","parent":"KAFKA"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"KAFKA_SENSOR","id":"KAFKA_SENSOR","icon":"skin/kafka.png","name":"Kafka Message Sensor","parent":"KAFKA"},{"processingType":"TASK","taskType":"JMS","id":"JMS","icon":"skin/java.png","name":"JMS","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"JMS_SEND","id":"JMS_SEND","icon":"skin/java.png","name":"Send JMS Message","parent":"JMS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"JMS_SENSOR","id":"JMS_SENSOR","icon":"skin/java.png","name":"JMS Sensor","parent":"JMS"},{"processingType":"TASK","id":"AMQP","icon":"skin/amqp.ico","name":"AMQP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"AMQP_SEND","id":"AMQP_SEND","icon":"skin/amqp.ico","name":"Send AMQP Message","parent":"AMQP"},{"processingType":"TASK","id":"MQTT","icon":"skin/mqtt.png","name":"MQTT","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"MQTT_SEND","id":"MQTT_SEND","icon":"skin/mqtt.png","name":"Send MQTT Message","parent":"MQTT"},{"id":"XMPP","icon":"skin/xmpp.png","name":"XMPP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"XMPP_SEND","id":"XMPP_SEND","icon":"skin/xmpp.png","name":"Send XMPP Message","parent":"XMPP"},{"id":"STOMP","icon":"skin/shoe.png","name":"STOMP","parent":"MESSAGE_QUEUE","folder":true},{"processingType":"TASK","taskType":"STOMP_SEND","id":"STOMP_SEND","icon":"skin/shoe.png","name":"Send STOMP Message","parent":"STOMP"},{"processingType":"TASK","taskType":"FILE_TRANSFER","id":"FILE_TRANSFER","icon":"skin/drive-network.png","name":"File Transfer","parent":"FILE_PROCESSING"},{"processingType":"TASK","taskType":"XFTP_COMMAND","id":"XFTP_COMMAND","icon":"skin/drive-network.png","name":"XFTP Command","parent":"FILE_PROCESSING"},{"id":"DATASOURCE_FILE","name":"Data Source","icon":"skin/drive-network.png","folder":true,"parent":"FILE_PROCESSING"},{"id":"DATASOURCE_UPLOAD_FILE","processingType":"TASK","taskType":"DATASOURCE_UPLOAD_FILE","name":"Upload File to Data Source","icon":"skin/drive-upload.png","parent":"DATASOURCE_FILE"},{"id":"DATASOURCE_DOWNLOAD_FILE","processingType":"TASK","taskType":"DATASOURCE_DOWNLOAD_FILE","name":"Download File from Data Source","icon":"skin/drive-download.png","parent":"DATASOURCE_FILE"},{"id":"DATASOURCE_DELETE_FILE","processingType":"TASK","taskType":"DATASOURCE_DELETE_FILE","name":"Delete File from Data Source","icon":"skin/drive_delete.png","parent":"DATASOURCE_FILE"},{"folder":true,"id":"WEB","icon":"skin/world.png","name":"Web","parent":"TASK"},{"folder":true,"id":"EMAIL","icon":"skin/mail.png","name":"Email","parent":"TASK"},{"folder":true,"id":"IBM_SERIES","icon":"skin/ibm.png","name":"IBM Series","parent":"TASK"},{"processingType":"TASK","taskType":"HTTP_REQUEST","id":"HTTP_REQUEST","icon":"skin/http.png","name":"HTTP Request","parent":"WEB"},{"processingType":"TASK","taskType":"REST_WEB_SERVICE_CALL","id":"REST_WEB_SERVICE_CALL","icon":"skin/rest.png","name":"REST Web Service Call","parent":"WEB"},{"processingType":"TASK","taskType":"SOAP_WEB_SERVICE_CALL","id":"SOAP_WEB_SERVICE_CALL","icon":"skin/soap.png","name":"SOAP Web Service Call","parent":"WEB"},{"processingType":"TASK","taskType":"EMAIL_SEND","id":"EMAIL_SEND","icon":"skin/mail.png","name":"Send Email","parent":"EMAIL"},{"processingType":"TASK","taskType":"EMAIL_CONFIRMATION","id":"EMAIL_CONFIRMATION","icon":"skin/mail--pencil.png","name":"Email Confirmation","parent":"EMAIL"},{"processingType":"TASK","taskType":"EMAIL_INPUT","id":"EMAIL_INPUT","icon":"skin/mail-open-table.png","name":"Email Input","parent":"EMAIL"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"EMAIL_SENSOR","id":"EMAIL_SENSOR","icon":"skin/mail.png","name":"Email Sensor","parent":"EMAIL"},{"id":"CLOUD_SERVICES","name":"Cloud Services","icon":"skin/cloud.png","folder":true,"parent":"TASK"},{"id":"AWS","name":"Amazon Web Services","icon":"skin/aws.png","parent":"CLOUD_SERVICES","folder":true},{"id":"AWS_GLUE","name":"Amazon Glue","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_GLUE_WORKFLOW","processingType":"TASK","taskType":"AWS_GLUE_WORKFLOW","name":"AWS Glue Workflow","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_TRIGGER","processingType":"TASK","taskType":"AWS_GLUE_TRIGGER","name":"AWS Glue Trigger","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_CRAWLER","processingType":"TASK","taskType":"AWS_GLUE_CRAWLER","name":"AWS Glue Crawler","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_GLUE_JOB","processingType":"TASK","taskType":"AWS_GLUE_JOB","name":"AWS Glue Job","icon":"skin/aws.png","parent":"AWS_GLUE"},{"id":"AWS_EMR","name":"Amazon EMR","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_EMR_WORKFLOW","processingType":"TASK","taskType":"AWS_EMR_WORKFLOW","name":"AWS EMR Workflow","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_ADD_STEPS","processingType":"TASK","taskType":"AWS_EMR_ADD_STEPS","name":"AWS EMR Add Steps","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_CANCEL_STEPS","processingType":"TASK","taskType":"AWS_EMR_CANCEL_STEPS","name":"AWS EMR Cancel Steps","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_TERMINATE_JOB_FLOW","processingType":"TASK","taskType":"AWS_EMR_TERMINATE_JOB_FLOW","name":"AWS EMR Terminate Job Flow","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_CONTAINER_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_CONTAINER_MONITOR","name":"AWS EMR Container Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_JOB_FLOW_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_JOB_FLOW_MONITOR","name":"AWS EMR Job Flow Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_STEP_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_STEP_MONITOR","name":"AWS EMR Step Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_NOTEBOOK_MONITOR","processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AWS_EMR_NOTEBOOK_MONITOR","name":"AWS EMR Notebook Monitor","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_PUT","processingType":"TASK","taskType":"AWS_EMR_PUT","name":"AWS EMR Put","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_GET","processingType":"TASK","taskType":"AWS_EMR_GET","name":"AWS EMR Get","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_START_NOTEBOOK_EXECUTION","processingType":"TASK","taskType":"AWS_EMR_START_NOTEBOOK_EXECUTION","name":"AWS EMR Start Notebook Execution","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_STOP_NOTEBOOK_EXECUTION","processingType":"TASK","taskType":"AWS_EMR_STOP_NOTEBOOK_EXECUTION","name":"AWS EMR Stop Notebook Execution","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_EMR_API_COMMAND","processingType":"TASK","taskType":"AWS_EMR_API_COMMAND","name":"AWS EMR API Command","icon":"skin/aws.png","parent":"AWS_EMR"},{"id":"AWS_SAGE_MAKER","name":"Amazon SageMaker","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_SAGE_MAKER_ADD_MODEL","processingType":"TASK","taskType":"AWS_SAGE_MAKER_ADD_MODEL","name":"AWS SageMaker Add Model","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_DELETE_MODEL","processingType":"TASK","taskType":"AWS_SAGE_MAKER_DELETE_MODEL","name":"AWS SageMaker Delete Model","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_PROCESSING","processingType":"TASK","taskType":"AWS_SAGE_MAKER_PROCESSING","name":"AWS SageMaker Processing","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_TRAINING","processingType":"TASK","taskType":"AWS_SAGE_MAKER_TRAINING","name":"AWS SageMaker Training","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_TRANSFORM","processingType":"TASK","taskType":"AWS_SAGE_MAKER_TRANSFORM","name":"AWS SageMaker Transform","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_SAGE_MAKER_API_COMMAND","processingType":"TASK","taskType":"AWS_SAGE_MAKER_API_COMMAND","name":"AWS SageMaker API Command","icon":"skin/aws.png","parent":"AWS_SAGE_MAKER"},{"id":"AWS_LAMBDA","name":"AWS Lambda","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_LAMBDA_INVOKE","name":"AWS Lambda Invoke","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_INVOKE"},{"id":"AWS_LAMBDA_CREATE_FUNCTION","name":"AWS Lambda Create Function","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_CREATE_FUNCTION"},{"id":"AWS_LAMBDA_DELETE_FUNCTION","name":"AWS Lambda Delete Function","icon":"skin/aws.png","parent":"AWS_LAMBDA","processingType":"TASK","taskType":"AWS_LAMBDA_DELETE_FUNCTION"},{"id":"AWS_EC2","name":"AWS EC2","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_EC2_START_INSTANCE","name":"AWS EC2 Start   Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_START_INSTANCE"},{"id":"AWS_EC2_STOP_INSTANCE","name":"AWS EC2 Stop Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_STOP_INSTANCE"},{"id":"AWS_EC2_TERMINATE_INSTANCE","name":"AWS EC2 Terminate Instance","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_TERMINATE_INSTANCE"},{"id":"AWS_EC2_DELETE_VOLUME","name":"AWS EC2 Delete Volume","icon":"skin/aws.png","parent":"AWS_EC2","processingType":"TASK","taskType":"AWS_EC2_DELETE_VOLUME"},{"id":"AWS_S3","name":"AWS S3","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_S3_DELETE_OBJECT","name":"AWS S3 Delete Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_DELETE_OBJECT"},{"id":"AWS_S3_COPY_OBJECT","name":"AWS S3 Copy Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_COPY_OBJECT"},{"id":"AWS_S3_MOVE_OBJECT","name":"AWS S3 Move Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_MOVE_OBJECT"},{"id":"AWS_S3_RENAME_OBJECT","name":"AWS S3 Rename Object","icon":"skin/aws.png","parent":"AWS_S3","processingType":"TASK","taskType":"AWS_S3_RENAME_OBJECT"},{"id":"AWS_BATCH","name":"AWS Batch","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_BATCH_JOB","name":"AWS Batch Job","icon":"skin/aws.png","parent":"AWS_BATCH","processingType":"TASK","taskType":"AWS_BATCH_JOB"},{"id":"AWS_STEP_FUNCTIONS","name":"AWS Step Functions","icon":"skin/aws.png","parent":"AWS","folder":true},{"id":"AWS_START_STEP_FUNCTION_STATE_MACHINE","name":"AWS Start Step Function State Machine","icon":"skin/aws.png","parent":"AWS_STEP_FUNCTIONS","processingType":"TASK","taskType":"AWS_START_STEP_FUNCTION_STATE_MACHINE"},{"id":"AZURE","name":"Azure","icon":"skin/azure.png","parent":"CLOUD_SERVICES","folder":true,"processingType":"TASK"},{"id":"AZURE_DATA_FACTORY","name":"Azure Data Factory","icon":"skin/azure.png","parent":"AZURE","folder":true,"processingType":"TASK"},{"id":"AZURE_DATA_FACTORY_TRIGGER","processingType":"TASK","taskType":"AZURE_DATA_FACTORY_TRIGGER","name":"Azure Data Factory Trigger","icon":"skin/azure.png","parent":"AZURE_DATA_FACTORY"},{"id":"AZURE_DATA_FACTORY_PIPELINE","processingType":"TASK","taskType":"AZURE_DATA_FACTORY_PIPELINE","name":"Azure Data Factory Pipeline","icon":"skin/azure.png","parent":"AZURE_DATA_FACTORY"},{"id":"AZURE_DATA_LAKE_JOB","processingType":"TASK","taskType":"AZURE_DATA_LAKE_JOB","name":"Azure Data Lake Job","icon":"skin/azure.png","parent":"AZURE"},{"id":"AZURE_DATABRICKS","name":"Azure DataBricks","icon":"skin/azure.png","parent":"AZURE","folder":true},{"id":"AZURE_DATABRICKS_JOB","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Run Job","processingType":"TASK","taskType":"AZURE_DATABRICKS_JOB"},{"id":"AZURE_DATABRICKS_TERMINATE_CLUSTER","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Terminate Cluster","processingType":"TASK","taskType":"AZURE_DATABRICKS_TERMINATE_CLUSTER"},{"id":"AZURE_DATABRICKS_START_CLUSTER","parent":"AZURE_DATABRICKS","icon":"skin/azure.png","name":"Azure DataBricks Start Cluster","processingType":"TASK","taskType":"AZURE_DATABRICKS_START_CLUSTER"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"AZURE_DATABRICKS_CLUSTER_MONITOR","id":"AZURE_DATABRICKS_CLUSTER_MONITOR","icon":"skin/azure.png","name":"Azure DataBricks Cluster Monitor","parent":"AZURE_DATABRICKS"},{"processingType":"TASK","taskType":"AZURE_DATABRICKS_LIST_CLUSTERS","id":"AZURE_DATABRICKS_LIST_CLUSTERS","icon":"skin/azure.png","name":"Azure DataBricks List Clusters","parent":"AZURE_DATABRICKS"},{"processingType":"TASK","taskType":"AZURE_DATABRICKS_DELETE_CLUSTER","id":"AZURE_DATABRICKS_DELETE_CLUSTER","icon":"skin/azure.png","name":"Azure DataBricks Delete Cluster Permanently","parent":"AZURE_DATABRICKS"},{"id":"INFORMATICA_CLOUD","name":"Informatica Cloud","icon":"skin/informatica.ico","parent":"CLOUD_SERVICES","folder":true},{"processingType":"TASK","taskType":"INFORMATICA_CLOUD_TASKFLOW","id":"INFORMATICA_CLOUD_TASKFLOW","icon":"skin/informatica.ico","name":"Informatica Cloud Taskflow","parent":"INFORMATICA_CLOUD"},{"folder":true,"id":"ETL","icon":"skin/etl.png","name":"ETL","parent":"TASK"},{"processingType":"TASK","taskType":"INFORMATICA_WORKFLOW","id":"INFORMATICA_WORKFLOW","icon":"skin/informatica.ico","name":"Informatica Power Center Workflow","parent":"ETL"},{"processingType":"TASK","taskType":"INFORMATICA_WS_WORKFLOW","id":"INFORMATICA_WS_WORKFLOW","icon":"skin/informatica.ico","name":"Informatica Power Center Web Service Workflow","parent":"ETL"},{"processingType":"TASK","taskType":"IBM_DATASTAGE","id":"IBM_DATASTAGE","icon":"skin/ibminfosphere.png","name":"IBM Infosphere DataStage","parent":"ETL"},{"processingType":"TASK","taskType":"MS_SSIS","id":"MS_SSIS","icon":"skin/ssis.png","name":"MS SQL Server Integration Services","parent":"ETL"},{"folder":true,"id":"ORACLE_DATA_INTEGRATOR","icon":"skin/odi.png","name":"Oracle Data Integrator","parent":"ETL"},{"processingType":"TASK","taskType":"ODI_SESSION","id":"ODI_SESSION","icon":"skin/odi.png","name":"ODI Session","parent":"ORACLE_DATA_INTEGRATOR"},{"processingType":"TASK","taskType":"ODI_LOAD_PLAN","id":"ODI_LOAD_PLAN","icon":"skin/odi.png","name":"ODI Load Plan","parent":"ORACLE_DATA_INTEGRATOR"},{"folder":true,"id":"SAS","icon":"skin/sas.png","name":"SAS","parent":"ETL"},{"processingType":"TASK","taskType":"SAS_4GL","id":"SAS_4GL","icon":"skin/sas.png","name":"SAS Dynamic Code","parent":"SAS"},{"processingType":"TASK","taskType":"SAS_DI","id":"SAS_DI","icon":"skin/sas.png","name":"SAS Stored Code","parent":"SAS"},{"processingType":"TASK","taskType":"SAS_JOB","id":"SAS_JOB","icon":"skin/sas.png","name":"SAS Job","parent":"SAS"},{"folder":true,"id":"SAS_VIYA","icon":"skin/sas_viya.png","name":"SAS Viya","parent":"ETL"},{"processingType":"TASK","taskType":"SAS_VIYA_JOB","id":"SAS_VIYA_JOB","icon":"skin/sas_viya.png","name":"SAS Viya Job","parent":"SAS_VIYA"},{"id":"TALEND","parent":"ETL","icon":"[SKINIMG]/skin/talend.png","name":"Talend"},{"processingType":"TASK","taskType":"TALEND_JOB","id":"TALEND_JOB","icon":"[SKINIMG]/skin/talend.png","name":"Talend Job","parent":"TALEND"},{"id":"DBT","parent":"ETL","icon":"[SKINIMG]/skin/dbt.ico","name":"dbt"},{"processingType":"TASK","taskType":"DBT_JOB","id":"DBT_JOB","icon":"[SKINIMG]/skin/dbt.ico","name":"dbt Job","parent":"DBT"},{"folder":true,"id":"ERP","icon":"skin/erp.png","name":"ERP","parent":"TASK"},{"folder":true,"id":"SAP_R3","icon":"skin/sap.png","name":"SAP R/3","parent":"ERP"},{"folder":true,"id":"SAP_R3_JOBS","icon":"skin/sap.png","name":"SAP R/3 Job","parent":"SAP_R3"},{"folder":true,"id":"SAP_R3_OTHER","icon":"skin/sap.png","name":"SAP R/3 Other","parent":"SAP_R3"},{"folder":true,"id":"SAP_4H","icon":"skin/sap.png","name":"SAP S/4HANA","parent":"ERP"},{"folder":true,"id":"SAP_4H_JOBS","icon":"skin/sap.png","name":"SAP 4/HANA Job","parent":"SAP_4H"},{"folder":true,"id":"SAP_4H_OTHER","icon":"skin/sap.png","name":"SAP 4/HANA Other","parent":"SAP_4H"},{"folder":true,"id":"SAP_4HC","icon":"skin/sap.png","name":"SAP S/4HANA Cloud","parent":"ERP"},{"processingType":"TASK","taskType":"SAP_R3_JOB","id":"SAP_R3_JOB","icon":"skin/sap.png","name":"SAP R/3 Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_CREATE","id":"SAP_R3_VARIANT_CREATE","icon":"skin/sap.png","name":"SAP R/3 Create Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_COPY","id":"SAP_R3_VARIANT_COPY","icon":"skin/sap.png","name":"SAP R/3 Copy Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_UPDATE","id":"SAP_R3_VARIANT_UPDATE","icon":"skin/sap.png","name":"SAP R/3 Update Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_VARIANT_DELETE","id":"SAP_R3_VARIANT_DELETE","icon":"skin/sap.png","name":"SAP R/3 Delete Variant","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_RAISE_EVENT","id":"SAP_R3_RAISE_EVENT","icon":"skin/sap.png","name":"SAP R/3 Raise Event","parent":"SAP_R3_OTHER"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_R3_EVENT_SENSOR","id":"SAP_R3_EVENT_SENSOR","icon":"skin/sap.png","name":"SAP R/3 Event Sensor","parent":"SAP_R3_OTHER"},{"processingType":"TASK","taskType":"SAP_R3_COPY_EXISTING_JOB","id":"SAP_R3_COPY_EXISTING_JOB","icon":"skin/sap.png","name":"SAP R/3 Copy Existing Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_START_SCHEDULED_JOB","id":"SAP_R3_START_SCHEDULED_JOB","icon":"skin/sap.png","name":"SAP R/3 Start Scheduled Job","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_R3_JOB_INTERCEPTOR","id":"SAP_R3_JOB_INTERCEPTOR","icon":"skin/sap.png","name":"SAP R/3 Job Interceptor","parent":"SAP_R3_JOBS"},{"processingType":"TASK","id":"SAP_BW_PROCESS_CHAIN","taskType":"SAP_BW_PROCESS_CHAIN","name":"SAP BW Process Chain","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_ARCHIVE","taskType":"SAP_ARCHIVE","name":"SAP Data Archive","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_FUNCTION_MODULE_CALL","taskType":"SAP_FUNCTION_MODULE_CALL","name":"SAP Function Module Call","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_READ_TABLE","taskType":"SAP_READ_TABLE","name":"SAP Read Table","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_CM_PROFILE_ACTIVATE","taskType":"SAP_CM_PROFILE_ACTIVATE","name":"SAP Activate CM Profile","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_CM_PROFILE_DEACTIVATE","taskType":"SAP_CM_PROFILE_DEACTIVATE","name":"SAP Deactivate CM Profile","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_EXPORT_CALENDAR","taskType":"SAP_EXPORT_CALENDAR","name":"SAP Export Calendar","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_EXPORT_JOB","taskType":"SAP_EXPORT_JOB","name":"SAP Export Job","icon":"skin/sap.png","parent":"SAP_R3_OTHER"},{"processingType":"TASK","id":"SAP_MODIFY_INTERCEPTION_CRITERIA","taskType":"SAP_MODIFY_INTERCEPTION_CRITERIA","name":"SAP R/3 Modify Interception Criteria","icon":"skin/sap.png","parent":"SAP_R3_JOBS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_R3_INTERCEPTED_JOB_SENSOR","id":"SAP_R3_INTERCEPTED_JOB_SENSOR","icon":"skin/sap.png","name":"SAP R/3 Intercepted Job Sensor","parent":"SAP_R3_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_JOB","id":"SAP_4H_JOB","icon":"skin/sap.png","name":"SAP 4/H Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_CREATE","id":"SAP_4H_VARIANT_CREATE","icon":"skin/sap.png","name":"SAP 4/H Create Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_COPY","id":"SAP_4H_VARIANT_COPY","icon":"skin/sap.png","name":"SAP 4/H Copy Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_UPDATE","id":"SAP_4H_VARIANT_UPDATE","icon":"skin/sap.png","name":"SAP 4/H Update Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_VARIANT_DELETE","id":"SAP_4H_VARIANT_DELETE","icon":"skin/sap.png","name":"SAP 4/H Delete Variant","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_RAISE_EVENT","id":"SAP_4H_RAISE_EVENT","icon":"skin/sap.png","name":"SAP 4/H Raise Event","parent":"SAP_4H_OTHER"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_4H_EVENT_SENSOR","id":"SAP_4H_EVENT_SENSOR","icon":"skin/sap.png","name":"SAP 4/H Event Sensor","parent":"SAP_4H_OTHER"},{"processingType":"TASK","taskType":"SAP_4H_COPY_EXISTING_JOB","id":"SAP_4H_COPY_EXISTING_JOB","icon":"skin/sap.png","name":"SAP 4/H Copy Existing Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_START_SCHEDULED_JOB","id":"SAP_4H_START_SCHEDULED_JOB","icon":"skin/sap.png","name":"SAP 4/H Start Scheduled Job","parent":"SAP_4H_JOBS"},{"processingType":"TASK","taskType":"SAP_4H_JOB_INTERCEPTOR","id":"SAP_4H_JOB_INTERCEPTOR","icon":"skin/sap.png","name":"SAP 4/H Job Interceptor","parent":"SAP_4H_JOBS"},{"processingType":"TASK","id":"SAP_4H_BW_PROCESS_CHAIN","taskType":"SAP_4H_BW_PROCESS_CHAIN","name":"SAP 4/H BW Process Chain","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_ARCHIVE","taskType":"SAP_4H_ARCHIVE","name":"SAP 4/H Data Archive","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_FUNCTION_MODULE_CALL","taskType":"SAP_4H_FUNCTION_MODULE_CALL","name":"SAP 4/H Function Module Call","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_READ_TABLE","taskType":"SAP_4H_READ_TABLE","name":"SAP 4/H Read Table","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_CM_PROFILE_ACTIVATE","taskType":"SAP_4H_CM_PROFILE_ACTIVATE","name":"SAP 4/H Activate CM Profile","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_CM_PROFILE_DEACTIVATE","taskType":"SAP_4H_CM_PROFILE_DEACTIVATE","name":"SAP 4/H Deactivate CM Profile","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_EXPORT_CALENDAR","taskType":"SAP_4H_EXPORT_CALENDAR","name":"SAP 4/H Export Calendar","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_EXPORT_JOB","taskType":"SAP_4H_EXPORT_JOB","name":"SAP 4/H Export Job","icon":"skin/sap.png","parent":"SAP_4H_OTHER"},{"processingType":"TASK","id":"SAP_4H_MODIFY_INTERCEPTION_CRITERIA","taskType":"SAP_4H_MODIFY_INTERCEPTION_CRITERIA","name":"SAP 4/H Modify Interception Criteria","icon":"skin/sap.png","parent":"SAP_4H_JOBS"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SAP_4H_INTERCEPTED_JOB_SENSOR","id":"SAP_4H_INTERCEPTED_JOB_SENSOR","icon":"skin/sap.png","name":"SAP 4/H Intercepted Job Sensor","parent":"SAP_4H_JOBS"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SAP_4H_JOB_MONITOR","id":"SAP_4H_JOB_MONITOR","icon":"skin/sap.png","name":"SAP 4/H Job Monitor","parent":"SAP_4H_JOBS"},{"processingType":"TASK","id":"SAP_ODATA_API_CALL","taskType":"SAP_ODATA_API_CALL","name":"SAP ODATA API Call","icon":"skin/sap.png","parent":"SAP_4HC"},{"processingType":"TASK","id":"SAP_IBP_JOB","taskType":"SAP_IBP_JOB","name":"SAP IBP Job","icon":"skin/sap.png","parent":"SAP_4HC"},{"processingType":"TASK","id":"SAP_IBP_CREATE_PROCESS","taskType":"SAP_IBP_CREATE_PROCESS","name":"SAP IBP Create Process","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SAP_IBP_DELETE_PROCESS","taskType":"SAP_IBP_DELETE_PROCESS","name":"SAP IBP Delete Process","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"processingType":"TASK","id":"SAP_IBP_SET_PROCESS_STEP_STATUS","taskType":"SAP_IBP_SET_PROCESS_STEP_STATUS","name":"SAP IBP Set Process Job Status","icon":"skin/sap.png","parent":"SAP_4HC","inactive":"hideInactiveFeatures"},{"folder":true,"id":"ORACLE_EBS","icon":"skin/oracle.png","name":"Oracle EBS","parent":"ERP"},{"processingType":"TASK","taskType":"ORACLE_EBS_PROGRAM","id":"ORACLE_EBS_PROGRAM","icon":"skin/oracle.png","name":"Oracle EBS Program","parent":"ORACLE_EBS"},{"processingType":"TASK","taskType":"ORACLE_EBS_REQUEST_SET","id":"ORACLE_EBS_REQUEST_SET","icon":"skin/oracle.png","name":"Oracle EBS Request Set","parent":"ORACLE_EBS"},{"id":"ITSM","folder":true,"icon":"skin/compress_repair.png","name":"ITSM","parent":"TASK"},{"id":"JIRA","parent":"ITSM","icon":"skin/jira.png","name":"Jira","folder":true},{"processingType":"TASK","taskType":"ORACLE_EBS_EXECUTE_PROGRAM","id":"ORACLE_EBS_EXECUTE_PROGRAM","icon":"skin/oracle.png","name":"Oracle EBS Execute Program","parent":"ORACLE_EBS"},{"processingType":"TASK","taskType":"ORACLE_EBS_EXECUTE_REQUEST_SET","id":"ORACLE_EBS_EXECUTE_REQUEST_SET","icon":"skin/oracle.png","name":"Oracle EBS Execute Request Set","parent":"ORACLE_EBS"},{"id":"SERVICE_NOW","parent":"ITSM","icon":"skin/servicenow.png","name":"ServiceNow","folder":true},{"id":"SERVICE_NOW_CREATE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_CREATE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Create Incident"},{"id":"SERVICE_NOW_RESOLVE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_RESOLVE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Resolve Incident"},{"id":"SERVICE_NOW_CLOSE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_CLOSE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Close Incident"},{"id":"SERVICE_NOW_UPDATE_INCIDENT","parent":"SERVICE_NOW","processingType":"TASK","taskType":"SERVICE_NOW_UPDATE_INCIDENT","icon":"skin/servicenow.png","name":"ServiceNow Update Incident"},{"id":"SERVICE_NOW_INCIDENT_STATUS_SENSOR","parent":"SERVICE_NOW","processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SERVICE_NOW_INCIDENT_STATUS_SENSOR","icon":"skin/servicenow.png","name":"ServiceNow Incident Status Sensor"},{"id":"BMC_REMEDY","parent":"ITSM","icon":"skin/bmc.ico","name":"BMC Remedy","folder":true},{"id":"BMC_REMEDY_INCIDENT","parent":"BMC_REMEDY","icon":"skin/bmc.ico","processingType":"TASK","name":"BMC Remedy Incident","taskType":"BMC_REMEDY_INCIDENT"},{"id":"PEOPLESOFT","name":"Peoplesoft","icon":"skin/oracle.png","parent":"ERP","folder":true},{"id":"PEOPLESOFT_APPLICATION_ENGINE_TASK","taskType":"PEOPLESOFT_APPLICATION_ENGINE_TASK","name":"Peoplesoft Application Engine","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_COBOL_SQL_TASK","name":"Peoplesoft COBOL SQL","icon":"skin/oracle.png","parent":"PEOPLESOFT"},{"id":"PEOPLESOFT_CRW_ONLINE_TASK","taskType":"PEOPLESOFT_CRW_ONLINE_TASK","name":"Peoplesoft CRW Online","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_CRYSTAL_REPORTS_TASK","taskType":"PEOPLESOFT_CRYSTAL_REPORTS_TASK","name":"Peoplesoft Crystal Reports","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_CUBE_BUILDER_TASK","taskType":"PEOPLESOFT_CUBE_BUILDER_TASK","name":"Peoplesoft Cube Builder","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_NVISION_TASK","taskType":"PEOPLESOFT_NVISION_TASK","name":"Peoplesoft nVision","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_SQR_PROCESS_TASK","taskType":"PEOPLESOFT_SQR_PROCESS_TASK","name":"Peoplesoft SQR Process","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_SQR_REPORT_TASK","taskType":"PEOPLESOFT_SQR_REPORT_TASK","name":"Peoplesoft SQR Report","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_WINWORD_TASK","taskType":"PEOPLESOFT_WINWORD_TASK","name":"Peoplesoft Winword","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"PEOPLESOFT_JOB_TASK","taskType":"PEOPLESOFT_JOB_TASK","name":"Peoplesoft Job","icon":"skin/oracle.png","parent":"PEOPLESOFT","processingType":"TASK"},{"id":"WLA","folder":true,"icon":"skin/gears.png","name":"Workload Automation","parent":"TASK"},{"id":"AUTOMATE_NOW_TRIGGER_EVENT","parent":"WLA","icon":"skin/favicon.png","name":"AutomateNOW! Trigger Event","processingType":"TASK","taskType":"AUTOMATE_NOW_TRIGGER_EVENT"},{"id":"APACHE_AIRFLOW_RUN_DAG","parent":"WLA","icon":"skin/airflow.png","name":"Run Apache Airflow DAG","processingType":"TASK","taskType":"APACHE_AIRFLOW_RUN_DAG"},{"id":"ANSIBLE_PLAYBOOK","parent":"WLA","icon":"skin/ansible.png","name":"Ansible playbook","processingType":"TASK","taskType":"ANSIBLE_PLAYBOOK"},{"id":"ANSIBLE_PLAYBOOK_PATH","parent":"WLA","icon":"skin/ansible.png","name":"Ansible script","processingType":"TASK","taskType":"ANSIBLE_PLAYBOOK_PATH"},{"folder":true,"id":"CTRL_M","icon":"skin/bmc.png","name":"Ctrl-M","parent":"WLA"},{"id":"CTRLM_ADD_CONDITION","parent":"CTRL_M","icon":"skin/bmc.png","name":"Add Condition","processingType":"TASK","taskType":"CTRLM_ADD_CONDITION"},{"id":"CTRLM_DELETE_CONDITION","parent":"CTRL_M","icon":"skin/bmc.png","name":"Delete Condition","processingType":"TASK","taskType":"CTRLM_DELETE_CONDITION"},{"id":"CTRLM_ORDER_JOB","parent":"CTRL_M","icon":"skin/bmc.png","name":"Order Job","processingType":"TASK","taskType":"CTRLM_ORDER_JOB"},{"id":"CTRLM_CREATE_JOB","parent":"CTRL_M","icon":"skin/bmc.png","name":"Create Job","processingType":"TASK","taskType":"CTRLM_CREATE_JOB"},{"folder":true,"id":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Ctrl-M Resource","parent":"CTRL_M"},{"id":"CTRLM_RESOURCE_TABLE_ADD","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Add resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_ADD"},{"id":"CTRLM_RESOURCE_TABLE_UPDATE","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Update resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_UPDATE"},{"id":"CTRLM_RESOURCE_TABLE_DELETE","parent":"CTRL_M_RESOURCE","icon":"skin/bmc.png","name":"Update resource","processingType":"TASK","taskType":"CTRLM_RESOURCE_TABLE_DELETE"},{"folder":true,"id":"INTERNAL","icon":"skin/milestone.png","name":"Internal Task"},{"folder":true,"id":"PROCESSING","icon":"skin/gear.png","name":"Processing","parent":"INTERNAL"},{"processingType":"TASK","taskType":"RESTART","id":"RESTART","icon":"skin/restart.png","name":"Restart","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_COMPLETED","id":"FORCE_COMPLETED","icon":"skin/accept.png","name":"Force Completed","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_FAILED","id":"FORCE_FAILED","icon":"skin/forceFailed.png","name":"Force Failed","parent":"PROCESSING"},{"processingType":"TASK","taskType":"FORCE_READY","id":"FORCE_READY","icon":"skin/exe.png","name":"Force Launch","parent":"PROCESSING"},{"processingType":"TASK","taskType":"HOLD","id":"HOLD","icon":"skin/hold.png","name":"Hold","parent":"PROCESSING"},{"processingType":"TASK","taskType":"RESUME","id":"RESUME","icon":"skin/resume.png","name":"Resume","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ABORT","id":"ABORT","icon":"skin/kill.png","name":"Abort","parent":"PROCESSING"},{"processingType":"TASK","taskType":"KILL","id":"KILL","icon":"skin/kill.png","name":"Kill","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SKIP_ON","id":"SKIP_ON","icon":"skin/passByOn.png","name":"Skip On","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SKIP_OFF","id":"SKIP_OFF","icon":"skin/passByOff.png","name":"Skip Off","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_ACTION_SKIP_ON","id":"PROCESSING_ACTION_SKIP_ON","icon":"skin/passByOn.png","name":"Skip On Action","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_ACTION_SKIP_OFF","id":"PROCESSING_ACTION_SKIP_OFF","icon":"skin/passByOff.png","name":"Skip Off Action","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ARCHIVE","id":"ARCHIVE","icon":"skin/archive.png","name":"Archive","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_PRIORITY","id":"SET_PRIORITY","icon":"skin/numeric_stepper.png","name":"Set Priority","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_STATUS_CODE","id":"SET_STATUS_CODE","icon":"skin/sort_number.png","name":"Set Status Code","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_CONTEXT_VARIABLE_VALUE","id":"SET_CONTEXT_VARIABLE_VALUE","icon":"skin/pi_math--pencil.png","name":"Set context variable","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_CONTEXT_VARIABLE_VALUES","id":"SET_CONTEXT_VARIABLE_VALUES","icon":"skin/pi_math--pencil.png","name":"Set multiple context variables","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_RUN_NOW","id":"PROCESSING_RUN_NOW","icon":"skin/gear.png","name":"Add processing from template","parent":"PROCESSING"},{"processingType":"TASK","taskType":"CHECK_PROCESSING_STATE","id":"CHECK_PROCESSING_STATE","icon":"skin/system-monitor.png","name":"Check processing state","parent":"PROCESSING"},{"processingType":"TASK","taskType":"ADD_TAG","id":"ADD_TAG","icon":"skin/price_tag_plus.png","name":"Add Tag","parent":"PROCESSING"},{"processingType":"TASK","taskType":"REMOVE_TAG","id":"REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Remove Tag","parent":"PROCESSING"},{"processingType":"TASK","taskType":"SET_FOLDER","id":"SET_FOLDER","icon":"skin/folder.png","name":"Set Folder","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_REGISTER_STATE","id":"PROCESSING_REGISTER_STATE","icon":"skin/system-monitor.png","name":"Register Processing State","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_UNREGISTER_STATE","id":"PROCESSING_UNREGISTER_STATE","icon":"skin/system-monitor.png","name":"Unregister Processing State","parent":"PROCESSING"},{"processingType":"TASK","taskType":"PROCESSING_CLEAR_STATE_REGISTRY","id":"PROCESSING_CLEAR_STATE_REGISTRY","icon":"skin/system-monitor.png","name":"Clear Processing Registry","parent":"PROCESSING"},{"folder":true,"id":"RESOURCE","icon":"skin/traffic-light.png","name":"Resource","parent":"INTERNAL"},{"folder":true,"id":"SET_RESOURCE","icon":"skin/traffic-light--pencil.png","name":"Set Resource","parent":"RESOURCE"},{"processingType":"TASK","id":"SET_SEMAPHORE_STATE","name":"Set semaphore state","icon":"skin/traffic-light--pencil.png","parent":"SET_RESOURCE","taskType":"SET_SEMAPHORE_STATE"},{"processingType":"TASK","id":"SET_TIME_WINDOW_STATE","name":"Set time window state","icon":"skin/clock--pencil.png","parent":"SET_RESOURCE","taskType":"SET_TIME_WINDOW_STATE"},{"processingType":"TASK","id":"SET_STOCK_TOTAL_PERMITS","name":"Set stock total permits","icon":"skin/stock--pencil.png","parent":"SET_RESOURCE","taskType":"SET_STOCK_TOTAL_PERMITS"},{"processingType":"TASK","id":"SET_VARIABLE_VALUE","name":"Set variable","icon":"skin/pi_math--pencil.png","parent":"SET_RESOURCE","taskType":"SET_VARIABLE_VALUE"},{"processingType":"TASK","id":"SET_PHYSICAL_RESOURCE","name":"Set physical resource","icon":"skin/memory.png","parent":"SET_RESOURCE","taskType":"SET_PHYSICAL_RESOURCE"},{"processingType":"TASK","id":"SET_METRIC","name":"Set metric","icon":"skin/gauge.png","parent":"SET_RESOURCE","taskType":"SET_METRIC"},{"processingType":"TASK","id":"TRIGGER_EVENT","name":"Trigger Event","icon":"skin/arrow-out.png","parent":"SET_RESOURCE","taskType":"TRIGGER_EVENT"},{"folder":true,"id":"CHECK_RESOURCE","icon":"skin/traffic-light--check.png","name":"Check Resource","parent":"RESOURCE"},{"processingType":"TASK","id":"CHECK_SEMAPHORE_STATE","name":"Check semaphore state","icon":"skin/traffic-light--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_SEMAPHORE_STATE"},{"processingType":"TASK","id":"CHECK_TIME_WINDOW_STATE","name":"Check time window state","icon":"skin/clock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_TIME_WINDOW_STATE"},{"processingType":"TASK","id":"CHECK_STOCK_AVAILABLE_PERMITS","name":"Check stock available permits","icon":"skin/stock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_STOCK_AVAILABLE_PERMITS"},{"processingType":"TASK","id":"CHECK_CALENDAR","name":"Check calendar","icon":"skin/date_control.png","parent":"CHECK_RESOURCE","taskType":"CHECK_CALENDAR"},{"processingType":"TASK","id":"CHECK_STOCK_TOTAL_PERMITS","name":"Check stock total permits","icon":"skin/stock-total--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_STOCK_TOTAL_PERMITS"},{"processingType":"TASK","id":"CHECK_LOCK_STATE","name":"Check lock state","icon":"skin/lock--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_LOCK_STATE"},{"processingType":"TASK","id":"CHECK_VARIABLE_VALUE","name":"Check variable value","icon":"skin/pi_math--check.png","parent":"CHECK_RESOURCE","taskType":"CHECK_VARIABLE_VALUE"},{"processingType":"TASK","id":"CHECK_PHYSICAL_RESOURCE","name":"Check physical resource","icon":"skin/memory.png","parent":"CHECK_RESOURCE","taskType":"CHECK_PHYSICAL_RESOURCE"},{"processingType":"TASK","id":"CHECK_METRIC","name":"Check metric","icon":"skin/gauge.png","parent":"CHECK_RESOURCE","taskType":"CHECK_METRIC"},{"processingType":"TASK","taskType":"RESOURCE_ADD_TAG","id":"RESOURCE_ADD_TAG","icon":"skin/price_tag_plus.png","name":"Resource Add Tag","parent":"RESOURCE"},{"processingType":"TASK","taskType":"RESOURCE_REMOVE_TAG","id":"RESOURCE_REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Resource Remove Tag","parent":"RESOURCE"},{"processingType":"TASK","taskType":"RESOURCE_SET_FOLDER","id":"RESOURCE_SET_FOLDER","icon":"skin/folder.png","name":"Set Resource Folder","parent":"RESOURCE"},{"folder":true,"id":"SERVER_NODE","icon":"skin/servers.png","name":"Server Node","parent":"INTERNAL"},{"processingType":"TASK","taskType":"SERVER_NODE_HOLD","id":"SERVER_NODE_HOLD","icon":"skin/hold.png","name":"Server Node Hold","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_RESUME","id":"SERVER_NODE_RESUME","icon":"skin/resume.png","name":"Server Node Resume","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SKIP_ON","id":"SERVER_NODE_SKIP_ON","icon":"skin/passByOn.png","name":"Server Node Skip On","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SKIP_OFF","id":"SERVER_NODE_SKIP_OFF","icon":"skin/passByOff.png","name":"Server Node Skip Off","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_ABORT_ALL","id":"SERVER_NODE_ABORT_ALL","icon":"skin/kill.png","name":"Server Node Abort All","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_KILL_ALL","id":"SERVER_NODE_KILL_ALL","icon":"skin/kill.png","name":"Server Node Kill All","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_STOP","id":"SERVER_NODE_STOP","icon":"skin/stop.png","name":"Server Node Stop","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_ADD_TAG","id":"SERVER_NODE_ADD_TAG","icon":"skin/price_tag_plus.png","name":"Server Node Add Tag","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_REMOVE_TAG","id":"SERVER_NODE_REMOVE_TAG","icon":"skin/price_tag_minus.png","name":"Server Node Remove Tag","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SET_FOLDER","id":"SERVER_NODE_SET_FOLDER","icon":"skin/folder.png","name":"Server Node Set Folder","parent":"SERVER_NODE"},{"processingType":"TASK","taskType":"SERVER_NODE_SET_TOTAL_WEIGHT_CAPACITY","id":"SERVER_NODE_SET_TOTAL_WEIGHT_CAPACITY","icon":"skin/folder.png","name":"Server Node Set Capacity","parent":"SERVER_NODE"},{"folder":true,"id":"PROCESSING_TEMPLATE","icon":"skin/clock.png","name":"Processing Template","parent":"INTERNAL"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_HOLD","id":"PROCESSING_TEMPLATE_HOLD","icon":"skin/hold.png","name":"Processing Template Hold","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_RESUME","id":"PROCESSING_TEMPLATE_RESUME","icon":"skin/resume.png","name":"Processing Template Resume","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_SKIP_ON","id":"PROCESSING_TEMPLATE_SKIP_ON","icon":"skin/passByOn.png","name":"Processing Template Skip On","parent":"PROCESSING_TEMPLATE"},{"processingType":"TASK","taskType":"PROCESSING_TEMPLATE_SKIP_OFF","id":"PROCESSING_TEMPLATE_SKIP_OFF","icon":"skin/passByOff.png","name":"Processing Template Skip Off","parent":"PROCESSING_TEMPLATE"},{"folder":true,"id":"MAINTENANCE","icon":"skin/gear.png","name":"Maintenance","parent":"INTERNAL"},{"processingType":"TASK","taskType":"ARCHIVE_INTERVAL","id":"ARCHIVE_INTERVAL","icon":"skin/archive.png","name":"Archive old processing items","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"ARCHIVE_CLEANUP","id":"ARCHIVE_CLEANUP","icon":"skin/archive.png","name":"Archive cleanup","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"RECALCULATE_STATISTICS","id":"RECALCULATE_STATISTICS","icon":"skin/calculator.png","name":"Recalculate Statistic","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"DESIGN_BACKUP","id":"DESIGN_BACKUP","icon":"skin/drive-download.png","name":"Design Backup","parent":"MAINTENANCE"},{"processingType":"TASK","taskType":"DESIGN_IMPORT","id":"DESIGN_IMPORT","icon":"skin/drive-download.png","name":"Design Import","parent":"MAINTENANCE"},{"folder":true,"id":"OTHER","icon":"skin/alarm.png","name":"Other","parent":"INTERNAL"},{"processingType":"TASK","taskType":"WAIT","id":"WAIT","icon":"skin/alarm.png","name":"Wait","parent":"OTHER"},{"processingType":"TASK","taskType":"CHECK_TIME","id":"CHECK_TIME","icon":"skin/clock.png","name":"Check Time","parent":"OTHER"},{"id":"USER_TASKS","name":"User","icon":"skin/user.png","parent":"INTERNAL","folder":true},{"processingType":"TASK","taskType":"USER_CONFIRM","id":"USER_CONFIRM","icon":"skin/thumbUp.png","name":"User confirmation","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"USER_INPUT","id":"USER_INPUT","icon":"skin/pencil.png","name":"User input","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_GROUP","id":"NOTIFY_GROUP","icon":"skin/users.png","name":"Notify Group","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_CHANNEL","id":"NOTIFY_CHANNEL","icon":"skin/mail_server_exim.png","name":"Notify Channel","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"NOTIFY_EMAIL","id":"NOTIFY_EMAIL","icon":"skin/mail.png","name":"Notify Email","parent":"USER_TASKS"},{"processingType":"TASK","taskType":"ADHOC_REPORT_SEND","id":"ADHOC_REPORT_SEND","icon":"skin/table.png","name":"Adhoc Report Send","parent":"USER_TASKS"},{"processingType":"TASK","id":"AE","icon":"skin/terminal.gif","name":"AE","parent":"INTERNAL","folder":true},{"processingType":"TASK","taskType":"AE_SCRIPT","id":"AE_SCRIPT","icon":"skin/terminal.gif","name":"AE Script","parent":"AE"},{"processingType":"WORKFLOW","id":"WORKFLOW","name":"Workflow","icon":"skin/diagram.png","folder":true},{"processingType":"WORKFLOW","workflowType":"STANDARD","id":"STANDARD","icon":"skin/diagram.png","name":"Workflow","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"BROADCAST","id":"BROADCAST","icon":"skin/rss.png","name":"Broadcast","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"FOR_EACH","id":"FOR_EACH","icon":"skin/ordered_list.png","name":"For Each","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"SWITCH","id":"SWITCH","icon":"skin/switch.png","name":"Switch","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"CYCLE","id":"CYCLE","icon":"skin/cycle.png","name":"Cycle","parent":"WORKFLOW"},{"processingType":"WORKFLOW","workflowType":"TIME_SERIES","id":"TIME_SERIES","icon":"skin/ui-paginator.png","name":"Time Series","parent":"WORKFLOW"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"FILE_SENSOR","id":"FILE_SENSOR","icon":"skin/fileWatcher.png","name":"File Sensor","parent":"FILE_PROCESSING"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"JIRA_ISSUE_SENSOR","id":"JIRA_ISSUE_SENSOR","icon":"skin/jira.png","name":"Jira Issue Sensor","parent":"JIRA"},{"processingType":"TASK","id":"JIRA_ADD_ISSUE","parent":"JIRA","icon":"skin/jira.png","name":"Jira Add Issue","taskType":"JIRA_ADD_ISSUE"},{"id":"RPA","icon":"skin/robot.png","name":"Robotic Process Automation","parent":"TASK","folder":true},{"processingType":"TASK","id":"UI_PATH","icon":"skin/uipath.ico","name":"UiPath","parent":"RPA","taskType":"UI_PATH"},{"processingType":"TASK","id":"BLUE_PRISM","icon":"skin/blueprism.ico","name":"Blue Prism","parent":"RPA","taskType":"BLUE_PRISM"},{"processingType":"TASK","id":"ROBOT_FRAMEWORK_START_ROBOT","icon":"skin/robotFramework.png","name":"Robot Framework Start Robot","parent":"RPA","taskType":"ROBOT_FRAMEWORK_START_ROBOT"},{"id":"BI","icon":"skin/table_chart.png","name":"Business Intelligence","parent":"TASK","folder":true},{"id":"MICROSOFT_POWER_BI","icon":"skin/table_chart.png","name":"Microsoft Power BI","parent":"BI","folder":true},{"processingType":"TASK","id":"MICROSOFT_POWER_BI_DATASET_REFRESH","icon":"skin/powerBi.ico","name":"Microsoft Power BI Refresh Data Set","parent":"MICROSOFT_POWER_BI","taskType":"MICROSOFT_POWER_BI_DATASET_REFRESH"},{"processingType":"TASK","id":"MICROSOFT_POWER_BI_DATAFLOW_REFRESH","icon":"skin/powerBi.ico","name":"Microsoft Power BI Refresh Data Flow","parent":"MICROSOFT_POWER_BI","taskType":"MICROSOFT_POWER_BI_DATAFLOW_REFRESH"},{"id":"INSTANT_MESSAGING","name":"Instant Messaging","icon":"skin/comment_edit.png","parent":"TASK","folder":true},{"processingType":"TASK","id":"TELEGRAM_MESSAGE","icon":"skin/telegram.png","name":"Telegram Message","parent":"INSTANT_MESSAGING","taskType":"TELEGRAM_MESSAGE"},{"processingType":"TASK","id":"WHATSAPP_MESSAGE","icon":"skin/whatsapp.png","name":"WhatsApp Message","parent":"INSTANT_MESSAGING","taskType":"WHATSAPP_MESSAGE"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"SQL_SENSOR","id":"SQL_SENSOR","icon":"skin/database-sql.png","name":"SQL Sensor","parent":"SQL"},{"processingType":"SERVICE","serviceType":"SENSOR","sensorType":"Z_OS_JES_JOB_SENSOR","id":"Z_OS_JES_JOB_SENSOR","icon":"skin/zos.png","name":"z/OS JES Job Sensor","parent":"Z_OS"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SH_MONITOR","id":"SH_MONITOR","icon":"skin/terminal.gif","name":"Shell Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PYTHON_MONITOR","id":"PYTHON_MONITOR","icon":"skin/python.png","name":"Python Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PERL_MONITOR","id":"PERL_MONITOR","icon":"skin/perl.png","name":"Perl Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"RUBY_MONITOR","id":"RUBY_MONITOR","icon":"skin/ruby.png","name":"Ruby Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"GROOVY_MONITOR","id":"GROOVY_MONITOR","icon":"skin/groovy.png","name":"Groovy Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"POWERSHELL_MONITOR","id":"POWERSHELL_MONITOR","icon":"skin/powershell.png","name":"PowerShell Monitor","parent":"CODE"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"HTTP_MONITOR","id":"HTTP_MONITOR","icon":"skin/http.png","name":"HTTP Monitor","parent":"WEB"},{"folder":true,"id":"OPERATING_SYSTEM_MONITOR","icon":"skin/system-monitor.png","name":"OS Monitors","parent":"TASK"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SYSTEM_MONITOR","id":"SYSTEM_MONITOR","icon":"skin/memory.png","name":"System Monitor","parent":"OPERATING_SYSTEM_MONITOR"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SYSTEM_PROCESS_MONITOR","id":"SYSTEM_PROCESS_MONITOR","icon":"skin/system-monitor.png","name":"System Process Monitor","parent":"OPERATING_SYSTEM_MONITOR"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"SAP_R3_JOB_MONITOR","id":"SAP_R3_JOB_MONITOR","icon":"skin/sap.png","name":"SAP R/3 Job Monitor","parent":"SAP_R3_JOBS"},{"id":"SLA","title":"Service Manager","name":"Service Manager","icon":"skin/traffic-light.png","folder":true},{"id":"BUSINESS_VIEW","title":"Business View","icon":"skin/chart_organisation.png","processingType":"SERVICE","serviceType":"SERVICE_MANAGER","serviceManagerType":"BUSINESS_VIEW","name":"Business View"},{"id":"SLA_SERVICE_MANAGER","title":"Service Level Agreement","icon":"skin/traffic-light.png","processingType":"SERVICE","serviceType":"SERVICE_MANAGER","serviceManagerType":"SLA_SERVICE_MANAGER","name":"Service Level Agreement","parent":"SLA"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PROCESSING_BASELINE_DEVIATION_MONITOR","id":"PROCESSING_BASELINE_DEVIATION_MONITOR","icon":"skin/chart_down_color.png","name":"Baseline Deviation Monitor","parent":"PROCESSING"},{"processingType":"SERVICE","serviceType":"MONITOR","monitorType":"PROCESSING_DEADLINE_MONITOR","id":"PROCESSING_DEADLINE_MONITOR","icon":"skin/chart_stock.png","name":"Processing Deadline Monitor","parent":"SLA"},{"processingType":"TRIGGER","id":"TRIGGER","name":"Trigger","icon":"skin/arrow-out.png","folder":true},{"processingType":"TRIGGER","triggerType":"SCHEDULE","id":"SCHEDULE","icon":"skin/clock.png","name":"Time Schedule","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"USER","id":"USER","icon":"skin/user.png","name":"User","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"EVENT","id":"EVENT","icon":"skin/arrow-out.png","name":"Event Schedule","parent":"TRIGGER"},{"processingType":"TRIGGER","triggerType":"SELF_SERVICE","id":"SELF_SERVICE","icon":"skin/user.png","name":"Self Service","parent":"TRIGGER"},{"parent":"NONEXISTING_ITEM_TO_HIDE_FROM_VIEW","processingType":"TASK","taskType":"TRIGGER_ITEM","id":"TRIGGER_ITEM","name":"Trigger Item","icon":"skin/exe.png","inactive":true},{"processingType":"TASK","taskType":"PROCESSING_OBSERVER","id":"PROCESSING_OBSERVER","icon":"skin/emotion_eye.png","name":"Processing Observer","parent":"NONEXISTING_ITEM_TO_HIDE_FROM_VIEW","inactive":true}]' | ConvertFrom-Json
    [array]$TaskTypesArray = $TaskTypesJson | ForEach-Object { [PSCustomObject]@{ Parent = $_.parent; Id = $_.id; Name = $_.name; } }
    Return $TaskTypesArray
}

Function Get-AutomateNOWTask {
    <#
    .SYNOPSIS
    Gets the tasks from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWTask` cmdlet gets the tasks from an instance of AutomateNOW!
    
    .PARAMETER Type
    A string representing the type of task (of which there are 218). For example, 'SH' for shell scripts. Valid choices are: 'SH','AE_SHELL_SCRIPT','PYTHON','PERL','RUBY','GROOVY','POWERSHELL','JAVA','SCALA','SH_MONITOR','PYTHON_MONITOR','PERL_MONITOR','RUBY_MONITOR','GROOVY_MONITOR','POWERSHELL_MONITOR','FILE_TRANSFER','XFTP_COMMAND','DATASOURCE_UPLOAD_FILE','DATASOURCE_DOWNLOAD_FILE','DATASOURCE_DELETE_FILE','FILE_SENSOR','RDBMS_STORED_PROCEDURE','RDBMS_SQL_STATEMENT','RDBMS_SQL','SQL_SENSOR','REDIS_SET','REDIS_GET','REDIS_DELETE','REDIS_CLI','MONGO_DB_INSERT','IBM_MQ_SEND','IBM_MQ_SENSOR','RABBIT_MQ_SEND','RABBIT_MQ_SENSOR','KAFKA_SEND','KAFKA_SENSOR','JMS_SEND','JMS_SENSOR','AMQP_SEND','MQTT_SEND','XMPP_SEND','STOMP_SEND','Z_OS_DYNAMIC_JCL','Z_OS_STORED_JCL','Z_OS_COMMAND','Z_OS_JES_JOB_SENSOR','AS400_BATCH_JOB','AS400_PROGRAM_CALL','RAINCODE_DYNAMIC_JCL','RAINCODE_STORED_JCL','OPENTEXT_DYNAMIC_JCL','OPENTEXT_STORED_JCL','HDFS_UPLOAD_FILE','HDFS_APPEND_FILE','HDFS_DOWNLOAD_FILE','HDFS_DELETE_FILE','HDFS_CREATE_DIRECTORY','HDFS_DELETE_DIRECTORY','HDFS_RENAME','SPARK_JAVA','SPARK_SCALA','SPARK_PYTHON','SPARK_R','SPARK_SQL','FLINK_RUN_JOB','FLINK_JAR_UPLOAD','FLINK_JAR_DELETE','HTTP_REQUEST','REST_WEB_SERVICE_CALL','SOAP_WEB_SERVICE_CALL','HTTP_MONITOR','EMAIL_SEND','EMAIL_CONFIRMATION','EMAIL_INPUT','EMAIL_SENSOR','AWS_GLUE_WORKFLOW','AWS_GLUE_TRIGGER','AWS_GLUE_CRAWLER','AWS_GLUE_JOB','AWS_EMR_WORKFLOW','AWS_EMR_ADD_STEPS','AWS_EMR_CANCEL_STEPS','AWS_EMR_TERMINATE_JOB_FLOW','AWS_EMR_CONTAINER_MONITOR','AWS_EMR_JOB_FLOW_MONITOR','AWS_EMR_STEP_MONITOR','AWS_EMR_NOTEBOOK_MONITOR','AWS_EMR_PUT','AWS_EMR_GET','AWS_EMR_START_NOTEBOOK_EXECUTION','AWS_EMR_STOP_NOTEBOOK_EXECUTION','AWS_EMR_API_COMMAND','AWS_SAGE_MAKER_ADD_MODEL','AWS_SAGE_MAKER_DELETE_MODEL','AWS_SAGE_MAKER_PROCESSING','AWS_SAGE_MAKER_TRAINING','AWS_SAGE_MAKER_TRANSFORM','AWS_SAGE_MAKER_API_COMMAND','AWS_LAMBDA_INVOKE','AWS_LAMBDA_CREATE_FUNCTION','AWS_LAMBDA_DELETE_FUNCTION','AWS_EC2_START_INSTANCE','AWS_EC2_STOP_INSTANCE','AWS_EC2_TERMINATE_INSTANCE','AWS_EC2_DELETE_VOLUME','AWS_S3_DELETE_OBJECT','AWS_S3_COPY_OBJECT','AWS_S3_MOVE_OBJECT','AWS_S3_RENAME_OBJECT','AWS_BATCH_JOB','AWS_START_STEP_FUNCTION_STATE_MACHINE','AZURE_DATA_FACTORY_TRIGGER','AZURE_DATA_FACTORY_PIPELINE','AZURE_DATA_LAKE_JOB','AZURE_DATABRICKS_JOB','AZURE_DATABRICKS_TERMINATE_CLUSTER','AZURE_DATABRICKS_START_CLUSTER','AZURE_DATABRICKS_CLUSTER_MONITOR','AZURE_DATABRICKS_LIST_CLUSTERS','AZURE_DATABRICKS_DELETE_CLUSTER','INFORMATICA_CLOUD_TASKFLOW','INFORMATICA_WORKFLOW','INFORMATICA_WS_WORKFLOW','IBM_DATASTAGE','MS_SSIS','ODI_SESSION','ODI_LOAD_PLAN','SAS_4GL','SAS_DI','SAS_JOB','SAS_VIYA_JOB','TALEND_JOB','DBT_JOB','SAP_R3_JOB','SAP_R3_VARIANT_CREATE','SAP_R3_VARIANT_COPY','SAP_R3_VARIANT_UPDATE','SAP_R3_VARIANT_DELETE','SAP_R3_COPY_EXISTING_JOB','SAP_R3_START_SCHEDULED_JOB','SAP_R3_JOB_INTERCEPTOR','SAP_MODIFY_INTERCEPTION_CRITERIA','SAP_R3_INTERCEPTED_JOB_SENSOR','SAP_R3_JOB_MONITOR','SAP_R3_RAISE_EVENT','SAP_R3_EVENT_SENSOR','SAP_BW_PROCESS_CHAIN','SAP_ARCHIVE','SAP_FUNCTION_MODULE_CALL','SAP_READ_TABLE','SAP_CM_PROFILE_ACTIVATE','SAP_CM_PROFILE_DEACTIVATE','SAP_EXPORT_CALENDAR','SAP_EXPORT_JOB','SAP_4H_JOB','SAP_4H_VARIANT_CREATE','SAP_4H_VARIANT_COPY','SAP_4H_VARIANT_UPDATE','SAP_4H_VARIANT_DELETE','SAP_4H_COPY_EXISTING_JOB','SAP_4H_START_SCHEDULED_JOB','SAP_4H_JOB_INTERCEPTOR','SAP_4H_MODIFY_INTERCEPTION_CRITERIA','SAP_4H_INTERCEPTED_JOB_SENSOR','SAP_4H_JOB_MONITOR','SAP_4H_RAISE_EVENT','SAP_4H_EVENT_SENSOR','SAP_4H_BW_PROCESS_CHAIN','SAP_4H_ARCHIVE','SAP_4H_FUNCTION_MODULE_CALL','SAP_4H_READ_TABLE','SAP_4H_CM_PROFILE_ACTIVATE','SAP_4H_CM_PROFILE_DEACTIVATE','SAP_4H_EXPORT_CALENDAR','SAP_4H_EXPORT_JOB','SAP_ODATA_API_CALL','SAP_IBP_JOB','ORACLE_EBS_PROGRAM','ORACLE_EBS_REQUEST_SET','ORACLE_EBS_EXECUTE_PROGRAM','ORACLE_EBS_EXECUTE_REQUEST_SET','PEOPLESOFT_APPLICATION_ENGINE_TASK','PEOPLESOFT_CRW_ONLINE_TASK','PEOPLESOFT_CRYSTAL_REPORTS_TASK','PEOPLESOFT_CUBE_BUILDER_TASK','PEOPLESOFT_NVISION_TASK','PEOPLESOFT_SQR_PROCESS_TASK','PEOPLESOFT_SQR_REPORT_TASK','PEOPLESOFT_WINWORD_TASK','PEOPLESOFT_JOB_TASK','JIRA_ISSUE_SENSOR','JIRA_ADD_ISSUE','SERVICE_NOW_CREATE_INCIDENT','SERVICE_NOW_RESOLVE_INCIDENT','SERVICE_NOW_CLOSE_INCIDENT','SERVICE_NOW_UPDATE_INCIDENT','SERVICE_NOW_INCIDENT_STATUS_SENSOR','BMC_REMEDY_INCIDENT','AUTOMATE_NOW_TRIGGER_EVENT','APACHE_AIRFLOW_RUN_DAG','ANSIBLE_PLAYBOOK','ANSIBLE_PLAYBOOK_PATH','CTRLM_ADD_CONDITION','CTRLM_DELETE_CONDITION','CTRLM_ORDER_JOB','CTRLM_CREATE_JOB','CTRLM_RESOURCE_TABLE_ADD','CTRLM_RESOURCE_TABLE_UPDATE','CTRLM_RESOURCE_TABLE_DELETE','UI_PATH','BLUE_PRISM','ROBOT_FRAMEWORK_START_ROBOT','MICROSOFT_POWER_BI_DATASET_REFRESH','MICROSOFT_POWER_BI_DATAFLOW_REFRESH','TELEGRAM_MESSAGE','WHATSAPP_MESSAGE','SYSTEM_MONITOR','SYSTEM_PROCESS_MONITOR'

    .PARAMETER Templates
    Important optional switch parameter to select Task Templates or Task Monitoring. If you are looking for tasks to EXECUTE then use this parameter to list available Task Templates. By default, this function shows the Tasks under the Monitors tab of the UI not the Design tab!

    .PARAMETER OnlyRunning
    An optional switch parameter that filters the tasks to only those that are actively running

    .PARAMETER Formatted
    An optional switch parameter that returns select columns. Intended for display purposes!
    
    .PARAMETER startRow
    An optional int32 representing what row to start the download from. This is intended for multi-page transfers.

    .PARAMETER endRow
    An optional int32 representing how many rows of data to receive. The default is 2000. This is ideal for testing when you only want a few items.

    .PARAMETER sortBy
    Optional string parameter which defines the sorting order (default is by 'id'). Valid choices are: 'id', 'startTime', 'agent', 'createdBy', 'dateCreated', 'duration', 'endTime', 'firstStartTime', 'lastUpdated', 'name', 'node', 'pid', 'processingLaunchType', 'processingStatus', 'template', 'weight'

    .PARAMETER sortTemplatesBy
    Optional string parameter not implemented yet which will allow to sort the output when Templates are chosen

    .PARAMETER Descending
    Optional switch parameter which changes the sort order from the default ascending to descending (applies to both -sortBy and -sortTemplatesBy)
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWTask.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWTask -Type SH -Templates
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The Type, sortBy and SortTemplatesBy parameter values are CASE-SENSITIVE!
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [ValidateSet('SH', 'AE_SHELL_SCRIPT', 'PYTHON', 'PERL', 'RUBY', 'GROOVY', 'POWERSHELL', 'JAVA', 'SCALA', 'SH_MONITOR', 'PYTHON_MONITOR', 'PERL_MONITOR', 'RUBY_MONITOR', 'GROOVY_MONITOR', 'POWERSHELL_MONITOR', 'FILE_TRANSFER', 'XFTP_COMMAND', 'DATASOURCE_UPLOAD_FILE', 'DATASOURCE_DOWNLOAD_FILE', 'DATASOURCE_DELETE_FILE', 'FILE_SENSOR', 'RDBMS_STORED_PROCEDURE', 'RDBMS_SQL_STATEMENT', 'RDBMS_SQL', 'SQL_SENSOR', 'REDIS_SET', 'REDIS_GET', 'REDIS_DELETE', 'REDIS_CLI', 'MONGO_DB_INSERT', 'IBM_MQ_SEND', 'IBM_MQ_SENSOR', 'RABBIT_MQ_SEND', 'RABBIT_MQ_SENSOR', 'KAFKA_SEND', 'KAFKA_SENSOR', 'JMS_SEND', 'JMS_SENSOR', 'AMQP_SEND', 'MQTT_SEND', 'XMPP_SEND', 'STOMP_SEND', 'Z_OS_DYNAMIC_JCL', 'Z_OS_STORED_JCL', 'Z_OS_COMMAND', 'Z_OS_JES_JOB_SENSOR', 'AS400_BATCH_JOB', 'AS400_PROGRAM_CALL', 'RAINCODE_DYNAMIC_JCL', 'RAINCODE_STORED_JCL', 'OPENTEXT_DYNAMIC_JCL', 'OPENTEXT_STORED_JCL', 'HDFS_UPLOAD_FILE', 'HDFS_APPEND_FILE', 'HDFS_DOWNLOAD_FILE', 'HDFS_DELETE_FILE', 'HDFS_CREATE_DIRECTORY', 'HDFS_DELETE_DIRECTORY', 'HDFS_RENAME', 'SPARK_JAVA', 'SPARK_SCALA', 'SPARK_PYTHON', 'SPARK_R', 'SPARK_SQL', 'FLINK_RUN_JOB', 'FLINK_JAR_UPLOAD', 'FLINK_JAR_DELETE', 'HTTP_REQUEST', 'REST_WEB_SERVICE_CALL', 'SOAP_WEB_SERVICE_CALL', 'HTTP_MONITOR', 'EMAIL_SEND', 'EMAIL_CONFIRMATION', 'EMAIL_INPUT', 'EMAIL_SENSOR', 'AWS_GLUE_WORKFLOW', 'AWS_GLUE_TRIGGER', 'AWS_GLUE_CRAWLER', 'AWS_GLUE_JOB', 'AWS_EMR_WORKFLOW', 'AWS_EMR_ADD_STEPS', 'AWS_EMR_CANCEL_STEPS', 'AWS_EMR_TERMINATE_JOB_FLOW', 'AWS_EMR_CONTAINER_MONITOR', 'AWS_EMR_JOB_FLOW_MONITOR', 'AWS_EMR_STEP_MONITOR', 'AWS_EMR_NOTEBOOK_MONITOR', 'AWS_EMR_PUT', 'AWS_EMR_GET', 'AWS_EMR_START_NOTEBOOK_EXECUTION', 'AWS_EMR_STOP_NOTEBOOK_EXECUTION', 'AWS_EMR_API_COMMAND', 'AWS_SAGE_MAKER_ADD_MODEL', 'AWS_SAGE_MAKER_DELETE_MODEL', 'AWS_SAGE_MAKER_PROCESSING', 'AWS_SAGE_MAKER_TRAINING', 'AWS_SAGE_MAKER_TRANSFORM', 'AWS_SAGE_MAKER_API_COMMAND', 'AWS_LAMBDA_INVOKE', 'AWS_LAMBDA_CREATE_FUNCTION', 'AWS_LAMBDA_DELETE_FUNCTION', 'AWS_EC2_START_INSTANCE', 'AWS_EC2_STOP_INSTANCE', 'AWS_EC2_TERMINATE_INSTANCE', 'AWS_EC2_DELETE_VOLUME', 'AWS_S3_DELETE_OBJECT', 'AWS_S3_COPY_OBJECT', 'AWS_S3_MOVE_OBJECT', 'AWS_S3_RENAME_OBJECT', 'AWS_BATCH_JOB', 'AWS_START_STEP_FUNCTION_STATE_MACHINE', 'AZURE_DATA_FACTORY_TRIGGER', 'AZURE_DATA_FACTORY_PIPELINE', 'AZURE_DATA_LAKE_JOB', 'AZURE_DATABRICKS_JOB', 'AZURE_DATABRICKS_TERMINATE_CLUSTER', 'AZURE_DATABRICKS_START_CLUSTER', 'AZURE_DATABRICKS_CLUSTER_MONITOR', 'AZURE_DATABRICKS_LIST_CLUSTERS', 'AZURE_DATABRICKS_DELETE_CLUSTER', 'INFORMATICA_CLOUD_TASKFLOW', 'INFORMATICA_WORKFLOW', 'INFORMATICA_WS_WORKFLOW', 'IBM_DATASTAGE', 'MS_SSIS', 'ODI_SESSION', 'ODI_LOAD_PLAN', 'SAS_4GL', 'SAS_DI', 'SAS_JOB', 'SAS_VIYA_JOB', 'TALEND_JOB', 'DBT_JOB', 'SAP_R3_JOB', 'SAP_R3_VARIANT_CREATE', 'SAP_R3_VARIANT_COPY', 'SAP_R3_VARIANT_UPDATE', 'SAP_R3_VARIANT_DELETE', 'SAP_R3_COPY_EXISTING_JOB', 'SAP_R3_START_SCHEDULED_JOB', 'SAP_R3_JOB_INTERCEPTOR', 'SAP_MODIFY_INTERCEPTION_CRITERIA', 'SAP_R3_INTERCEPTED_JOB_SENSOR', 'SAP_R3_JOB_MONITOR', 'SAP_R3_RAISE_EVENT', 'SAP_R3_EVENT_SENSOR', 'SAP_BW_PROCESS_CHAIN', 'SAP_ARCHIVE', 'SAP_FUNCTION_MODULE_CALL', 'SAP_READ_TABLE', 'SAP_CM_PROFILE_ACTIVATE', 'SAP_CM_PROFILE_DEACTIVATE', 'SAP_EXPORT_CALENDAR', 'SAP_EXPORT_JOB', 'SAP_4H_JOB', 'SAP_4H_VARIANT_CREATE', 'SAP_4H_VARIANT_COPY', 'SAP_4H_VARIANT_UPDATE', 'SAP_4H_VARIANT_DELETE', 'SAP_4H_COPY_EXISTING_JOB', 'SAP_4H_START_SCHEDULED_JOB', 'SAP_4H_JOB_INTERCEPTOR', 'SAP_4H_MODIFY_INTERCEPTION_CRITERIA', 'SAP_4H_INTERCEPTED_JOB_SENSOR', 'SAP_4H_JOB_MONITOR', 'SAP_4H_RAISE_EVENT', 'SAP_4H_EVENT_SENSOR', 'SAP_4H_BW_PROCESS_CHAIN', 'SAP_4H_ARCHIVE', 'SAP_4H_FUNCTION_MODULE_CALL', 'SAP_4H_READ_TABLE', 'SAP_4H_CM_PROFILE_ACTIVATE', 'SAP_4H_CM_PROFILE_DEACTIVATE', 'SAP_4H_EXPORT_CALENDAR', 'SAP_4H_EXPORT_JOB', 'SAP_ODATA_API_CALL', 'SAP_IBP_JOB', 'ORACLE_EBS_PROGRAM', 'ORACLE_EBS_REQUEST_SET', 'ORACLE_EBS_EXECUTE_PROGRAM', 'ORACLE_EBS_EXECUTE_REQUEST_SET', 'PEOPLESOFT_APPLICATION_ENGINE_TASK', 'PEOPLESOFT_CRW_ONLINE_TASK', 'PEOPLESOFT_CRYSTAL_REPORTS_TASK', 'PEOPLESOFT_CUBE_BUILDER_TASK', 'PEOPLESOFT_NVISION_TASK', 'PEOPLESOFT_SQR_PROCESS_TASK', 'PEOPLESOFT_SQR_REPORT_TASK', 'PEOPLESOFT_WINWORD_TASK', 'PEOPLESOFT_JOB_TASK', 'JIRA_ISSUE_SENSOR', 'JIRA_ADD_ISSUE', 'SERVICE_NOW_CREATE_INCIDENT', 'SERVICE_NOW_RESOLVE_INCIDENT', 'SERVICE_NOW_CLOSE_INCIDENT', 'SERVICE_NOW_UPDATE_INCIDENT', 'SERVICE_NOW_INCIDENT_STATUS_SENSOR', 'BMC_REMEDY_INCIDENT', 'AUTOMATE_NOW_TRIGGER_EVENT', 'APACHE_AIRFLOW_RUN_DAG', 'ANSIBLE_PLAYBOOK', 'ANSIBLE_PLAYBOOK_PATH', 'CTRLM_ADD_CONDITION', 'CTRLM_DELETE_CONDITION', 'CTRLM_ORDER_JOB', 'CTRLM_CREATE_JOB', 'CTRLM_RESOURCE_TABLE_ADD', 'CTRLM_RESOURCE_TABLE_UPDATE', 'CTRLM_RESOURCE_TABLE_DELETE', 'UI_PATH', 'BLUE_PRISM', 'ROBOT_FRAMEWORK_START_ROBOT', 'MICROSOFT_POWER_BI_DATASET_REFRESH', 'MICROSOFT_POWER_BI_DATAFLOW_REFRESH', 'TELEGRAM_MESSAGE', 'WHATSAPP_MESSAGE', 'SYSTEM_MONITOR', 'SYSTEM_PROCESS_MONITOR', IgnoreCase = $false)]
        [Parameter(Mandatory = $True, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $True, ParameterSetName = 'Templates')]
        [string]$Type,
        [Parameter(Mandatory = $True, ParameterSetName = 'Templates')]
        [switch]$Templates,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [switch]$OnlyRunning,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [switch]$Formatted,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Templates')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Templates')]
        [int32]$endRow = 2000,        
        [ValidateSet('id', 'startTime', 'agent', 'createdBy', 'dateCreated', 'duration', 'endTime', 'firstStartTime', 'lastUpdated', 'name', 'node', 'pid', 'processingLaunchType', 'processingStatus', 'template', 'weight', IgnoreCase = $false)]
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [string]$sortBy = 'id',
        [ValidateSet('createdBy', 'dateCreated', 'id', 'lastUpdated', 'priority', 'simpleId', 'tags', 'weight', IgnoreCase = $false)]
        [Parameter(Mandatory = $False, ParameterSetName = 'Templates')]
        [string]$sortTemplatesBy = 'id',
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $False, ParameterSetName = 'Templates')]
        [switch]$Descending
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_constructor', 'AdvancedCriteria')
    $BodyObject.Add('operator', 'and')
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    $BodyObject.Add('_textMatchStyle', 'substring')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    If ($Templates -eq $true) {        
        $BodyObject.Add('criteria', '{"fieldName":"taskType","operator":"equals","value":"' + $Type + '"}')
        $BodyObject.Add('_componentId', 'ProcessingTemplateList')
        $BodyObject.Add('_dataSource', 'ProcessingTemplateDataSource')
        If ($Descending -eq $true) {
            [string]$sortTemplatesBy = ('-' + $sortTemplatesBy)
        }
        $BodyObject.Add('_sortBy', $sortTemplatesBy)
        [string]$command = '/processingTemplate/read'
    }
    Else {
        $BodyObject.Add('criteria1', '{"fieldName":"archived","operator":"equals","value":false}')
        $BodyObject.Add('criteria2', '{"fieldName":"isProcessing","operator":"equals","value":true}')
        $BodyObject.Add('criteria3', '{"fieldName":"itemType","operator":"equals","value":"' + $Type + '"}')
        $BodyObject.Add('_componentId', 'ProcessingList')
        $BodyObject.Add('_dataSource', 'ProcessingDataSource')
        If ($Descending -eq $true) {
            [string]$sortBy = ('-' + $sortBy)
        }
        $BodyObject.Add('_sortBy', ($sortBy))
        [string]$command = '/processing/read'
    }
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
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
    [array]$Tasks = $results.response.data
    [int32]$Tasks_count = $Tasks.Count
    If ($Tasks_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 tasks. Is there something else wrong? Was this instance recently built?"
        Break
    }
    If ($OnlyRunning -eq $true) {
        [array]$Tasks = $Tasks | Where-Object { $_.processingStatus -eq 'EXECUTING' }
        [int32]$Tasks_Running_Count = $Tasks.Count
        If ($Tasks_Running_Count -eq 0) {
            Write-Warning -Message "There were [$Tasks_count] tasks found but 0 of them were running. Are you sure you intended to use the -OnlyRunning parameter?"
            Break
        }
    }
    If ($Formatted -eq $true) {
        [datetime]$Current_Date = (Microsoft.PowerShell.Utility\Get-Date).ToUniversalTime()
        [array]$Tasks = $Tasks | ForEach-Object {
            [string]$status = $_.processingStatus
            If ($status -eq 'EXECUTING') {
                [string]$Progress = "{0:P2}" -f (([int64]($Current_Date - (Get-Date $_.startTime)).TotalMilliseconds) / $_.estimatedDuration)
                [string]$processing_status = "Executing $Progress"
                [string]$duration = ($Current_Date - (Microsoft.PowerShell.Utility\Get-Date -Date ($_.startTime))).ToString("dd'd 'hh'h 'mm'm 'ss's'");
            }
            Else {
                [string]$duration = (New-TimeSpan -Seconds ($_.duration / 1000)).ToString("dd'd 'hh'h 'mm'm 'ss's'")
                [string]$processing_status = $_.processingStatus
            }
            [PSCustomObject]@{
                'Processing'        = $_.rootProcessingName;
                'Processing Status' = $processing_status;
                'Tags'              = $_.Tags;
                'Duration'          = $duration;
                'Type'              = $_.taskType;
            }
        }
    }
    Return $Tasks
}

Function Start-AutomateNOWTask {
    <#
    .SYNOPSIS
    Starts a task from the Design templates of an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Start-AutomateNOWTask` cmdlet starts a task from the Design templates of an instance of AutomateNOW!
    
    .PARAMETER Type
    Mandatory string representing the type of task (of which there are 218). For example, 'SH' for shell scripts. Valid choices are: 'SH','AE_SHELL_SCRIPT','PYTHON','PERL','RUBY','GROOVY','POWERSHELL','JAVA','SCALA','SH_MONITOR','PYTHON_MONITOR','PERL_MONITOR','RUBY_MONITOR','GROOVY_MONITOR','POWERSHELL_MONITOR','FILE_TRANSFER','XFTP_COMMAND','DATASOURCE_UPLOAD_FILE','DATASOURCE_DOWNLOAD_FILE','DATASOURCE_DELETE_FILE','FILE_SENSOR','RDBMS_STORED_PROCEDURE','RDBMS_SQL_STATEMENT','RDBMS_SQL','SQL_SENSOR','REDIS_SET','REDIS_GET','REDIS_DELETE','REDIS_CLI','MONGO_DB_INSERT','IBM_MQ_SEND','IBM_MQ_SENSOR','RABBIT_MQ_SEND','RABBIT_MQ_SENSOR','KAFKA_SEND','KAFKA_SENSOR','JMS_SEND','JMS_SENSOR','AMQP_SEND','MQTT_SEND','XMPP_SEND','STOMP_SEND','Z_OS_DYNAMIC_JCL','Z_OS_STORED_JCL','Z_OS_COMMAND','Z_OS_JES_JOB_SENSOR','AS400_BATCH_JOB','AS400_PROGRAM_CALL','RAINCODE_DYNAMIC_JCL','RAINCODE_STORED_JCL','OPENTEXT_DYNAMIC_JCL','OPENTEXT_STORED_JCL','HDFS_UPLOAD_FILE','HDFS_APPEND_FILE','HDFS_DOWNLOAD_FILE','HDFS_DELETE_FILE','HDFS_CREATE_DIRECTORY','HDFS_DELETE_DIRECTORY','HDFS_RENAME','SPARK_JAVA','SPARK_SCALA','SPARK_PYTHON','SPARK_R','SPARK_SQL','FLINK_RUN_JOB','FLINK_JAR_UPLOAD','FLINK_JAR_DELETE','HTTP_REQUEST','REST_WEB_SERVICE_CALL','SOAP_WEB_SERVICE_CALL','HTTP_MONITOR','EMAIL_SEND','EMAIL_CONFIRMATION','EMAIL_INPUT','EMAIL_SENSOR','AWS_GLUE_WORKFLOW','AWS_GLUE_TRIGGER','AWS_GLUE_CRAWLER','AWS_GLUE_JOB','AWS_EMR_WORKFLOW','AWS_EMR_ADD_STEPS','AWS_EMR_CANCEL_STEPS','AWS_EMR_TERMINATE_JOB_FLOW','AWS_EMR_CONTAINER_MONITOR','AWS_EMR_JOB_FLOW_MONITOR','AWS_EMR_STEP_MONITOR','AWS_EMR_NOTEBOOK_MONITOR','AWS_EMR_PUT','AWS_EMR_GET','AWS_EMR_START_NOTEBOOK_EXECUTION','AWS_EMR_STOP_NOTEBOOK_EXECUTION','AWS_EMR_API_COMMAND','AWS_SAGE_MAKER_ADD_MODEL','AWS_SAGE_MAKER_DELETE_MODEL','AWS_SAGE_MAKER_PROCESSING','AWS_SAGE_MAKER_TRAINING','AWS_SAGE_MAKER_TRANSFORM','AWS_SAGE_MAKER_API_COMMAND','AWS_LAMBDA_INVOKE','AWS_LAMBDA_CREATE_FUNCTION','AWS_LAMBDA_DELETE_FUNCTION','AWS_EC2_START_INSTANCE','AWS_EC2_STOP_INSTANCE','AWS_EC2_TERMINATE_INSTANCE','AWS_EC2_DELETE_VOLUME','AWS_S3_DELETE_OBJECT','AWS_S3_COPY_OBJECT','AWS_S3_MOVE_OBJECT','AWS_S3_RENAME_OBJECT','AWS_BATCH_JOB','AWS_START_STEP_FUNCTION_STATE_MACHINE','AZURE_DATA_FACTORY_TRIGGER','AZURE_DATA_FACTORY_PIPELINE','AZURE_DATA_LAKE_JOB','AZURE_DATABRICKS_JOB','AZURE_DATABRICKS_TERMINATE_CLUSTER','AZURE_DATABRICKS_START_CLUSTER','AZURE_DATABRICKS_CLUSTER_MONITOR','AZURE_DATABRICKS_LIST_CLUSTERS','AZURE_DATABRICKS_DELETE_CLUSTER','INFORMATICA_CLOUD_TASKFLOW','INFORMATICA_WORKFLOW','INFORMATICA_WS_WORKFLOW','IBM_DATASTAGE','MS_SSIS','ODI_SESSION','ODI_LOAD_PLAN','SAS_4GL','SAS_DI','SAS_JOB','SAS_VIYA_JOB','TALEND_JOB','DBT_JOB','SAP_R3_JOB','SAP_R3_VARIANT_CREATE','SAP_R3_VARIANT_COPY','SAP_R3_VARIANT_UPDATE','SAP_R3_VARIANT_DELETE','SAP_R3_COPY_EXISTING_JOB','SAP_R3_START_SCHEDULED_JOB','SAP_R3_JOB_INTERCEPTOR','SAP_MODIFY_INTERCEPTION_CRITERIA','SAP_R3_INTERCEPTED_JOB_SENSOR','SAP_R3_JOB_MONITOR','SAP_R3_RAISE_EVENT','SAP_R3_EVENT_SENSOR','SAP_BW_PROCESS_CHAIN','SAP_ARCHIVE','SAP_FUNCTION_MODULE_CALL','SAP_READ_TABLE','SAP_CM_PROFILE_ACTIVATE','SAP_CM_PROFILE_DEACTIVATE','SAP_EXPORT_CALENDAR','SAP_EXPORT_JOB','SAP_4H_JOB','SAP_4H_VARIANT_CREATE','SAP_4H_VARIANT_COPY','SAP_4H_VARIANT_UPDATE','SAP_4H_VARIANT_DELETE','SAP_4H_COPY_EXISTING_JOB','SAP_4H_START_SCHEDULED_JOB','SAP_4H_JOB_INTERCEPTOR','SAP_4H_MODIFY_INTERCEPTION_CRITERIA','SAP_4H_INTERCEPTED_JOB_SENSOR','SAP_4H_JOB_MONITOR','SAP_4H_RAISE_EVENT','SAP_4H_EVENT_SENSOR','SAP_4H_BW_PROCESS_CHAIN','SAP_4H_ARCHIVE','SAP_4H_FUNCTION_MODULE_CALL','SAP_4H_READ_TABLE','SAP_4H_CM_PROFILE_ACTIVATE','SAP_4H_CM_PROFILE_DEACTIVATE','SAP_4H_EXPORT_CALENDAR','SAP_4H_EXPORT_JOB','SAP_ODATA_API_CALL','SAP_IBP_JOB','ORACLE_EBS_PROGRAM','ORACLE_EBS_REQUEST_SET','ORACLE_EBS_EXECUTE_PROGRAM','ORACLE_EBS_EXECUTE_REQUEST_SET','PEOPLESOFT_APPLICATION_ENGINE_TASK','PEOPLESOFT_CRW_ONLINE_TASK','PEOPLESOFT_CRYSTAL_REPORTS_TASK','PEOPLESOFT_CUBE_BUILDER_TASK','PEOPLESOFT_NVISION_TASK','PEOPLESOFT_SQR_PROCESS_TASK','PEOPLESOFT_SQR_REPORT_TASK','PEOPLESOFT_WINWORD_TASK','PEOPLESOFT_JOB_TASK','JIRA_ISSUE_SENSOR','JIRA_ADD_ISSUE','SERVICE_NOW_CREATE_INCIDENT','SERVICE_NOW_RESOLVE_INCIDENT','SERVICE_NOW_CLOSE_INCIDENT','SERVICE_NOW_UPDATE_INCIDENT','SERVICE_NOW_INCIDENT_STATUS_SENSOR','BMC_REMEDY_INCIDENT','AUTOMATE_NOW_TRIGGER_EVENT','APACHE_AIRFLOW_RUN_DAG','ANSIBLE_PLAYBOOK','ANSIBLE_PLAYBOOK_PATH','CTRLM_ADD_CONDITION','CTRLM_DELETE_CONDITION','CTRLM_ORDER_JOB','CTRLM_CREATE_JOB','CTRLM_RESOURCE_TABLE_ADD','CTRLM_RESOURCE_TABLE_UPDATE','CTRLM_RESOURCE_TABLE_DELETE','UI_PATH','BLUE_PRISM','ROBOT_FRAMEWORK_START_ROBOT','MICROSOFT_POWER_BI_DATASET_REFRESH','MICROSOFT_POWER_BI_DATAFLOW_REFRESH','TELEGRAM_MESSAGE','WHATSAPP_MESSAGE','SYSTEM_MONITOR','SYSTEM_PROCESS_MONITOR'

    .PARAMETER SimpleID
    Mandatory string representing the 'name' of the task. DO NOT include the domain in the name. In other words, 'my_task1' is correct but '[MyDomain]my_task1' is incorrect.

    .PARAMETER Domain
    Mandatory string representing the domain. Out of caution, this must be explicitly stated rather then assuming the domain based on the current session.

    .PARAMETER Description
    Optional string to specify the description

    .PARAMETER Priority
    Optional integer between 1 and 1000 indicating the priority of the task. The default is 0. See the docs for more.
    
    .PARAMETER Tags
    Optional string array containing the tags to include on running task

    .PARAMETER Folder
    Otional string representing the folder that the running tasks should be placed into

    .PARAMETER Hold
    Optional switch where "Items will be loaded with On Hold flag set on"
    
    .PARAMETER ForceLoad
    Optional switch where "Items will be loaded even if they Ignore Condition set on"

    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Start-AutomateNOWTask -Type SH -SimpleID 'Task1' -Domain 'Domain1' -Priority 5 -Tags "Tag1", "Tag2" -Folder "Folder1" -Hold -ForceLoad -Description "My task description"
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function (yet)
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
        [ValidateSet('SH', 'AE_SHELL_SCRIPT', 'PYTHON', 'PERL', 'RUBY', 'GROOVY', 'POWERSHELL', 'JAVA', 'SCALA', 'SH_MONITOR', 'PYTHON_MONITOR', 'PERL_MONITOR', 'RUBY_MONITOR', 'GROOVY_MONITOR', 'POWERSHELL_MONITOR', 'FILE_TRANSFER', 'XFTP_COMMAND', 'DATASOURCE_UPLOAD_FILE', 'DATASOURCE_DOWNLOAD_FILE', 'DATASOURCE_DELETE_FILE', 'FILE_SENSOR', 'RDBMS_STORED_PROCEDURE', 'RDBMS_SQL_STATEMENT', 'RDBMS_SQL', 'SQL_SENSOR', 'REDIS_SET', 'REDIS_GET', 'REDIS_DELETE', 'REDIS_CLI', 'MONGO_DB_INSERT', 'IBM_MQ_SEND', 'IBM_MQ_SENSOR', 'RABBIT_MQ_SEND', 'RABBIT_MQ_SENSOR', 'KAFKA_SEND', 'KAFKA_SENSOR', 'JMS_SEND', 'JMS_SENSOR', 'AMQP_SEND', 'MQTT_SEND', 'XMPP_SEND', 'STOMP_SEND', 'Z_OS_DYNAMIC_JCL', 'Z_OS_STORED_JCL', 'Z_OS_COMMAND', 'Z_OS_JES_JOB_SENSOR', 'AS400_BATCH_JOB', 'AS400_PROGRAM_CALL', 'RAINCODE_DYNAMIC_JCL', 'RAINCODE_STORED_JCL', 'OPENTEXT_DYNAMIC_JCL', 'OPENTEXT_STORED_JCL', 'HDFS_UPLOAD_FILE', 'HDFS_APPEND_FILE', 'HDFS_DOWNLOAD_FILE', 'HDFS_DELETE_FILE', 'HDFS_CREATE_DIRECTORY', 'HDFS_DELETE_DIRECTORY', 'HDFS_RENAME', 'SPARK_JAVA', 'SPARK_SCALA', 'SPARK_PYTHON', 'SPARK_R', 'SPARK_SQL', 'FLINK_RUN_JOB', 'FLINK_JAR_UPLOAD', 'FLINK_JAR_DELETE', 'HTTP_REQUEST', 'REST_WEB_SERVICE_CALL', 'SOAP_WEB_SERVICE_CALL', 'HTTP_MONITOR', 'EMAIL_SEND', 'EMAIL_CONFIRMATION', 'EMAIL_INPUT', 'EMAIL_SENSOR', 'AWS_GLUE_WORKFLOW', 'AWS_GLUE_TRIGGER', 'AWS_GLUE_CRAWLER', 'AWS_GLUE_JOB', 'AWS_EMR_WORKFLOW', 'AWS_EMR_ADD_STEPS', 'AWS_EMR_CANCEL_STEPS', 'AWS_EMR_TERMINATE_JOB_FLOW', 'AWS_EMR_CONTAINER_MONITOR', 'AWS_EMR_JOB_FLOW_MONITOR', 'AWS_EMR_STEP_MONITOR', 'AWS_EMR_NOTEBOOK_MONITOR', 'AWS_EMR_PUT', 'AWS_EMR_GET', 'AWS_EMR_START_NOTEBOOK_EXECUTION', 'AWS_EMR_STOP_NOTEBOOK_EXECUTION', 'AWS_EMR_API_COMMAND', 'AWS_SAGE_MAKER_ADD_MODEL', 'AWS_SAGE_MAKER_DELETE_MODEL', 'AWS_SAGE_MAKER_PROCESSING', 'AWS_SAGE_MAKER_TRAINING', 'AWS_SAGE_MAKER_TRANSFORM', 'AWS_SAGE_MAKER_API_COMMAND', 'AWS_LAMBDA_INVOKE', 'AWS_LAMBDA_CREATE_FUNCTION', 'AWS_LAMBDA_DELETE_FUNCTION', 'AWS_EC2_START_INSTANCE', 'AWS_EC2_STOP_INSTANCE', 'AWS_EC2_TERMINATE_INSTANCE', 'AWS_EC2_DELETE_VOLUME', 'AWS_S3_DELETE_OBJECT', 'AWS_S3_COPY_OBJECT', 'AWS_S3_MOVE_OBJECT', 'AWS_S3_RENAME_OBJECT', 'AWS_BATCH_JOB', 'AWS_START_STEP_FUNCTION_STATE_MACHINE', 'AZURE_DATA_FACTORY_TRIGGER', 'AZURE_DATA_FACTORY_PIPELINE', 'AZURE_DATA_LAKE_JOB', 'AZURE_DATABRICKS_JOB', 'AZURE_DATABRICKS_TERMINATE_CLUSTER', 'AZURE_DATABRICKS_START_CLUSTER', 'AZURE_DATABRICKS_CLUSTER_MONITOR', 'AZURE_DATABRICKS_LIST_CLUSTERS', 'AZURE_DATABRICKS_DELETE_CLUSTER', 'INFORMATICA_CLOUD_TASKFLOW', 'INFORMATICA_WORKFLOW', 'INFORMATICA_WS_WORKFLOW', 'IBM_DATASTAGE', 'MS_SSIS', 'ODI_SESSION', 'ODI_LOAD_PLAN', 'SAS_4GL', 'SAS_DI', 'SAS_JOB', 'SAS_VIYA_JOB', 'TALEND_JOB', 'DBT_JOB', 'SAP_R3_JOB', 'SAP_R3_VARIANT_CREATE', 'SAP_R3_VARIANT_COPY', 'SAP_R3_VARIANT_UPDATE', 'SAP_R3_VARIANT_DELETE', 'SAP_R3_COPY_EXISTING_JOB', 'SAP_R3_START_SCHEDULED_JOB', 'SAP_R3_JOB_INTERCEPTOR', 'SAP_MODIFY_INTERCEPTION_CRITERIA', 'SAP_R3_INTERCEPTED_JOB_SENSOR', 'SAP_R3_JOB_MONITOR', 'SAP_R3_RAISE_EVENT', 'SAP_R3_EVENT_SENSOR', 'SAP_BW_PROCESS_CHAIN', 'SAP_ARCHIVE', 'SAP_FUNCTION_MODULE_CALL', 'SAP_READ_TABLE', 'SAP_CM_PROFILE_ACTIVATE', 'SAP_CM_PROFILE_DEACTIVATE', 'SAP_EXPORT_CALENDAR', 'SAP_EXPORT_JOB', 'SAP_4H_JOB', 'SAP_4H_VARIANT_CREATE', 'SAP_4H_VARIANT_COPY', 'SAP_4H_VARIANT_UPDATE', 'SAP_4H_VARIANT_DELETE', 'SAP_4H_COPY_EXISTING_JOB', 'SAP_4H_START_SCHEDULED_JOB', 'SAP_4H_JOB_INTERCEPTOR', 'SAP_4H_MODIFY_INTERCEPTION_CRITERIA', 'SAP_4H_INTERCEPTED_JOB_SENSOR', 'SAP_4H_JOB_MONITOR', 'SAP_4H_RAISE_EVENT', 'SAP_4H_EVENT_SENSOR', 'SAP_4H_BW_PROCESS_CHAIN', 'SAP_4H_ARCHIVE', 'SAP_4H_FUNCTION_MODULE_CALL', 'SAP_4H_READ_TABLE', 'SAP_4H_CM_PROFILE_ACTIVATE', 'SAP_4H_CM_PROFILE_DEACTIVATE', 'SAP_4H_EXPORT_CALENDAR', 'SAP_4H_EXPORT_JOB', 'SAP_ODATA_API_CALL', 'SAP_IBP_JOB', 'ORACLE_EBS_PROGRAM', 'ORACLE_EBS_REQUEST_SET', 'ORACLE_EBS_EXECUTE_PROGRAM', 'ORACLE_EBS_EXECUTE_REQUEST_SET', 'PEOPLESOFT_APPLICATION_ENGINE_TASK', 'PEOPLESOFT_CRW_ONLINE_TASK', 'PEOPLESOFT_CRYSTAL_REPORTS_TASK', 'PEOPLESOFT_CUBE_BUILDER_TASK', 'PEOPLESOFT_NVISION_TASK', 'PEOPLESOFT_SQR_PROCESS_TASK', 'PEOPLESOFT_SQR_REPORT_TASK', 'PEOPLESOFT_WINWORD_TASK', 'PEOPLESOFT_JOB_TASK', 'JIRA_ISSUE_SENSOR', 'JIRA_ADD_ISSUE', 'SERVICE_NOW_CREATE_INCIDENT', 'SERVICE_NOW_RESOLVE_INCIDENT', 'SERVICE_NOW_CLOSE_INCIDENT', 'SERVICE_NOW_UPDATE_INCIDENT', 'SERVICE_NOW_INCIDENT_STATUS_SENSOR', 'BMC_REMEDY_INCIDENT', 'AUTOMATE_NOW_TRIGGER_EVENT', 'APACHE_AIRFLOW_RUN_DAG', 'ANSIBLE_PLAYBOOK', 'ANSIBLE_PLAYBOOK_PATH', 'CTRLM_ADD_CONDITION', 'CTRLM_DELETE_CONDITION', 'CTRLM_ORDER_JOB', 'CTRLM_CREATE_JOB', 'CTRLM_RESOURCE_TABLE_ADD', 'CTRLM_RESOURCE_TABLE_UPDATE', 'CTRLM_RESOURCE_TABLE_DELETE', 'UI_PATH', 'BLUE_PRISM', 'ROBOT_FRAMEWORK_START_ROBOT', 'MICROSOFT_POWER_BI_DATASET_REFRESH', 'MICROSOFT_POWER_BI_DATAFLOW_REFRESH', 'TELEGRAM_MESSAGE', 'WHATSAPP_MESSAGE', 'SYSTEM_MONITOR', 'SYSTEM_PROCESS_MONITOR', IgnoreCase = $false)]
        [Parameter(Mandatory = $True)]
        [string]$Type,
        [Parameter(Mandatory = $True)]
        [string]$SimpleID,
        [Parameter(Mandatory = $True)]
        [string]$Domain,
        [Parameter(Mandatory = $False)]
        [string]$Description,        
        [Parameter(Mandatory = $False)]
        [ValidateRange(0, 1000)]
        [int32]$Priority = 0,
        [Parameter(Mandatory = $False)]
        [string[]]$Tags,
        [Parameter(Mandatory = $False)]
        [string]$Folder,
        [Parameter(Mandatory = $False)]
        [switch]$Hold,
        [Parameter(Mandatory = $False)]
        [switch]$ForceLoad
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    If ($SimpleID -match '^\[[0-9a-zA-Z]{1,}][0-9a-zA-Z_.-]{1,}$') {
        Write-Warning -Message "Please do not include the name of the domain in the Id of the task. This will be handled automatically."
        Break
    }
    ElseIf ($SimpleID -notmatch '^[0-9a-zA-Z_.-]{1,}$') {
        Write-Warning -Message "The Id or name of the task is limited to digits, letters (upper/lower case), underscores, periods and hyphens. Please adjust."
        Break
    }
    [string]$command = '/processing/executeNow'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    

    [string]$id = ('[' + $Domain + ']' + $SimpleID)
    $BodyObject.Add('id', $id)

    [string]$processingTimestamp = Microsoft.PowerShell.Utility\Get-Date -Date ((Microsoft.PowerShell.Utility\Get-Date).ToUniversalTime()) -Format 'yyyy-MM-ddTHH:mm:ss.fff'
    $BodyObject.Add('processingTimestamp', $processingTimestamp)

    If ($Hold -eq $True) {
        $BodyObject.Add('hold', $true)
    }

    If ($ForceLoad -eq $True) {
        $BodyObject.Add('forceLoad', $true)
    }

    $BodyObject.Add('runId', $id)

    $BodyObject.Add('operationId', 'executeNow')

    [string]$formattedTimeStamp = Microsoft.PowerShell.Utility\Get-Date -Date ((Microsoft.PowerShell.Utility\Get-Date).ToUniversalTime()) -Format 'yyyy-MM-dd HH:mm:ss'    
    $BodyObject.Add('name', "Manual execution - $SimpleID - $formattedTimeStamp")

    If ($Tags.Count -gt 0) {
        $BodyObject.Add('tags', $Tags)
    }

    If ($Folder.Length -gt 0) {
        $BodyObject.Add('folder', $Folder)
    }

    If ($Description.Length -gt 0) {
        $BodyObject.Add('description', $Description)
    }
    
    If ($Priority -gt 0) {
        $BodyObject.Add('priority', $Priority)
    }

    $BodyObject.Add('parameters', '{}')
    $BodyObject.Add('_operationType', 'add')
    $BodyObject.Add('_operationId', 'executeNow')
    $BodyObject.Add('_textMatchStyle', 'exact')
    $BodyObject.Add('_dataSource', 'ProcessingDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject
    Write-Verbose -Message "Sending the following URL-encoded body: $Body"
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
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
    Return $results
}

#EndRegion

#Region - TimeZones
Function Read-AutomateNOWTimeZone {
    <#
    .SYNOPSIS
    Reads the available time zones from the assets of an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Read-AutomateNOWTimeZone` reads the available time zones from the assets of an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Read-AutomateNOWTimeZone.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Read-AutomateNOWTimeZone
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([AutomateNOWTimezone[]])]
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
    [string]$Body = ConvertTo-QueryString -InputObjects $BodyObject    
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
    [AutomateNOWTimezone[]]$TimeZones = $results.response.data
    [int32]$TimeZones_count = $TimeZones.Count
    If ($TimeZones_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 time zones..."
        Break
    }
    Return $TimeZones
}

#EndRegion

#Region - TriggerLog
Function Get-AutomateNOWTriggerLog {
    <#
    .SYNOPSIS
    Gets the trigger logs from the domain of an AutomateNOW! instance
    
    .DESCRIPTION    
    The `Get-AutomateNOWTriggerLog` retrieves all of the trigger logs from the domain of an AutomateNOW! instance
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWTriggerLog.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWTriggerLog
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    There are no parameters yet for this function.
    #>
    [OutputType([array])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/executeProcessingTriggerLog'
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
    [PSCustomObject[]]$nodes = $results.response.data
    [int32]$nodes_count = $nodes.Count
    If ($nodes_count -eq 0) {
        Write-Warning -Message "Somehow there are no trigger logs available. Is this a newly installed instance which has not been configured yet?"
        Break
    }
    Return $nodes
}
#Endregion

#Region - Users
Function Get-AutomateNOWUser {
    <#
    .SYNOPSIS
    Gets the details of the currently authenticated user
    
    .DESCRIPTION    
    The `Get-AutomateNOWUser` cmdlet invokes the /secUser/getUserInfo endpoint to retrieve information about the currently authenticated user (meaning you)
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWUser.
    
    .OUTPUTS
    A PSCustomObject
    
    .EXAMPLE
    Get-AutomateNOWUser
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.

    Get-AutomateNOWUser DOES NOT refresh the token automatically!
    #>
    [OutputType([PSCustomObject])]
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
        [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Invoke-AutomateNOWAPI failed due to execute [$command] due to [$Message]."
        Break
    }
    Return $results
}

#Endregion

#Region - Workflows

Function Get-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Gets the workflow objects from an instance of AutomateNOW!
    
    .DESCRIPTION    
    The `Get-AutomateNOWWorkflow` cmdlet gets the workflow objects from an instance of AutomateNOW!
    
    .INPUTS
    None. You cannot pipe objects to Get-AutomateNOWWorkflow.
    
    .OUTPUTS
    An array of PSCustomObjects
    
    .EXAMPLE
    Get-AutomateNOWWorkflow
    
    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters yet for this function.
    #>
    [OutputType([PSCustomObject])]
    [Cmdletbinding()]
    Param(
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$command = '/processingTemplate/read'
    $BodyObject = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
    $BodyObject.Add('_constructor', 'AdvancedCriteria')
    $BodyObject.Add('operator', 'and')
    $BodyObject.Add('criteria', '{"fieldName":"workflowType","operator":"equals","value":"STANDARD"}')
    $Body = ConvertTo-QueryString -InputObjects $BodyObject    
    [string]$Instance = $anow_session.Instance
    [hashtable]$parameters = @{}
    $parameters.Add('Command', $command)
    $parameters.Add('Method', 'POST')
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
    [array]$WorkFlows = $Results.response.data
    [int32]$WorkFlows_count = $WorkFlows.Count
    If ($WorkFlows_count -eq 0) {
        Write-Warning -Message "Somehow there are 0 workflows..."
        Break
    }
    Return $WorkFlows
}

#endregion

