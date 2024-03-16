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
                ElseIf ($ParameterName -eq '_oldValues') {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, $Item.value)
                }
                Else {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($Item.value))
                }
            }
        }
        ElseIf ($InputObject.GetType().FullName.StartsWith('ANOW')) {
            foreach ($Item in $IncludeProperties) {
                if ($QueryString.Length -gt 0) { [void]$QueryString.Append('&') }
                [string]$ParameterName = $Item
                If ($InputObject."$Item" -is [boolean]) {
                    If ($InputObject."$Item" -eq $true) {
                        [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('true'))
                    }
                    Else {
                        [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode('false'))
                    }
                }
                ElseIf ($ParameterName -eq 'tags') {
                    [int32]$tag_count = $InputObject."$Item".Count
                    If ($tag_count -eq 0) {
                        Write-Warning -Message "Somehow there were no tags found while converting a parameter block to query string!"
                        Break
                    }
                    [int32]$current_tag = 1
                    ForEach ($tag_id in $InputObject."$Item") {
                        If ($current_tag -lt $tag_count) {
                            [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, ([System.Net.WebUtility]::UrlEncode($tag_id) + '&'))
                        }
                        Else {
                            [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($tag_id))
                        }
                        $current_tag++
                    }
                }
                Else {
                    [void]$QueryString.AppendFormat('{0}={1}', $ParameterName, [System.Net.WebUtility]::UrlEncode($InputObject."$Item"))
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
        [string]$Result = $Result -creplace '\+', '%20' -creplace 'criteria[0-9]{1,}=', 'criteria=' -creplace 'setWorkspaceTags[0-9]{1,}=', 'setWorkspaceTags=' -creplace 'tags[0-9]{1,}=', 'tags='
        Write-Output $Result
    }
}

Function New-AutomateNOWDefaultProcessingTitle {
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [string]$simpleId
    )
    $Error.Clear()
    Try {
        [ANOWTimeZone]$user_timezone_object = $anow_session.supported_timezones | Where-Object { $_.id -eq ($anow_session.user_timezone) } | Select-Object -First 1
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Could not extract the current AutomateNOW timezone details for the logged in user due to [$Message]."
        Break
    }
    [int64]$current_offset = $user_timezone_object.rawOffset
    If ($user_timezone_object.inDaylightTime -eq $true) {
        [int64]$current_offset = ($current_offset + $user_timezone_object.dstsavings)
    }
    [datetime]$current_utc_time = (Get-Date).ToUniversalTime()
    [datetime]$current_offset_time = $current_utc_time.AddMilliseconds($current_offset)
    $current_server_time_display = Get-Date -Date $current_offset_time -format 'yyyy-MM-dd HH:mm:ss'
    [string]$title = ('Manual execution - ' + $simpleId + ' - ' + $current_server_time_display)
    Return $title
}

Function New-WebkitBoundaryString {
    [string]$webkit_boundary = (((65..90) | Sort-Object { Get-Random } | Select-Object -First 5 | ForEach-Object { [char]$_ }) + ((48..57) | Sort-Object { Get-Random } | Select-Object -First 5 | ForEach-Object { [char]$_ }) + ((97..122) | Sort-Object { Get-Random } | Select-Object -First 6 | ForEach-Object { [char]$_ }) | Sort-Object { Get-Random }) -join ''
    Return $webkit_boundary
}

Function Protect-AutomateNOWAuthenticationString {
    <#
    .SYNOPSIS
    "Encrypts" and encodes a plain text string for use of authentication with certain object types within an instance of AutomateNOW!

    .DESCRIPTION
    "Encrypts" and encodes a plain text string for use of authentication with certain object types within an instance of AutomateNOW!

    .PARAMETER Pass
    The plain text string to "encrypt" and decode

    .PARAMETER Key
    Optional 16-byte encryption key. The default will be used when this parameter is not specified.

    .INPUTS
    A single plain text string is accepted.

    .OUTPUTS
    The protected string is returned in plain text (base64 encoded) format

    .EXAMPLE
    Protect-AutomateNOWEncryptedString -Pass 'MySecretString'

    Return 'DxEIEAwFBQoMChMQBQoREAwFERATEAgKFgoQCg=='

    .NOTES

    #>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Pass,
        [Parameter(Mandatory = $false)]
        [byte[]]$Key = @(7, 22, 15, 11, 1, 24, 8, 13, 16, 10, 5, 17, 12, 19, 27, 9),
        [Parameter(Mandatory = $false)]
        [switch]$IncludePrefix
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
    If ($IncludePrefix -eq $true) {
        [string]$encrypted_string = ('ENCRYPTED::' + $encrypted_string)
    }
    Return $encrypted_string
}

Function Unprotect-AutomateNOWEncryptedString {
    <#
    .SYNOPSIS
    Decrypts and decodes a protected string from certain object types within an instance of AutomateNOW!

    .DESCRIPTION
    Decrypts and decodes a protected string from certain object types within an instance of AutomateNOW!

    .PARAMETER protected_string
    Mandatory valid base64 string that you retrieved from the AutomateNOW console while viewing the Endpoint objects. Do not include the 'ENCRYPTED::' portion of the string but if you do it will be removed for you automatically.

    .PARAMETER Key
    Optional 16-byte encryption key. The default will be used when this parameter is not specified.

    .INPUTS
    A single base64 encoded string is accepted.

    .OUTPUTS
    The unprotected string is returned in plain text.

    .EXAMPLE
    Unprotect-AutomateNOWEncryptedString -protected_string 'DREFCgsKCwoHChEFDQoFChMQBQobEw=='

    .NOTES

    #>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [ValidateScript({ $_ -cmatch '^([ENCRYPTED::]{11}|)(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$' })]
        [Parameter(Mandatory = $true)]
        [string]$protected_string,
        [Parameter(Mandatory = $false)]
        [int32[]]$Key = @(7, 22, 15, 11, 1, 24, 8, 13, 16, 10, 5, 17, 12, 19, 27, 9)
    )
    Function Format-Byte {
        [OutputType([int32[]])]
        [CmdletBinding()]
        Param(
            [byte]$byte
        )
        [int32]$first = (-bnot $byte -shr 0) -band 0x0f
        [int32]$second = (-bnot $byte -shr 4) -band 0x0f
        Return @($first, $second)
    }
    Function Confirm-Byte {
        [OutputType([int32])]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [int32]$first_byte,
            [Parameter(Mandatory = $true)]
            [int32]$second_byte
        )
        For ($i = 0; $i -lt 256; $i++) {
            [int32[]]$attempted_bytes = Format-Byte -byte ([byte]$i)
            [int32]$attempted_byte_first = $attempted_bytes[0]
            [int32]$attempted_byte_second = $attempted_bytes[1]
            If (($attempted_byte_first -eq $first_byte) -and ($attempted_byte_second -eq $second_byte)) {
                Return $i
                Break
            }
        }
    }
    If ($protected_string -match '^ENCRYPTED::') {
        [string]$protected_string = $protected_string -replace 'ENCRYPTED::'
    }
    $Error.Clear()
    Try {
        [int32[]]$encrypted_byte_array = [System.Convert]::FromBase64String($protected_string)
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Decoding the protected string [$protected_string] from base64 failed due to [$Message]"
        Break
    }
    [int32[]]$decoded_byte_array = For ($i = 0; $i -lt $encrypted_byte_array.Count; $i = $i + 2) {
        [int32]$first_byte = $Key.IndexOf($encrypted_byte_array[$i])
        [int32]$second_byte = $Key.IndexOf($encrypted_byte_array[$i + 1])
        [int32]$decoded_byte = Confirm-Byte -first_byte $first_byte -second_byte $second_byte
        $decoded_byte
    }
    [string]$unprotected_password = ([char[]]$decoded_byte_array -join '')
    Return $unprotected_password
}

#EndRegion

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
            401 { "You received HTTP Code $return_code (Unauthorized). HAS YOUR TOKEN EXPIRED? ARE YOU ON THE CORRECT DOMAIN? :-)" }
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
#EndRegion

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
        Write-Warning -Message 'Please use Switch-AutomateNOWDomain to switch your domain. Use Get-AutomateNOWDomain or include the -Domain parameter with Connect-AutomateNOW'
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
    Function New-ANOWAuthenticationPayload {
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
        [string]$encrypted_string = Protect-AutomateNOWAuthenticationString -Pass $Pass -Key $Key
        [hashtable]$payload = @{}
        $payload.Add('j_username', $User)
        $payload.Add('j_password', "ENCRYPTED::$encrypted_string")
        $payload.Add('superuser', $SuperUser)
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
        If ($current_date.IsDaylightSavingTime() -eq $true) {
            $current_date.AddHours(1)
        }
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
        ElseIf ($AuthenticationObject.expires_in -isnot [int64]) {
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
    [boolean]$dst = (Get-Date).IsDaylightSavingTime()
    If ($dst -eq $true) {
        [System.TimeSpan]$utc_offset = ($timezone.BaseUtcOffset + (New-TimeSpan -Minutes 60))
    }
    Else {
        [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    }
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
    $anow_session.Add('header', $Header)
    Write-Verbose -Message 'Global variable $anow_session.header has been set. Refer to this as your authentication header.'
    $Error.Clear()
    Try {
        New-Variable -Name 'anow_session' -Scope Global -Value $anow_session
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning "New-Variable failed to create the session properties object due to [$Message]"
        Break
    }
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
        If ($Domain.Length -gt 0) {            
            $Header['domain'] = $Domain
            Import-AutomateNOWTimeZone
            $Error.Clear()
            Try {
                [ANOWTimeZone]$server_timezone = Get-AutomateNOWTimeZone -Id ($instance_info.defaultTimeZone)
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to parse the available time zones from [$Instance] into an array of valid ANOWTimeZone class objects due to [$Message]. We were so close! Did something change in InfiniteDATA's code? :-)"
                Break
            }
            $Error.Clear()
            Try {
                [ANOWTimeZone[]]$available_timezones = ($instance_info.timeZones) -split ',' | Get-AutomateNOWTimeZone
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
        }
        Else {
            Import-AutomateNOWLocalTimeZone
        }    
        $anow_session.Add('server_timezone', $server_timezone)
        $anow_session.Add('instance_info', $instance_info_table)
        [PSCustomObject]$CalendarInfo = [PSCustomObject]@{'firstDayOfWeek' = $instance_info.firstDayOfWeek; 'firstCalendarYear' = $instance_info.firstCalendarYear; 'lastCalendarYear' = $instance_info.lastCalendarYear; }
        $anow_session.Add('calendar_info', $CalendarInfo)
        [string]$applicationVersion = $anow_session.instance_info.applicationVersion
        [string]$application = $anow_session.instance_info.application
        If ($Id.length -eq 0) {
            $Error.Clear()
            Try {
                [ANOWUserInfo]$userInfo = Get-AutomateNOWUser -LoggedOnUser
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning "Get-AutomateNOWUser failed to get the currently logged in user info due to [$Message]."
                Break
            }
            [string]$Id = $userInfo.Id
        }
        $Error.Clear()
        $anow_session['user_details'] = $userInfo
        [string]$userName = $userInfo.id
        If ($userName.Length -eq 0) {
            Write-Warning -Message "Somehow the username property is not present from the user object. This is fatal."
            Break
        }
        $anow_session['User'] = $userName
        If ($userInfo.domains -match ',') {
            [string[]]$domains = $userInfo.domains -split ',' | Sort-Object
        }
        Else {
            [string[]]$domains = $userInfo.domains -split ' ' | Sort-Object
        }
        [int32]$domain_count = $domains.Count
        Write-Verbose -Message "Detected $domain_count domains"
        If ($domain_count -gt 0) {
            $anow_session.Add('available_domains', $domains)
        }
        Else {
            Write-Warning "Somehow the count of domains is zero."
            Break
        }
        If ($Domain.Length -eq 0) {
            [string]$domains_display = $domains -join ', '
            Write-Warning -Message "Please try Connect-AutomateNOW again with the -Domain parameter with one of these case-sensitive domains: $domains_display"
            Remove-Variable anow_session -Force
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
                Write-Warning -Message "The domain you chose with -Domain [$Domain] is not the same as the one on [$instance]. Please check the domain name again and note that it is case-sensitive."
                Break
            }
        }
        Else {
            If ($domains -ccontains $Domain) {
                If ($Domain.Length -gt 0) {
                    $anow_session.header['domain'] = $Domain
                }
            }
            ElseIf ($Domain.Length -gt 0) {
                Write-Warning -Message "The domain you chose with -Domain [$Domain] is not available on [$instance]. Please check the domain name again and note that it is case-sensitive."
                Break
            }
            Else {
                Write-Verbose -Message "Proceeding without a domain selected"
            }
        }
        $anow_session.Add('current_domain', $Domain)
        $anow_session.Add('protocol', $protocol)
        $Error.Clear()
        Try {
            [ANOWTimeZone]$defaultTimeZone = $userInfo.defaultTimeZone
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning "Failed to convert the user object's default time zone into an [ANOWTimeZone] object due to [$message]"
            Break
        }
        If ($defaultTimeZone.Length -gt 0) {
            $anow_session.Add('user_timezone', $defaultTimeZone)
        }
        [string]$motd_message = "`r`nWelcome to $application version $applicationVersion"
        If ($SkipMOTD -ne $true) {
            Write-Information -MessageData $motd_message
        }
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
    If ($Quiet -ne $true) {
        Format-Table -InputObject $anow_session_display -AutoSize -Wrap
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
        [string]$response_display = $results.response | ConvertTo-Json -Compress
        Write-Verbose -Message $response_display
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Somehow there was no response data. Please look into this."
        Break
    }
    Else {
        [string]$response_display = $results.response | ConvertTo-Json -Compress
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
    Switch-AutomateNOWDomain -Domain 'Production'

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
    If ($anow_session.available_domains -cnotcontains $Domain) {
        [string]$available_domains = $anow_session.available_domains -join ', '
        If ($anow_session.available_domains -contains $Domain) {
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
        If ($null -eq $anow_session.current_domain) {
            $anow_session.header.Add('current_domain', $Domain)
        }
        Else {
            $anow_session.current_domain = $Domain
        }

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
    The global session variable $anow_session will be updated.

    .EXAMPLE
    Update-AutomateNOWToken

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
    [boolean]$dst = (Get-Date).IsDaylightSavingTime()
    If ($dst -eq $true) {
        [System.TimeSpan]$utc_offset = ($timezone.BaseUtcOffset + (New-TimeSpan -Minutes 60))
    }
    Else {
        [System.TimeSpan]$utc_offset = $timezone.BaseUtcOffset
    }
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

#EndRegion

#Region - Object Functions

#Region - Approvals

Function Get-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Gets the Approvals from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Approvals from an AutomateNOW! instance

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the Approval from the pipeline or individually (but not an array) or you can specify by start and end rows.

    .OUTPUTS
    An array of one or more [ANOWApproval] class objects

    .EXAMPLE
    Gets all of the Approval objects
    Get-AutomateNOWApproval

    .EXAMPLE
    Gets a specific Approval object
    Get-AutomateNOWApproval -Id 'my_Approval_01'

    .EXAMPLE
    Gets a series of Approvals using the pipeline
    @( 'my_Approval_01', 'my_Approval_02' ) | Get-AutomateNOWApproval

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Approvals.

    #>
    [OutputType([ANOWApproval[]])]
    [Cmdletbinding( DefaultParameterSetName = 'Default' )]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$endRow = 100,
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $False, ParameterSetName = 'Id', ValueFromPipeline = $true)]
        [string]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
            [string]$textMatchStyle = 'exactCase'
            $Body.'_operationId' = 'read'
        }
        Else {
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            [string]$textMatchStyle = 'exact'
            $Body.'_componentId' = 'ApprovalConfigurationList'
        }
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_dataSource' = 'ApprovalConfigurationDataSource'
        $Body.'_operationType' = 'fetch'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/approvalConfiguration/read?' + $Body)
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] while running Get-AutomateNOWApproval due to [$Message]."
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
            [ANOWApproval[]]$approvals = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWApproval] objects due to [$Message]."
            Break
        }
        If ($Approvals.Count -gt 0) {
            Return $Approvals
        }
    }
    End {

    }
}

Function Set-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Changes the settings of an Approval on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of an Approval on an AutomateNOW! instance

    .PARAMETER Approval
    An [ANOWApproval] object representing the Approval to be changed.

    .PARAMETER Description
    Optional description of the Approval (may not exceed 255 characters).

    .PARAMETER UnsetDescription
    Switch parameter to remove the Description (i.e. set it to null)

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWApproval] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWApproval] object will be returned

    .EXAMPLE
    Changes the description of an Approval

    $approval = Get-AutomateNOWApproval -Id 'Approval1'
    Set-AutomateNOWApproval -Approval $approval -Description 'My Description'

    .EXAMPLE
    Forcibly removes all of the Approval Rules from an Approval (using the pipeline)
    
    $approval = Get-AutomateNOWApproval -Id 'TestApproval.mjs.apr'
    $approval | Set-AutomateNOWApproval -UnsetRules -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Use Add-AutomateNOWApprovalRule to add new Approval Rules to an Approval

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWApproval]$Approval,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetRules,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetDescription -eq $true -and $Description.Length -gt 0) {
            Write-Warning -Message 'You cannot set the description and remove it at the same time. Please choose one or the other.'
            Break
        }
        [string]$command = '/approvalConfiguration/update'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Approval.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Approval_id = $_.id
            }
            Else {
                [string]$Approval_id = $Approval.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$Approval_exists = ($null -eq (Get-AutomateNOWApproval -Id $Approval_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWApproval failed to check if the Approval [$Approval_id] already existed due to [$Message]."
                Break
            }
            If ($Approval_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Approval named [$Approval_id] in the [$current_domain] domain. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Approval_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($UnsetDescription -eq $true) {
                $BodyMetaData.'description' = $null
            }
            If ($UnsetRules -eq $true) {
                $BodyMetaData.'rules' = $null
            }
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'ApprovalConfigurationDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Approval_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Approval [$Approval_id] was successfully updated"
        }
    }
    End {

    }
}

Function Export-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Exports the Approvals from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Approvals from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWApproval] object (Use Get-AutomateNOWApproval to retrieve them)

    .INPUTS
    ONLY [ANOWApproval] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWApproval] objects are exported to the local disk in CSV format

    .EXAMPLE
    Get-AutomateNOWApproval | Export-AutomateNOWApproval

    .EXAMPLE
    Get-AutomateNOWApproval -Id 'Approval01' | Export-AutomateNOWApproval

    .EXAMPLE
    @( 'Approval01', 'Approval02' ) | Get-AutomateNOWApproval | Export-AutomateNOWApproval

    .NOTES
	You must present [ANOWApproval] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWApproval]$Approval
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Approvals-' + $current_time + '.csv'
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
            [ANOWApproval]$Approval = $_
        }
        $Error.Clear()
        Try {
            $Approval | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWApproval] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Creates a Approval within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Approval within an AutomateNOW! instance and returns back the newly created [ANOWApproval] object

    .PARAMETER Id
    The intended name of the Approval. For example: 'MyApproval1'. This value may not contain the domain in brackets.

    .PARAMETER Description
    Optional description of the Approval (may not exceed 255 characters).

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Approval into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWApproval.

    .OUTPUTS
    An [ANOWApproval] object representing the newly created Approval

    .EXAMPLE
    New-AutomateNOWApproval -Id 'Approval01' -Description 'the description' -CodeRepository 'Repo1'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Approval must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWApproval])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$approval_exists = ($null -ne (Get-AutomateNOWApproval -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWApproval failed to check if the Approval [$Id] already existed due to [$Message]."
        Break
    }
    If ($approval_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already an Approval named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'id' = $Id
    If ($Description.Length -gt 0) {
        $BodyMetaData.'description' = $Description
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWApproval due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWApproval. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWApproval] [$Id]"
        $BodyMetaData.'codeRepository' = $codeRepository
        $include_properties += 'codeRepository'
    }
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_oldValues' = '{}'
    $BodyMetaData.'_componentId' = 'ApprovalConfigurationCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'ApprovalConfigurationDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/approvalConfiguration/create'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Approval [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Approval [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWApproval]$approval = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWApproval] object due to [$Message]."
        Break
    }
    If ($Approval.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWApproval] Approval is empty!"
        Break
    }
    If ($Quiet -ne $true) {
        Return $approval
    }
}

Function New-AutomateNOWApprovalRule {
    <#
    .SYNOPSIS
    Creates an Approval Rule object for use with an Approval object within an AutomateNOW! instance

    .DESCRIPTION
    Creates an Approval Rule object for use with an Approval object within an AutomateNOW! instance

    .PARAMETER approvalLevel
    Mandatory string that sets the approval level. Valid choices are: LOW, MEDIUM, HIGH

    .PARAMETER approvalActionType
    Mandatory string that sets the approval level. Valid choices are: READY_TO_START, PROCESSING_RESTART, PROCESSING_FORCE_READY, PROCESSING_FORCE_COMPLETED, PROCESSING_FORCE_FAILED, PROCESSING_SKIP_ON, PROCESSING_SKIP_OFF, PROCESSING_HOLD, PROCESSING_RESUME, PROCESSING_INTERNAL_ACTION, PROCESSING_ABORT, PROCESSING_KILL, PROCESSING_ARCHIVED, PROCESSING_ARCHIVED_CLEANUP

    .PARAMETER noSelfApproval
    Optional switch that requires a different user account to approve the approval

    .PARAMETER passwordConfirmation
    Optional switch that will ask the approver for a password.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWApprovalRule.

    .OUTPUTS
    An [ANOWApprovalRule] object representing the newly created Approval Rule

    .EXAMPLE
    New-AutomateNOWApprovalRule ?

    .NOTES

    This function does not require connectivity to the AutomateNOW! instance

    #>
    [OutputType([ANOWApprovalRule])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [ANOWApprovalRule_approvalLevel]$approvalLevel,
        [Parameter(Mandatory = $True)]
        [ANOWApprovalRule_approvalActionType]$approvalActionType,
        [Parameter(Mandatory = $False)]
        [switch]$noSelfApproval,
        [Parameter(Mandatory = $False)]
        [switch]$passwordConfirmation
    )
    $Error.Clear()
    Try {
        [ANOWApprovalRule]$ApprovalRule = [ANOWApprovalRule]::new()
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "The [ANOWApprovalRule] failed to instantiate due to [$Message]."
        Break
    }
    $Error.Clear()
    Try {
        $ApprovalRule.approvalLevel = [string]$approvalLevel
        $ApprovalRule.approvalActionType = [string]$approvalActionType
        If ($noSelfApproval -eq $true) {
            $ApprovalRule.noSelfApproval = [boolean]$noSelfApproval
        }
        If ($passwordConfirmation -eq $true) {
            $ApprovalRule.passwordConfirmation = [boolean]$passwordConfirmation
        }
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "The [ANOWApprovalRule] object failed to populate one of the properties due to [$Message]."
        Break
    }
    Return $ApprovalRule
}

Function Remove-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Removes a Approval from an AutomateNOW! instance

    .DESCRIPTION
    Removes a Approval from an AutomateNOW! instance

    .PARAMETER Approval
    An [ANOWApproval] object representing the Approval to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWApproval] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Removes a single Approval
    Get-AutomateNOWApproval -Id 'Approval01' | Remove-AutomateNOWApproval

    .EXAMPLE
    Forcefully removes three Approvals by way of the pipeline
    @( 'Approval1', 'Approval2', 'Approval3') | Remove-AutomateNOWApproval -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWApproval]$Approval,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/approvalConfiguration/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Approval.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Approval_id = $_.id
            }
            ElseIf ($Approval.id.Length -gt 0) {
                [string]$Approval_id = $Approval.id
            }
            Else {
                [string]$Approval_id = $Id
            }
            [string]$Body = 'id=' + $Approval_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Approval_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Approval $Approval_id successfully removed"
        }
    }
    End {

    }
}

Function Copy-AutomateNOWApproval {
    <#
    .SYNOPSIS
    Copies a Approval from an AutomateNOW! instance

    .DESCRIPTION
    Copies a Approval from an AutomateNOW! instance. AutomateNOW object id can never be changed, but we can copy the object to a new id and it will include all of the items therein.

    .PARAMETER Approval
    Mandatory [ANOWApproval] object to be copied.

    .PARAMETER NewId
    The name (Id) of the new Approval. The new Id must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    .PARAMETER UnsetDescription
    Optional switch that will ensure that the newly created Approval will not have a description set.

    .PARAMETER Description
    Optional description to set on the new Approval object. If you do not set this, the new Approval object will use the description of the source object.

    .INPUTS
    ONLY [ANOWApproval] objects are accepted. Pipeline support is intentionally unavailable.

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Creates a copy of an Approval and changes the description (multi-line format)
    $Approval01 = Get-AutomateNOWApproval -Id 'approval_01'
    Copy-AutomateNOWApproval -Approval $Approval01 -NewId 'approval_01_production' -Description 'Approval 01 Production'

    .EXAMPLE
    Creates a copy of an Approval that omits the description (one-liner format)
    Copy-AutomateNOWApproval -Approval (Get-AutomateNOWApproval -Id 'approval_01') -NewId 'approval_01_production' -UnsetDescription

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWApproval]$Approval,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,1024}$' })]
        [string]$NewId,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetDescription -eq $true -and $Description.Length -gt 0) {
            Write-Warning -Message "You cannot set the description and unset it at the same time. Please choose one or the other."
            Break
        }
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. Technically, the console will not allow a duplicate object to be created. However, it would be cleaner to use the Get function first to ensure we are not trying to create a duplicate here.
        $Error.Clear()
        Try {
            [boolean]$approval_exists = ($null -ne (Get-AutomateNOWApproval -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWApproval failed to check if the Approval [$NewId] already existed due to [$Message]."
            Break
        }
        If ($approval_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a Approval named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        ## End warning ##
        [string]$command = '/approvalConfiguration/copy'
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
            [string]$Approval_oldId = $Approval.id
            If ($Approval_oldId -eq $NewId) {
                Write-Warning -Message "The new id cannot be the same as the old id."
                Break
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'oldId' = $Approval_oldId
            $BodyMetaData.'domain' = $Approval.domain
            $BodyMetaData.'id' = $NewId
            If ($UnsetDescription -ne $true) {
                If ($Description.Length -gt 0) {
                    $BodyMetaData.'description' = $Description
                }
                Else {
                    $BodyMetaData.'description' = $Approval.description
                }
            }
            $BodyMetaData.'_operationType' = 'add'
            $BodyMetaData.'_operationId' = 'copy'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'ApprovalConfigurationDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            $Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties oldId, domain, NewId, description
            $parameters.Body = $Body
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Approval_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWApproval]$Approval = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create copied [ANOWApproval] object $NewId due to [$Message]."
                Break
            }
            If ($Approval.id.Length -eq 0) {
                Write-Warning -Message "Somehow the newly created (copied) [ANOWApproval] object is empty!"
                Break
            }
            Return $Approval
        }
    }
    End {

    }
}

Function Add-AutomateNOWApprovalRule {
    <#
    .SYNOPSIS
    Adds a Rule (a.k.a. "Action") to a Approval on an AutomateNOW! instance

    .DESCRIPTION
    Adds a Rule (a.k.a. "Action") to a Approval on an AutomateNOW! instance

    .PARAMETER Approval
    Mandatory [ANOWApproval] object (Use Get-AutomateNOWApproval).

    .PARAMETER ApprovalRule
    Mandatory [ANOWApprovalRule] object (Use New-AutomateNOWApprovalRule)

    .PARAMETER Quiet
    Switch parameter to silence the output from a successful update

    .INPUTS
    ONLY [ANOWApproval] objects are accepted (including from the pipeline).

    .OUTPUTS
    The updated [ANOWApproval] object will be returned.

    .EXAMPLE
    $approval = Get-AutomateNOWApproval -Id 'approval_01'
    $approval_rule = New-AutomateNOWApprovalRule -approvalLevel HIGH -approvalActionType READY_TO_START -noSelfApproval -passwordConfirmation
    Add-AutomateNOWApprovalRule -Approval $approval -ApprovalRule $approval_rule

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    To remove the rules from an Approval, use Set-AutomateNOWApproval with the -UnsetRules parameter
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWApproval]$Approval,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWApprovalRule]$ApprovalRule,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
        [PSCustomObject]$ApprovalRuleArray = @()
        [string]$command = '/approvalConfiguration/update'
    }
    Process {
        If ($_.Length -eq 0) {
            [ANOWApprovalRule[]]$ApprovalRuleArray += $ApprovalRule
        }
        Else {
            [ANOWApprovalRule[]]$ApprovalRuleArray += $_
        }
    }
    End {
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
        [string]$Approval_id = $Approval.simpleId
        $Error.Clear()
        Try {
            [ANOWApproval]$current_result = Get-AutomateNOWApproval -Id $Approval_id
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTask failed to check if the Approval [$Approval_id] existed under Add-AutomateNOWApprovalRule due to [$Message]."
            Break
        }
        If ($current_result.id.length -eq 0) {
            Write-Warning "The Approval object that you specified [$Approval_id] does not seem to exist under Add-AutomateNOWApprovalRule"
            Break
        }
        ## End warning ##
        If ($Approval.rules -is [ANOWApprovalRule[]]) {
            $ApprovalRuleArray += [ANOWApprovalRule[]]$Approval.rules
        }
        $Error.Clear()
        Try {
            [string]$ConvertedApprovalRuleArray = $ApprovalRuleArray | ForEach-Object { [PSCustomObject]@{ approvalLevel = [string]$_.approvalLevel; approvalActionType = [string]$_.approvalActionType; noSelfApproval = $_.noSelfApproval; passwordConfirmation = $_.passwordConfirmation; } } | ConvertTo-Json -Compress
            If ($ConvertedApprovalRuleArray[0] -ne '[') {
                [string]$ConvertedApprovalRuleArray = ('[' + $ConvertedApprovalRuleArray + ']')
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "ConvertTo-Json failed to convert the array of Approval rules due to [$Message]."
            Break
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $Approval_id )
        If ($Approval.description.Length -gt 0) {
            $BodyMetaData.Add('description', $Approval.description)
        }
        Else {
            $BodyMetaData.Add('description', $null)
        }
        If ($Approval.codeRepository.Length -gt 0) {
            $BodyMetaData.Add('codeRepository', $Approval.codeRepository)
        }
        Else {
            $BodyMetaData.Add('codeRepository', $null)
        }
        $BodyMetaData.Add('rules', $ConvertedApprovalRuleArray )
        $BodyMetaData.Add('_operationType', 'update')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_oldValues', $Approval.CreateOldValues())
        $BodyMetaData.Add('_componentId', 'ApprovalEditForm')
        $BodyMetaData.Add('_dataSource', 'ApprovalDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        If ($null -eq $parameters.Body) {
            $parameters.Add('Body', $Body)
        }
        Else {
            $parameters.Body = $Body
        }
        $parameters.Add('command', $command)
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
        $Error.Clear()
        [ANOWApprovalRule[]]$rules = Try {
            ForEach ($rule in $results.response.data.rules) {
                [ANOWApprovalRule]$rule
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response [ANOWApproval] object rules objects under Add-AutomateNOWApprovalRule due to [$Message]."
            Break
        }
        [PSCustomObject]$temp_results = $results.response.data | Select-Object -ExcludeProperty rules
        $temp_results | Add-Member -MemberType NoteProperty -Name rules -Value $rules -TypeName ANOWApprovalRule
        [ANOWApproval]$UpdatedApproval = $temp_results
        If ($Quiet -ne $true) {
            Return $UpdatedApproval
        }
    }
}

#endregion

#Region - AuditLogs
Function Get-AutomateNOWAuditLog {
    <#
    .SYNOPSIS
    Gets the Audit log from an instance of AutomateNOW!

    .DESCRIPTION
    The `Get-AutomateNOWAuditLog` cmdlet gets the Audit log from an instance of AutomateNOW!

    .PARAMETER Type
    An optional string to filter the results based on type. Valid choices are: UPDATE, INSERT and DELETE

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
    Gets the most recent 100 audit log entries

    Get-AutomateNOWAuditLog

    .EXAMPLE
    Gets the most recent 1000 audit log entries

    Get-AutomateNOWAuditLog -startRow 0 -endRow 1000

    .EXAMPLE
    Gets the most recent 1000 UPDATE audit log entries

    Get-AutomateNOWAuditLog -startRow 0 -endRow 1000 -Type UPDATE

    .EXAMPLE
    Gets the oldest 1000 audit log entries

    Get-AutomateNOWAuditLog -startRow 0 -endRow 1000 -Ascending


    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The sort order from the console is by timestamp which is NOT ACCURATE! This function will sort by Id instead which is unique.

    #>
    [OutputType([ANOWAuditLog[]])]
    [Cmdletbinding()]
    Param(
        [ValidateSet('UPDATE', 'INSERT', 'DELETE')]
        [Parameter(Mandatory = $False)]
        [string]$Type,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 100,
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
    [System.Collections.Specialized.OrderedDictionary]$BodyObject = [System.Collections.Specialized.OrderedDictionary]@{}
    If ($Type.Length -gt 0) {
        $BodyObject.Add('operator', 'and')
        $BodyObject.Add('_constructor', 'AdvancedCriteria')
        $BodyObject.Add('criteria', '{"fieldName":"actionType","operator":"equals","value":"' + $Type + '"}')
    }
    $BodyObject.Add('_operationType', 'fetch')
    $BodyObject.Add('_startRow', $startRow)
    $BodyObject.Add('_endRow', $endRow)
    If ($Ascending -ne $true) {
        $BodyObject.Add('_sortBy', '-id')
    }
    Else {
        $BodyObject.Add('_sortBy', 'id')
    }
    $BodyObject.Add('_textMatchStyle', 'substring')
    $BodyObject.Add('_componentId', 'AuditLogEventList')
    $BodyObject.Add('_dataSource', 'AuditLogDataSource')
    $BodyObject.Add('isc_metaDataPrefix', '_')
    $BodyObject.Add('isc_dataFormat', 'json')
    [string]$Body = ConvertTo-QueryString -InputObject $BodyObject
    [string]$command = ('/auditLog/read?' + $Body)
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
    [int32]$AuditLogs_count = $results.response.data.Count
    If ($AuditLogs_count -eq 0 -and $startRow -eq 0) {
        Write-Warning -Message "Somehow there were 0 AuditLog entries returned. This can't be correct."
        Break
    }
    ElseIf ($AuditLogs_count -eq 0 -and $startRow -gt 0) {
        Write-Warning -Message "There are not any more rows of data past this point. Please try different -startRow value."
        Break
    }
    $Error.Clear()
    Try {
        [ANOWAuditLog[]]$AuditLogs = ForEach ($entry in $results.response.data) {
            Try {
                $entry | Add-Member -MemberType NoteProperty -Name changedValuesText -TypeName String -Value ''
                $entry | Add-Member -MemberType NoteProperty -Name changedValues -TypeName PSCustomObject -Value ''
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Add-Member failed to add the NoteProperty changedValues to an audit log UPDATE entry due to [$Message]."
                Break
            }
            If ($entry.actionType -eq 'UPDATE') {
                $Error.Clear()
                Try {
                    [PSCustomObject]$ChangedValues = Compare-ObjectProperty -ReferenceObject $entry.oldValues -DifferenceObject $entry.newValues
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Compare-ObjectProperty failed to compare an audit log UPDATE entry due to [$Message]."
                    Break
                }
                $Error.Clear()
                Try {
                    [PSCustomObject[]]$ObjectValues = $ChangedValues | ForEach-Object { [PSCustomObject]@{ name = $_.PropertyName; oldValue = $_.RefValue; newValue = $_.DiffValue; } }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "ForEach-Object failed to format an audit log UPDATE entry due to [$Message]."
                    Break
                }
                $Error.Clear()
                Try {
                    [string]$JSONValues = $ObjectValues | Sort-Object -Property name | ConvertTo-Json -Compress -Depth 10
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "ConvertTo-Json failed to convert an audit log UPDATE entry due to [$Message]."
                    Break
                }
                $entry.changedValues = $ObjectValues
                $entry.changedValuesText = $JSONValues
            }
            $entry
        }
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to parse the returned AuditLog entries under Get-AutomateNOWAuditLog due to [$Message]."
        Break
    }
    Return $AuditLogs
}

Function Export-AutomateNOWAuditLog {
    <#
    .SYNOPSIS
    Exports the AuditLog entries from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the AuditLog entries from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWAuditLog] object (Use Get-AutomateNOWAuditLog to retrieve them)

    .INPUTS
    ONLY [ANOWAuditLog] objects are accepted (including from the pipeline)

    .OUTPUTS
    The [ANOWAuditLog] objects are exported to the local disk in CSV format

    .EXAMPLE
    Get-AutomateNOWAuditLog | Export-AutomateNOWAuditLog

    .NOTES
	You must present [ANOWAuditLog] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWAuditLog]$AuditLog
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-AuditLogs-' + $current_time + '.csv'
        [string]$ExportFilePath = ((Get-Location | Select-Object -ExpandProperty Path) + '\' + $ExportFileName)
        [hashtable]$parameters = @{}
        $parameters.Add('Path', $ExportFilePath)
        $parameters.Add('Append', $true)
        $parameters.Add('Delimiter', "`t")
        If ($PSVersionTable.PSVersion.Major -eq 5) {
            $parameters.Add('NoTypeInformation', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWAuditLog]$AuditLog = $_
        }
        $Error.Clear()
        Try {
            $AuditLog | Select-Object -ExcludeProperty oldValues, newValues, changedValues | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWAuditLog] object on the pipeline due to [$Message]"
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

#Region - Calendars

Function Get-AutomateNOWCalendar {
    <#
    .SYNOPSIS
    Gets the Calendar objects from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Calendar objects from an AutomateNOW! instance

    .PARAMETER Id
    Optional string containing the simple id of the Calendar to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER Detailed
    Switch parameter to provide an [ANOWCalendarDetail] object instead of the basic [ANOWCalendar] object. This may only be used in conjunction with -Id.

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100. The console default hard limit is 10,000.

    .PARAMETER sortBy
    Optional string parameter to sort the results by (may not be used with the Id parameter). Valid choices are: {To be continued...}

    .PARAMETER Descending
    Optional switch parameter to sort in descending order

    .INPUTS
    Accepts a string representing the simple id of the Calendar from the pipeline or individually (but not an array).

    .OUTPUTS
    Either one or more [ANOWCalendar] objects or one or more [ANOWCalendarDetail] objects

    .EXAMPLE
    Gets all Calendar objects (defaults to 100 per page)

    Get-AutomateNOWCalendar

    .EXAMPLE
    Gets the first 500 Calendar objects in a single page

    Get-AutomateNOWCalendar -startRow 0 -endRow 500

    .EXAMPLE
    Gets a single non-detailed Calendar by name

    Get-AutomateNOWCalendar -Id 'Calendar_01'

    .EXAMPLE
    Gets a single detailed Calendar by name

    Get-AutomateNOWCalendar -Id 'Calendar_01' -Detailed

    .EXAMPLE
    Gets a series of Calendar objects through the pipeline

    @( 'Calendar_01', 'Calendar_02' ) | Get-AutomateNOWCalendar

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Calendar objects. Use the -Detailed parameter to get the details of a particular calendar.

    #>
    [Cmdletbinding(DefaultParameterSetName = 'Id')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Id', ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False, ParameterSetName = 'Id')]
        [switch]$Detailed,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [string]$sortBy = 'id',
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [switch]$Descending
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_.Length -gt 0 ) {
            [string]$Calendar_Id = $_
        }
        Else {
            [string]$Calendar_Id = $Id
        }
        If ($Detailed -eq $true) {
            [string]$Method = 'POST'
            $Body.'id' = $Calendar_Id
            [string]$textMatchStyle = 'exactCase'
            $Body.'_operationId' = 'readDetailed'
        }
        Else {
            [string]$Method = 'GET'
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'operator' = 'and'
            $Body.'criteria1' = '{"fieldName":"resourceType","operator":"equals","value":"CALENDAR"}'
            If ($Calendar_Id.Length -gt 0) {
                $Body.'criteria2' = ('{"fieldName":"simpleId","operator":"equals","value":"' + $Calendar_Id + '"}')
            }
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            [string]$textMatchStyle = 'exact'
            $Body.'_componentId' = 'ResourceList'
            If ($Descending -eq $true) {
                $Body.'_sortBy' = '-' + $sortBy
            }
            Else {
                $Body.'_sortBy' = $sortBy
            }
        }
        $parameters.Add('Method', $Method)
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_dataSource' = 'ResourceDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        If ($Detailed -eq $true) {
            [string]$command = ('/resource/readDetailed')
            If ($Null -eq $parameters["Body"]) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
            If ($null -eq $parameters["Command"]) {
                $parameters.Add('Command', $command)
            }
            Else {
                $parameters.Command = $command
            }
        }
        Else {
            [string]$command = ('/resource/read?' + $Body)
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
        If ($Detailed -eq $true) {
            $Error.Clear()
            Try {
                [ANOWCalendarDetail]$CalendarDetail = $results.response.data | Select-Object -First 1
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWCalendar failed to parse the results into an [ANOWCalendarDetail] object due to [$Message]."
                Break
            }
            If ($CalendarDetail.Id.Length -gt 0) {
                Return $CalendarDetail
            }
        }
        Else {
            $Error.Clear()
            Try {
                [ANOWCalendar[]]$Calendars = $results.response.data
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWCalendar failed to parse the results into [ANOWCalendar] objects due to [$Message]."
                Break
            }
            If ($Calendars.Count -gt 0) {
                If ($Id.Length -gt 0) {
                    [ANOWCalendar]$Calendar = $Calendars | Where-Object { $_.simpleId -eq $Id } | Select-Object -First 1
                    Return $Calendar
                }
                Else {
                    Return $Calendars
                }
            }
        }
    }
    End {

    }
}

Function Export-AutomateNOWCalendar {
    <#
    .SYNOPSIS
    Exports the Calendar objects from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Calendar objects from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWCalendar] object (Use Get-AutomateNOWCalendar to retrieve them)

    .INPUTS
    ONLY [ANOWCalendar] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWCalendar] objects are exported to the local disk in CSV format

    .EXAMPLE
    Exports all of the Calendar objects (up to 100 by default)

    Get-AutomateNOWCalendar | Export-AutomateNOWCalendar

    .EXAMPLE
    Exports 1 Calendar by name

    Get-AutomateNOWCalendar -Id 'Calendar01' | Export-AutomateNOWCalendar

    .EXAMPLE
    Exports a series of Calendar objects by the pipeline

    @( 'Calendar01', 'Calendar02' ) | Get-AutomateNOWCalendar | Export-AutomateNOWCalendar

    .NOTES
	You must present [ANOWCalendar] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWCalendar]$Calendar
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Calendars-' + $current_time + '.csv'
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
            [ANOWCalendar]$Calendar = $_
        }
        $Error.Clear()
        Try {
            $Calendar | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWCalendar] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWCalendar {
    <#
    .SYNOPSIS
    Creates a Calendar within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Calendar within an AutomateNOW! instance and returns back the newly created [ANOWCalendar] object

    .PARAMETER Id
    The intended name of the Calendar. For example: 'result_mapping1'. This value may not contain the domain in brackets.

    .PARAMETER Description
    Optional description of the Calendar (may not exceed 255 characters).

    .PARAMETER Timezone
    Optional timezone for the calendar. If not specified, the default server timezone will be used. Valid choices are: 'Africa/Abidjan', 'Africa/Accra', 'Africa/Addis_Ababa', 'Africa/Algiers', 'Africa/Asmara', 'Africa/Asmera', 'Africa/Bamako', 'Africa/Bangui', 'Africa/Banjul', 'Africa/Bissau', 'Africa/Blantyre', 'Africa/Brazzaville', 'Africa/Bujumbura', 'Africa/Cairo', 'Africa/Casablanca', 'Africa/Ceuta', 'Africa/Conakry', 'Africa/Dakar', 'Africa/Dar_es_Salaam', 'Africa/Djibouti', 'Africa/Douala', 'Africa/El_Aaiun', 'Africa/Freetown', 'Africa/Gaborone', 'Africa/Harare', 'Africa/Johannesburg', 'Africa/Juba', 'Africa/Kampala', 'Africa/Khartoum', 'Africa/Kigali', 'Africa/Kinshasa', 'Africa/Lagos', 'Africa/Libreville', 'Africa/Lome', 'Africa/Luanda', 'Africa/Lubumbashi', 'Africa/Lusaka', 'Africa/Malabo', 'Africa/Maputo', 'Africa/Maseru', 'Africa/Mbabane', 'Africa/Mogadishu', 'Africa/Monrovia', 'Africa/Nairobi', 'Africa/Ndjamena', 'Africa/Niamey', 'Africa/Nouakchott', 'Africa/Ouagadougou', 'Africa/Porto-Novo', 'Africa/Sao_Tome', 'Africa/Timbuktu', 'Africa/Tripoli', 'Africa/Tunis', 'Africa/Windhoek', 'America/Adak', 'America/Anchorage', 'America/Anguilla', 'America/Antigua', 'America/Araguaina', 'America/Argentina/Buenos_Aires', 'America/Argentina/Catamarca', 'America/Argentina/ComodRivadavia', 'America/Argentina/Cordoba', 'America/Argentina/Jujuy', 'America/Argentina/La_Rioja', 'America/Argentina/Mendoza', 'America/Argentina/Rio_Gallegos', 'America/Argentina/Salta', 'America/Argentina/San_Juan', 'America/Argentina/San_Luis', 'America/Argentina/Tucuman', 'America/Argentina/Ushuaia', 'America/Aruba', 'America/Asuncion', 'America/Atikokan', 'America/Atka', 'America/Bahia', 'America/Bahia_Banderas', 'America/Barbados', 'America/Belem', 'America/Belize', 'America/Blanc-Sablon', 'America/Boa_Vista', 'America/Bogota', 'America/Boise', 'America/Buenos_Aires', 'America/Cambridge_Bay', 'America/Campo_Grande', 'America/Cancun', 'America/Caracas', 'America/Catamarca', 'America/Cayenne', 'America/Cayman', 'America/Chicago', 'America/Chihuahua', 'America/Coral_Harbour', 'America/Cordoba', 'America/Costa_Rica', 'America/Creston', 'America/Cuiaba', 'America/Curacao', 'America/Danmarkshavn', 'America/Dawson', 'America/Dawson_Creek', 'America/Denver', 'America/Detroit', 'America/Dominica', 'America/Edmonton', 'America/Eirunepe', 'America/El_Salvador', 'America/Ensenada', 'America/Fort_Nelson', 'America/Fort_Wayne', 'America/Fortaleza', 'America/Glace_Bay', 'America/Godthab', 'America/Goose_Bay', 'America/Grand_Turk', 'America/Grenada', 'America/Guadeloupe', 'America/Guatemala', 'America/Guayaquil', 'America/Guyana', 'America/Halifax', 'America/Havana', 'America/Hermosillo', 'America/Indiana/Indianapolis', 'America/Indiana/Knox', 'America/Indiana/Marengo', 'America/Indiana/Petersburg', 'America/Indiana/Tell_City', 'America/Indiana/Vevay', 'America/Indiana/Vincennes', 'America/Indiana/Winamac', 'America/Indianapolis', 'America/Inuvik', 'America/Iqaluit', 'America/Jamaica', 'America/Jujuy', 'America/Juneau', 'America/Kentucky/Louisville', 'America/Kentucky/Monticello', 'America/Knox_IN', 'America/Kralendijk', 'America/La_Paz', 'America/Lima', 'America/Los_Angeles', 'America/Louisville', 'America/Lower_Princes', 'America/Maceio', 'America/Managua', 'America/Manaus', 'America/Marigot', 'America/Martinique', 'America/Matamoros', 'America/Mazatlan', 'America/Mendoza', 'America/Menominee', 'America/Merida', 'America/Metlakatla', 'America/Mexico_City', 'America/Miquelon', 'America/Moncton', 'America/Monterrey', 'America/Montevideo', 'America/Montreal', 'America/Montserrat', 'America/Nassau', 'America/New_York', 'America/Nipigon', 'America/Nome', 'America/Noronha', 'America/North_Dakota/Beulah', 'America/North_Dakota/Center', 'America/North_Dakota/New_Salem', 'America/Nuuk', 'America/Ojinaga', 'America/Panama', 'America/Pangnirtung', 'America/Paramaribo', 'America/Phoenix', 'America/Port-au-Prince', 'America/Port_of_Spain', 'America/Porto_Acre', 'America/Porto_Velho', 'America/Puerto_Rico', 'America/Punta_Arenas', 'America/Rainy_River', 'America/Rankin_Inlet', 'America/Recife', 'America/Regina', 'America/Resolute', 'America/Rio_Branco', 'America/Rosario', 'America/Santa_Isabel', 'America/Santarem', 'America/Santiago', 'America/Santo_Domingo', 'America/Sao_Paulo', 'America/Scoresbysund', 'America/Shiprock', 'America/Sitka', 'America/St_Barthelemy', 'America/St_Johns', 'America/St_Kitts', 'America/St_Lucia', 'America/St_Thomas', 'America/St_Vincent', 'America/Swift_Current', 'America/Tegucigalpa', 'America/Thule', 'America/Thunder_Bay', 'America/Tijuana', 'America/Toronto', 'America/Tortola', 'America/Vancouver', 'America/Virgin', 'America/Whitehorse', 'America/Winnipeg', 'America/Yakutat', 'America/Yellowknife', 'Antarctica/Casey', 'Antarctica/Davis', 'Antarctica/DumontDUrville', 'Antarctica/Macquarie', 'Antarctica/Mawson', 'Antarctica/McMurdo', 'Antarctica/Palmer', 'Antarctica/Rothera', 'Antarctica/South_Pole', 'Antarctica/Syowa', 'Antarctica/Troll', 'Antarctica/Vostok', 'Arctic/Longyearbyen', 'Asia/Aden', 'Asia/Almaty', 'Asia/Amman', 'Asia/Anadyr', 'Asia/Aqtau', 'Asia/Aqtobe', 'Asia/Ashgabat', 'Asia/Ashkhabad', 'Asia/Atyrau', 'Asia/Baghdad', 'Asia/Bahrain', 'Asia/Baku', 'Asia/Bangkok', 'Asia/Barnaul', 'Asia/Beirut', 'Asia/Bishkek', 'Asia/Brunei', 'Asia/Calcutta', 'Asia/Chita', 'Asia/Choibalsan', 'Asia/Chongqing', 'Asia/Chungking', 'Asia/Colombo', 'Asia/Dacca', 'Asia/Damascus', 'Asia/Dhaka', 'Asia/Dili', 'Asia/Dubai', 'Asia/Dushanbe', 'Asia/Famagusta', 'Asia/Gaza', 'Asia/Harbin', 'Asia/Hebron', 'Asia/Ho_Chi_Minh', 'Asia/Hong_Kong', 'Asia/Hovd', 'Asia/Irkutsk', 'Asia/Istanbul', 'Asia/Jakarta', 'Asia/Jayapura', 'Asia/Jerusalem', 'Asia/Kabul', 'Asia/Kamchatka', 'Asia/Karachi', 'Asia/Kashgar', 'Asia/Kathmandu', 'Asia/Katmandu', 'Asia/Khandyga', 'Asia/Kolkata', 'Asia/Krasnoyarsk', 'Asia/Kuala_Lumpur', 'Asia/Kuching', 'Asia/Kuwait', 'Asia/Macao', 'Asia/Macau', 'Asia/Magadan', 'Asia/Makassar', 'Asia/Manila', 'Asia/Muscat', 'Asia/Nicosia', 'Asia/Novokuznetsk', 'Asia/Novosibirsk', 'Asia/Omsk', 'Asia/Oral', 'Asia/Phnom_Penh', 'Asia/Pontianak', 'Asia/Pyongyang', 'Asia/Qatar', 'Asia/Qostanay', 'Asia/Qyzylorda', 'Asia/Rangoon', 'Asia/Riyadh', 'Asia/Saigon', 'Asia/Sakhalin', 'Asia/Samarkand', 'Asia/Seoul', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Srednekolymsk', 'Asia/Taipei', 'Asia/Tashkent', 'Asia/Tbilisi', 'Asia/Tehran', 'Asia/Tel_Aviv', 'Asia/Thimbu', 'Asia/Thimphu', 'Asia/Tokyo', 'Asia/Tomsk', 'Asia/Ujung_Pandang', 'Asia/Ulaanbaatar', 'Asia/Ulan_Bator', 'Asia/Urumqi', 'Asia/Ust-Nera', 'Asia/Vientiane', 'Asia/Vladivostok', 'Asia/Yakutsk', 'Asia/Yangon', 'Asia/Yekaterinburg', 'Asia/Yerevan', 'Atlantic/Azores', 'Atlantic/Bermuda', 'Atlantic/Canary', 'Atlantic/Cape_Verde', 'Atlantic/Faeroe', 'Atlantic/Faroe', 'Atlantic/Jan_Mayen', 'Atlantic/Madeira', 'Atlantic/Reykjavik', 'Atlantic/South_Georgia', 'Atlantic/St_Helena', 'Atlantic/Stanley', 'Australia/ACT', 'Australia/Adelaide', 'Australia/Brisbane', 'Australia/Broken_Hill', 'Australia/Canberra', 'Australia/Currie', 'Australia/Darwin', 'Australia/Eucla', 'Australia/Hobart', 'Australia/LHI', 'Australia/Lindeman', 'Australia/Lord_Howe', 'Australia/Melbourne', 'Australia/NSW', 'Australia/North', 'Australia/Perth', 'Australia/Queensland', 'Australia/South', 'Australia/Sydney', 'Australia/Tasmania', 'Australia/Victoria', 'Australia/West', 'Australia/Yancowinna', 'Brazil/Acre', 'Brazil/DeNoronha', 'Brazil/East', 'Brazil/West', 'CET', 'CST6CDT', 'Canada/Atlantic', 'Canada/Central', 'Canada/Eastern', 'Canada/Mountain', 'Canada/Newfoundland', 'Canada/Pacific', 'Canada/Saskatchewan', 'Canada/Yukon', 'Chile/Continental', 'Chile/EasterIsland', 'Cuba', 'EET', 'EST5EDT', 'Egypt', 'Eire', 'Etc/GMT', 'Etc/GMT+0', 'Etc/GMT+1', 'Etc/GMT+10', 'Etc/GMT+11', 'Etc/GMT+12', 'Etc/GMT+2', 'Etc/GMT+3', 'Etc/GMT+4', 'Etc/GMT+5', 'Etc/GMT+6', 'Etc/GMT+7', 'Etc/GMT+8', 'Etc/GMT+9', 'Etc/GMT-0', 'Etc/GMT-1', 'Etc/GMT-10', 'Etc/GMT-11', 'Etc/GMT-12', 'Etc/GMT-13', 'Etc/GMT-14', 'Etc/GMT-2', 'Etc/GMT-3', 'Etc/GMT-4', 'Etc/GMT-5', 'Etc/GMT-6', 'Etc/GMT-7', 'Etc/GMT-8', 'Etc/GMT-9', 'Etc/GMT0', 'Etc/Greenwich', 'Etc/UCT', 'Etc/UTC', 'Etc/Universal', 'Etc/Zulu', 'Europe/Amsterdam', 'Europe/Andorra', 'Europe/Astrakhan', 'Europe/Athens', 'Europe/Belfast', 'Europe/Belgrade', 'Europe/Berlin', 'Europe/Bratislava', 'Europe/Brussels', 'Europe/Bucharest', 'Europe/Budapest', 'Europe/Busingen', 'Europe/Chisinau', 'Europe/Copenhagen', 'Europe/Dublin', 'Europe/Gibraltar', 'Europe/Guernsey', 'Europe/Helsinki', 'Europe/Isle_of_Man', 'Europe/Istanbul', 'Europe/Jersey', 'Europe/Kaliningrad', 'Europe/Kiev', 'Europe/Kirov', 'Europe/Lisbon', 'Europe/Ljubljana', 'Europe/London', 'Europe/Luxembourg', 'Europe/Madrid', 'Europe/Malta', 'Europe/Mariehamn', 'Europe/Minsk', 'Europe/Monaco', 'Europe/Moscow', 'Europe/Nicosia', 'Europe/Oslo', 'Europe/Paris', 'Europe/Podgorica', 'Europe/Prague', 'Europe/Riga', 'Europe/Rome', 'Europe/Samara', 'Europe/San_Marino', 'Europe/Sarajevo', 'Europe/Saratov', 'Europe/Simferopol', 'Europe/Skopje', 'Europe/Sofia', 'Europe/Stockholm', 'Europe/Tallinn', 'Europe/Tirane', 'Europe/Tiraspol', 'Europe/Ulyanovsk', 'Europe/Uzhgorod', 'Europe/Vaduz', 'Europe/Vatican', 'Europe/Vienna', 'Europe/Vilnius', 'Europe/Volgograd', 'Europe/Warsaw', 'Europe/Zagreb', 'Europe/Zaporozhye', 'Europe/Zurich', 'GB', 'GB-Eire', 'GMT', 'GMT0', 'Greenwich', 'Hongkong', 'Iceland', 'Indian/Antananarivo', 'Indian/Chagos', 'Indian/Christmas', 'Indian/Cocos', 'Indian/Comoro', 'Indian/Kerguelen', 'Indian/Mahe', 'Indian/Maldives', 'Indian/Mauritius', 'Indian/Mayotte', 'Indian/Reunion', 'Iran', 'Israel', 'Jamaica', 'Japan', 'Kwajalein', 'Libya', 'MET', 'MST7MDT', 'Mexico/BajaNorte', 'Mexico/BajaSur', 'Mexico/General', 'NZ', 'NZ-CHAT', 'Navajo', 'PRC', 'PST8PDT', 'Pacific/Apia', 'Pacific/Auckland', 'Pacific/Bougainville', 'Pacific/Chatham', 'Pacific/Chuuk', 'Pacific/Easter', 'Pacific/Efate', 'Pacific/Enderbury', 'Pacific/Fakaofo', 'Pacific/Fiji', 'Pacific/Funafuti', 'Pacific/Galapagos', 'Pacific/Gambier', 'Pacific/Guadalcanal', 'Pacific/Guam', 'Pacific/Honolulu', 'Pacific/Johnston', 'Pacific/Kiritimati', 'Pacific/Kosrae', 'Pacific/Kwajalein', 'Pacific/Majuro', 'Pacific/Marquesas', 'Pacific/Midway', 'Pacific/Nauru', 'Pacific/Niue', 'Pacific/Norfolk', 'Pacific/Noumea', 'Pacific/Pago_Pago', 'Pacific/Palau', 'Pacific/Pitcairn', 'Pacific/Pohnpei', 'Pacific/Ponape', 'Pacific/Port_Moresby', 'Pacific/Rarotonga', 'Pacific/Saipan', 'Pacific/Samoa', 'Pacific/Tahiti', 'Pacific/Tarawa', 'Pacific/Tongatapu', 'Pacific/Truk', 'Pacific/Wake', 'Pacific/Wallis', 'Pacific/Yap', 'Poland', 'Portugal', 'ROK', 'Singapore', 'Turkey', 'UCT', 'US/Alaska', 'US/Aleutian', 'US/Arizona', 'US/Central', 'US/East-Indiana', 'US/Eastern', 'US/Hawaii', 'US/Indiana-Starke', 'US/Michigan', 'US/Mountain', 'US/Pacific', 'US/Samoa', 'UTC', 'Universal', 'W-SU', 'WET', 'Zulu', 'EST', 'HST', 'MST'

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Calendar. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the Calendar into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Calendar into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWCalendar.

    .OUTPUTS
    An [ANOWCalendar] object representing the newly created Calendar

    .EXAMPLE
    New-AutomateNOWCalendar -Id 'Calendar01' -Type 'CAL_SELECT' -Description 'Description01' -Tags 'Tag01' -Folder 'Folder01'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Calendar must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWCalendar])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWCalendar_calendarType]$Type,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [string]$Description,
        [ValidateSet('Africa/Abidjan', 'Africa/Accra', 'Africa/Addis_Ababa', 'Africa/Algiers', 'Africa/Asmara', 'Africa/Asmera', 'Africa/Bamako', 'Africa/Bangui', 'Africa/Banjul', 'Africa/Bissau', 'Africa/Blantyre', 'Africa/Brazzaville', 'Africa/Bujumbura', 'Africa/Cairo', 'Africa/Casablanca', 'Africa/Ceuta', 'Africa/Conakry', 'Africa/Dakar', 'Africa/Dar_es_Salaam', 'Africa/Djibouti', 'Africa/Douala', 'Africa/El_Aaiun', 'Africa/Freetown', 'Africa/Gaborone', 'Africa/Harare', 'Africa/Johannesburg', 'Africa/Juba', 'Africa/Kampala', 'Africa/Khartoum', 'Africa/Kigali', 'Africa/Kinshasa', 'Africa/Lagos', 'Africa/Libreville', 'Africa/Lome', 'Africa/Luanda', 'Africa/Lubumbashi', 'Africa/Lusaka', 'Africa/Malabo', 'Africa/Maputo', 'Africa/Maseru', 'Africa/Mbabane', 'Africa/Mogadishu', 'Africa/Monrovia', 'Africa/Nairobi', 'Africa/Ndjamena', 'Africa/Niamey', 'Africa/Nouakchott', 'Africa/Ouagadougou', 'Africa/Porto-Novo', 'Africa/Sao_Tome', 'Africa/Timbuktu', 'Africa/Tripoli', 'Africa/Tunis', 'Africa/Windhoek', 'America/Adak', 'America/Anchorage', 'America/Anguilla', 'America/Antigua', 'America/Araguaina', 'America/Argentina/Buenos_Aires', 'America/Argentina/Catamarca', 'America/Argentina/ComodRivadavia', 'America/Argentina/Cordoba', 'America/Argentina/Jujuy', 'America/Argentina/La_Rioja', 'America/Argentina/Mendoza', 'America/Argentina/Rio_Gallegos', 'America/Argentina/Salta', 'America/Argentina/San_Juan', 'America/Argentina/San_Luis', 'America/Argentina/Tucuman', 'America/Argentina/Ushuaia', 'America/Aruba', 'America/Asuncion', 'America/Atikokan', 'America/Atka', 'America/Bahia', 'America/Bahia_Banderas', 'America/Barbados', 'America/Belem', 'America/Belize', 'America/Blanc-Sablon', 'America/Boa_Vista', 'America/Bogota', 'America/Boise', 'America/Buenos_Aires', 'America/Cambridge_Bay', 'America/Campo_Grande', 'America/Cancun', 'America/Caracas', 'America/Catamarca', 'America/Cayenne', 'America/Cayman', 'America/Chicago', 'America/Chihuahua', 'America/Coral_Harbour', 'America/Cordoba', 'America/Costa_Rica', 'America/Creston', 'America/Cuiaba', 'America/Curacao', 'America/Danmarkshavn', 'America/Dawson', 'America/Dawson_Creek', 'America/Denver', 'America/Detroit', 'America/Dominica', 'America/Edmonton', 'America/Eirunepe', 'America/El_Salvador', 'America/Ensenada', 'America/Fort_Nelson', 'America/Fort_Wayne', 'America/Fortaleza', 'America/Glace_Bay', 'America/Godthab', 'America/Goose_Bay', 'America/Grand_Turk', 'America/Grenada', 'America/Guadeloupe', 'America/Guatemala', 'America/Guayaquil', 'America/Guyana', 'America/Halifax', 'America/Havana', 'America/Hermosillo', 'America/Indiana/Indianapolis', 'America/Indiana/Knox', 'America/Indiana/Marengo', 'America/Indiana/Petersburg', 'America/Indiana/Tell_City', 'America/Indiana/Vevay', 'America/Indiana/Vincennes', 'America/Indiana/Winamac', 'America/Indianapolis', 'America/Inuvik', 'America/Iqaluit', 'America/Jamaica', 'America/Jujuy', 'America/Juneau', 'America/Kentucky/Louisville', 'America/Kentucky/Monticello', 'America/Knox_IN', 'America/Kralendijk', 'America/La_Paz', 'America/Lima', 'America/Los_Angeles', 'America/Louisville', 'America/Lower_Princes', 'America/Maceio', 'America/Managua', 'America/Manaus', 'America/Marigot', 'America/Martinique', 'America/Matamoros', 'America/Mazatlan', 'America/Mendoza', 'America/Menominee', 'America/Merida', 'America/Metlakatla', 'America/Mexico_City', 'America/Miquelon', 'America/Moncton', 'America/Monterrey', 'America/Montevideo', 'America/Montreal', 'America/Montserrat', 'America/Nassau', 'America/New_York', 'America/Nipigon', 'America/Nome', 'America/Noronha', 'America/North_Dakota/Beulah', 'America/North_Dakota/Center', 'America/North_Dakota/New_Salem', 'America/Nuuk', 'America/Ojinaga', 'America/Panama', 'America/Pangnirtung', 'America/Paramaribo', 'America/Phoenix', 'America/Port-au-Prince', 'America/Port_of_Spain', 'America/Porto_Acre', 'America/Porto_Velho', 'America/Puerto_Rico', 'America/Punta_Arenas', 'America/Rainy_River', 'America/Rankin_Inlet', 'America/Recife', 'America/Regina', 'America/Resolute', 'America/Rio_Branco', 'America/Rosario', 'America/Santa_Isabel', 'America/Santarem', 'America/Santiago', 'America/Santo_Domingo', 'America/Sao_Paulo', 'America/Scoresbysund', 'America/Shiprock', 'America/Sitka', 'America/St_Barthelemy', 'America/St_Johns', 'America/St_Kitts', 'America/St_Lucia', 'America/St_Thomas', 'America/St_Vincent', 'America/Swift_Current', 'America/Tegucigalpa', 'America/Thule', 'America/Thunder_Bay', 'America/Tijuana', 'America/Toronto', 'America/Tortola', 'America/Vancouver', 'America/Virgin', 'America/Whitehorse', 'America/Winnipeg', 'America/Yakutat', 'America/Yellowknife', 'Antarctica/Casey', 'Antarctica/Davis', 'Antarctica/DumontDUrville', 'Antarctica/Macquarie', 'Antarctica/Mawson', 'Antarctica/McMurdo', 'Antarctica/Palmer', 'Antarctica/Rothera', 'Antarctica/South_Pole', 'Antarctica/Syowa', 'Antarctica/Troll', 'Antarctica/Vostok', 'Arctic/Longyearbyen', 'Asia/Aden', 'Asia/Almaty', 'Asia/Amman', 'Asia/Anadyr', 'Asia/Aqtau', 'Asia/Aqtobe', 'Asia/Ashgabat', 'Asia/Ashkhabad', 'Asia/Atyrau', 'Asia/Baghdad', 'Asia/Bahrain', 'Asia/Baku', 'Asia/Bangkok', 'Asia/Barnaul', 'Asia/Beirut', 'Asia/Bishkek', 'Asia/Brunei', 'Asia/Calcutta', 'Asia/Chita', 'Asia/Choibalsan', 'Asia/Chongqing', 'Asia/Chungking', 'Asia/Colombo', 'Asia/Dacca', 'Asia/Damascus', 'Asia/Dhaka', 'Asia/Dili', 'Asia/Dubai', 'Asia/Dushanbe', 'Asia/Famagusta', 'Asia/Gaza', 'Asia/Harbin', 'Asia/Hebron', 'Asia/Ho_Chi_Minh', 'Asia/Hong_Kong', 'Asia/Hovd', 'Asia/Irkutsk', 'Asia/Istanbul', 'Asia/Jakarta', 'Asia/Jayapura', 'Asia/Jerusalem', 'Asia/Kabul', 'Asia/Kamchatka', 'Asia/Karachi', 'Asia/Kashgar', 'Asia/Kathmandu', 'Asia/Katmandu', 'Asia/Khandyga', 'Asia/Kolkata', 'Asia/Krasnoyarsk', 'Asia/Kuala_Lumpur', 'Asia/Kuching', 'Asia/Kuwait', 'Asia/Macao', 'Asia/Macau', 'Asia/Magadan', 'Asia/Makassar', 'Asia/Manila', 'Asia/Muscat', 'Asia/Nicosia', 'Asia/Novokuznetsk', 'Asia/Novosibirsk', 'Asia/Omsk', 'Asia/Oral', 'Asia/Phnom_Penh', 'Asia/Pontianak', 'Asia/Pyongyang', 'Asia/Qatar', 'Asia/Qostanay', 'Asia/Qyzylorda', 'Asia/Rangoon', 'Asia/Riyadh', 'Asia/Saigon', 'Asia/Sakhalin', 'Asia/Samarkand', 'Asia/Seoul', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Srednekolymsk', 'Asia/Taipei', 'Asia/Tashkent', 'Asia/Tbilisi', 'Asia/Tehran', 'Asia/Tel_Aviv', 'Asia/Thimbu', 'Asia/Thimphu', 'Asia/Tokyo', 'Asia/Tomsk', 'Asia/Ujung_Pandang', 'Asia/Ulaanbaatar', 'Asia/Ulan_Bator', 'Asia/Urumqi', 'Asia/Ust-Nera', 'Asia/Vientiane', 'Asia/Vladivostok', 'Asia/Yakutsk', 'Asia/Yangon', 'Asia/Yekaterinburg', 'Asia/Yerevan', 'Atlantic/Azores', 'Atlantic/Bermuda', 'Atlantic/Canary', 'Atlantic/Cape_Verde', 'Atlantic/Faeroe', 'Atlantic/Faroe', 'Atlantic/Jan_Mayen', 'Atlantic/Madeira', 'Atlantic/Reykjavik', 'Atlantic/South_Georgia', 'Atlantic/St_Helena', 'Atlantic/Stanley', 'Australia/ACT', 'Australia/Adelaide', 'Australia/Brisbane', 'Australia/Broken_Hill', 'Australia/Canberra', 'Australia/Currie', 'Australia/Darwin', 'Australia/Eucla', 'Australia/Hobart', 'Australia/LHI', 'Australia/Lindeman', 'Australia/Lord_Howe', 'Australia/Melbourne', 'Australia/NSW', 'Australia/North', 'Australia/Perth', 'Australia/Queensland', 'Australia/South', 'Australia/Sydney', 'Australia/Tasmania', 'Australia/Victoria', 'Australia/West', 'Australia/Yancowinna', 'Brazil/Acre', 'Brazil/DeNoronha', 'Brazil/East', 'Brazil/West', 'CET', 'CST6CDT', 'Canada/Atlantic', 'Canada/Central', 'Canada/Eastern', 'Canada/Mountain', 'Canada/Newfoundland', 'Canada/Pacific', 'Canada/Saskatchewan', 'Canada/Yukon', 'Chile/Continental', 'Chile/EasterIsland', 'Cuba', 'EET', 'EST5EDT', 'Egypt', 'Eire', 'Etc/GMT', 'Etc/GMT+0', 'Etc/GMT+1', 'Etc/GMT+10', 'Etc/GMT+11', 'Etc/GMT+12', 'Etc/GMT+2', 'Etc/GMT+3', 'Etc/GMT+4', 'Etc/GMT+5', 'Etc/GMT+6', 'Etc/GMT+7', 'Etc/GMT+8', 'Etc/GMT+9', 'Etc/GMT-0', 'Etc/GMT-1', 'Etc/GMT-10', 'Etc/GMT-11', 'Etc/GMT-12', 'Etc/GMT-13', 'Etc/GMT-14', 'Etc/GMT-2', 'Etc/GMT-3', 'Etc/GMT-4', 'Etc/GMT-5', 'Etc/GMT-6', 'Etc/GMT-7', 'Etc/GMT-8', 'Etc/GMT-9', 'Etc/GMT0', 'Etc/Greenwich', 'Etc/UCT', 'Etc/UTC', 'Etc/Universal', 'Etc/Zulu', 'Europe/Amsterdam', 'Europe/Andorra', 'Europe/Astrakhan', 'Europe/Athens', 'Europe/Belfast', 'Europe/Belgrade', 'Europe/Berlin', 'Europe/Bratislava', 'Europe/Brussels', 'Europe/Bucharest', 'Europe/Budapest', 'Europe/Busingen', 'Europe/Chisinau', 'Europe/Copenhagen', 'Europe/Dublin', 'Europe/Gibraltar', 'Europe/Guernsey', 'Europe/Helsinki', 'Europe/Isle_of_Man', 'Europe/Istanbul', 'Europe/Jersey', 'Europe/Kaliningrad', 'Europe/Kiev', 'Europe/Kirov', 'Europe/Lisbon', 'Europe/Ljubljana', 'Europe/London', 'Europe/Luxembourg', 'Europe/Madrid', 'Europe/Malta', 'Europe/Mariehamn', 'Europe/Minsk', 'Europe/Monaco', 'Europe/Moscow', 'Europe/Nicosia', 'Europe/Oslo', 'Europe/Paris', 'Europe/Podgorica', 'Europe/Prague', 'Europe/Riga', 'Europe/Rome', 'Europe/Samara', 'Europe/San_Marino', 'Europe/Sarajevo', 'Europe/Saratov', 'Europe/Simferopol', 'Europe/Skopje', 'Europe/Sofia', 'Europe/Stockholm', 'Europe/Tallinn', 'Europe/Tirane', 'Europe/Tiraspol', 'Europe/Ulyanovsk', 'Europe/Uzhgorod', 'Europe/Vaduz', 'Europe/Vatican', 'Europe/Vienna', 'Europe/Vilnius', 'Europe/Volgograd', 'Europe/Warsaw', 'Europe/Zagreb', 'Europe/Zaporozhye', 'Europe/Zurich', 'GB', 'GB-Eire', 'GMT', 'GMT0', 'Greenwich', 'Hongkong', 'Iceland', 'Indian/Antananarivo', 'Indian/Chagos', 'Indian/Christmas', 'Indian/Cocos', 'Indian/Comoro', 'Indian/Kerguelen', 'Indian/Mahe', 'Indian/Maldives', 'Indian/Mauritius', 'Indian/Mayotte', 'Indian/Reunion', 'Iran', 'Israel', 'Jamaica', 'Japan', 'Kwajalein', 'Libya', 'MET', 'MST7MDT', 'Mexico/BajaNorte', 'Mexico/BajaSur', 'Mexico/General', 'NZ', 'NZ-CHAT', 'Navajo', 'PRC', 'PST8PDT', 'Pacific/Apia', 'Pacific/Auckland', 'Pacific/Bougainville', 'Pacific/Chatham', 'Pacific/Chuuk', 'Pacific/Easter', 'Pacific/Efate', 'Pacific/Enderbury', 'Pacific/Fakaofo', 'Pacific/Fiji', 'Pacific/Funafuti', 'Pacific/Galapagos', 'Pacific/Gambier', 'Pacific/Guadalcanal', 'Pacific/Guam', 'Pacific/Honolulu', 'Pacific/Johnston', 'Pacific/Kiritimati', 'Pacific/Kosrae', 'Pacific/Kwajalein', 'Pacific/Majuro', 'Pacific/Marquesas', 'Pacific/Midway', 'Pacific/Nauru', 'Pacific/Niue', 'Pacific/Norfolk', 'Pacific/Noumea', 'Pacific/Pago_Pago', 'Pacific/Palau', 'Pacific/Pitcairn', 'Pacific/Pohnpei', 'Pacific/Ponape', 'Pacific/Port_Moresby', 'Pacific/Rarotonga', 'Pacific/Saipan', 'Pacific/Samoa', 'Pacific/Tahiti', 'Pacific/Tarawa', 'Pacific/Tongatapu', 'Pacific/Truk', 'Pacific/Wake', 'Pacific/Wallis', 'Pacific/Yap', 'Poland', 'Portugal', 'ROK', 'Singapore', 'Turkey', 'UCT', 'US/Alaska', 'US/Aleutian', 'US/Arizona', 'US/Central', 'US/East-Indiana', 'US/Eastern', 'US/Hawaii', 'US/Indiana-Starke', 'US/Michigan', 'US/Mountain', 'US/Pacific', 'US/Samoa', 'UTC', 'Universal', 'W-SU', 'WET', 'Zulu', 'EST', 'HST', 'MST')]
        [Parameter(Mandatory = $false)]
        [string]$Timezone,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$Calendar_exists = ($null -ne (Get-AutomateNOWCalendar -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWCalendar failed to check if the Calendar [$Id] already existed due to [$Message]."
        Break
    }
    If ($Calendar_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Calendar named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWCalendar = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWCalendar.Add('id', $Id)
    If ($Description.Length -gt 0) {
        $ANOWCalendar.Add('description', $Description)
    }
    If ($Timezone.Length -gt 0) {
        $Error.Clear()
        Try {
            If ($null -eq (Get-AutomateNOWTimeZone -Id $Timezone)) {
                Write-Warning -Message "Somehow the provided Timezone $Timezone is not actually valid. Please look into this."
                Break
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTimeZone had an error while retrieving the timezone Id [$Timezone] running under New-AutomateNOWCalendar due to [$message]"
            Break
        }
        $ANOWCalendar.Add('timeZone', $Timezone)
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWCalendar due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWCalendar has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWCalendar.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] existed under New-AutomateNOWCalendar due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under New-AutomateNOWCalendar. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWCalendar] [$Id]"
        $ANOWCalendar.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWCalendar due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWCalendar. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWCalendar] [$Id]"
        $ANOWCalendar.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    $ANOWCalendar.Add('calendarType', $Type)
    [string]$title = Switch ($Type) {
        'BASE' { 'Base' }
        'OR' { 'Sum' }
        'AND' { 'Conjunction' }
        'NOT' { 'Inversion' }
        'CAL_SELECT' { 'Select' }
        Default { 'Unknown' }
    }
    $ANOWCalendar.Add('title', $title)
    $ANOWCalendar.Add('icon', '[SKINIMG]/skin/date_control.png')
    $oldvalues = ('{"title":"' + $title + '","resourceType":"CALENDAR","calendarType":"' + $Type + '","icon":"[SKINIMG]/skin/date_control.png"}')
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWCalendar -IncludeProperties id, description, calendarType, title, icon, tags, folder, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'resourceType' = 'CALENDAR'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = $oldvalues
    $BodyMetaData.'_componentId' = 'CalendarCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'CalendarDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/resource/create'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Calendar [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Calendar [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWCalendar]$Calendar = $results.response.data | Select-Object -First 1
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create the [ANOWCalendar] object due to [$Message]."
        Break
    }
    If ($Calendar.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWCalendar] Calendar is empty!"
        Break
    }
    If ($Quiet -ne $true) {
        Return $Calendar
    }
}

Function Remove-AutomateNOWCalendar {
    <#
    .SYNOPSIS
    Removes a Calendar from an AutomateNOW! instance

    .DESCRIPTION
    Removes a Calendar from an AutomateNOW! instance

    .PARAMETER Calendar
    An [ANOWCalendar] object representing the Calendar to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWCalendar] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Remove a single Calendar by name

    Get-AutomateNOWCalendar -Id 'calendar01' | Remove-AutomateNOWCalendar

    .EXAMPLE
    Removes a series of Calendar objects via input from the pipeline

    @( 'calendar01', 'calendar02', 'calendar03') | Get-AutomateNOWCalendar | Remove-AutomateNOWCalendar

    .EXAMPLE
    Forcefully removes all Calendar objects that have a timezone configured as UTC

    Get-AutomateNOWCalendar | Where-Object { $_.timeZone -eq 'UTC'} | Remove-AutomateNOWCalendar -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWCalendar]$Calendar,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/resource/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Calendar.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [ANOWCalendar]$Calendar = $_
            }
            [string]$Calendar_id = $Calendar.id
            [string]$oldvalues = $Calendar.CreateOldValues()
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Calendar.id
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_operationType' = 'remove'
            $BodyMetaData.'_oldValues' = $oldvalues
            $BodyMetaData.'_componentId' = 'ResourceList'
            $BodyMetaData.'_dataSource' = 'ResourceDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            If ($null -eq $parameters["Body"]) {
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Calendar_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Calendar [$Calendar_id] successfully removed"
        }
    }
    End {

    }
}

#endregion

#Region - CodeRepositories

Function Get-AutomateNOWCodeRepository {
    <#
    .SYNOPSIS
    Gets the Code Repositories from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Code Repositories from an AutomateNOW! instance

    .PARAMETER Id
    Optional string containing the simple id of the Code Repository to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the Code Repository from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWCodeRepository] class objects

    .EXAMPLE
    Get-AutomateNOWCodeRepository

    .EXAMPLE
    Get-AutomateNOWCodeRepository -Id 'CodeRepository01'

    .EXAMPLE
    @( 'Code Repository01', 'Code Repository02' ) | Get-AutomateNOWCodeRepository

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Code Repositories

    #>
    [OutputType([ANOWCodeRepository[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $True, ParameterSetName = 'Id', ValueFromPipeline = $true)]
        [string]$Id
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            $Body.'_textMatchStyle' = 'substring'
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_componentId' = 'CodeRepositoryList'
        $Body.'_dataSource' = 'CodeRepositoryDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/codeRepository/read?' + $Body)
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
            [ANOWCodeRepository[]]$CodeRepositories = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWCodeRepository] objects due to [$Message]."
            Break
        }
        If ($CodeRepositories.Count -gt 0) {
            Return $CodeRepositories
        }
    }
    End {

    }
}

Function Export-AutomateNOWCodeRepository {
    <#
    .SYNOPSIS
    Exports the Code Repositories from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Code Repositories from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWCodeRepository] object (Use Get-AutomateNOWFolder to retrieve them)

    .INPUTS
    ONLY [ANOWCodeRepository] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWCodeRepository] objects are exported to the local disk in CSV format

    .EXAMPLE
    Get-AutomateNOWCodeRepository | Export-AutomateNOWCodeRepository

    .EXAMPLE
    Get-AutomateNOWCodeRepository -Id 'CodeRepository01' | Export-AutomateNOWCodeRepository

    .EXAMPLE
    @( 'CodeRepository01', 'CodeRepository02' ) | Get-AutomateNOWCodeRepository | Export-AutomateNOWCodeRepository

    .EXAMPLE
    Get-AutomateNOWCodeRepository | Where-Object { $_.simpleId -eq 'CodeRepository01' } | Export-AutomateNOWCodeRepository

    .NOTES
	You must present [ANOWCodeRepository] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWCodeRepository]$CodeRepository
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-CodeRepositories-' + $current_time + '.csv'
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
            [ANOWCodeRepository]$CodeRepository = $_
        }
        $Error.Clear()
        Try {
            $CodeRepository | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWCodeRepository] object on the pipeline due to [$Message]"
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
        [int32]$endRow = 100,
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
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
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
    Optional string array containing the id's of the tags to assign to the new DataSource.

    .PARAMETER Folder
    Optional name of the folder to place the DataSource into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the DataSource into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

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
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
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
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
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
    If ($Quiet -ne $true) {
        Return $DataSource
    }
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

Function Set-AutomateNOWDataSource {
    <#
    .SYNOPSIS
    Changes the settings of a DataSource on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of a DataSource on an AutomateNOW! instance

    .PARAMETER DataSource
    An [ANOWDataSource] object representing the DataSource to be changed.

    .PARAMETER Description
    Optional description of the DataSource (may not exceed 255 characters).

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWDataSource] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWDataSource] object will be returned

    .EXAMPLE
    Changes the settings of a DataSource

    $datasource = Get-AutomateNOWDataSource -Id 'DataSource1'
    Set-AutomateNOWDataSource -DataSource $datasource -DataType STRING -ErrorHandling INIT -Validity FREE

    .EXAMPLE
    Quietly changes the settings of two DataSources by way of the pipeline

    @((Get-AutomateNOWDataSource -Id 'DataSource1'), (Get-AutomateNOWDataSource -Id 'DataSource2')) | Set-AutomateNOWDataSource -DataType NUMBER -ErrorHandling INIT -Validity JOB -Description 'description!' -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function is for modifying the settings of a DataSource. Use Add-AutomateNOWDataSourceItem if you want to add a DataSource Item to the DataSource.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWDataSource]$DataSource,
        [Parameter(Mandatory = $false)]
        [ANOWDataSource_dataType]$DataType = 'STRING',
        [Parameter(Mandatory = $false)]
        [ANOWDataSource_errorHandling]$ErrorHandling = 'INIT',
        [Parameter(Mandatory = $false)]
        [ANOWDataSource_validity]$Validity = 'FREE',
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false)]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/dataSource/update'
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
            Else {
                [string]$DataSource_id = $DataSource.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$DataSource_exists = ($null -eq (Get-AutomateNOWDataSource -Id $DataSource_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWDataSource failed to check if the DataSource [$DataSource_id] already existed due to [$Message]."
                Break
            }
            If ($DataSource_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Result Mapping named [$DataSource_id] in the [$current_domain] domain. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $DataSource_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($DataSource.description.length -gt 0) {
                $BodyMetaData.'description' = $DataSource.description
            }
            If ($DataSource.codeRepository.Length -gt 0) {
                $BodyMetaData.'codeRepository' = $DataSource.codeRepository
            }
            Else {
                $BodyMetaData.'codeRepository' = $null
            }
            $BodyMetaData.'validity' = $Validity
            $BodyMetaData.'errorHandling' = $ErrorHandling
            $BodyMetaData.'dataType' = $DataType
            $BodyMetaData.'_oldValues' = $DataSource.CreateOldValues()
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_componentId' = 'DataSourceValuesManager'
            $BodyMetaData.'_dataSource' = 'DataSourceDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$DataSource_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Result Mapping [$DataSource_id] was successfully updated"
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
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
    Exports all of the local dictionary values from all local dictionary data sources

    Get-AutomateNOWDataSource -Type LOCAL_DICTIONARY | Get-AutomateNOWDataSourceItem | Export-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY

    .EXAMPLE
    Exports all of the local dictionary values from a single local dictionary data source

    Get-AutomateNOWDataSource -Id 'DataSource01' | Get-AutomateNOWDataSourceItem | Export-AutomateNOWDataSourceItem -Type LOCAL_DICTIONARY

    .EXAMPLE
    Exports the the first 5 local dictionary values from a series of local dictionary data sources

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
    Gets all of the domains

    Get-AutomateNOWDomain

    .EXAMPLE
    Gets a single domain

    Get-AutomateNOWDomain -Id 'Training'

    .EXAMPLE
    Gets a series of domains based on an array of strings presented to the pipeline

    @('Training', 'Production', 'Test') | Get-AutomateNOWDomain

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [OutputType([ANOWDomain[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Id
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
        If ($results.response.data.count -gt 0) {
            [ANOWDomain[]]$Domains = ForEach ($domain in $results.response.data) {
                [string]$domain_name = $domain.id
                If ($domain_name.Length -eq 0) {
                    Write-Warning -Message 'Somehow the domain information could not be read during Get-AutomateNOWDomain'
                    Break
                }
                [string]$defaultTimeZoneId = $domain.defaultTimeZone
                If ($defaultTimezoneId.Length -eq 0) {
                    Write-Verbose -Message "There is not a default timezone set for this domain, therefore will use the server default"
                    Try {
                        $domain | Add-Member -MemberType NoteProperty -Name defaultTimezone -Value $anow_session.server_timezone
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Add-Member failed to add the server timezone to the domain [$domain_name] due to [$Message]."
                        Break
                    }
                }
                Else {
                    $Error.Clear()
                    Try {
                        [ANOWTimeZone]$defaultTimezone = Get-AutomateNOWTimeZone -Id $defaultTimeZoneId
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Get-AutomateNOWTimeZone failed to get [$defaultTimeZoneId] under Get-AutomateNOWDomain due to [$Message]."
                        Break
                    }
                    $domain.defaultTimeZone = $defaultTimezone
                }
                [ANOWDomain]$domain
            }
        }
    }
    Process {
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            If ($_.Length -gt 0) {
                [string]$domain_id = $_
            }
            Else {
                [string]$domain_id = $Id
            }
            [ANOWDomain]$selected_domain = $Domains | Where-Object { $_.Id -eq $domain_id }
            If ($selected_domain.Id.Length -gt 0) {
                Return $selected_domain
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

#Region - Endpoints

Function Get-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Gets the Endpoints from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Endpoints from an AutomateNOW! instance

    .PARAMETER Id
    Optional string containing the simple id of the Endpoint to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER EndpointType
    Optional string that will return all endpoints of that type. Valid choices are: USER; FTP; MAINFRAME_FTP; FTPS; MAINFRAME_FTPS; SFTP; S3; HDFS; AZURE_BLOB; AZURE_FILE; GOOGLE_COULD_STORAGE_BUCKET; PGP; HTTP; REST_WEB_SERVICE; SOAP_WEB_SERVICE; EMAIL; EMAIL_EWS; AWS; AZURE; GOOGLE_CLOUD; GOOGLE_DATA_FLOW; AZURE_DATABRICKS; INFORMATICA_CLOUD; AWS_COMMON; IBM_MQ; RABBIT_MQ; SQS; ACTIVE_MQ; QPID; IBM_SIBUS; HORNETQ; SOLACE; JORAM_MQ; QMQ; ZERO_MQ; KAFKA; PULSAR; AMAZON_KINESIS; GOOGLE_CLOUD_PUB_SUB; MICROSOFT_AZURE_EVENT_HUB; AMQP; XMPP; STOMP; REDIS; HADOOP; HIVE; IMPALA; SQOOP; YARN; SPARK; FLUME; FLINK; STORM; OOZIE; AMBARI; ELASTIC_SEARCH; CASSANDRA; SAP_HANA; MONGO_DB; COUCH_DB; COUCH_BASE; DYNAMO_DB; ARANGO_DB; NEO4J; ORIENT_DB; TITAN; SSH; WINRM; HIVE_QL; GOOGLE_BIG_QUERY; DASHDB; DB2; MYSQL; NETEZZA; AZURE_SQL_DATABASE; AZURE_SQL_DATA_WAREHOUSE; ORACLE; POSTGRESQL; SQL_SERVER; SQL_SERVER_JTDS; TERADATA; SINGLESTORE; VERTICA; SNOWFLAKE; PRESTO_DB; SYBASE; INFORMIX; H2; AS400; Z_OS; Z_OS_REST; RAINCODE; OPENTEXT; CTRL_M; INFORMATICA; INFORMATICA_WS; SAS; SAS_VIYA; IBM_DATASTAGE; ODI; MS_SSIS; AB_INITIO; SAP_BODI; SKYVIA; TALEND; DBT; SAP; SAP_S4_HANA; SAP_S4_HANA_CLOUD; SAP_IBP; JD_EDWARDS; ORACLE_EBS; PEOPLESOFT; MICROSOFT_DYNAMICS; JIRA; SERVICE_NOW; ORACLE_SERVICE_CENTER; BMC_REMEDY; CA_SERVICE_MANAGEMENT; IBM_CONTROL_DESK; HP_OPEN_VIEW_SERVICE_MANAGER; SAP_SOLUTION_MANAGER; FACEBOOK; INSTAGRAM; TWITTER; YOUTUBE; LINKED_IN; TUMBLR; TIKTOK; REDDIT; TELEGRAM; WHATSAPP; MICROSOFT_POWER_BI; TABLEAU; BLUE_PRISM; UI_PATH; AUTOMATION_ANYWHERE; WORK_FUSION; PEGA; ROBOT_FRAMEWORK; AUTOMATE_NOW; APACHE_AIRFLOW; ANSIBLE;

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100. The console default hard limit is 10,000.

    .INPUTS
    Accepts a string representing the simple id of the Endpoint from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWEndpoint] class objects

    .EXAMPLE
    Gets all of the Endpoints
    Get-AutomateNOWEndpoint

    .EXAMPLE
    Gets a single Endpoint by name
    Get-AutomateNOWEndpoint -Id 'my_endpoint_01'

    .EXAMPLE
    Gets a series of Endpoints by feeding their names through the pipeline.
    @( 'endpoint_01', 'endpoint_02' ) | Get-AutomateNOWEndpoint

    .EXAMPLE
    Gets all Endpoints of type AZURE_BLOB
    Get-AutomateNOWEndpoint -EndpointType 'AZURE_BLOB'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Endpoints.

    #>
    [OutputType([ANOWEndpoint[]])]
    [Cmdletbinding(DefaultParameterSetName = 'All')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Single', ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [ANOWEndpoint_endpointType]$EndpointType,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_.Length -gt 0 -or $Id.Length -gt 0 ) {
            If ($_.Length -gt 0) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            [string]$textMatchStyle = 'exactCase'
            $Body.'_operationId' = 'read'
        }
        Else {
            $Body.'operator' = 'and'
            $Body.'_constructor' = 'AdvancedCriteria'
            If ($EndpointType.Length -gt 0) {
                $Body.'criteria' = ('{"fieldName":"endpointType","operator":"equals","value":' + $EndpointType + '}')
            }
            $Body.'_componentId' = 'EndpointList'
            [string]$textMatchStyle = 'substring'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_dataSource' = 'EndpointDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/endpoint/read?' + $Body)
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
            [ANOWEndpoint[]]$Endpoints = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWEndpoint] objects due to [$Message]."
            Break
        }
        If ($Endpoints.Count -gt 0) {
            Return $Endpoints
        }
    }
    End {

    }
}

Function Set-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Changes the settings of an Endpoint on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of an Endpoint on an AutomateNOW! instance

    .PARAMETER Endpoint
    An [ANOWEndpoint] object representing the Endpoint to be modified.

    .PARAMETER UnsetDescription
    Optional switch that will remove the Description from the Endpoint object.

    .PARAMETER Description
    Optional string to set on the new Endpoint object.

    .PARAMETER UnsetFolder
    Optional switch that will remove the Folder assignment from the Endpoint object.

    .PARAMETER Folder
    Optional string to set a different folder on the Endpoint object.

    .PARAMETER UnsetTags
    Optional switch that will remove the Tags from the Endpoint object.

    .PARAMETER Tags
    Optional strings to set a different set of Tags on the new Endpoint object.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWEndpoint] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWEndpoint] object will be returned

    .EXAMPLE
    Changes the description of an Endpoint

    $Endpoint = Get-AutomateNOWEndpoint -Id 'Endpoint1'
    Set-AutomateNOWEndpoint -Endpoint $Endpoint -Description 'My Description'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function is a work-in-progress. Only common properties can be modified (Description, Folder, Tags). Credentials are not supported yet :(

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWEndpoint]$Endpoint,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetFolder,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetDescription -eq $true -and $Description.Length -gt 0) {
            Write-Warning -Message "You cannot set the description and unset it at the same time. Please choose one or the other."
            Break
        }
        If ($UnsetFolder -eq $true -and $Folder.Length -gt 0) {
            Write-Warning -Message "You cannot set the Folder and unset it at the same time. Please choose one or the other."
            Break
        }
        If ($UnsetTags -eq $true -and $Tags.Count -gt 0) {
            Write-Warning -Message "You cannot set the Tags and unset them at the same time. Please choose one or the other. Tags from the source object will be carried over to the new object if you do not specify any tag-related parameters."
            Break
        }
        [string]$command = '/endpoint/update'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [ANOWEndpoint]$Endpoint = $_
        }
        [string]$Endpoint_id = $Endpoint.id
        [string]$Endpoint_type = $Endpoint.endpointType
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Endpoint.id)")) -eq $true) {
            Else {
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$Endpoint_exists = ($null -eq (Get-AutomateNOWEndpoint -Id $Endpoint_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWEndpoint failed to check if the Endpoint [$Endpoint_id] already existed due to [$Message]."
                Break
            }
            If ($Endpoint_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Result Mapping named [$Endpoint_id] in the [$current_domain] domain. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Endpoint_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($UnsetDescription -eq $true) {
                $BodyMetaData.'description' = $Null
            }
            Else {
                If ($Endpoint.description.Length -gt 0) {
                    $BodyMetaData.'description' = $Endpoint.description
                }
            }
            If ($UnsetFolder -eq $True) {
                $BodyMetaData.'folder' = $Null
            }
            ElseIf ($Folder.Length -gt 0) {
                $BodyMetaData.'folder' = $Folder
            }
            Else {
                If ($Endpoint.folder.Length -gt 0) {
                    $BodyMetaData.'folder' = $Endpoint.folder
                }
            }
            If ($Tags.Count -gt 0) {
                [int32]$tag_count = 1
                ForEach ($tag in $Tags) {
                    $BodyMetaData.('tags' + $tag_count ) = $tag
                    $tag_count++
                }
            }
            ElseIf ($UnsetTags -eq $true) {
                $BodyMetaData.'tags' = $Null
            }
            Else {
                If ($Endpoint.Tags -gt 0) {
                    [int32]$tag_count = 1
                    ForEach ($tag in $Endpoint.tags) {
                        $BodyMetaData.('tags' + $tag_count ) = $tag
                        $tag_count++
                    }
                }
            }
            [string]$old_values = $Endpoint.CreateOldValues()
            $BodyMetaData.'_oldValues' = $old_values
            $BodyMetaData.'_componentId' = 'EndpointVM'
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'EndpointDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Endpoint_id] of type [$Endpoint_type] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Endpoint object [$Endpoint_id] of type [$Endpoint_type] was successfully updated"
        }
    }
    End {
    }
}

Function Export-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Exports the Endpoints from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Endpoints from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWEndpoint] object (Use Get-AutomateNOWEndpoint to retrieve them)

    .INPUTS
    ONLY [ANOWEndpoint] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWEndpoint] objects are exported to the local disk in CSV format

    .EXAMPLE
    Exports all endpoints
    Get-AutomateNOWEndpoint | Export-AutomateNOWEndpoint

    .EXAMPLE
    Exports a single endpoint
    Get-AutomateNOWEndpoint -Id 'Endpoint01' | Export-AutomateNOWEndpoint

    .EXAMPLE
    Exports a series of endpoints through the pipeline
    @( 'Endpoint01', 'Endpoint02' ) | Get-AutomateNOWEndpoint | Export-AutomateNOWEndpoint

    .EXAMPLE
    Exports all endpoints of a given type
    Get-AutomateNOWEndpoint -Type AZURE_BLOB | Export-AutomateNOWEndpoint

    .NOTES
	You must present [ANOWEndpoint] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWEndpoint]$Endpoint
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-Endpoints-' + $current_time + '.csv'
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
            [ANOWEndpoint]$Endpoint = $_
        }
        $Error.Clear()
        Try {
            $Endpoint | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWEndpoint] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Creates a Endpoint within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Endpoint within an AutomateNOW! instance and returns back the newly created [ANOWEndpoint] object

    .PARAMETER Id
    The intended name of the Endpoint. For example: 'LinuxEndpoint1'. This value may not contain the domain in brackets.

    .PARAMETER EndpointType
    Required type of the Endpoint. Valid choices are: USER; FTP; MAINFRAME_FTP; FTPS; MAINFRAME_FTPS; SFTP; S3; HDFS; AZURE_BLOB; AZURE_FILE; GOOGLE_COULD_STORAGE_BUCKET; PGP; HTTP; REST_WEB_SERVICE; SOAP_WEB_SERVICE; EMAIL; EMAIL_EWS; AWS; AZURE; GOOGLE_CLOUD; GOOGLE_DATA_FLOW; AZURE_DATABRICKS; INFORMATICA_CLOUD; AWS_COMMON; IBM_MQ; RABBIT_MQ; SQS; ACTIVE_MQ; QPID; IBM_SIBUS; HORNETQ; SOLACE; JORAM_MQ; QMQ; ZERO_MQ; KAFKA; PULSAR; AMAZON_KINESIS; GOOGLE_CLOUD_PUB_SUB; MICROSOFT_AZURE_EVENT_HUB; AMQP; XMPP; STOMP; REDIS; HADOOP; HIVE; IMPALA; SQOOP; YARN; SPARK; FLUME; FLINK; STORM; OOZIE; AMBARI; ELASTIC_SEARCH; CASSANDRA; SAP_HANA; MONGO_DB; COUCH_DB; COUCH_BASE; DYNAMO_DB; ARANGO_DB; NEO4J; ORIENT_DB; TITAN; SSH; WINRM; HIVE_QL; GOOGLE_BIG_QUERY; DASHDB; DB2; MYSQL; NETEZZA; AZURE_SQL_DATABASE; AZURE_SQL_DATA_WAREHOUSE; ORACLE; POSTGRESQL; SQL_SERVER; SQL_SERVER_JTDS; TERADATA; SINGLESTORE; VERTICA; SNOWFLAKE; PRESTO_DB; SYBASE; INFORMIX; H2; AS400; Z_OS; Z_OS_REST; RAINCODE; OPENTEXT; CTRL_M; INFORMATICA; INFORMATICA_WS; SAS; SAS_VIYA; IBM_DATASTAGE; ODI; MS_SSIS; AB_INITIO; SAP_BODI; SKYVIA; TALEND; DBT; SAP; SAP_S4_HANA; SAP_S4_HANA_CLOUD; SAP_IBP; JD_EDWARDS; ORACLE_EBS; PEOPLESOFT; MICROSOFT_DYNAMICS; JIRA; SERVICE_NOW; ORACLE_SERVICE_CENTER; BMC_REMEDY; CA_SERVICE_MANAGEMENT; IBM_CONTROL_DESK; HP_OPEN_VIEW_SERVICE_MANAGER; SAP_SOLUTION_MANAGER; FACEBOOK; INSTAGRAM; TWITTER; YOUTUBE; LINKED_IN; TUMBLR; TIKTOK; REDDIT; TELEGRAM; WHATSAPP; MICROSOFT_POWER_BI; TABLEAU; BLUE_PRISM; UI_PATH; AUTOMATION_ANYWHERE; WORK_FUSION; PEGA; ROBOT_FRAMEWORK; AUTOMATE_NOW; APACHE_AIRFLOW; ANSIBLE;

    .PARAMETER Description
    Optional description of the Endpoint (may not exceed 255 characters).

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Endpoint. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the Endpoint into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Endpoint into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWEndpoint.

    .OUTPUTS
    An [ANOWEndpoint] object representing the newly created Endpoint

    .EXAMPLE
    New-AutomateNOWEndpoint -Id 'endpoint_01' -EndpointType 'AZURE_BLOB' -Description 'Description!' -Tags 'Tag1', 'Tag2' -Folder 'Folder1'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Endpoint must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWEndpoint])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [ANOWEndpoint_endpointType]$endpointType,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$Endpoint_exists = ($null -ne (Get-AutomateNOWEndpoint -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWEndpoint failed to check if the Endpoint [$Id] already existed due to [$Message]."
        Break
    }
    If ($Endpoint_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Endpoint named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWEndpoint = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWEndpoint.Add('id', $Id)
    $ANOWEndpoint.Add('endpointType', $endpointType)
    If ($Description.Length -gt 0) {
        $ANOWEndpoint.Add('description', $Description)
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWEndpoint due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWEndpoint has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWEndpoint.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] existed under New-AutomateNOWEndpoint due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under New-AutomateNOWEndpoint. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWEndpoint] [$Id]"
        $ANOWEndpoint.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWEndpoint due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWEndpoint. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWEndpoint] [$Id]"
        $ANOWEndpoint.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWEndpoint -IncludeProperties id, serverEndpointType, loadBalancer, totalWeightCapacity, description, tags, folder, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = '{"endpointType":"' + $endpointType + '"}'
    $BodyMetaData.'_componentId' = 'EndpointCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'EndpointDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/endpoint/create'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Endpoint [$Id] of type [$endpointType] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Endpoint [$Id] of type [$endpointType] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWEndpoint]$Endpoint = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWEndpoint] object due to [$Message]."
        Break
    }
    If ($Endpoint.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWEndpoint] Endpoint is empty!"
        Break
    }
    If ($Quiet -ne $true) {
        Return $Endpoint
    }
}

Function Copy-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Copies an Endpoint from an AutomateNOW! instance

    .DESCRIPTION
    Copies an Endpoint from an AutomateNOW! instance. AutomateNOW object id can never be changed, but we can copy the object to a new id and it will include all of the items therein.

    .PARAMETER Endpoint
    Mandatory [ANOWEndpoint] object to be copied.

    .PARAMETER NewId
    The name (Id) of the new Endpoint. The new Id must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    .PARAMETER UnsetDescription
    Optional switch that will ensure that the newly created Endpoint will not have a description set.

    .PARAMETER Description
    Optional description to set on the new Endpoint object. If you do not set this, the new Endpoint object will copy the Description of the source object.

    .PARAMETER UnsetFolder
    Optional switch that will ensure that the newly created Endpoint will not have a Folder set.

    .PARAMETER Folder
    Optional description to set a different folder on the new Endpoint object. If you do not set this, the new Endpoint object will use the same Folder of the source object.

    .PARAMETER UnsetTags
    Optional switch that will ensure that the newly created Endpoint will not have any Tags set.

    .PARAMETER Tags
    Optional strings to set a different set of Tags on the new Endpoint object. If you do not set this, the new Endpoint object will appy the same Tags of the source object.

    .INPUTS
    ONLY [ANOWEndpoint] object is accepted. Pipeline support is intentionally unavailable.

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Creates a copy of an Endpoint and changes the description (multi-line format)
    $Endpoint01 = Get-AutomateNOWEndpoint -Id 'endpoint_01'
    Copy-AutomateNOWEndpoint -Endpoint $Endpoint01 -NewId 'endpoint_01_production' -Description 'Endpoint 01 Production'

    .EXAMPLE
    Creates a copy of an Endpoint that omits the description (one-liner format)
    Copy-AutomateNOWEndpoint -Endpoint (Get-AutomateNOWEndpoint -Id 'endpoint_01') -NewId 'Endpoint_01_production' -UnsetDescription -Tags 'Tag1', 'Tag2'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWEndpoint]$Endpoint,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,1024}$' })]
        [string]$NewId,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetFolder
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetDescription -eq $true -and $Description.Length -gt 0) {
            Write-Warning -Message "You cannot set the description and unset it at the same time. Please choose one or the other."
            Break
        }
        If ($UnsetFolder -eq $true -and $Folder.Length -gt 0) {
            Write-Warning -Message "You cannot set the Folder and unset it at the same time. Please choose one or the other."
            Break
        }
        If ($UnsetTags -eq $true -and $Tags.Count -gt 0) {
            Write-Warning -Message "You cannot set the Tags and unset them at the same time. Please choose one or the other. Tags from the source object will be carried over to the new object if you do not specify any tag-related parameters."
            Break
        }
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. Technically, the console will not allow a duplicate object to be created. However, it would be cleaner to use the Get function first to ensure we are not trying to create a duplicate here.
        $Error.Clear()
        Try {
            [boolean]$Endpoint_exists = ($null -ne (Get-AutomateNOWEndpoint -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWEndpoint failed to check if the Endpoint [$NewId] already existed due to [$Message]."
            Break
        }
        If ($Endpoint_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already an Endpoint named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        ## End warning ##
        [string]$command = '/endpoint/copy'
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
            [string]$Endpoint_oldId = $Endpoint.id
            If ($Endpoint_oldId -eq $NewId) {
                Write-Warning -Message "The new id cannot be the same as the old id."
                Break
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            If ($UnsetFolder -eq $True) {
                $BodyMetaData.'folder' = $Null
            }
            ElseIf ($Folder.Length -gt 0) {
                $BodyMetaData.'folder' = $Folder
            }
            Else {
                If ($Endpoint.folder.Length -gt 0) {
                    $BodyMetaData.'folder' = $Endpoint.folder
                }
            }
            If ($Tags.Count -gt 0) {
                [int32]$tag_count = 1
                ForEach ($tag in $Tags) {
                    $BodyMetaData.('tags' + $tag_count ) = $tag
                    $tag_count++
                }
            }
            ElseIf ($UnsetTags -eq $true) {
                $BodyMetaData.'tags' = $Null
            }
            Else {
                If ($Endpoint.Tags -gt 0) {
                    [int32]$tag_count = 1
                    ForEach ($tag in $Endpoint.tags) {
                        $BodyMetaData.('tags' + $tag_count ) = $tag
                        $tag_count++
                    }
                }
            }
            $BodyMetaData.'oldId' = $Endpoint_oldId
            $BodyMetaData.'domain' = $Endpoint.domain
            $BodyMetaData.'id' = $NewId
            If ($UnsetDescription -ne $true) {
                If ($Description.Length -gt 0) {
                    $BodyMetaData.'description' = $Description
                }
                Else {
                    $BodyMetaData.'description' = $Endpoint.description
                }
            }
            $BodyMetaData.'_operationType' = 'add'
            $BodyMetaData.'_operationId' = 'copy'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'EndpointDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            $Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties oldId, domain, NewId, description, folder, tags
            $parameters.Body = $Body
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Endpoint_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWEndpoint]$Endpoint = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create copied [ANOWEndpoint] object $NewId due to [$Message]."
                Break
            }
            If ($Endpoint.id.Length -eq 0) {
                Write-Warning -Message "Somehow the newly created (copied) [ANOWEndpoint] object is empty!"
                Break
            }
            Return $Endpoint
        }
    }
    End {

    }
}

Function Remove-AutomateNOWEndpoint {
    <#
    .SYNOPSIS
    Removes an Endpoint from an AutomateNOW! instance

    .DESCRIPTION
    Removes an Endpoint from an AutomateNOW! instance

    .PARAMETER Endpoint
    An [ANOWEndpoint] object representing the Endpoint to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWEndpoint] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Remove a single endpoint based on its name.
    Get-AutomateNOWEndpoint -Id 'Endpoint01' | Remove-AutomateNOWEndpoint

    .EXAMPLE
    Remove a series of endpoints based on the pipeline
    @( 'Endpoint1', 'Endpoint2', 'Endpoint3') | Get-AutomateNOWEndpoint | Remove-AutomateNOWEndpoint

    .EXAMPLE
    Forcibly remove all Azure Blob endpoints
    Get-AutomateNOWEndpoint -endpointType 'AZURE_BLOB' | Remove-AutomateNOWEndpoint -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWEndpoint]$Endpoint,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/endpoint/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($Endpoint.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$Endpoint_id = $_.id
            }
            ElseIf ($Endpoint.id.Length -gt 0) {
                [string]$Endpoint_id = $Endpoint.id
            }
            Else {
                [string]$Endpoint_id = $Id
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            [string]$old_values = $Endpoint.CreateOldValues()
            $BodyMetaData.'id' = $Endpoint_id
            $BodyMetaData.'_operationType' = 'remove'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_oldValues' = $old_values
            $BodyMetaData.'_componentId' = 'EndpointList'
            $BodyMetaData.'_dataSource' = 'EndpointDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $BodyMetaDataString)
            }
            Else {
                $parameters.Body = $BodyMetaDataString
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Endpoint_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Endpoint $Endpoint_id successfully removed"
        }
    }
    End {

    }
}

Function Show-AutomateNOWEndpointType {
    <#
    .SYNOPSIS
    Shows all of the available Endpoint types for AutomateNOW! in human readable format

    .DESCRIPTION
    Shows all of the available Endpoint types for AutomateNOW! in human readable format (this was statically coded and will become outdated!)

    .INPUTS
    None. You cannot pipe objects to Show-AutomateNOWEndpointType.

    .OUTPUTS
    An array of PSCustomObjects

    .EXAMPLE
    Show-AutomateNOWEndpointType | Where-Object { $_.name -match 'SQL'} | Select-Object Id, Name

    .NOTES
    This is a stand-alone function which does not require connectivity to the AutomateNOW! console

    There are no parameters yet for this function
    #>
    [PSCustomObject]$TaskTypesJson = '[{"id":"REMOTE_CONNECTION","icon":"[SKINIMG]/skin/terminal.gif","name":"Remote Connection","folder":true},{"id":"SSH","parent":"REMOTE_CONNECTION","icon":"[SKINIMG]/skin/terminal.gif","name":"SSH"},{"id":"WINRM","parent":"REMOTE_CONNECTION","name":"Windows RM","icon":"[SKINIMG]/skin/win.png"},{"id":"FILE_MANAGER","folder":true,"icon":"[SKINIMG]/skin/network_folder.png","name":"File Manager"},{"id":"FTP","parent":"FILE_MANAGER","name":"FTP","icon":"[SKINIMG]/skin/ftp.png"},{"id":"MAINFRAME_FTPS","parent":"FILE_MANAGER","name":"Mainframe FTPS","icon":"[SKINIMG]/skin/folder.png"},{"id":"MAINFRAME_FTP","parent":"FILE_MANAGER","name":"Mainframe FTP","icon":"[SKINIMG]/skin/ftp.png"},{"id":"FTPS","parent":"FILE_MANAGER","name":"FTPS","icon":"[SKINIMG]/skin/folder.png"},{"id":"SFTP","name":"SFTP","parent":"FILE_MANAGER","icon":"[SKINIMG]/skin/gnome.png"},{"id":"HDFS","name":"HDFS","parent":"HADOOP","icon":"[SKINIMG]/skin/hadoop.png"},{"id":"S3","name":"Amazon S3","parent":"FILE_MANAGER","icon":"[SKINIMG]/skin/amazon.png"},{"id":"AZURE_BLOB","parent":"FILE_MANAGER","name":"Azure Blob","icon":"[SKINIMG]/skin/azure.png"},{"id":"AZURE_FILE","parent":"FILE_MANAGER","name":"Azure File","icon":"[SKINIMG]/skin/azure.png"},{"id":"GOOGLE_COULD_STORAGE_BUCKET","parent":"FILE_MANAGER","name":"Google Cloud Storage Bucket","icon":"[SKINIMG]/skin/googleCloud.png"},{"id":"USER","name":"User","icon":"[SKINIMG]/skin/user.png"},{"id":"ENCRYPTION","icon":"[SKINIMG]/skin/pgp.png","name":"Encryption","folder":true},{"id":"PGP","parent":"ENCRYPTION","icon":"[SKINIMG]/skin/pgp.png","name":"PGP"},{"id":"IBM_SERIES","folder":true,"icon":"[SKINIMG]/skin/ibm.png","name":"IBM Series"},{"id":"AS400","parent":"IBM_SERIES","icon":"[SKINIMG]/skin/ibm_as400.gif","name":"IBM AS/400"},{"id":"Z_OS","parent":"IBM_SERIES","icon":"[SKINIMG]/skin/zos.png","name":"IBM z/OS Mainframe"},{"id":"Z_OS_REST","parent":"IBM_SERIES","icon":"[SKINIMG]/skin/zos.png","name":"IBM z/OS Mainframe - REST"},{"id":"RAINCODE","parent":"IBM_SERIES","icon":"[SKINIMG]/skin/raincode.ico","name":"Raincode"},{"id":"OPENTEXT","parent":"IBM_SERIES","icon":"[SKINIMG]/skin/microfocus.png","name":"OpenText"},{"id":"SQL_DATABASE","folder":true,"icon":"[SKINIMG]/skin/oracle.png","name":"SQL Database"},{"id":"ORACLE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/oracle.png","name":"Oracle"},{"id":"TERADATA","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/teradata.png","name":"Teradata"},{"id":"SINGLESTORE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/singlestore.jpg","name":"SingleStore"},{"id":"SQL_SERVER","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/sql_server.png","name":"MS SQL Server"},{"id":"SQL_SERVER_JTDS","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/sql_server.png","name":"MS SQL Server - JTDS"},{"id":"POSTGRESQL","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/postgres.png","name":"PostgreSQL"},{"id":"MYSQL","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/mysql.png","name":"MySQL"},{"id":"DB2","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/db2.png","name":"IBM DB2"},{"id":"NETEZZA","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/netezza.png","name":"Netezza"},{"id":"DASHDB","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/dashDB.png","name":"IBM DB2 on Cloud"},{"id":"SNOWFLAKE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/snowflake.png","name":"Snowflake"},{"id":"VERTICA","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/vertica.png","name":"Vertica"},{"id":"PRESTO_DB","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/prestodb.png","name":"Presto DB"},{"id":"INFORMIX","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/informix.png","name":"Informix"},{"id":"H2","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/h2.png","name":"H2"},{"id":"SYBASE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/sybase.png","name":"Sybase"},{"id":"AZURE_SQL_DATABASE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/azure-sql.png","name":"Azure SQL Database"},{"id":"AZURE_SQL_DATA_WAREHOUSE","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/azure-warehouse.png","name":"Azure Synapse Analytics"},{"id":"HIVE_QL","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/hive.png","name":"Hive QL Database"},{"id":"GOOGLE_BIG_QUERY","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/bigquery.png","name":"Google BigQuery"},{"id":"SAP_HANA","parent":"SQL_DATABASE","icon":"[SKINIMG]/skin/sap.png","name":"SAP Hana"},{"id":"BIG_DATA","folder":true,"icon":"[SKINIMG]/skin/database.png","name":"Big Data"},{"id":"HADOOP","parent":"BIG_DATA","folder":true,"icon":"[SKINIMG]/skin/hadoop.png","name":"Hadoop"},{"id":"SPARK","parent":"HADOOP","icon":"[SKINIMG]/skin/spark.png","name":"Spark"},{"id":"FLINK","parent":"HADOOP","icon":"[SKINIMG]/skin/flink.jpg","name":"Flink"},{"id":"REDIS","parent":"BIG_DATA","icon":"[SKINIMG]/skin/redis.png","name":"Redis"},{"id":"NOSQL_DATABASE","folder":true,"icon":"[SKINIMG]/skin/mongodb.gif","name":"NoSQL Database"},{"id":"MONGO_DB","parent":"NOSQL_DATABASE","icon":"[SKINIMG]/skin/mongodb.gif","name":"Mongo DB"},{"id":"TITAN","parent":"NOSQL_DATABASE","icon":"[SKINIMG]/skin/titan.png","name":"Titan"},{"id":"MQ","folder":true,"icon":"[SKINIMG]/skin/queue.png","name":"Message Queues"},{"id":"IBM_MQ","parent":"MQ","icon":"[SKINIMG]/skin/ibm_mq.png","name":"IBM MQ"},{"id":"ACTIVE_MQ","parent":"MQ","icon":"[SKINIMG]/skin/activemq.png","name":"Active MQ"},{"id":"RABBIT_MQ","parent":"MQ","icon":"[SKINIMG]/skin/rabbitmq.png","name":"Rabbit MQ"},{"id":"KAFKA","parent":"MQ","icon":"[SKINIMG]/skin/kafka.png","name":"Kafka"},{"id":"HORNETQ","parent":"MQ","icon":"[SKINIMG]/skin/hornetq.png","name":"HornetQ"},{"id":"AMQP","parent":"MQ","icon":"[SKINIMG]/skin/amqp.png","name":"AMQP"},{"id":"XMPP","parent":"MQ","icon":"[SKINIMG]/skin/xmpp.png","name":"XMPP"},{"id":"STOMP","parent":"MQ","icon":"[SKINIMG]/skin/shoe.png","name":"STOMP"},{"id":"SOLACE","parent":"MQ","icon":"[SKINIMG]/skin/solace.png","name":"Solace"},{"id":"ETL","folder":true,"icon":"[SKINIMG]/skin/etl.png","name":"ETL Systems"},{"id":"INFORMATICA","parent":"ETL","icon":"[SKINIMG]/skin/informatica.ico","name":"Informatica Power Center"},{"id":"INFORMATICA_WS","parent":"ETL","icon":"[SKINIMG]/skin/informatica.ico","name":"Informatica WS Power Center"},{"id":"IBM_DATASTAGE","parent":"ETL","icon":"[SKINIMG]/skin/ibminfosphere.png","name":"IBM Infosphere DataStage"},{"id":"SAS","parent":"ETL","icon":"[SKINIMG]/skin/sas.png","name":"SAS"},{"id":"SAS_VIYA","parent":"ETL","icon":"[SKINIMG]/skin/sas_viya.png","name":"SAS Viya"},{"id":"MS_SSIS","parent":"ETL","icon":"[SKINIMG]/skin/ssis.png","name":"MS SQL Server Integration Services"},{"id":"ODI","parent":"ETL","icon":"[SKINIMG]/skin/odi.png","name":"Oracle Data Integrator"},{"id":"TALEND","parent":"ETL","icon":"[SKINIMG]/skin/talend.png","name":"Talend"},{"id":"DBT","parent":"ETL","icon":"[SKINIMG]/skin/dbt.ico","name":"dbt"},{"id":"ERP","folder":true,"icon":"[SKINIMG]/skin/erp.png","name":"ERP Systems"},{"id":"SAP","parent":"ERP","icon":"[SKINIMG]/skin/sap.png","name":"SAP R/3"},{"id":"SAP_S4_HANA","parent":"ERP","icon":"[SKINIMG]/skin/sap.png","name":"SAP S/4HANA"},{"id":"SAP_S4_HANA_CLOUD","parent":"ERP","icon":"[SKINIMG]/skin/sap.png","name":"SAP S/4HANA Cloud"},{"id":"ORACLE_EBS","parent":"ERP","icon":"[SKINIMG]/skin/oracle.png","name":"Oracle EBS"},{"id":"PEOPLESOFT","parent":"ERP","icon":"[SKINIMG]/skin/oracle.png","name":"Peoplesoft"},{"id":"WEB","folder":true,"icon":"[SKINIMG]/skin/globe_network.png","name":"Web Service"},{"id":"HTTP","parent":"WEB","icon":"[SKINIMG]/skin/world.png","name":"Http"},{"id":"REST_WEB_SERVICE","parent":"WEB","icon":"[SKINIMG]/skin/rest.png","name":"REST Web Service"},{"id":"SOAP_WEB_SERVICE","parent":"WEB","icon":"[SKINIMG]/skin/soap.png","name":"SOAP Web Service"},{"id":"EMAIL","parent":"WEB","icon":"[SKINIMG]/skin/mail.png","name":"Email"},{"id":"EMAIL_EWS","parent":"WEB","icon":"[SKINIMG]/skin/mail.png","name":"Email Exchange Web Service"},{"id":"ITSM","folder":true,"icon":"skin/compress_repair.png","name":"ITSM"},{"id":"SERVICE_NOW","parent":"ITSM","icon":"skin/servicenow.png","name":"ServiceNow"},{"id":"JIRA","parent":"ITSM","icon":"skin/jira.png","name":"Jira"},{"id":"BMC_REMEDY","parent":"ITSM","icon":"skin/bmc.ico","name":"BMC Remedy"},{"id":"BI","folder":true,"icon":"[SKINIMG]/skin/table_chart.png","name":"Business Intelligence"},{"id":"TABLEAU","parent":"BI","icon":"[SKINIMG]/skin/tableau.ico","name":"Tableau"},{"id":"MICROSOFT_POWER_BI","parent":"BI","icon":"[SKINIMG]/skin/powerBi.ico","name":"Microsoft Power BI"},{"id":"CLOUD","folder":true,"icon":"[SKINIMG]/skin/cloud.png","name":"Cloud"},{"id":"AWS","parent":"CLOUD","icon":"[SKINIMG]/skin/aws.png","name":"Amazon Web Services"},{"id":"AWS_COMMON","parent":"CLOUD","icon":"[SKINIMG]/skin/aws.png","name":"Amazon Web Services Common"},{"id":"AZURE","parent":"CLOUD","icon":"[SKINIMG]/skin/azure.png","name":"Azure"},{"id":"AZURE_DATABRICKS","parent":"CLOUD","icon":"[SKINIMG]/skin/azure.png","name":"Azure DataBricks"},{"id":"INFORMATICA_CLOUD","parent":"CLOUD","icon":"[SKINIMG]/skin/informatica.ico","name":"Informatica Cloud"},{"id":"INSTANT_MESSAGING","name":"Instant Messaging","icon":"[SKINIMG]/skin/comment_edit.png","folder":true},{"id":"TELEGRAM","name":"Telegram","icon":"[SKINIMG]/skin/telegram.png","parent":"INSTANT_MESSAGING"},{"id":"WHATSAPP","name":"WhatsApp","icon":"[SKINIMG]/skin/whatsapp.png","parent":"INSTANT_MESSAGING"},{"id":"RPA","folder":true,"icon":"[SKINIMG]/skin/robot.png","name":"Robotic Process Automation"},{"id":"BLUE_PRISM","parent":"RPA","icon":"[SKINIMG]/skin/blueprism.ico","name":"Blue Prism"},{"id":"UI_PATH","parent":"RPA","icon":"[SKINIMG]/skin/uipath.ico","name":"UI Path"},{"id":"ROBOT_FRAMEWORK","parent":"RPA","icon":"[SKINIMG]/skin/robotFramework.png","name":"Robot Framework"},{"id":"WLA","folder":true,"icon":"[SKINIMG]/skin/gears.png","name":"Workload Automation"},{"id":"AUTOMATE_NOW","parent":"WLA","icon":"[SKINIMG]/skin/favicon.png","name":"AutomateNOW!"},{"id":"APACHE_AIRFLOW","parent":"WLA","icon":"skin/airflow.png","name":"Apache Airflow"},{"id":"VC","folder":true,"icon":"skin/vcs.png","name":"Version Control"},{"id":"GIT","parent":"VC","icon":"skin/git.png","name":"Git"},{"id":"ANSIBLE","parent":"WLA","icon":"skin/ansible.png","name":"Ansible"},{"id":"CTRL_M","parent":"WLA","icon":"skin/bmc.png","name":"Ctrl-M"}]' | ConvertFrom-Json
    [array]$EndpointTypesArray = $TaskTypesJson | ForEach-Object { [PSCustomObject]@{ Parent = $_.parent; Id = $_.id; Name = $_.name; Icon = $_.icon } }
    Return $EndpointTypesArray
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
            $BodyMetaData.'isc_dataFormat' = 'json'
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

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

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
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
        Write-Warning -Message "Get-AutomateNOWFolder failed to check if the Folder [$Id] existed under New-AutomateNOWFolder due to [$Message]."
        Break
    }
    If ($Folder_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Folder named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWFolder = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWFolder.Add('id', $Id)
    If ($Description.Length -gt 0) {
        $ANOWFolder.Add('description', $Description)
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWFolder due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWFolder. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWFolder.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWFolder -IncludeProperties id, description, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_oldValues' = '{}'
    $BodyMetaData.'_componentId' = 'FolderCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'FolderDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
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
    If ($Quiet -ne $true) {
        Return $Folder
    }
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

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100. The console default hard limit is 10,000.

    .PARAMETER LoadBalancerOnly
    Optional switch that will return only the nodes that are load balancers.

    .PARAMETER ChildNodesOnly
    Optional switch that will return only the nodes that are added to a load balancer node.

    .INPUTS
    Accepts a string representing the simple id of the node from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWNode] class objects

    .EXAMPLE
    Gets all of the nodes
    Get-AutomateNOWNode

    .EXAMPLE
    Gets a single node by name
    Get-AutomateNOWNode -Id 'my_node_01'

    .EXAMPLE
    Gets a series of nodes by feeding their names through the pipeline.
    @( 'my_node_01', 'my_node_02' ) | Get-AutomateNOWNode

    .EXAMPLE
    Gets all of the nodes which have the load balancer role
    Get-AutomateNOW -LoadBalancerOnly

    .EXAMPLE
    Gets all of the nodes which are joined to a load balancer a child node
    Get-AutomateNOW -ChildNodesOnly

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the nodes.

    #>
    [OutputType([ANOWNode[]])]
    [Cmdletbinding(DefaultParameterSetName = 'All')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Single', ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [switch]$LoadBalancerOnly,
        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [switch]$ChildNodesOnly
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'GET')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
        If ($LoadBalancerOnly -eq $true -and $ChildNodesOnly -eq $true) {
            Write-Warning -Message "You can't request only load balancer and then only load balancer nodes in the same request. Please choose one or the other."
            Break
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_.Length -gt 0 -or $Id.Length -gt 0 ) {
            If ($_.Length -gt 0) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            [string]$textMatchStyle = 'exactCase'
            $Body.'_operationId' = 'read'
        }
        ElseIf ($LoadBalancerOnly -eq $true) {
            $Body.'operator' = 'and'
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'criteria1' = '{"fieldName":"loadBalancer","operator":"equals","value":true}'
            $Body.'criteria2' = '{"fieldName":"parentLoadBalancer","value":null,"operator":"equals"}'
            $Body.'_operationId' = 'ServerNodeDataSource_fetch'
            $Body.'_componentId' = 'ServerNodeTree'
            [string]$textMatchStyle = 'exact'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
        }
        ElseIf ($ChildNodesOnly -eq $true) {
            $Body.'operator' = 'and'
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'criteria1' = '{"fieldName":"loadBalancer","operator":"equals","value":false}'
            $Body.'criteria2' = '{"fieldName":"parentLoadBalancer","value":null,"operator":"iNotEqual"}'
            $Body.'_operationId' = 'ServerNodeDataSource_fetch'
            $Body.'_componentId' = 'ServerNodeTree'
            [string]$textMatchStyle = 'exact'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
        }
        Else {
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'operator' = 'and'
            $Body.'_componentId' = 'ServerNodeList'
            [string]$textMatchStyle = 'substring'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_dataSource' = 'ServerNodeDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/serverNode/read?' + $Body)
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

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

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
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
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
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
    [System.Collections.Specialized.OrderedDictionary]$ANOWNode = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWNode.Add('id', $Id)
    $ANOWNode.Add('serverNodeType', $Type)
    $ANOWNode.Add('loadBalancer', $False)
    $ANOWNode.Add('totalWeightCapacity', $WeightCapacity)
    If ($Description.Length -gt 0) {
        $ANOWNode.Add('description', $Description)
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWNode due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWNode has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWNode.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] existed under New-AutomateNOWNode due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under New-AutomateNOWNode. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWNode] [$Id]"
        $ANOWNode.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWNode due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWNode. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWNode] [$Id]"
        $ANOWNode.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
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
    If ($Quiet -ne $true) {
        Return $node
    }
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

Function Start-AutomateNOWNode {
    <#
    .SYNOPSIS
    Starts a Node from an AutomateNOW! instance

    .DESCRIPTION
    Starts a Node from an AutomateNOW! instance

    .PARAMETER Node
    An [ANOWNode] object representing the Node to be started.

    .PARAMETER Quiet
    Switch parameter to silence the returned [ANOWNode] object

    .INPUTS
    ONLY [ANOWNode] objects are accepted (including from the pipeline)

    .OUTPUTS
    An [ANOWNode] object representing the started node will be returned.

    .EXAMPLE
    Starts a single node

    Get-AutomateNOWNode -Id 'Node_01' | Start-AutomateNOWNode

    .EXAMPLE
    Starts a single node quietly

    Get-AutomateNOWNode -Id 'Node_01' | Start-AutomateNOWNode -Quiet

    .EXAMPLE
    Starts a series of nodes quietly through the pipeline

    @('Node01', 'Node02') | Start-AutomateNOWNode -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(DefaultParameterSetName = 'UseAutomaticName')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWNode]$Node,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/serverNode/start'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Node_id = $_.id
            [string]$Node_simpleId = $_.simpleId
        }
        Else {
            [string]$Node_id = $Node.id
            [string]$Node_simpleId = $Node.simpleId
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $Node_id )
        $BodyMetaData.Add('_operationType', 'custom')
        $BodyMetaData.Add('_operationId', 'start')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ServerNodeDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Node_id] due to [$Message]."
            Break
        }
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
        }
        Write-Verbose -Message "Task $Node_id successfully started"
        $Error.Clear()
        Try {
            [ANOWNode]$ANOWNode = $results.response.data[0]
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the [ANOWNode] object under Start-AutomateNOWNode from the response due to [$Message]."
            Break
        }
        If ($Quiet -ne $true) {
            Return $ANOWNode
        }
    }
    End {

    }
}

Function Stop-AutomateNOWNode {
    <#
    .SYNOPSIS
    Stops a Node on an AutomateNOW! instance

    .DESCRIPTION
    Stops a Node on an AutomateNOW! instance

    .PARAMETER Node
    An [ANOWNode] object representing the Node to be stopped.

    .PARAMETER Kill
    Switch parameter to kill tasks running on the server instead of waiting for them to complete

    .PARAMETER Abort
    Switch parameter to abort tasks running on the server instead of waiting for them to complete

    .PARAMETER Quiet
    Switch parameter to silence the returned [ANOWNode] object

    .INPUTS
    ONLY [ANOWNode] objects are accepted (including from the pipeline)

    .OUTPUTS
    An [ANOWNode] object representing the stopped node will be returned.

    .EXAMPLE
    Stops a single node

    Get-AutomateNOWNode -Id 'Node_01' | Stop-AutomateNOWNode

    .EXAMPLE
    Stops a single node quietly

    Get-AutomateNOWNode -Id 'Node_01' | Stop-AutomateNOWNode -Quiet

    .EXAMPLE
    Stops a series of nodes quietly through the pipeline

    @('Node01', 'Node02') | Stop-AutomateNOWNode -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The default behavior of this function is the 'Stop' option 'Wait for executing tasks to complete'. Use -Kill or -Abort to use one or the other of the two stop options. (Stop executing tasks is not added yet)

    #>
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default', ValueFromPipeline = $True)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Kill')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Abort')]
        [ANOWNode]$Node,
        [Parameter(Mandatory = $true, ParameterSetName = 'Kill')]
        [switch]$Kill,
        [Parameter(Mandatory = $true, ParameterSetName = 'Abort')]
        [switch]$Abort,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Kill -eq $true) {
            [string]$operation_id = 'stopKill'
            [string]$stop_message = 'stopped and killed'
        }
        ElseIf ($Abort -eq $true) {
            [string]$operation_id = 'stopAbort'
            [string]$stop_message = 'stopped and aborted'
        }
        Else {
            [string]$operation_id = 'stop'
            [string]$stop_message = 'stopped'
        }  
        [string]$command = ('/serverNode/' + $operation_id)
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Node_id = $_.id
            [string]$Node_simpleId = $_.simpleId
        }
        Else {
            [string]$Node_id = $Node.id
            [string]$Node_simpleId = $Node.simpleId
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $Node_id )
        $BodyMetaData.Add('_operationType', 'custom')
        $BodyMetaData.Add('_operationId', $operation_id)
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ServerNodeDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Node_id] due to [$Message]."
            Break
        }
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
        }
        Write-Verbose -Message "Task $Node_id successfully $stop_message"
        $Error.Clear()
        Try {
            [ANOWNode]$ANOWNode = $results.response.data[0]
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the [ANOWNode] object under Stop-AutomateNOWNode (performing $operation_id) from the response due to [$Message]."
            Break
        }
        If ($Quiet -ne $true) {
            Return $ANOWNode
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
    Get-AutomateNOWTaskTemplate -TaskType PYTHON | Find-AutomateNOWObjectReferral -Count

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
        [int32]$endRow = 100,
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
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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

#Region - Result Mappings

Function Get-AutomateNOWResultMapping {
    <#
    .SYNOPSIS
    Gets the Result Mapping objects from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Result Mapping objects from an AutomateNOW! instance

    .PARAMETER Id
    Optional string containing the simple id of the Result Mapping to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100. The console default hard limit is 10,000.

    .INPUTS
    Accepts a string representing the simple id of the Result Mapping from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWResultMapping] class objects

    .EXAMPLE
    Gets all Result Mapping objects (defaults 100 per page)

    Get-AutomateNOWResultMapping

    .EXAMPLE
    Gets the first 500 Result Mapping objects in a single page

    Get-AutomateNOWResultMapping -startRow 0 -endRow 500

    .EXAMPLE
    Gets a single Result Mapping by name

    Get-AutomateNOWResultMapping -Id 'resultmapping_01'

    .EXAMPLE
    Gets a series of Result Mapping objects through the pipeline

    @( 'resultmapping_01', 'resultmapping_02' ) | Get-AutomateNOWResultMapping

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Result Mapping objects.

    #>
    [OutputType([ANOWResultMapping[]])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
            $Body.'_operationId' = 'read'
            [string]$textMatchStyle = 'exactCase'
        }
        Else {
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            $Body.'_textMatchStyle' = 'substring'
            $Body.'_componentId' = 'ResultMappingList'
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_dataSource' = 'ResultMappingDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/resultMapping/read?' + $Body)
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
        [ANOWResultMapping[]]$ResultMappings = ForEach ($ResultMapping in $results.response.data) {
            If ($null -ne $ResultMapping.definition) {
                If ($ResultMapping.definition[0] -is [string]) {
                    Try {
                        $ResultMapping.definition = $ResultMapping.definition | ConvertFrom-Json -Depth 10
                        [ANOWResultMapping]$ResultMapping
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Failed to parse the response into a series of [ANOWResultMapping] under Get-AutomateNOWResultMapping objects due to [$Message]."
                        Break
                    }
                }
                Else {
                    $Error.Clear()
                    [ANOWResultMappingRule[]]$definitions = Try {
                        ForEach ($definition in $resultmapping.definition) {
                            [ANOWResultMappingRule]$definition_placeholder
                        }
                    }
                    Catch {
                        [string]$definition_placeholder_display = $definition_placeholder | ConvertTo-Json -Compress
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Failed to parse the response definition [$definition_placeholder_display] into an [ANOWResultMappingRule] object under Get-AutomateNOWResultMappingRule due to [$Message]."
                        Break
                    }
                    $ResultMapping.definition = $definitions
                }
            }
            [ANOWResultMapping]$ResultMapping
        }
        If ($ResultMappings.Count -gt 0) {
            Return $ResultMappings
        }
    }
    End {

    }
}

Function Export-AutomateNOWResultMapping {
    <#
    .SYNOPSIS
    Exports the Result Mapping objects from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Result Mapping objects from an instance of AutomateNOW! to a local .csv file

    .PARAMETER Domain
    Mandatory [ANOWResultMapping] object (Use Get-AutomateNOWResultMapping to retrieve them)

    .INPUTS
    ONLY [ANOWResultMapping] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWResultMapping] objects are exported to the local disk in CSV format

    .EXAMPLE
    Exports all of the Result Mapping objects (up to 100 by default)

    Get-AutomateNOWResultMapping | Export-AutomateNOWResultMapping

    .EXAMPLE
    Exports 1 Result Mapping by name

    Get-AutomateNOWResultMapping -Id 'result_mapping01' | Export-AutomateNOWResultMapping

    .EXAMPLE
    Exports a series of Result Mapping objects by the pipeline

    @( 'result_mapping01', 'result_mapping02' ) | Get-AutomateNOWResultMapping | Export-AutomateNOWResultMapping

    .NOTES
	You must present [ANOWResultMapping] objects to the pipeline to use this function.
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWResultMapping]$ResultMapping
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-ResultMappings-' + $current_time + '.csv'
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
            [ANOWResultMapping]$ResultMapping = $_
        }
        $Error.Clear()
        Try {
            $ResultMapping | Export-CSV @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Export-CSV failed to export the [ANOWResultMapping] object on the pipeline due to [$Message]"
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

Function New-AutomateNOWResultMapping {
    <#
    .SYNOPSIS
    Creates a Result Mapping within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Result Mapping within an AutomateNOW! instance and returns back the newly created [ANOWResultMapping] object

    .PARAMETER Id
    The intended name of the Result Mapping. For example: 'result_mapping1'. This value may not contain the domain in brackets.

    .PARAMETER Description
    Optional description of the Result Mapping (may not exceed 255 characters).

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Result Mapping. Do not pass [ANOWTag] objects here.

    .PARAMETER Folder
    Optional name of the folder to place the Result Mapping into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Result Mapping into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWResultMapping.

    .OUTPUTS
    An [ANOWResultMapping] object representing the newly created Result Mapping

    .EXAMPLE
    New-AutomateNOWResultMapping

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Result Mapping must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWResultMapping])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$ResultMapping_exists = ($null -ne (Get-AutomateNOWResultMapping -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWResultMapping failed to check if the Result Mapping [$Id] already existed due to [$Message]."
        Break
    }
    If ($ResultMapping_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Result Mapping named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWResultMapping = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWResultMapping.Add('id', $Id)
    If ($Description.Length -gt 0) {
        $ANOWResultMapping.Add('description', $Description)
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWResultMapping due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWResultMapping has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWResultMapping.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] existed under New-AutomateNOWResultMapping due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under New-AutomateNOWResultMapping. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWResultMapping] [$Id]"
        $ANOWResultMapping.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] existed under New-AutomateNOWResultMapping due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWResultMapping. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWResultMapping] [$Id]"
        $ANOWResultMapping.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWResultMapping -IncludeProperties id, description, tags, folder, codeRepository
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = '{}'
    $BodyMetaData.'_componentId' = 'ResultMappingCreateWindow_form'
    $BodyMetaData.'_dataSource' = 'ResultMappingDataSource'
    $BodyMetaData.'isc_metaDataPrefix' = '_'
    $BodyMetaData.'isc_dataFormat' = 'json'
    [string]$BodyMetaDataString = ConvertTo-QueryString -InputObject $BodyMetaData
    [string]$Body = ($BodyObject + '&' + $BodyMetaDataString)
    [string]$command = '/resultMapping/create'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Result Mapping [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Result Mapping [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWResultMapping]$ResultMapping = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWResultMapping] object due to [$Message]."
        Break
    }
    If ($ResultMapping.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWResultMapping] ResultMapping is empty!"
        Break
    }
    If ($Quiet -ne $true) {
        Return $ResultMapping
    }
}

Function Remove-AutomateNOWResultMapping {
    <#
    .SYNOPSIS
    Removes a Result Mapping from an AutomateNOW! instance

    .DESCRIPTION
    Removes a Result Mapping from an AutomateNOW! instance

    .PARAMETER ResultMapping
    An [ANOWResultMapping] object representing the Result Mapping to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWResultMapping] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Remove a single Result Mapping by name

    Get-AutomateNOWResultMapping -Id 'result_mapping01' | Remove-AutomateNOWResultMapping

    .EXAMPLE
    Removes a series of Result Mapping objects via input from the pipeline

    @( 'result_mapping01', 'result_mapping02', 'result_mapping03') | Remove-AutomateNOWResultMapping

    .EXAMPLE
    Forcefully removes all Result Mapping objects that reside within a particular folder

    Get-AutomateNOWResultMapping | Where-Object { $_.folder -eq 'folder_01'} | Remove-AutomateNOWResultMapping -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWResultMapping]$ResultMapping,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/resultMapping/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($ResultMapping.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$ResultMapping_id = $_.id
            }
            ElseIf ($ResultMapping.id.Length -gt 0) {
                [string]$ResultMapping_id = $ResultMapping.id
            }
            ElseIf ($Id.Length -gt 0) {
                [string]$ResultMapping_id = $Id
            }
            Else {
                Write-Warning -Message "Unable to resolve the identity of the target under Remove-AutomateNOWResultMapping"
                Break
            }
            [string]$Body = 'id=' + $ResultMapping_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$ResultMapping_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Result Mapping [$ResultMapping_id] successfully removed"
        }
    }
    End {

    }
}

Function Add-AutomateNOWResultMappingRule {
    <#
    .SYNOPSIS
    Adds a Rule to a Result Mapping on an AutomateNOW! instance

    .DESCRIPTION
    Adds a Rule to a Result Mapping on an AutomateNOW! instance

    .PARAMETER ResultMapping
    Mandatory [ANOWResultMapping] object (Use Get-AutomateNOWResultMapping to retrieve them). This is the object you created with New-AutomateNOWResultMapping.

    .PARAMETER ResultMappingRule
    Mandatory [ANOWResultMappingRule] object (use New-AutomateNOWResultMappingRule to create them).

    .PARAMETER Quiet
    Switch parameter to silence the output from a successful update

    .INPUTS
    ONLY [ANOWResultMapping] objects are accepted (including from the pipeline).

    .OUTPUTS
    The updated [ANOWResultMapping] object will be returned.

    .EXAMPLE
    Creates and adds two Rules to an existing Result Mapping object named 'result_mapping1' (multi-line format)

    $criteria1 = New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '1'
    $criteria2 = New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '2'
    $criteria3 = New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '3'
    $criteria4 = New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '4'
    $condition1 = @($criteria1, $criteria2) | New-AutomateNOWResultMappingRuleCondition -operator 'AllMatch'
    $condition2 = @($criteria3, $criteria4) | New-AutomateNOWResultMappingRuleCondition -operator 'AllMatch'
    $rule1 = New-AutomateNOWResultMappingRule -ProcessingStatus 'COMPLETED' -StatusCode 0 -StatusMessage 'SUCCESS' -Condition $condition1
    $rule2 = New-AutomateNOWResultMappingRule -ProcessingStatus 'FAILED' -StatusCode 1 -StatusMessage 'FAILED' -Condition $condition2
    $result_mapping = Get-AutomateNOWResultMapping -Id 'result_mapping1'
    @($rule1, $rule2) | Add-AutomateNOWResultMappingRule -ResultMapping $result_mapping -Quiet

    .EXAMPLE
    Creates and adds two Rules to an existing Result Mapping object named 'result_mapping1' (multi-line format)

    @((New-AutomateNOWResultMappingRule -ProcessingStatus 'COMPLETED' -StatusCode 0 -StatusMessage 'SUCCESS' -Condition (@((New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '1'), (New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '2')) | New-AutomateNOWResultMappingRuleCondition -operator 'AllMatch')), (New-AutomateNOWResultMappingRule -ProcessingStatus 'FAILED' -StatusCode 1 -StatusMessage 'FAILED' -Condition (@((New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '3'), (New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '4')) | New-AutomateNOWResultMappingRuleCondition -operator 'AllMatch'))) | Add-AutomateNOWResultMappingRule -ResultMapping (Get-AutomateNOWResultMapping -Id 'result_mapping1') -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This capability should be considered limited. There are complex configurations of criteria and conditions which may not be supported. Avoid the "or" operators for now to avoid complexity.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWResultMapping]$ResultMapping,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWResultMappingRule]$ResultMappingRule,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
        [PSCustomObject]$ResultMappingRuleArray = @()
        [string]$command = '/resultMapping/update'
    }
    Process {
        If ($_.Length -eq 0) {
            [PSCustomObject[]]$ResultMappingRuleArray += $ResultMappingRule
        }
        Else {
            [PSCustomObject[]]$ResultMappingRuleArray += $_
        }
    }
    End {
        ## Begin warning ##
        ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
        [string]$ResultMapping_id = $ResultMapping.simpleId
        $Error.Clear()
        Try {
            [ANOWResultMapping]$current_result = Get-AutomateNOWResultMapping -Id $ResultMapping_id
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTask failed to check if the Result Mapping [$ResultMapping_id] existed under Add-AutomateNOWResultMappingRule due to [$Message]."
            Break
        }
        If ($current_result.id.length -eq 0) {
            Write-Warning "The Result Mapping object that you specified [$ResultMapping_id] does not seem to exist under Add-AutomateNOWResultMappingRule"
            Break
        }
        ## End warning ##
        If ($ResultMapping.definition -is [ANOWResultMappingRule[]]) {
            $ResultMappingRuleArray += $ResultMapping.definition
        }
        $Error.Clear()
        Try {
            [string]$ConvertedResultMappingRuleArray = $ResultMappingRuleArray | ConvertTo-Json -Depth 10 -Compress
            If ($ConvertedResultMappingRuleArray[0] -ne '[') {
                [string]$ResultMappingArrayFormatted = ('[' + $ConvertedResultMappingRuleArray + ']')
            }
            Else {
                [string]$ResultMappingArrayFormatted = $ResultMappingRuleArray | ConvertTo-Json -Depth 10 -Compress
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "ConvertTo-Json failed to convert the array of Result Mapping rules due to [$Message]."
            Break
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $ResultMapping_id )
        If ($ResultMapping.description.Length -gt 0) {
            $BodyMetaData.Add('description', $ResultMapping.description)
        }
        Else {
            $BodyMetaData.Add('description', $null)
        }
        If ($ResultMapping.codeRepository.Length -gt 0) {
            $BodyMetaData.Add('codeRepository', $ResultMapping.codeRepository)
        }
        Else {
            $BodyMetaData.Add('codeRepository', $null)
        }
        $BodyMetaData.Add('definition', $ResultMappingArrayFormatted )
        $BodyMetaData.Add('_operationType', 'update')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_oldValues', $ResultMapping.CreateOldValues())
        $BodyMetaData.Add('_componentId', 'ResultMappingEditForm')
        $BodyMetaData.Add('_dataSource', 'ResultMappingDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        If ($null -eq $parameters.Body) {
            $parameters.Add('Body', $Body)
        }
        Else {
            $parameters.Body = $Body
        }
        $parameters.Add('command', $command)
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
        $Error.Clear()
        [ANOWResultMappingRule[]]$definitions = Try {
            ForEach ($definition in $results.response.data.definition) {
                [ANOWResultMappingRule]$definition
            }
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a [ANOWResultMapping] object under Add-AutomateNOWResultMappingRule due to [$Message]."
            Break
        }
        [PSCustomObject]$temp_results = $results.response.data | Select-Object -ExcludeProperty definition
        $temp_results | Add-Member -MemberType NoteProperty -Name definition -Value $definitions -TypeName ANOWResultMappingRule
        [ANOWResultMapping]$UpdatedResultMapping = $temp_results
        If ($Quiet -ne $true) {
            Return $UpdatedResultMapping
        }
    }
}

Function New-AutomateNOWResultMappingRuleConditionCriteria {
    <#

    .SYNOPSIS
    Creates a Result Mapping Rule Condition Criteria object

    .DESCRIPTION
    Creates a Result Mapping Rule Condition Criteria object for use with Result Mapping Rule Condition objects

    .PARAMETER operatorText
    The name of the operator for text based criteria

    .PARAMETER operatorNumber
    The name of the operator for numeric based criteria

    .PARAMETER operatorDate
    The name of the operator for time based criteria

    .PARAMETER fieldName
    The name of the field to which the criteria is applied against. Valid values are: 'cycleActualCounter', 'duration', 'endTime', 'exitCode', 'exitMessage', 'id', 'name', 'owner', 'parentId', 'parentName', 'parentTemplate', 'processingStatus', 'processingTimestamp', 'rootId', 'rootName', 'rootTemplate', 'serviceStatus', 'skip', 'startTime', 'statusCode', 'statusMessage', 'template', 'timesRestarted'

    .PARAMETER value
    The value of the criteria.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWResultMappingRuleConditionCriteria.

    .OUTPUTS
    An [ANOWResultMappingRuleConditionCriteria] object representing the newly created Result Mapping Rule Condition Criteria object

    .EXAMPLE
    New-AutomateNOWResultMappingRuleConditionCriteria -operatorNumber 'EQ_NUM' -FieldName 'statusCode' -value '1'

    .NOTES
    This function is intended to be used in conjunction with New-AutomateNOWResultMappingRuleCondition

    Below is a table of the criteria operators based on their type (i.e. Text, Number or Date)

    "Text"
    ------
    'EQ' = '=='
    'NE' = '!='
    'LT_TEXT' = '<'
    'GT_TEXT' = '>'
    'LE_TEXT' = '<='
    'GE_TEXT' = '>='
    'SW' = 'starts with'
    'NSW' = 'does not start with'
    'EW' = 'ends with'
    'NEW' = 'does not end with'
    'CONTAINS' = 'contains'
    'NOT_CONTAIN' = 'does not contain'
    'REGEXP' = 'matches'
    'NOT_REGEXP' = 'does not match'
    'IS_NULL' = 'is empty'
    'IS_NOT_NULL' = 'is not empty'

    "Number"
    --------
    'EQ_NUM' = '=='
    'NE_NUM' = '!='
    'LT_NUM' = '<'
    'GT_NUM' = '>'
    'LE_NUM' = '<='
    'GE_NUM' = '>='

    "Date"
    ------
    'EQ_DATE' = '=='
    'NE_DATE' = '!='
    'LT_DATE' = '<'
    'GT_DATE' = '>'
    'LE_DATE' = '<='
    'GE_DATE' = '>='
    'CAL' = 'in calendar'
    'NOT_IN_CAL' = 'not in calendar'

    #>
    [OutputType([ANOWResultMappingRuleConditionCriteria])]
    [CmdletBinding()]
    Param(
        [ValidateSet('EQ', 'NE', 'LT_TEXT', 'GT_TEXT', 'LE_TEXT', 'GE_TEXT', 'SW', 'NSW', 'EW', 'NEW', 'CONTAINS', 'NOT_CONTAIN', 'REGEXP', 'NOT_REGEXP', 'IS_NULL', 'IS_NOT_NULL')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]$operatorText,
        [ValidateSet('EQ_NUM', 'NE_NUM', 'LT_NUM', 'GT_NUM', 'LE_NUM', 'GE_NUM')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Number')]
        [string]$operatorNumber,
        [ValidateSet('EQ_DATE', 'NE_DATE', 'LT_DATE', 'GT_DATE', 'LE_DATE', 'GE_DATE', 'CAL', 'NOT_IN_CAL')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Date')]
        [string]$operatorDate,
        [ValidateSet('cycleActualCounter', 'duration', 'endTime', 'exitCode', 'exitMessage', 'id', 'name', 'owner', 'parentId', 'parentName', 'parentTemplate', 'processingStatus', 'processingTimestamp', 'rootId', 'rootName', 'rootTemplate', 'serviceStatus', 'skip', 'startTime', 'statusCode', 'statusMessage', 'template', 'timesRestarted')]
        [Parameter(Mandatory = $true)]
        [string]$FieldName,
        [Parameter(Mandatory = $true)]
        [string]$value
    )
    If ($operatorText.Length -gt 0) {
        [string]$operator = $operatorText
    }
    ElseIf ($operatorNumber.Length -gt 0) {
        [string]$operator = $operatorNumber
    }
    Else {
        [string]$operator = $operatorDate
    }
    [ANOWResultMappingRuleConditionCriteria]$criteria = [PSCustomObject]@{'operator' = $operator; 'fieldName' = $FieldName; 'value' = $value; }
    Return $criteria
}

Function New-AutomateNOWResultMappingRuleCondition {
    <#

    .SYNOPSIS
    Creates a Result Mapping Rule Condition object

    .DESCRIPTION
    Creates a Result Mapping Rule Condition object for use with Result Mapping Rule objects

    .PARAMETER operator
    The name of the operator for the condition. Valid values are: 'AllMatch', 'AnyMatch', 'SingleMatch', 'AllMismatch', 'AnyMismatch', 'SingleMismatch'

    .PARAMETER criteria
    A [ANOWResultMappingRuleConditionCriteria] representing the criteria for this condition. Use New-AutomateNOWResultMappingRuleConditionCriteria to create these.

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWResultMappingRuleCondition.

    .OUTPUTS
    An [ANOWResultMappingRuleCondition] object representing the newly created Result Mapping Rule Condition Criteria object

    .EXAMPLE
    New-AutomateNOWResultMappingRuleCondition -operator 'AllMatch' -criteria $criteria

    .NOTES
    This function is intended to be used in conjunction with New-AutomateNOWResultMapping

    #>
    [OutputType([ANOWResultMappingRuleCondition])]
    [CmdletBinding()]
    Param(
        [ValidateSet('AllMatch', 'AnyMatch', 'SingleMatch', 'AllMismatch', 'AnyMismatch', 'SingleMismatch')]
        [Parameter(Mandatory = $true)]
        [string]$operator,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ANOWResultMappingRuleConditionCriteria]$criteria
    )
    Begin {
        [string]$operator_formatted = Switch ($operator) {
            'AllMatch' { 'AND'; Break }
            'AnyMatch' { 'OR'; Break }
            'SingleMatch' { 'XOR'; Break }
            'AllMismatch' { 'NAND'; Break }
            'AnyMismatch' { 'NOR'; Break }
            'SingleMismatch' { 'XNOR'; Break }
        }
        [ANOWResultMappingRuleConditionCriteria[]]$CriteriaArray = @()
    }
    Process {
        If ($_.Length -eq 0) {
            [ANOWResultMappingRuleConditionCriteria[]]$CriteriaArray += $criteria
        }
        Else {
            [ANOWResultMappingRuleConditionCriteria[]]$CriteriaArray += $_
        }
    }
    End {
        [ANOWResultMappingRuleCondition]$condition = [PSCustomObject]@{'operator' = $operator_formatted; 'criteria' = $CriteriaArray; }
        Return $condition
    }
}

Function New-AutomateNOWResultMappingRule {
    <#
    .SYNOPSIS
    Creates a Result Mapping Rule for use with Add-AutomateNOWResultMapping

    .DESCRIPTION
    Creates a Result Mapping Rule for use with Add-AutomateNOWResultMapping

    .PARAMETER Condition
    The mandatory condition object that must be included. Use New-AutomateNOWResultMappingRuleCondition to create it.

    .PARAMETER ProcessingStatus
    Processing Status to be set on the Task if condition is true. Valid values are: COMPLETED, FAILED

    .PARAMETER StatusCode
    Optional status code string to be set on the Task if condition is true. If not specified, the Result Mapping object will use exit code of the processing item.

    .PARAMETER StatusMessage
    Optional status message string to be set on the Task if condition is true. If not specified, the Result Mapping object will use exit code of the processing item.

    .INPUTS
    A single [ANOWResultMappingRuleCondition] object

    .OUTPUTS
    An [ANOWResultMapping] object representing the newly created Result Mapping

    .EXAMPLE
    New-AutomateNOWResultMappingRule -ProcessingStatus 'COMPLETED' -StatusCode 0 -StatusMessage 'SUCCESS' -Condition $condition

    .NOTES
    This cmdlet does not require a connection to the AutomateNOW console.

    The statusCode and statusMessage parameters appear to have unlimited character length allowance!

    #>
    [OutputType([ANOWResultMappingRule])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWResultMappingRuleCondition]$condition,
        [ValidateSet('COMPLETED', 'FAILED')]
        [Parameter(Mandatory = $true)]
        [string]$ProcessingStatus,
        [Parameter(Mandatory = $false)]
        [string]$StatusCode,
        [Parameter(Mandatory = $false)]
        [string]$StatusMessage
    )
    $Error.Clear()
    Try {
        [ANOWResultMappingRule]$rule = [PSCustomObject]@{ 'condition' = $condition; 'processingStatus' = $ProcessingStatus; 'statusCode' = $StatusCode; 'statusMessage' = $StatusMessage }
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create the [ANOWResultMappingRule] object (under New-AutomateNOWResultMappingRule) due to [$Message]."
        Break
    }
    Return $rule
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

    In the case of multiple results when using the -Id parameter, only the result from the current domain will be returned.
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
                    [ANOWTag[]]$Tags = ($Tags | Where-Object { $_.simpleId -in $Id -and $_.domain -eq $anow_session.header.domain })
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
    c

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
            $BodyMetaData.'isc_dataFormat' = 'json'
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
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
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
        [string]$backgroundColor = '#FF0000',
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
            If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
                [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
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

# Region Note: These functions are for managing executed tasks (i.e. in the Overview tab). If you are looking for templates, please check the *-AutomateNOWTaskTemplate functions.

Function Get-AutomateNOWTask {
    <#
    .SYNOPSIS
    Gets the tasks from an AutomateNOW! instance

    .DESCRIPTION
    Gets the tasks from an AutomateNOW! instance

    .PARAMETER Id
    Optional int64 containing the NUMERICAL id of the task to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER taskType
    Optional string representing the type of task to return. For example, a Shell Task template is SH. This parameter cannot be combined with -monitorType or -sensorType.

    .PARAMETER monitorType
    Optional string representing the type of monitor to return. For example, a python monitor is PYTHON_MONITOR. This parameter cannot be combined with -taskType or -sensorType.

    .PARAMETER sensorType
    Optional string representing the type of sensor to return. For example, a file sensor is FILE_SENSOR. This parameter cannot be combined with -monitorType or -taskType.

    .PARAMETER sortBy
    Optional string parameter to sort the results by (may not be used with the Id parameter). Valid choices are: {To be continued...}

    .PARAMETER Descending
    Optional switch parameter to sort in descending order

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100. The console default hard limit is 10,000.

    .INPUTS
    Accepts a string representing the simple id of the task template from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWtask] class objects

    .EXAMPLE
    Get-AutomateNOWTask

    .EXAMPLE
    Get-AutomateNOWTask -taskType 'SH'

    .EXAMPLE
    Gets a Task by its numerical Id

    Get-AutomateNOWTask -Id 1738954

    .EXAMPLE
    Gets a series of Tasks based on their numerical ID
    @( 1738954, 1738955 ) | Get-AutomateNOWTask

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the tasks (not recommended)

    #>
    [OutputType([ANOWTask[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default' )]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ParameterSetName = 'Default')]
        [int64]$Id,
        [Parameter(Mandatory = $True, ParameterSetName = 'taskType')]
        [ANOWTaskTemplate_taskType]$taskType,
        [Parameter(Mandatory = $True, ParameterSetName = 'monitorType')]
        [ANOWTaskTemplate_monitorType]$monitorType,
        [Parameter(Mandatory = $True, ParameterSetName = 'sensorType')]
        [ANOWTaskTemplate_sensorType]$sensorType,
        [Parameter(Mandatory = $False, ParameterSetName = 'taskType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'monitorType')]
        [Parameter(Mandatory = $False, ParameterSetName = 'sensorType')]
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
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'POST')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        If ($_ -gt 0 -or $Id -gt 0) {
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            $Body.'_textMatchStyle' = 'exact'
            $Body.'_operationId' = 'read'
        }
        Else {
            $Body.'_textMatchStyle' = 'substring'
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'operator' = 'and'
            $Body.'_operationType' = 'fetch'
            $Body.'_componentId' = 'ProcessingList'
            If ($Descending -eq $true) {
                $Body.'_sortBy' = '-' + $sortBy
            }
            Else {
                $Body.'_sortBy' = $sortBy
            }
            $Body.'criteria1' = '{"fieldName":"archived","operator":"equals","value":false}'
            $Body.'criteria2' = '{"fieldName":"isProcessing","operator":"equals","value":true}'
            If ($null -ne $taskType) {
                $Body.'criteria3' = '{"fieldName":"taskType","operator":"equals","value":"' + $taskType + '"}'
            }
            ElseIf ($null -ne $monitorType) {
                $Body.'criteria3' = '{"fieldName":"monitorType","operator":"equals","value":"' + $monitorType + '"}'
            }
            ElseIf ($null -ne $sensorType) {
                $Body.'criteria3' = '{"fieldName":"sensorType","operator":"equals","value":"' + $sensorType + '"}'
            }
            Else {
                $Body.'criteria3' = '{"_constructor":"AdvancedCriteria","operator":"or","criteria":[{"fieldName":"processingType","operator":"equals","value":"TASK"},{"fieldName":"serviceType","operator":"equals","value":"SENSOR"},{"fieldName":"serviceType","operator":"equals","value":"MONITOR"}]}'
                $Body.'criteria4' = '{"fieldName":"serverNodeType","operator":"notNull"}'
            }
        }
        $Body.'_dataSource' = 'ProcessingDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/processing/read?' + $Body)
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
        End {

        }
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

Function Remove-AutomateNOWTask {
    <#
    .SYNOPSIS
    Archives a Task from an AutomateNOW! instance

    .DESCRIPTION
    Archives a Task from an AutomateNOW! instance

    .PARAMETER Task
    An [ANOWTask] object representing the Task Template to be archived.

    .PARAMETER Force
    Force the archiving without confirmation. This is equivalent to -Confirm:$false

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

    The term Remove and Archive are synonymous from the API perspective. In ANOW parlance, Templates are 'Deleted' and Tasks are 'Archived'.
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
        [string]$command = '/processing/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Task_id = $_.id
        }
        ElseIf ($Task.id.Length -gt 0) {
            [string]$Task_id = $Task.id
        }
        Else {
            [string]$Task_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($Task_id, 'Archive')) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
            $Body.Add('id', $Task_id)
            $Body.Add('_operationType', 'remove')
            $Body.Add('_operationId', 'delete')
            $Body.Add('_textMatchStyle', 'exact')
            $Body.Add('_dataSource', 'ProcessingDataSource')
            $Body.Add('isc_metaDataPrefix', '_')
            $Body.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $Body
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
                Break
            }
            Write-Verbose -Message "Task $Task_id successfully archived"
        }
    }
    End {

    }
}

Function Restart-AutomateNOWTask {
    <#
    .SYNOPSIS
    Restarts a Task from an AutomateNOW! instance

    .DESCRIPTION
    Restarts a Task from an AutomateNOW! instance

    .PARAMETER Task
    An [ANOWTask] object representing the Task to be restarted

    .PARAMETER Quiet
    Switch parameter to omit the informational message if the Restart was successful

    .PARAMETER Force
    Force the restart without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)

    .OUTPUTS
    An informational message is written to the screen unless -Quiet is used

    .EXAMPLE
    Restarts a single Task

    Get-AutomateNOWTask -Id 'Task_01' | Restart-AutomateNOWTask

    .EXAMPLE
    Quietly restarts multiple Tasks

    @('Task1', 'Task2') | Get-AutomateNOWTask | Restart-AutomateNOWTask -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/restart'
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
            If ($_.id -gt 0) {
                [int64]$Task_id = $_.id
            }
            Else {
                [int64]$Task_id = $Task.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWTask]$current_task = Get-AutomateNOWTask -Id $Task_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTask failed to check if the Task [$Task_id] existed under Restart-AutomateNOWTask due to [$Message]."
                Break
            }
            If ($current_task.id.length -eq 0) {
                Write-Warning "The Task you specified does not seem to exist (Restart-AutomateNOWTask)"
                Break
            }
            [string]$current_task_status = $current_task.processingStatus
            If ($current_task_status -notin [ANOWTask_processingStatus].GetEnumNames()) {
                Write-Warning -Message "Somehow the processing status of the task [$Task_id] cannot be read (Restart-AutomateNOWTask)"
                Break
            }
            If ($current_task_status -notin @('COMPLETED', 'FAILED')) {
                Write-Warning -Message "[$Task_id] cannot be restarted as it currently in [$current_task_status] processing status"
                Break
            }
            Else {
                Write-Verbose -Message "[$Task_id] had a status of $current_task_status"
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('restartType', 'RESTART_FROM_BEGINNING')
            $BodyMetaData.Add('restartFailedOnly', 'false' ) # Note this value is currently not available in the console
            $BodyMetaData.Add('id', $Task_id )
            $BodyMetaData.Add('_operationType', 'custom')
            $BodyMetaData.Add('_operationId', 'restart')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Task_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            If ($Quiet -ne $true) {
                Write-Information -MessageData "Task $Task_id was successfully restarted"
            }
        }
    }
    End {

    }
}

Function Stop-AutomateNOWTask {
    <#
    .SYNOPSIS
    Stops a Task on an AutomateNOW! instance

    .DESCRIPTION
    Stops a Task on an AutomateNOW! instance with either a soft or hard stop

    .PARAMETER Task
    An [ANOWTask] object representing the Task to be stopped

    .PARAMETER Kill
    Switch parameter to indicate 'Hard kill' of the Task. You must include either this parameter or -Abort

    .PARAMETER Abort
    Switch parameter to indicate 'Soft abort' of the Task. You must include either this parameter or -Kill

    .PARAMETER Quiet
    Switch parameter to omit the informational message if the stop was successful

    .PARAMETER Force
    Force the stoppage without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)

    .OUTPUTS
    An informational message is written to the screen unless -Quiet is used

    .EXAMPLE
    Stops a single Task

    Get-AutomateNOWTask -Id 'Task_01' | Stop-AutomateNOWTask -Abort

    .EXAMPLE
    Quietly stops multiple Tasks

    @('Task1', 'Task2') | Get-AutomateNOWTask | Stop-AutomateNOWTask -Kill -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $true, ParameterSetName = 'Kill')]
        [switch]$Kill,
        [Parameter(Mandatory = $true, ParameterSetName = 'Abort')]
        [switch]$Abort,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Kill -eq $true) {
            [string]$operation_id = 'kill'
        }
        Else {
            [string]$operation_id = 'abort'
        }
        [string]$command = ('/processing/' + $operation_id)
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
            If ($_.id -gt 0) {
                [int64]$Task_id = $_.id
            }
            Else {
                [int64]$Task_id = $Task.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWTask]$current_task = Get-AutomateNOWTask -Id $Task_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTask failed to check if the Task [$Task_id] existed under Restart-AutomateNOWTask due to [$Message]."
                Break
            }
            If ($current_task.id.length -eq 0) {
                Write-Warning "The Task you specified does not seem to exist (Stop-AutomateNOWTask)"
                Break
            }
            [string]$current_task_status = $current_task.processingStatus
            If ($current_task_status -notin [ANOWTask_processingStatus].GetEnumNames()) {
                Write-Warning -Message "Somehow the processing status of the task [$Task_id] cannot be read (Stop-AutomateNOWTask)"
                Break
            }
            If ($current_task_status -in @('COMPLETED', 'FAILED')) {
                Write-Warning -Message "[$Task_id] cannot be stopped as it currently in [$current_task_status] processing status"
                Break
            }
            Else {
                Write-Verbose -Message "[$Task_id] had a status of $current_task_status"
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Task_id )
            $BodyMetaData.Add('_operationType', 'custom')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Task_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            If ($Quiet -ne $true) {
                Write-Information -MessageData "Task $Task_id was successfully stopped"
            }
        }
    }
    End {

    }
}

Function Resume-AutomateNOWTask {
    <#
    .SYNOPSIS
    Resumes a Task that is on hold (suspended) on an AutomateNOW! instance

    .DESCRIPTION
    Resumes a Task that is on hold (suspended) on an AutomateNOW! instance

    .PARAMETER Task
    An [ANOWTask] object representing the Task to be resumed

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)

    .OUTPUTS
    A verbose information message will be sent indicating success

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01' | Resume-AutomateNOWTask -Force

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01', 'Task02' | Resume-AutomateNOWTask 

    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Resume-AutomateNOWTask 

    .EXAMPLE
    Get-AutomateNOWTask | ? { $_.serverTaskType -eq 'LINUX' } | Resume-AutomateNOWTask

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/resume'
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
                [int64]$Task_id = $_.id
            }
            ElseIf ($Task.id.Length -gt 0) {
                [int64]$Task_id = $Task.id
            }
            Else {
                Write-Warning -Message "Unable to determine the Id of the Task."
                Break
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWTask]$current_task = Get-AutomateNOWTask -Id $Task_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTask failed to check if the Task [$Task_id] existed under Resume-AutomateNOWTask due to [$Message]."
                Break
            }
            If ($current_task.id.length -eq 0) {
                Write-Warning "The Task you specified does not seem to exist (Resume-AutomateNOWTask)"
                Break
            }
            [boolean]$current_task_hold_status = $current_task.onHold
            If ($current_task_hold_status -eq $false) {
                Write-Warning -Message "[$Task_id] cannot be resumed as it is not currently suspended (on hold)"
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Task_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'resume')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
            Write-Verbose -Message "Task $Task_id successfully resumed"
        }
    }
    End {

    }
}

Function Suspend-AutomateNOWTask {
    <#
    .SYNOPSIS
    Places a Task on hold (suspend) from execution on an AutomateNOW! instance

    .DESCRIPTION
    Places a Task on hold (suspend) from execution on an AutomateNOW! instance

    .PARAMETER Task
    An [ANOWTask] object representing the Task to be suspended (placed on hold)

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)

    .OUTPUTS
    A verbose information message will be sent indicating success

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01' | Suspend-AutomateNOWTask -Force

    .EXAMPLE
    Get-AutomateNOWTask -Id 'Task01', 'Task02' | Suspend-AutomateNOWTask 

    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Suspend-AutomateNOWTask 

    .EXAMPLE
    Get-AutomateNOWTask | ? { $_.serverTaskType -eq 'LINUX' } | Suspend-AutomateNOWTask 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/hold'
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
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWTask]$current_task = Get-AutomateNOWTask -Id $Task_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTask failed to check if the Task [$Task_id] existed under Resume-AutomateNOWTask due to [$Message]."
                Break
            }
            If ($current_task.id.length -eq 0) {
                Write-Warning "The Task you specified does not seem to exist (Resume-AutomateNOWTask)"
                Break
            }
            [boolean]$current_task_hold_status = $current_task.onHold
            If ($current_task_hold_status -eq $true) {
                Write-Warning -Message "[$Task_id] cannot be suspended (placed on hold) as it is already suspended (on hold)"
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Task_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'hold')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
            Write-Verbose -Message "Task $Task_id successfully suspended (placed on hold)"
        }
    }
    End {

    }
}

Function Skip-AutomateNOWTask {
    <#
    .SYNOPSIS
    Sets or unsets the Skip flag on a Task on an AutomateNOW! instance

    .DESCRIPTION
    Sets or unsets the Skip flag on a Task on an AutomateNOW! instance

    .PARAMETER Task
    An [ANOWTask] object representing the Task to be set to skipped or unskipped

    .PARAMETER UnSkip
    Removes the skip flag from an [ANOWTask] object. This is the opposite of the default behavior.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWTask] object

    .INPUTS
    ONLY [ANOWTask] objects are accepted (including from the pipeline)

    .OUTPUTS
    The skipped/unskipped [ANOWTask] object will be returned

    .EXAMPLE
    Sets a Task to Skip (bypass)

    Get-AutomateNOWTask -Id 1234567 | Skip-AutomateNOWTask -Force

    .EXAMPLE
    Unsets the Skip (bypass) flag on a Task

    12374894 | Get-AutomateNOWTask | Skip-AutomateNOWTask -UnSkip

    .EXAMPLE
    Sets an array of Task to Skip (bypass)

    @( 'Task1', 'Task2', 'Task3') | Skip-AutomateNOWTask 

    .EXAMPLE
    Get-AutomateNOWTask | ? { $_.TaskType -eq 'FOR_EACH' } | Skip-AutomateNOWTask -UnSkip -Force -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTask]$Task,
        [Parameter(Mandatory = $false)]
        [switch]$UnSkip,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnSkip -ne $True) {
            [string]$skip_flag_status = 'On'
            [string]$operation_id = 'passByOn'
            [string]$ProcessDescription = 'Add the Skip flag'
        }
        Else {
            [string]$skip_flag_status = 'Off'
            [string]$operation_id = 'passByOff'
            [string]$ProcessDescription = 'Remove the Skip flag'
        }
        [string]$command = ('/processing/' + $operation_id)
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Task_id = $_.id
        }
        ElseIf ($Task.id.Length -gt 0) {
            [string]$Task_id = $Task.id
        }
        Else {
            [string]$Task_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($Task_id, $ProcessDescription)) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Task_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
            Write-Verbose -Message "Successfully set the skip flag to [$skip_flag_status] on [$Task_id]"
        }
    }
    End {

    }
}

#endregion

#Region - TaskTemplates

Function Get-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Gets the task templates from an AutomateNOW! instance

    .DESCRIPTION
    Gets the task templates from an AutomateNOW! instance

    .PARAMETER Id
    Optional string containing the simple id of the task template to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER taskType
    Optional string representing the type of Task Template to return. For example, a Shell Task template is SH. This parameter cannot be combined with -monitorType or -sensorType.

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
    Accepts a string representing the simple id of the Task Template from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWTaskTemplate] class objects

    .EXAMPLE
    Get-AutomateNOWTaskTemplate

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'task_template_01'

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -taskType POWERSHELL

    .EXAMPLE
    @( 'task_template_01', 'task_template_02' ) | Get-AutomateNOWTaskTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the task templates

    Templates are divided into 3 types which is not directly illustrated in the console. The three types are: Task Templates, Monitors and Sensors. That is why there needs to be three separate exclusive parameters to specify the type of task template.

    Sorting by default is by id. You can specify an alternate string here but you must make sure it is case-sensitive. This is on the wish list to improve.

    #>
    [OutputType([ANOWTaskTemplate[]])]
    [Cmdletbinding(DefaultParameterSetName = 'Default' )]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
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
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
        $Body.'_startRow' = $startRow
        $Body.'_endRow' = $endRow
        $Body.'_textMatchStyle' = 'exact'
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
            If ($TaskTemplates.Count -eq 1 -and $TaskTemplates.processingType -ne 'TASK') {
                [string]$processingType = $TaskTemplates.processingType
                If ($processingType -eq 'WORKFLOW') {
                    Write-Warning -Message "$Id is actually a workflow template. Please use Get-AutomateNOWWorkflowTemplate to retrieve this item."
                }
                Else {
                    Write-Warning -Message "$Id is not actually a task template, it is a $processingType template."
                }
                Break
            }
            Return $TaskTemplates
        }
    }
    End {

    }
}

Function Set-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Changes the settings of a Task Template on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of a Task Template on an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be changed.

    .PARAMETER Description
    Optional description of the Task Template (may not exceed 255 characters).

    .PARAMETER Workspace
    A string representing the name of the Workspace you wish to move this Task Template into.

    .PARAMETER UnsetWorkspace
    A switch parameter that will move the Task Template out of its current Workspace.

    .PARAMETER Folder
    A string representing the name of the Folder to move the Task Template into.

    .PARAMETER UnsetFolder
    A switch parameter that will move the Task Template out of its current folder.

    .PARAMETER Tags
    Optional array of strings representing the Tags to include with this object.

    .PARAMETER UnsetTags
    A switch parameter that will the Tags from the Task Template

    .PARAMETER Title
    A string representing the "alias" of the Task Template (this property needs a better explanation)

    .PARAMETER ServerNode
    An [ANOWNode] object representing the node to connect to the Task Template. Note that load balancers are considered nodes in this context. Be careful with this as the lookup table which prevents mismatched server node / task types may not be perfectly correct. Always be sure that the node type matches the task type.

    .PARAMETER UnsetServerNode
    A switch parameter that will remove the Server Node from the Task Template.

    .PARAMETER Endpoint
    An [Endpoint] object representing the Endpoint object to assign to the Task Template. CAUTION: There is not yet any check to confirm if the endpoint type matches the expected type.

    .PARAMETER UnsetEndpoint
    A switch parameter that will remove the Endpoint assignment from the Task Template.

    .PARAMETER ResultMapping
    An [ResultMapping] object representing the Result Mapping object to set on the Task Template.

    .PARAMETER UnsetResultMapping
    A switch parameter that will remove the Result Mapping assignment from the Task Template.

    .PARAMETER Calendar
    A [ANOWCalendar] object representing the Calendar object to set on the Task Template.

    .PARAMETER UnsetCalendar
    A switch parameter that will remove the Calendar assignment from the Task Template.

    .PARAMETER Approval
    A [ANOWApproval] object representing the Approval object to set on the Task Template.

    .PARAMETER UnsetApproval
    A switch parameter that will remove the Approval assignment from the Task Template.

    .PARAMETER Weight
    An integer representing a logical measure of resources required to process the item by the Server Node. Each Server Node has [a] maximum weight capacity[.] Weight determines [the] number of parallel processes that can run simultaneously. Default processing Weight is 1. Minimal Weight is 0.

    .PARAMETER Priority
    An integer representing the items priority which determines the order when queuing for resources (Stock and Locks) and [for] being executed by Server Nodes. Default Priority is 0. Minimal Priority is 0.

    .PARAMETER Owner
    A string which appears to represent the user who owns the object. In practice, it is just a string. This particular property does not appear to be explained anywhere in the documentation.

    .PARAMETER OnHold
    A boolean to put the Task Template on Hold status. You must specify $true or $false here. When $true, it's the same as the Suspend-AutomateNOWTaskTemplate function. When $false, Resume-AutomateNOWTaskTemplate function.

    .PARAMETER Skip
    A boolean to put the Task Template on Skip status. You must specify $true or $false here. When $true, it's the same as the Skip-AutomateNOWTaskTemplate function. When $false, Skip-AutomateNOWTaskTemplate with -UnSkip parameter.

    .PARAMETER AutoArchive
    A boolean that causes the Tasks from this Task Template to be archived immediately after execution. You must specify $true or $false here.

    .PARAMETER KeepResources
    A boolean that indicates if the Tasks from this Task Template should keep its resources (Stocks and Locks) and reuse them on the restart so that they are not consumed by other tasks or workflows. You must specify $true or $false here.

    .PARAMETER UseScripts
    A boolean that indicates if the Tasks from this Task Template should ?

    .PARAMETER EagerScriptExecution
    A boolean that indicates if the scripts from the Tasks from this Task Template should use "Eager" load strategy. In orderto use this parameter, you must include -UseScripts $true.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWTaskTemplate] object will be returned

    .EXAMPLE
    Forcefully moves a Task Template to a different Workspace
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Workspace 'MJS_Workspace' -Force

    .EXAMPLE
    Removes a Task Template from a Workspace
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -UnsetWorkspace

    .EXAMPLE
    Removes a Task Template from its current Folder
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Force -UnsetFolder

    .EXAMPLE
    Places a Task Template into a Folder
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Force -Folder 'MJS'

    .EXAMPLE
    Sets all of the minor properties
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Description 'description' -Title 'title' -Workspace 'Workspace1' -Weight 15 -Priority 5 -Owner 'the_owner' -OnHold $true -Skip $false -AutoArchive $true -KeepResources $false -UseScripts $true -EagerScriptExecution $true -Force

    .EXAMPLE
    Forcefully sets a Server Node on the Task Template
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Force -ServerNode $node

    .EXAMPLE
    Removes the Server Node from the Task Template
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -UnsetServerNode

    .EXAMPLE
    Forcefully sets a Result Mapping on the Task Template
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -Force -ResultMapping $result_mapping

    .EXAMPLE
    Removes the Result Mapping from the Task Template
    Set-AutomateNOWTaskTemplate -TaskTemplate $task_template -UnsetResultMapping

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    #>
    [Cmdletbinding(SupportsShouldProcess, DefaultParameterSetName = 'Default', ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false, ParameterSetName = 'SetDescription')]
        [string]$Description,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetDescription')]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetWorkspace')]
        [string]$Workspace,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetWorkspace')]
        [switch]$UnsetWorkspace,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetFolder')]
        [string]$Folder,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetFolder')]
        [switch]$UnsetFolder,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTags')]
        [string[]]$Tags,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTags')]
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTitle')]
        [string]$Title,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTitle')]
        [switch]$UnsetTitle,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetServerNode')]
        [ANOWNode]$ServerNode,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetServerNode')]
        [switch]$UnsetServerNode,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetEndpoint')]
        [ANOWEndpoint]$Endpoint,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetEndpoint')]
        [switch]$UnsetEndpoint,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetResultMapping')]
        [ANOWResultMapping]$ResultMapping,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetResultMapping')]
        [switch]$UnsetResultMapping,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetCalendar')]
        [ANOWCalendar]$Calendar,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetCalendar')]
        [switch]$UnsetCalendar,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetApproval')]
        [ANOWApproval]$Approval,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetApproval')]
        [switch]$UnsetApproval,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [int32]$Priority,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [int32]$Weight,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$OnHold,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$Skip,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$AutoArchive,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$KeepResources,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$UseScripts,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$EagerScriptExecution,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string]$Owner,
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetFolder -eq $true -or $Folder.Length -gt 0) {
            [string]$command = '/processingTemplate/setFolder'
            [string]$operationId = 'setFolder'
        }
        Else {
            [string]$command = '/processingTemplate/update'
            [string]$componentId = 'ProcessingTemplateValuesManager'
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
        If ($Description.Length -gt 0 -and $UnsetDescription -eq $true) {
            Write-Warning -Message 'You cannot set the Description and unset it at the same time. Please choose one or the other.'
            Break
        }
        If ($Title.Length -gt 0 -and $UnsetTitle -eq $true) {
            Write-Warning -Message 'You cannot set the Title and unset it at the same time. Please choose one or the other.'
            Break
        }
        If ($EagerScriptExecution -eq $true -and $UseScripts -ne $true) {
            Write-Warning -Message 'To use -EagerScriptExecution, you must include -UseScripts $true'
            Break
        }
        If ($UnsetWorkspace -eq $true -and $Workspace.Length -gt 0) {
            Write-Warning -Message "You cannot set the Workspace and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($UnsetFolder -eq $true -and $Folder.Length -gt 0) {
            Write-Warning -Message "You cannot set the Folder and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($UnsetServerNode -eq $true -and $ServerNode.Id.Length -gt 0) {
            Write-Warning -Message "You cannot set the Server Node and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($Tags.count -gt 0 -and $UnsetTags -eq $true) {
            Write-Warning -Message "You cannot set the tags and unset them at the same time. Please choose one or the other."
        }
        If ($UnsetEndpoint -eq $true -and $Endpoint.id.Length -gt 0) {
            Write-Warning -Message "You cannot set the Endpoint and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($UnsetApproval -eq $true -and $Approval.id.Length -gt 0) {
            Write-Warning -Message "You cannot set the Approval and unset it at the same time. Please choose one or the other."
            Exit
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($TaskTemplate.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$TaskTemplate_id = $_.id
            }
            ElseIf ($TaskTemplate.id.Length -gt 0) {
                [string]$TaskTemplate_id = $TaskTemplate.id
            }
            Else {
                [string]$TaskTemplate_id = $Id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$TaskTemplate_exists = ($null -eq (Get-AutomateNOWTaskTemplate -Id $TaskTemplate_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to check if the Task Template [$TaskTemplate_id] already existed due to [$Message]."
                Break
            }
            If ($TaskTemplate_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Task Template named [$TaskTemplate_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.ArrayList]$include_properties = [System.Collections.ArrayList]@()
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $TaskTemplate_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($UnsetDescription -eq $true) {
                $BodyMetaData.'description' = $null
                $include_properties += 'description'
            }
            If ($Workspace.Length -gt 0) {
                $Error.Clear()
                Try {
                    [ANOWWorkspace]$workspace_object = Get-AutomateNOWWorkspace -Id $Workspace
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWWorkspace failed to confirm that the workspace [$Workspace] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($workspace_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWWorkspace failed to locate the Workspace [$Workspace] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding workspace $workspace_display to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'workspace' = $Workspace
                $include_properties += 'workspace'
            }
            ElseIf ($UnsetWorkspace -eq $true) {
                [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWTaskTemplate] [$TaskTemplate_id] from Workspace $workspace_display"
                $BodyMetaData.'workspace' = $null
                $include_properties += 'workspace'
            }
            If ($Folder.Length -gt 0) {
                $Error.Clear()
                Try {
                    [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the Folder [$Folder] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($folder_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                [string]$folder_display = $folder_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Folder $folder_display to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'folder' = $Folder
                $include_properties += 'folder'
            }
            ElseIf ($UnsetFolder -eq $true) {
                [string]$folder_display = $folder_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWTaskTemplate] [$TaskTemplate_id] from Folder $folder_display"
                $BodyMetaData.'folder' = $null
                $include_properties += 'folder'
            }
            If ($Tags.Count -gt 0) {
                [int32]$total_tags = $Tags.Count
                [int32]$current_tag = 1
                ForEach ($tag_id in $Tags) {
                    $Error.Clear()
                    Try {
                        [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWTaskTemplate due to [$message]"
                        Break
                    }
                    If ($tag_object.simpleId.length -eq 0) {
                        Throw "New-AutomateNOWTaskTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                        Break
                    }
                    [string]$tag_display = $tag_object | ConvertTo-Json -Compress
                    Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
                    [string]$tag_name_sequence = ('tags' + $current_tag)
                    $BodyMetaData.Add($tag_name_sequence, $tag_id)
                    $include_properties += $tag_name_sequence
                    $current_tag++
                }
            }
            ElseIf ($UnsetTags -eq $true) {
                [string]$tags_display = ($Calendar.tags) | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing tags [$tags_display] from [$TaskTemplate_id]"
                $BodyMetaData.'tags' = $null
                $include_properties += 'tags'
            }
            If ($Title.Length -gt 0) {
                $BodyMetaData.'title' = $Title
            }
            ElseIf ( $UnsetTitle -eq $true) {
                $BodyMetaData.'title' = $null
            }
            If ($ServerNode.simpleId.Length -gt 0) {
                [string]$ServerNode_id = $ServerNode.simpleId
                $Error.Clear()
                Try {
                    [ANOWNode]$node_object = Get-AutomateNOWNode -Id $ServerNode_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWNode failed to confirm that the Server Node [$ServerNode_id] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($node_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWNode failed to locate the Server Node [$ServerNode_id] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                [string]$TaskType = $TaskTemplate.taskType
                [string]$ServerNodeType = $ServerNode.serverNodeType
                [string[]]$ValidServerNodeTypes = Resolve-AutomateNOWTaskType2ServerNodeType -TaskType $TaskType
                [int32]$ValidServerNodeTypesCount = $ValidServerNodeTypes.Count
                If ($ValidServerNodeTypesCount -eq 0) {
                    Write-Warning -Message "Somehow the TaskType2ServerNodeType lookup table has failed"
                    Break
                }
                Else {
                    If ($ServerNodeType -notin $ValidServerNodeTypes) {
                        [string]$ValidServerNodeTypesDisplay = $ValidServerNodeTypes -join ', '
                        Write-Warning -Message "Sorry, [$ServerNodeType] is not a valid server node type for a [$TaskType] task (which $TaskTemplate_id is). Please use one of these instead: $ValidServerNodeTypesDisplay"
                        Break
                    }
                }
                [string]$node_display = $node_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Server Node $node_display to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'node' = ($ServerNode.id)
                $include_properties += 'node'
            }
            ElseIf ($UnsetServerNode -eq $true) {
                [string]$node_display = $node_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWTaskTemplate] [$TaskTemplate_id] from Server Node $node_display"
                $BodyMetaData.'node' = $null
                $include_properties += 'node'
            }
            If ($Endpoint.simpleId.Length -gt 0) {
                [string]$Endpoint_id = $Endpoint.simpleId
                $Error.Clear()
                Try {
                    [ANOWEndpoint]$endpoint_object = Get-AutomateNOWEndpoint -Id $Endpoint_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWEndpoint failed to confirm that the Endpoint [$Endpoint_id] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($endpoint_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWendpoint failed to locate the Endpoint [$Endpoint_id] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                [string]$endpoint_display = $endpoint_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Endpoint $endpoint_display to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'endpoint' = ($Endpoint.id)
                $include_properties += 'endpoint'
            }
            ElseIf ($UnsetEndpoint -eq $true) {
                $BodyMetaData.'endpoint' = $null
                $include_properties += 'endpoint'
            }
            If ($ResultMapping.simpleId.Length -gt 0) {
                [string]$ResultMapping_id = $ResultMapping.simpleId
                $Error.Clear()
                Try {
                    [ANOWResultMapping]$rm_object = Get-AutomateNOWResultMapping -Id $ResultMapping_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWResultMapping failed to confirm that the Result Mapping [$ResultMapping_id] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($rm_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWResultMapping failed to locate the Result Mapping [$ResultMapping_id] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                [string]$rm_display = $rm_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Result Mapping $rm_display to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'resultMapping' = $ResultMapping_id
                $include_properties += 'resultMapping'
            }
            ElseIf ($UnsetResultMapping -eq $true) {
                [string]$rm_display = $rm_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWTaskTemplate] [$ResultMapping_id] from Result Mapping $rm_display"
                $BodyMetaData.'resultMapping' = $null
                $include_properties += 'resultMapping'
            }
            If ($Calendar.Id.Length -gt 0) {
                [string]$Calendar_id = $Calendar.simpleId
                $Error.Clear()
                Try {
                    [ANOWCalendar]$Calendar_object = Get-AutomateNOWCalendar -Id $Calendar_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWCalendar failed to confirm that the Calendar object [$Calendar_id] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($Calendar_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWCalendar failed to locate the Calendar object [$Calendar_id] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                Write-Verbose -Message "Adding Calendar object [$Calendar_id] to [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'calendar' = $Calendar_id
                $include_properties += 'calendar'
            }
            ElseIf ($UnsetCalendar -eq $true) {
                [string]$Calendar_id = $Calendar.simpleId
                Write-Verbose -Message "Removing [ANOWCalendar] [$Calendar_id] from [ANOWTaskTemplate] [$TaskTemplate_id]"
                $BodyMetaData.'calendar' = $null
                $include_properties += 'calendar'
            }
            If ($Approval.Id.Length -gt 0) {
                [string]$Approval_id = $Approval.simpleId
                $Error.Clear()
                Try {
                    [ANOWApproval]$Approval_object = Get-AutomateNOWApproval -Id $Approval_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWApproval failed to confirm that the Approval object [$Approval_id] actually existed while running under Set-AutomateNOWTaskTemplate due to [$Message]"
                    Break
                }
                If ($Approval_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWApproval failed to locate the Approval object [$Approval_id] running under Set-AutomateNOWTaskTemplate. Please check again."
                    Break
                }
                Write-Verbose -Message "Adding Approval object [$Approval_id] to [ANOWTaskTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'approvalConfiguration' = $Approval_id
                $include_properties += 'approvalConfiguration'
            }
            ElseIf ($UnsetApproval -eq $true) {
                [string]$Approval_id = $Approval.simpleId
                Write-Verbose -Message "Removing [ANOWApproval] [$Approval_id] from [ANOWTaskTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'approvalConfiguration' = $null
                $include_properties += 'approvalConfiguration'
            }
            If ($Weight -ge 0) {
                $BodyMetaData.'weight' = $Weight
            }
            If ($Priority -ge 0) {
                $BodyMetaData.'priority' = $Priority
            }
            If ($Owner.Length -gt 0) {
                $BodyMetaData.'owner' = $Owner
            }
            If ($OnHold -eq $false) {
                $BodyMetaData.'onHold' = 'false'
            }
            ElseIf ($OnHold -eq $true) {
                $BodyMetaData.'onHold' = 'true'
            }
            If ($Skip -eq $false) {
                $BodyMetaData.'passBy' = 'false'
            }
            ElseIf ($Skip -eq $true) {
                $BodyMetaData.'passBy' = 'true'
            }
            If ($AutoArchive -eq $false) {
                $BodyMetaData.'autoArchive' = 'false'
            }
            ElseIf ($Skip -eq $true) {
                $BodyMetaData.'autoArchive' = 'true'
            }
            If ($KeepResources -eq $false) {
                $BodyMetaData.'keepResourcesOnFailure' = 'false'
            }
            ElseIf ($KeepResources -eq $true) {
                $BodyMetaData.'keepResourcesOnFailure' = 'true'
            }
            If ($UseScripts -eq $false) {
                $BodyMetaData.'useScripts' = 'false'
            }
            ElseIf ($UseScripts -eq $true) {
                $BodyMetaData.'useScripts' = 'true'
            }
            If ($EagerScriptExecution -eq $false) {
                $BodyMetaData.'eagerScriptExecution' = 'false'
            }
            ElseIf ($EagerScriptExecution -eq $true) {
                $BodyMetaData.'eagerScriptExecution' = 'true'
            }
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_oldValues' = $TaskTemplate.CreateOldValues()
            If ($componentId.Length -gt 0) {
                $BodyMetaData.'_componentId' = $componentId
            }
            If ($operationId.Length -gt 0) {
                $BodyMetaData.'_operationId' = $operationId
            }
            $BodyMetaData.'_dataSource' = 'ProcessingTemplateDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties $include_properties
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                If ($null -eq $results.response.status) {
                    Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                    Break
                }
                Else {
                    [string]$results_response = $results.response
                    Write-Warning -Message "Received status code [$response_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                    Break
                }
            }
            $Error.Clear()
            Try {
                [ANOWTaskTemplate]$UpdatedTaskTemplate = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to parse the response into a [ANOWTaskTemplate] object (under Set-AutomateNOWTaskTemplate) due to [$Message]."
                Break
            }
            If ($UpdatedTaskTemplate.id -eq $TaskTemplate_id) {
                Write-Verbose -Message "Task Template $TaskTemplate_id was successfully updated"
                Return $UpdatedTaskTemplate
            }
            Else {
                Write-Warning -Message "Somehow the returned Task Template (under Set-AutomateNOWTaskTemplate) has an error. Please look into this."
            }
        }
    }
    End {
    }
}

Function Export-AutomateNOWTaskTemplate {
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
        [ANOWTaskTemplate]$TaskTemplate
    )
    Begin {
        [string]$current_time = Get-Date -Format 'yyyyMMddHHmmssfff'
        [string]$ExportFileName = 'Export-AutomateNOW-TaskTemplates-' + $current_time + '.csv'
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
            [ANOWTaskTemplate]$TaskTemplate = $_
        }
        $Error.Clear()
        Try {
            $TaskTemplate | Export-CSV @parameters
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

Function New-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Creates a Task Template within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Task Template within an AutomateNOW! instance and returns back the newly created [ANOWTaskTemplate] object

    .PARAMETER InternalTaskType
    Type of the Internal Task Template. Valid options are: ABORT, ADD_TAG, ADHOC_REPORT_SEND, AE_SCRIPT, ARCHIVE, ARCHIVE_CLEANUP, ARCHIVE_INTERVAL, CHECK_PROCESSING_STATE, CHECK_RESOURCE, CHECK_TIME, DESIGN_BACKUP, DESIGN_IMPORT, FORCE_COMPLETED, FORCE_FAILED, FORCE_READY, HOLD, KILL, NOTIFY_CHANNEL, NOTIFY_EMAIL, NOTIFY_GROUP, PROCESSING_ACTION_SKIP_OFF, PROCESSING_ACTION_SKIP_ON, PROCESSING_BASELINE_DEVIATION_MONITOR, PROCESSING_CLEAR_STATE_REGISTRY, PROCESSING_REGISTER_STATE, PROCESSING_RUN_NOW, PROCESSING_TEMPLATE_HOLD, PROCESSING_TEMPLATE_RESUME, PROCESSING_TEMPLATE_SKIP_OFF, PROCESSING_TEMPLATE_SKIP_ON, PROCESSING_UNREGISTER_STATE, RECALCULATE_STATISTICS, REMOVE_TAG, RESOURCE_ADD_TAG, RESOURCE_REMOVE_TAG, RESOURCE_SET_FOLDER, RESTART, RESUME, SERVER_NODE_ABORT_ALL, SERVER_NODE_ADD_TAG, SERVER_NODE_HOLD, SERVER_NODE_KILL_ALL, SERVER_NODE_REMOVE_TAG, SERVER_NODE_RESUME, SERVER_NODE_SET_FOLDER, SERVER_NODE_SET_TOTAL_WEIGHT_CAPACITY, SERVER_NODE_SKIP_OFF, SERVER_NODE_SKIP_ON, SERVER_NODE_STOP, SET_CONTEXT_VARIABLE_VALUE, SET_CONTEXT_VARIABLE_VALUES, SET_FOLDER, SET_PRIORITY, SET_RESOURCE, SET_STATUS_CODE, SKIP_OFF, SKIP_ON, USER_CONFIRM, USER_INPUT, WAIT

    .PARAMETER TaskType
    Type of the Task Template. Valid options are: AE_SHELL_SCRIPT, AMQP_SEND, ANSIBLE_PLAYBOOK, ANSIBLE_PLAYBOOK_PATH, APACHE_AIRFLOW_RUN_DAG, ARANGO_DB_INSERT, AS400_BATCH_JOB, AS400_COMMAND_CALL, AS400_PROGRAM_CALL, AUTOMATE_NOW_RUN_JOB, AUTOMATE_NOW_TRIGGER_EVENT, AUTOMATION_ANYWHERE, AUTOMATION_ANYWHERE_DEPLOY_ROBOT, AUTOMATION_ANYWHERE_START_ROBOT, AUTOMATION_ANYWHERE_STOP_ROBOT, AUTOMATION_ANYWHERE_UNDEPLOY_ROBOT, AUTOMIC_WLA_RUN_JOB, AWS_BATCH_JOB, AWS_EC2_DELETE_VOLUME, AWS_EC2_START_INSTANCE, AWS_EC2_STOP_INSTANCE, AWS_EC2_TERMINATE_INSTANCE, AWS_EMR_ADD_STEPS, AWS_EMR_API_COMMAND, AWS_EMR_CANCEL_STEPS, AWS_EMR_GET, AWS_EMR_PUT, AWS_EMR_START_NOTEBOOK_EXECUTION, AWS_EMR_STOP_NOTEBOOK_EXECUTION, AWS_EMR_TERMINATE_JOB_FLOW, AWS_EMR_WORKFLOW, AWS_GLUE_CRAWLER, AWS_GLUE_JOB, AWS_GLUE_TRIGGER, AWS_GLUE_WORKFLOW, AWS_LAMBDA_CREATE_FUNCTION, AWS_LAMBDA_DELETE_FUNCTION, AWS_LAMBDA_INVOKE, AWS_S3_COPY_OBJECT, AWS_S3_DELETE_OBJECT, AWS_S3_MOVE_OBJECT, AWS_S3_RENAME_OBJECT, AWS_SAGE_MAKER_ADD_MODEL, AWS_SAGE_MAKER_API_COMMAND, AWS_SAGE_MAKER_DELETE_MODEL, AWS_SAGE_MAKER_PROCESSING, AWS_SAGE_MAKER_TRAINING, AWS_SAGE_MAKER_TRANSFORM, AWS_SAGE_MAKER_TUNING, AWS_START_STEP_FUNCTION_STATE_MACHINE, AZURE_BATCH_JOB, AZURE_DATA_FACTORY_PIPELINE, AZURE_DATA_FACTORY_TRIGGER, AZURE_DATA_LAKE_JOB, AZURE_DATABRICKS_DELETE_CLUSTER, AZURE_DATABRICKS_JOB, AZURE_DATABRICKS_LIST_CLUSTERS, AZURE_DATABRICKS_START_CLUSTER, AZURE_DATABRICKS_TERMINATE_CLUSTER, AZURE_RUN_LOGIC_APP, BLUE_PRISM, BLUE_PRISM_DEPLOY_ROBOT, BLUE_PRISM_START_ROBOT, BLUE_PRISM_STOP_ROBOT, BLUE_PRISM_UNDEPLOY_ROBOT, BMC_REMEDY_INCIDENT, C, CA_SERVICE_MANAGEMENT_INCIDENT, CA_WLA_RUN_JOB, CASSANDRA_CQL_SCRIPT, CHECK_BARRIER_AVAILABLE_PERMITS, CHECK_BARRIER_TOTAL_PERMITS, CHECK_CALENDAR, CHECK_LOCK_STATE, CHECK_METRIC, CHECK_PHYSICAL_RESOURCE, CHECK_QUEUE, CHECK_SEMAPHORE_STATE, CHECK_STOCK_AVAILABLE_PERMITS, CHECK_STOCK_TOTAL_PERMITS, CHECK_TIME_WINDOW_STATE, CHECK_VARIABLE_VALUE, CLEAR_QUEUE, CONTROL_M_RUN_JOB, COUCH_BASE_INSERT, COUCH_DB_INSERT, CPP, CTRLM_ADD_CONDITION, CTRLM_CREATE_JOB, CTRLM_DELETE_CONDITION, CTRLM_ORDER_JOB, CTRLM_RESOURCE_TABLE_ADD, CTRLM_RESOURCE_TABLE_DELETE, CTRLM_RESOURCE_TABLE_UPDATE, DATASOURCE_DELETE_FILE, DATASOURCE_DOWNLOAD_FILE, DATASOURCE_UPLOAD_FILE, DBT_JOB, DYNAMO_DB_INSERT, EMAIL_CONFIRMATION, EMAIL_INPUT, EMAIL_SEND, FACEBOOK_POST, FILE_CHECK, FILE_TRANSFER, FILE_WATCHER, FLINK_JAR_DELETE, FLINK_JAR_UPLOAD, FLINK_RUN_JOB, GO, GOOGLE_DATA_FLOW_JOB, GROOVY, HDFS_APPEND_FILE, HDFS_CREATE_DIRECTORY, HDFS_DELETE_DIRECTORY, HDFS_DELETE_FILE, HDFS_DOWNLOAD_FILE, HDFS_RENAME, HDFS_UPLOAD_FILE, HP_OPEN_VIEW_SERVICE_MANAGER_INCIDENT, HTTP_REQUEST, IBM_CONTROL_DESK_INCIDENT, IBM_DATASTAGE, IBM_MQ_SEND, IBM_WLA_RUN_JOB, INFORMATICA_ASSIGNMENT, INFORMATICA_CLOUD_TASKFLOW, INFORMATICA_COMMAND, INFORMATICA_CONTROL, INFORMATICA_EMAIL, INFORMATICA_EVENT_RAISE, INFORMATICA_EVENT_WAIT, INFORMATICA_SESSION, INFORMATICA_START, INFORMATICA_TIMER, INFORMATICA_WORKFLOW, INFORMATICA_WS_WORKFLOW, INSTAGRAM_POST, JAVA, JAVASCRIPT, JIRA_ADD_ISSUE, JMS_SEND, KAFKA_SEND, KOTLIN, LINKED_IN_POST, MICROSOFT_POWER_BI_DATAFLOW_REFRESH, MICROSOFT_POWER_BI_DATASET_REFRESH, MONGO_DB_INSERT, MQTT_SEND, MS_SSIS, NEO4J_INSERT, ODI_LOAD_PLAN, ODI_SESSION, OPENTEXT_DYNAMIC_JCL, OPENTEXT_STORED_JCL, ORACLE_EBS_EXECUTE_PROGRAM, ORACLE_EBS_EXECUTE_REQUEST_SET, ORACLE_EBS_PROGRAM, ORACLE_EBS_REQUEST_SET, ORACLE_SERVICE_CENTER_CASE, PEGA_DEPLOY_ROBOT, PEGA_START_ROBOT, PEGA_STOP_ROBOT, PEGA_UNDEPLOY_ROBOT, PEOPLESOFT_APPLICATION_ENGINE_TASK, PEOPLESOFT_COBOL_SQL_TASK, PEOPLESOFT_CRW_ONLINE_TASK, PEOPLESOFT_CRYSTAL_REPORTS_TASK, PEOPLESOFT_CUBE_BUILDER_TASK, PEOPLESOFT_JOB_TASK, PEOPLESOFT_NVISION_TASK, PEOPLESOFT_SQR_PROCESS_TASK, PEOPLESOFT_SQR_REPORT_TASK, PEOPLESOFT_WINWORD_TASK, PERL, POP_FROM_QUEUE, POWERSHELL, PROCESSING_OBSERVER, PUSH_TO_QUEUE, PYTHON, RABBIT_MQ_SEND, RAINCODE_DYNAMIC_JCL, RAINCODE_STORED_JCL, RDBMS_SQL, RDBMS_SQL_STATEMENT, RDBMS_STORED_PROCEDURE, REDDIT_POST, REDIS_CLI, REDIS_DELETE, REDIS_GET, REDIS_SET, REST_WEB_SERVICE_CALL, RETRY, ROBOT_FRAMEWORK_DEPLOY_ROBOT, ROBOT_FRAMEWORK_START_ROBOT, ROBOT_FRAMEWORK_STOP_ROBOT, ROBOT_FRAMEWORK_UNDEPLOY_ROBOT, RUBY, RUST, SAP_4H_ARCHIVE, SAP_4H_BW_PROCESS_CHAIN, SAP_4H_CM_PROFILE_ACTIVATE, SAP_4H_CM_PROFILE_DEACTIVATE, SAP_4H_COPY_EXISTING_JOB, SAP_4H_EXPORT_CALENDAR, SAP_4H_EXPORT_JOB, SAP_4H_FUNCTION_MODULE_CALL, SAP_4H_GET_APPLICATION_LOG, SAP_4H_JOB, SAP_4H_JOB_INTERCEPTOR, SAP_4H_MODIFY_INTERCEPTION_CRITERIA, SAP_4H_MONITOR_EXISTING_JOB, SAP_4H_RAISE_EVENT, SAP_4H_READ_TABLE, SAP_4H_RELEASE_EXISTING_JOB, SAP_4H_START_SCHEDULED_JOB, SAP_4H_SWITCH_OPERATION_MODE, SAP_4H_VARIANT_COPY, SAP_4H_VARIANT_CREATE, SAP_4H_VARIANT_DELETE, SAP_4H_VARIANT_UPDATE, SAP_ARCHIVE, SAP_BW_PROCESS_CHAIN, SAP_CM_PROFILE_ACTIVATE, SAP_CM_PROFILE_DEACTIVATE, SAP_EXPORT_CALENDAR, SAP_EXPORT_JOB, SAP_FUNCTION_MODULE_CALL, SAP_GET_APPLICATION_LOG, SAP_IBP_CREATE_PROCESS, SAP_IBP_DELETE_PROCESS, SAP_IBP_JOB, SAP_IBP_SET_PROCESS_STEP_STATUS, SAP_MODIFY_INTERCEPTION_CRITERIA, SAP_ODATA_API_CALL, SAP_R3_COPY_EXISTING_JOB, SAP_R3_JOB, SAP_R3_JOB_INTERCEPTOR, SAP_R3_MONITOR_EXISTING_JOB, SAP_R3_RAISE_EVENT, SAP_R3_RELEASE_EXISTING_JOB, SAP_R3_START_SCHEDULED_JOB, SAP_R3_VARIANT_COPY, SAP_R3_VARIANT_CREATE, SAP_R3_VARIANT_DELETE, SAP_R3_VARIANT_UPDATE, SAP_READ_TABLE, SAP_SOLUTION_MANAGER_TICKET, SAP_SWITCH_OPERATION_MODE, SAS_4GL, SAS_DI, SAS_JOB, SAS_VIYA_JOB, SCALA, SERVER_NODE_SET_CONNECTION, SERVER_NODE_SET_PARAMETERS, SERVICE_NOW_CLOSE_INCIDENT, SERVICE_NOW_CREATE_INCIDENT, SERVICE_NOW_INCIDENT_STATUS_SENSOR, SERVICE_NOW_RESOLVE_INCIDENT, SERVICE_NOW_UPDATE_INCIDENT, SET_BARRIER_TOTAL_PERMITS, SET_METRIC, SET_PHYSICAL_RESOURCE, SET_PROCESSING_STATUS, SET_RESOURCES, SET_SEMAPHORE_STATE, SET_SEMAPHORE_TIMESTAMP_STATE, SET_SERVER_NODE, SET_STOCK_TOTAL_PERMITS, SET_TIME_WINDOW_STATE, SET_VARIABLE_TIMESTAMP_VALUE, SET_VARIABLE_VALUE, SH, SOAP_WEB_SERVICE_CALL, SPARK_JAVA, SPARK_PYTHON, SPARK_R, SPARK_RUN_JOB, SPARK_SCALA, SPARK_SQL, STOMP_SEND, STONEBRANCH_RUN_JOB, SWIFT, TALEND_JOB, TCL, TELEGRAM_MESSAGE, TERMA_RUN_JOB, TIDAL_RUN_JOB, TIKTOK_POST, TITAN_INSERT, TRIGGER_EVENT, TRIGGER_ITEM, TUMBLR_POST, TWITTER_POST, TYPESCRIPT, UI_PATH, UI_PATH_DEPLOY_ROBOT, UI_PATH_START_ROBOT, UI_PATH_STOP_ROBOT, UI_PATH_UNDEPLOY_ROBOT, VBSCRIPT, WHATSAPP_MESSAGE, WORK_FUSION_DEPLOY_ROBOT, WORK_FUSION_START_ROBOT, WORK_FUSION_STOP_ROBOT, WORK_FUSION_UNDEPLOY_ROBOT, XFTP_COMMAND, XMPP_SEND, YOUTUBE_POST, Z_OS_COMMAND, Z_OS_DYNAMIC_JCL, Z_OS_STORED_JCL

    .PARAMETER ServiceManagerTaskType
    Type of the Task Template. Valid options are: SLA_SERVICE_MANAGER, PROCESSING_DEADLINE_MONITOR

    .PARAMETER Id
    Mandatory "name" of the Task Template. For example: 'LinuxTaskTemplate1'. This value may not contain the domain in brackets. This is the unique key of this object.

    .PARAMETER Description
    Optional description of the Task Template (may not exceed 255 characters).

    .PARAMETER Tags
    Optional array of strings representing the Tags to include with this object.

    .PARAMETER Folder
    Optional string representing the Folder to place this object into.

    .PARAMETER DesignTemplate
    Optional string representing the Design Template to place this object into.

    .PARAMETER Workspace
    Optional string representing the Workspace to place this object into.

    .PARAMETER CodeRepository
    Optional string representing the Code Repository to place this object into.

    .PARAMETER ServerNodeType
    Name of the Server Node Type that drives the Task Template. Use a string here! You cannot combine this parameter with -InternalTask. Valid options are: AZURE, AWS, GOOGLE_CLOUD, GOOGLE_DATA_FLOW, AZURE_DATABRICKS, INFORMATICA_CLOUD, UNIX, LINUX, WINDOWS, SOLARIS, HPUX, AIX, OPENVMS, MACOS, AS400, Z_OS, RAINCODE, CTRL_M, OPENTEXT, INFORMATICA, INFORMATICA_WS, SAS, SAS_VIYA, IBM_DATASTAGE, ODI, MS_SSIS, AB_INITIO, SAP_BODI, SKYVIA, TALEND, DBT, SAP, SAP_S4_HANA, SAP_S4_HANA_CLOUD, SAP_IBP, JD_EDWARDS, ORACLE_EBS, PEOPLESOFT, MICROSOFT_DYNAMICS, HIVE_QL, GOOGLE_BIG_QUERY, AZURE_SQL_DATA_WAREHOUSE, AZURE_SQL_DATABASE, DASHDB, DB2, MYSQL, NETEZZA, ORACLE, POSTGRESQL, SQL_SERVER, TERADATA, SINGLESTORE, SNOWFLAKE, VERTICA, PRESTO_DB, SYBASE, INFORMIX, H2, FILE_MANAGER, SNMP, HTTP, EMAIL, SOAP_WEB_SERVICE, REST_WEB_SERVICE, INTERNAL, IBM_MQ, RABBIT_MQ, SQS, ACTIVE_MQ, QPID, IBM_SIBUS, HORNETQ, SOLACE, JORAM_MQ, QMQ, ZERO_MQ, KAFKA, PULSAR, AMAZON_KINESIS, GOOGLE_CLOUD_PUB_SUB, MICROSOFT_AZURE_EVENT_HUB, AMQP, XMPP, STOMP, HDFS, REDIS, HADOOP, HIVE, IMPALA, SQOOP, YARN, SPARK, FLUME, FLINK, STORM, OOZIE, AMBARI, ELASTIC_SEARCH, CASSANDRA, SAP_HANA, MONGO_DB, COUCH_DB, COUCH_BASE, DYNAMO_DB, ARANGO_DB, NEO4J, ORIENT_DB, TITAN, ANDROID, IOS, WINDOWS_MOBILE, MICROSOFT_POWER_BI, BLUE_PRISM, UI_PATH, AUTOMATION_ANYWHERE, WORK_FUSION, PEGA, ROBOT_FRAMEWORK, CONTROL_M, STONEBRANCH, CA_WLA, AUTOMIC_WLA, IBM_WLA, TIDAL, FACEBOOK, INSTAGRAM, TWITTER, YOUTUBE, LINKED_IN, TUMBLR, TIKTOK, REDDIT, TELEGRAM, WHATSAPP, JIRA, SERVICE_NOW, ORACLE_SERVICE_CENTER, BMC_REMEDY, CA_SERVICE_MANAGEMENT, IBM_CONTROL_DESK, HP_OPEN_VIEW_SERVICE_MANAGER, SAP_SOLUTION_MANAGER, AUTOMATE_NOW, APACHE_AIRFLOW, ANSIBLE

    .PARAMETER InternalTask
    Switch to indicate the task is internal. You cannot combine this parameter with -ServerNodeType.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWTaskTemplate.

    .OUTPUTS
    An [ANOWTaskTemplate] object representing the newly created Task Template. Use the -Quiet parameter to suppress this.

    .EXAMPLE
    Creates a new Shell Task Template

    New-AutomateNOWTaskTemplate -TaskType SH -ServerNodeType 'LINUX' -Id 'TaskTemplate01' -Description 'Description text' -Tags 'Tag01', 'Tag01' -Folder 'Folder01' -Workspace 'Workspace01' -CodeRepository 'CodeRepository01'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Task Template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    You must specify one of the three following parameters: -TaskType, -InternalTaskType or -ServiceManagerTaskType

    #>
    [OutputType([ANOWTaskTemplate])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'InternalTask')]
        [ANOWTaskTemplateCustom_InternalTasks]$InternalTaskType,
        [Parameter(Mandatory = $true, ParameterSetName = 'NodeTask')]
        [ANOWTaskTemplateCustom_Tasks]$TaskType,
        [Parameter(Mandatory = $true, ParameterSetName = 'ServiceManagerTask')]
        [ANOWTaskTemplateCustom_ServiceManagers]$ServiceManagerTaskType,
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$DesignTemplate,
        [Parameter(Mandatory = $false)]
        [string]$Workspace,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $true, ParameterSetName = 'NodeTask')]
        [ANOWTaskTemplate_serverNodeType]$ServerNodeType,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    [string]$processingType = 'TASK'
    If ($InternalTaskType.Length -gt 0 -or $ServiceManagerTaskType.Length -gt 0) {
        [string]$ServerNodeType = 'INTERNAL'
        If ($InternalTaskType.Length -gt 0) {
            [string]$TaskType = $InternalTaskType
        }
        Else {
            [string]$processingType = 'SERVICE'
        }
    }
    Else {
        [string[]]$ValidServerNodeTypes = Resolve-AutomateNOWTaskType2ServerNodeType -TaskType $TaskType
        [int32]$ValidServerNodeTypesCount = $ValidServerNodeTypes.Count
        If ($ValidServerNodeTypesCount -eq 0) {
            Write-Warning -Message "Somehow the TaskType2ServerNodeType lookup table has failed"
            Break
        }
        Else {
            If ($ServerNodeType -notin $ValidServerNodeTypes) {
                [string]$ValidServerNodeTypesDisplay = $ValidServerNodeTypes -join ', '
                Write-Warning -Message "Sorry, [$ServerNodeType] is not a valid server node type for a [$TaskType] task. Please use one of these instead: $ValidServerNodeTypesDisplay"
                Break
            }
        }
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$TaskTemplate_exists = ($null -ne (Get-AutomateNOWTaskTemplate -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to check if the Task Template [$Id] already existed due to [$Message]."
        Break
    }
    If ($TaskTemplate_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Task Template named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWTaskTemplate = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWTaskTemplate.Add('id', $Id)
    $ANOWTaskTemplate.Add('processingType', $processingType)
    If ($ServiceManagerTaskType.Length -eq 0) {
        $ANOWTaskTemplate.Add('taskType', $TaskType)
        [string]$old_values = ('{"processingType":"TASK","taskType":"' + $TaskType + '","serverNodeType":"' + $ServerNodeType + '"}')
    }
    Else {
        $ANOWTaskTemplate.Add('serviceType', 'SERVICE_MANAGER')
        $ANOWTaskTemplate.Add('serviceManagerType', $ServiceManagerTaskType)
        [string]$old_values = '{"processingType":"SERVICE","serviceType":"SERVICE_MANAGER","serviceManagerType":"' + $ServiceManagerTaskType + '","workspace":null,"serverNodeType":"INTERNAL"}'
    }
    $ANOWTaskTemplate.Add('serverNodeType', $ServerNodeType)
    $ANOWTaskTemplate.Add('_oldValues', $old_values)
    [string[]]$include_properties = 'id', 'processingType', 'taskType', 'serverNodeType'
    If ($Description.Length -gt 0) {
        $ANOWTaskTemplate.Add('description', $Description)
        $include_properties += 'description'
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWTaskTemplate due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWTaskTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWTaskTemplate.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] actually existed while running under New-AutomateNOWTaskTemplate due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] running under New-AutomateNOWTaskTemplate. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWTaskTemplate] [$Id]"
        $ANOWTaskTemplate.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($DesignTemplate.Length -gt 0) {
        $ANOWTaskTemplate.Add('designTemplate', $DesignTemplate)
        $include_properties += 'designTemplate'
    }
    If ($Workspace.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWWorkspace]$workspace_object = Get-AutomateNOWWorkspace -Id $Workspace
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkspace failed to confirm that the workspace [$Workspace] actually existed while running under New-AutomateNOWTaskTemplate due to [$Message]"
            Break
        }
        If ($workspace_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWWorkspace failed to locate the Workspace [$Workspace] running under New-AutomateNOWTaskTemplate. Please check again."
            Break
        }
        [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding workspace $workspace_display to [ANOWTaskTemplate] [$Id]"
        $ANOWTaskTemplate.Add('workspace', $Workspace)
        $include_properties += 'workspace'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] actually existed while running under New-AutomateNOWTaskTemplate due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] running under New-AutomateNOWTaskTemplate. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWTaskTemplate] [$Id]"
        $ANOWTaskTemplate.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWTaskTemplate -IncludeProperties $include_properties
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = $old_values
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Task Template [$Id] of type [$TaskType] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Task Template [$Id] of type [$TaskType] due to [an empty response]. The parameters used: $parameters_display"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWTaskTemplate]$TaskTemplate = $results.response.data[0]
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Failed to create [ANOWTaskTemplate] object due to [$Message]."
        Break
    }
    If ($TaskTemplate.id.Length -eq 0) {
        Write-Warning -Message "Somehow the newly created [ANOWTaskTemplate] is empty!"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWTaskTemplate]$TaskTemplate = Get-AutomateNOWTaskTemplate -Id $Id
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to confirm that the [ANOWTaskTemplate] object [$Id] was created due to [$Message]."
        Break
    }
    If ($Quiet -ne $true) {
        Return $TaskTemplate
    }
}

Function Remove-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Removes a Task Template from an AutomateNOW! instance

    .DESCRIPTION
    Removes a Task Template from an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01' | Remove-AutomateNOWTaskTemplate 

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01', 'Task02' | Remove-AutomateNOWTaskTemplate 

    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Remove-AutomateNOWTaskTemplate 

    .EXAMPLE
    Get-AutomateNOWTaskTemplate | ? { $_.serverTaskType -eq 'LINUX' } | Remove-AutomateNOWTaskTemplate 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
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
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($TaskTemplate.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$TaskTemplate_id = $_.id
            }
            ElseIf ($TaskTemplate.id.Length -gt 0) {
                [string]$TaskTemplate_id = $TaskTemplate.id
            }
            Else {
                [string]$TaskTemplate_id = $Id
            }
            [string]$Body = 'id=' + $TaskTemplate_id
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$error_message = $results.response.data
                If ($error_message -match 'Object may still be in use') {
                    [string]$TaskTemplate_id_formatted = $TaskTemplate_id -split '\]' | Select-Object -Last 1
                    Write-Warning -Message "This object $TaskTemplate_id_formatted is still in use somewhere therefore it cannot be removed! Please use 'Find-AutomateNOWObjectReferral -Object $WorkflowTemplate_id_formatted' to list the references for this object and then remove them."
                }
                Else {
                    [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                    Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
                }
            }
            Write-Verbose -Message "Task $TaskTemplate_id successfully removed"
        }
    }
    End {

    }
}

Function Copy-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Copies a Task Template from an AutomateNOW! instance

    .DESCRIPTION
    Copies a Task Template from an AutomateNOW! instance. AutomateNOW object id can never be changed, but we can copy the object to a new id and it will include all of the items therein.

    .PARAMETER TaskTemplate
    Mandatory [ANOWTaskTemplate] object to be copied.

    .PARAMETER NewId
    Mandatory string indicating the new id or name of the Task Template. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

    .PARAMETER UnsetTags
    Optional switch that will purposely omit the previously existing tags on the new copy of the Task Template. You can still specify new tags with -Tags but the old previous ones will not be carried over. In the UI, this is accomplished by clicking the existing tags off.

    .PARAMETER NoFolder
    Optional switch that will ensure that the newly created Task Template will not be placed in a folder.

    .PARAMETER UnsetDescription
    Optional switch that will ensure that the newly created Task Template will not carry over its previous description.

    .PARAMETER Description
    Optional description of the Task Template (may not exceed 255 characters). You may send an empty string here to ensure that the description is blanked out. Do not use this parameter if your intention is to keep the description from the previous Task Template.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Task Template.

    .PARAMETER Folder
    Optional name of the folder to place the Task Template into. The NoFolder parameter overrides this setting.

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted. Pipeline support is intentionally unavailable.

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    This is a safe standard example that is recommended

    $Task01 = Get-AutomateNOWTaskTemplate -Id 'old_name_Task01'
    Copy-AutomateNOWTaskTemplate -TaskTemplate $TaskTemplate01 -NewId 'new_name_TaskTemplate02'

    .EXAMPLE
    This is a one-liner approach

    Copy-AutomateNOWTaskTemplate -TaskTemplate (Get-AutomateNOWTaskTemplate -Id 'old_name_TaskTemplate01') -NewId 'new_name_TaskTemplate02'

    .EXAMPLE
    This approach users a For Each loop to iterate through a standard renaming pattern. This approach is not recommended.

    @( 'TaskTemplate1', 'TaskTemplate2', 'TaskTemplate3') | Get-AutomateNOWTaskTemplate | ForEachObject { Copy-AutomateNOWTaskTemplate -TaskTemplate $_ -NewId ($_.simpleId -replace 'Task[0-9]', ()'Task-' + $_.simpleId[-1]))}

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The new id (name) of the Task Template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.
    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWTaskTemplate]$TaskTemplate,
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
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription,
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
            [boolean]$Task_template_exists = ($null -ne (Get-AutomateNOWTaskTemplate -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to check if the Task template [$NewId] already existed due to [$Message]."
            Break
        }
        If ($Task_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a Task Template named [$NewId] in [$current_domain]. You may not proceed."
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
            [string]$TaskTemplate_oldId = $TaskTemplate.id
            If ($TaskTemplate_oldId -eq $NewId) {
                Write-Warning -Message "The new id cannot be the same as the old id."
                Break
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'oldId' = $TaskTemplate_oldId
            $BodyMetaData.'domain' = $TaskTemplate.domain
            $BodyMetaData.'id' = $NewId
            If ($UnsetDescription -ne $true) {
                If ($Description.Length -gt 0) {
                    $BodyMetaData.'description' = $Description
                }
                Else {
                    $BodyMetaData.'description' = $TaskTemplate.description
                }
            }
            If ($NoFolder -ne $True) {
                If ($Folder.Length -gt 0) {
                    $BodyMetaData.'folder' = $Folder
                }
                Else {
                    $BodyMetaData.'folder' = $TaskTemplate.folder
                }
            }
            [int32]$tag_count = 1
            If ($Tags.Count -gt 0) {
                ForEach ($tag in $Tags) {
                    $BodyMetaData.('tags' + $tag_count ) = $tag
                    $tag_count++
                }
            }
            If ($UnsetTags -ne $true) {
                If ($TaskTemplate.tags -gt 0) {
                    ForEach ($tag in $TaskTemplate.tags) {
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWTaskTemplate]$TaskTemplate = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create copied [ANOWTaskTemplate] object due to [$Message]."
                Break
            }
            If ($TaskTemplate.id.Length -eq 0) {
                Write-Warning -Message "Somehow the newly created (copied) [ANOWTaskTemplate] object is empty!"
                Break
            }
            Return $TaskTemplate
        }
    }
    End {

    }
}

Function Rename-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Renames a Task Template from an AutomateNOW! instance

    .DESCRIPTION
    Performs a psuedo-rename operations of a Task Template from an AutomateNOW! instance by copying it first and then deleting the source. This function merely combines Copy-AutomateNOWTaskTemplate and Remove-AutomateNOWTaskTemplate therefore it is to be considered destructive.

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be renamed.

    .PARAMETER NewId
    Mandatory string indicating the new id or name of the Task Template. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

    .PARAMETER Force
    Force the renaming without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted. There is inventionally no support for the pipeline.

    .OUTPUTS
    The newly renamed [ANOWTaskTemplate] object will be returned.

    .EXAMPLE
    $task_template = Get-AutomateNOWTaskTemplate -Id 'Task01'
    Rename-AutomateNOWTaskTemplate -TaskTemplate $task_template -NewId 'Task_TEMPLATE_01'

    .EXAMPLE
    Rename-AutomateNOWTaskTemplate -TaskTemplate (Get-AutomateNOWTaskTemplate -Id 'Task01') -NewId 'Task_TEMPLATE_01'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    When renaming, you may only specify a different Id (name).

    This action will be blocked if any existing referrals are found on the object.
    #>
    [OutputType([ANOWTaskTemplate])]
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWTaskTemplate]$TaskTemplate,
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
            [boolean]$new_task_template_exists = ($null -ne (Get-AutomateNOWTaskTemplate -Id $NewId))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to check if the Task Template [$NewId] already existed due to [$Message]."
            Break
        }
        If ($new_task_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a Task Template named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        [string]$TaskTemplate_id = $TaskTemplate.id
        $Error.Clear()
        Try {
            [boolean]$old_Task_template_exists = ($null -ne (Get-AutomateNOWTaskTemplate -Id $TaskTemplate_id))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWTaskTemplate failed to check if the Task Template [$TaskTemplate_id] already existed due to [$Message]."
            Break
        }
        If ($old_Task_template_exists -eq $false) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is not a Task Template named [$TaskTemplate_id] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        ## End standard warning ##
        ## Begin referrals warning ##
        ## Do not tamper with this below code which makes sure the object does not have referrals. The old object is removed but this can't happen if referrals exist. The API will prevent this from happening but it is checked here to stop any invalid requests from being sent to the API in the first place.
        $Error.Clear()
        Try {
            [int32]$referrals_count = Find-AutomateNOWObjectReferral -TaskTemplate $TaskTemplate -Count | Select-Object -Expandproperty referrals
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Find-AutomateNOWObjectReferral failed to extract the referrals on Task Template [$TaskTemplate_id] due to [$Message]."
            Break
        }
        If ($referrals_count -gt 0) {
            Write-Warning -Message "Unfortunately, you cannot rename a Task Template that has referrals. This is because the rename is not actually renaming but copying anew and deleting the old. Please, use the Find-AutomateNOWObjectReferral function to identify referrals and remove them."
            Break
        }
        Else {
            Write-Verbose -Message "The Task Template [$TaskTemplate_id] does not have any referrals. It is safe to proceed."
        }
    }
    Process {
        If ($PermissionToProceed -ne $false) {
            If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($TaskTemplate_id)")) -eq $true) {
                $Error.Clear()
                Try {
                    [ANOWTaskTemplate]$new_task_template = Copy-AutomateNOWTaskTemplate -TaskTemplate $TaskTemplate -NewId $NewId
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Copy-AutomateNOWTaskTemplate failed to create a new Task Template [$NewId] as Part 1 of the renaming process due to [$Message]."
                    Break
                }
                If ($new_Task_template.simpleId -eq $NewId) {
                    Write-Verbose -Message "Part 1: Task Template [$TaskTemplate_id] successfully copied to [$NewId]"
                }
                $Error.Clear()
                Try {
                    [ANOWTaskTemplate]$new_task_template = Remove-AutomateNOWTaskTemplate -TaskTemplate $TaskTemplate -confirm:$false # Note that confirmation was already provided a few lines above
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Remove-AutomateNOWTaskTemplate failed to remove [$TaskTemplate_id] as Part 2 of the renaming process due to [$Message]."
                    Break
                }
                If ($new_task_template.simpleId -eq $NewId) {
                    Write-Verbose -Message "Part 2: Task Template [$TaskTemplate_id] removed"
                }
                Write-Verbose -Message "Task [$TaskTemplate_id] successfully renamed to [$NewId]"
            }
        }
        Else {
            Write-Warning "No action was taken because either the source object didn't exist or the new object already existed"
        }
    }
    End {
    }
}

Function Start-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Starts a Task Template from an AutomateNOW! instance

    .DESCRIPTION
    Starts a Task Template from an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be started.

    .PARAMETER UseAutomaticName
    A switch parameter that is ENABLED BY DEFAULT. You do not need to enable this as it is defaulted to on. This parameter simulates the default format of the executed task name (see 'Name' below)

    .PARAMETER Name
    A string representing the name of the running executed task. Only use this if you want to OVERRIDE the default naming standard that the console suggests when executing a task. The console defaults to a format of "Manual Execution - [task name] - [date utc]".

    .PARAMETER Description
    Optional description of the executed task (may not exceed 255 characters).

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new task.

    .PARAMETER Folder
    Optional name of the folder to place the executed task into.

    .PARAMETER ProcessingTimestamp
    This parameter is -disabled- for now. Instead, the default timestamp will be used to ensure uniqueness. The documentation is unclear or mistaken around this parameter.

    .PARAMETER Priority
    Optional integer between 0 and 1000 to specify the priority of the executed task. Defaults to 0.

    .PARAMETER Hold
    Optional switch to set the 'On Hold' property of the executed task to enabled. This is $false by default but in the console the checkbox is enabled.

    .PARAMETER ForceLoad
    Optional switch that overrides any 'Ignore Condition' that might exist on the Task Template

    .PARAMETER Quiet
    Switch parameter to silence the newly created [ANOWTask] object

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    An [ANOWTask] object representing the started task will be returned.

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'TaskTemplate_01' | Start-AutomateNOWTaskTemplate

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'TaskTemplate_01' | Start-AutomateNOWTaskTemplate -Name 'Manual Execution - TaskTemplate_01' -Tags 'Tag1', 'Tag2' -ForceLoad -Hold -Priority 100 -Description 'My executed task'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function is under construction as the [ANOWTask] class object it returns is not defined yet. You can still use this function but the output is experimental.

    Avoid using the -Name parameter unless you really need to use it. If -Name is not supplied, the parameter set will use -UseAutomaticName instead, which simulates the behavior of the console.

    #>
    [Cmdletbinding(DefaultParameterSetName = 'UseAutomaticName')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $false, ParameterSetName = 'UseAutomaticName')]
        [switch]$UseAutomaticName,
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecifyNameManually')]
        [string]$Name,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder = '',
        [ValidateRange(0, 1000)]
        [Parameter(Mandatory = $false)]
        [int32]$Priority = 0,
        [Parameter(Mandatory = $false)]
        [switch]$Hold,
        [Parameter(Mandatory = $false)]
        [switch]$ForceLoad,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/executeNow'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$TaskTemplate_id = $_.id
            [string]$TaskTemplate_simpleId = $_.simpleId
        }
        Else {
            [string]$TaskTemplate_id = $TaskTemplate.id
            [string]$TaskTemplate_simpleId = $TaskTemplate.simpleId
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $TaskTemplate_id )
        $BodyMetaData.Add('runId', $TaskTemplate_id )
        $BodyMetaData.Add('priority', $priority )
        $BodyMetaData.Add('processingTimestamp', [string](Get-Date -Date ((Get-Date).ToUniversalTime()) -Format 'yyyy-MM-ddTHH:mm:ss.fff'))
        [string[]]$include_properties = 'id', 'runId', 'priority', 'processingTimestamp', 'hold', 'forceLoad', 'name'
        If ($Tags.Count -gt 0) {
            ForEach ($tag_id in $Tags) {
                $Error.Clear()
                Try {
                    [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] due to [$message]"
                    Break
                }
                If ($tag_object.simpleId.length -eq 0) {
                    Throw "Start-AutomateNOWTaskTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                    Break
                }
                [string]$tag_display = $tag_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding tag $tag_display"
            }
            $BodyMetaData.'tags' = $Tags
            $include_properties += 'tags'
        }
        If ($folder.Length -gt 0) {
            $Error.Clear()
            Try {
                [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $folder
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWFolder had an error while retrieving the folder [$folder] under Start-AutomateNOWTaskTemplate due to [$message]"
                Break
            }
            If ($folder_object.simpleId.Length -eq 0) {
                Throw "Start-AutomateNOWTaskTemplate has detected that the folder [$folder] does not appear to exist. Please check again."
                Break
            }
            $BodyMetaData.Add('folder', $folder)
            $include_properties += $folder
        }
        If ($hold -ne $true) {
            $BodyMetaData.Add('hold', 'false')
        }
        Else {
            $BodyMetaData.Add('hold', 'true')
        }
        If ($forceLoad -ne $true) {
            $BodyMetaData.Add('forceLoad', 'false')
        }
        Else {
            $BodyMetaData.Add('forceLoad', 'true')
        }
        If ($Name.Length -gt 0) {
            $BodyMetaData.Add('name', $Name)
        }
        Elseif ($UseAutomaticName -eq $true) {
            [string]$Name = New-AutomateNOWDefaultProcessingTitle -simpleId $TaskTemplate_simpleId
            Write-Verbose -Message "Generated automatic name [$Name] for this task"
        }
        Else {
            Write-Warning -Message "Unable to determine how to name this task that needs to be started"
            Break
        }
        $BodyMetaData.Add('parameters', '{}')
        $BodyMetaData.Add('_operationType', 'add')
        $BodyMetaData.Add('_operationId', 'executeNow')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
            Break
        }
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
        }
        Write-Verbose -Message "Task $TaskTemplate_id successfully started"
        $Error.Clear()
        Try {
            [ANOWTask]$ANOWTask = $results.response.data[0]
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the [ANOWTask] object under Start-AutomateNOWTaskTemplate from the response due to [$Message]."
            Break
        }
        If ($Quiet -ne $true) {
            Return $ANOWTask
        }
    }
    End {

    }
}

Function Resume-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Resumes a Task Template that is on hold (suspended) on an AutomateNOW! instance

    .DESCRIPTION
    Resumes a Task Template that is on hold (suspended) on an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be resumed

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWTaskTemplate] object

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The resumed [ANOWTaskTemplate] object will be returned

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01' | Resume-AutomateNOWTaskTemplate -Force

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01', 'Task02' | Resume-AutomateNOWTaskTemplate 

    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Resume-AutomateNOWTaskTemplate 

    .EXAMPLE
    Get-AutomateNOWTaskTemplate | ? { $_.serverTaskType -eq 'LINUX' } | Resume-AutomateNOWTaskTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processingTemplate/resume'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($TaskTemplate.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$TaskTemplate_id = $_.id
            }
            ElseIf ($TaskTemplate.id.Length -gt 0) {
                [string]$TaskTemplate_id = $TaskTemplate.id
            }
            Else {
                [string]$TaskTemplate_id = $Id
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $TaskTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'resume')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWTaskTemplate]$resumed_task_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWTaskTemplate] object after resuming [$TaskTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Task $TaskTemplate_id successfully resumed"
            If ($Quiet -ne $true) {
                Return $resumed_task_template
            }
        }
    }
    End {

    }
}

Function Suspend-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Places a Task Template on hold (suspend) from execution on an AutomateNOW! instance

    .DESCRIPTION
    Places a Task Template on hold (suspend) from execution on an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be suspended (placed on hold)

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWTaskTemplate] object

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The suspended [ANOWTaskTemplate] object will be returned

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01' | Suspend-AutomateNOWTaskTemplate -Force

    .EXAMPLE
    Get-AutomateNOWTaskTemplate -Id 'Task01', 'Task02' | Suspend-AutomateNOWTaskTemplate 

    .EXAMPLE
    @( 'Task1', 'Task2', 'Task3') | Suspend-AutomateNOWTaskTemplate 

    .EXAMPLE
    Get-AutomateNOWTaskTemplate | ? { $_.serverTaskType -eq 'LINUX' } | Suspend-AutomateNOWTaskTemplate 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processingTemplate/hold'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($TaskTemplate.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$TaskTemplate_id = $_.id
            }
            ElseIf ($TaskTemplate.id.Length -gt 0) {
                [string]$TaskTemplate_id = $TaskTemplate.id
            }
            Else {
                [string]$TaskTemplate_id = $Id
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $TaskTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'hold')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWTaskTemplate]$suspended_task_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWTaskTemplate] object after suspending [$TaskTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Task $TaskTemplate_id successfully suspended (placed on hold)"
            If ($Quiet -ne $true) {
                Return $suspended_task_template
            }
        }
    }
    End {

    }
}

Function Skip-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Sets or unsets the Skip flag on a Task Template on an AutomateNOW! instance

    .DESCRIPTION
    Sets or unsets the Skip flag on a Task Template on an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be set to skipped or unskipped

    .PARAMETER UnSkip
    Removes the skip flag from a [ANOWTaskTemplate] object. This is the opposite of the default behavior.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWTaskTemplate] object

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The skipped/unskipped [ANOWTaskTemplate] object will be returned

    .EXAMPLE
    Sets a Task Template to Skip (bypass)

    Get-AutomateNOWTaskTemplate -Id 'Task01' | Skip-AutomateNOWTaskTemplate -Force

    .EXAMPLE
    Unsets the Skip (bypass) flag on a Task Template

    Get-AutomateNOWTaskTemplate | Skip-AutomateNOWTaskTemplate -UnSkip

    .EXAMPLE
    Sets an array of Task Template to Skip (bypass)

    @( 'Task1', 'Task2', 'Task3') | Skip-AutomateNOWTaskTemplate 

    .EXAMPLE
    Get-AutomateNOWTaskTemplate | ? { $_.serverTaskType -eq 'LINUX' } | Skip-AutomateNOWTaskTemplate -UnSkip -Force -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$UnSkip,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnSkip -ne $True) {
            [string]$skip_flag_status = 'On'
            [string]$operation_id = 'passByOn'
            [string]$ProcessDescription = 'Add the Skip flag'
        }
        Else {
            [string]$skip_flag_status = 'Off'
            [string]$operation_id = 'passByOff'
            [string]$ProcessDescription = 'Remove the Skip flag'
        }
        [string]$command = ('/processingTemplate/' + $operation_id)
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$TaskTemplate_id = $_.id
        }
        ElseIf ($TaskTemplate.id.Length -gt 0) {
            [string]$TaskTemplate_id = $TaskTemplate.id
        }
        Else {
            [string]$TaskTemplate_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($TaskTemplate_id, $ProcessDescription)) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $TaskTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            $Error.Clear()
            Try {
                [ANOWTaskTemplate]$skipped_task_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWTaskTemplate] object after setting the skip flag to [$skip_flag_status] on [$TaskTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Successfully set the skip flag to [$skip_flag_status] on [$TaskTemplate_id]"
            If ($Quiet -ne $true) {
                Return $skipped_task_template
            }
        }
    }
    End {

    }
}

Function Confirm-AutomateNOWTaskTemplate {
    <#
    .SYNOPSIS
    Validates (confirms) a Task Template on an AutomateNOW! instance

    .DESCRIPTION
    Validates (confirms) a Task Template on an AutomateNOW! instance

    .PARAMETER TaskTemplate
    An [ANOWTaskTemplate] object representing the Task Template to be set to confirmed (verified)

    .PARAMETER Quiet
    Returns a boolean $true or $false based on the result of the validation check

    .INPUTS
    ONLY [ANOWTaskTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    A string with the results from the API will returned.

    .EXAMPLE
    Validates a single Task Template

    Get-AutomateNOWTaskTemplate -Id 'Task01' | Confirm-AutomateNOWTaskTemplate

    .EXAMPLE
    Validates a series of Task Templates

    @( 'TaskTemplate1', 'TaskTemplate2', 'TaskTemplate3') | Confirm-AutomateNOWTaskTemplate 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWTaskTemplate]$TaskTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
        If ($_.id.Length -gt 0) {
            [string]$TaskTemplate_id = $_.id
        }
        ElseIf ($TaskTemplate.id.Length -gt 0) {
            [string]$TaskTemplate_id = $TaskTemplate.id
        }
        Else {
            [string]$TaskTemplate_id = $Id
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $TaskTemplate_id )
        $BodyMetaData.Add('_operationType', 'custom')
        $BodyMetaData.Add('_operationId', 'validate')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$command = ('/processingTemplate/validate?' + $Body)
        $parameters.Add('Command', $command)
        $Error.Clear()
        Try {
            [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$TaskTemplate_id] due to [$Message]."
            Break
        }
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            If ($Quiet -eq $true) {
                Return $false
            }
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "The response code was [$response_code] instead of 0. The Task Template $TaskTemplate_id is not validated. Please see the full response $full_response_display"
        }
        Else {
            If ($Quiet -eq $true) {
                Return $true
            }
            Else {
                Write-Information -MessageData "The Task Template $TaskTemplate_id is confirmed as valid."
            }
        }
    }
    End {

    }
}

Function Show-AutomateNOWTaskTemplateType {
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

Function Import-AutomateNOWLocalTimeZone {
    <#
    .SYNOPSIS
    Imports all of the supported time zones from a local file

    .DESCRIPTION
    Imports all of the supported time zones from a local file

    .INPUTS
    None. You cannot pipe objects to Import-AutomateNOWTimeZone.

    .OUTPUTS
    There is no direct output as the timezone objects are loaded into the existing global session variable.

    .EXAMPLE
    Import-AutomateNOWLocalTimeZone

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There are no parameters for Import-AutomateNOWTimeZone.

    This function is intended for use when the end-user needs to use Connect-AutomateNOW without a -Domain parameter before they know what their available domains are.

    #>
    [string]$LocalTimezoneFile = ($PSScriptRoot + '\timezones.txt')
    If ((Test-Path -Path "$LocalTimezoneFile") -eq $false) {
        Write-Warning -Message "The timezones.txt file is not available!"
    }
    $Error.Clear()
    Try {
        [ANOWTimezone[]]$TimeZones = Get-Content -Path "$LocalTimezoneFile" | ConvertFrom-Json
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Unable to read the local time zones file [$LocalTimezoneFile] due to [$Message]"
        Break
    }
    If ($null -eq $anow_session) {
        Write-Warning -Message "You must already have an established session before trying to import the local timezone file."
    }
    If ($null -eq $anow_session.supported_timezones) {
        $anow_session.Add('supported_timezones', $TimeZones)
    }
    Else {
        $anow_session.supported_timezones = $TimeZones
    }
    Write-Verbose -Message "Imported [$TimeZones_count] timezones into the current session"
}

#endregion

#Region - Users

Function Get-AutomateNOWUser {
    <#
    .SYNOPSIS
    Gets the details of a user from an instance of AutomateNOW!

    .DESCRIPTION
    Gets the details of a user from an instance of AutomateNOW!

    .PARAMETER Id
    String parameter to specify the name or Id of the user. This is case-sensitive! If you do not know the username, you can try using the -LoggedOnUser parameter instead.

    .PARAMETER LoggedOnUser
    Switch parameter which skips entering the Id of the user. This is intended for use during the initial logon.

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100.

    .INPUTS
    You may pipe strings representing the Id of the user.

    .OUTPUTS
    1 or more [ANOWUser] objects or 1 [ANOWUserInfo] object

    .EXAMPLE
    Gets a single user object

    Get-AutomateNOWUser -Id 'username'

    .EXAMPLE
    Gets the logged on userinfo object

    Get-AutomateNOWUser -LoggedOnUser

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Get-AutomateNOWUser DOES NOT refresh the token automatically. This is because it is used during the authentication process.

    The startRow and endRow parameters may only be used when retrieving all users.

    ONLY ADMINS CAN GET ALL USERS! You will get unauthorized error otherwise.

    #>
    [Cmdletbinding(DefaultParameterSetName = 'AllUsers')]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificUser')]
        [string]$Id,
        [Parameter(Mandatory = $true, ParameterSetName = 'LoggedOnUser')]
        [switch]$LoggedOnUser,
        [Parameter(Mandatory = $false, ParameterSetName = 'AllUsers')]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $false, ParameterSetName = 'AllUsers')]
        [int32]$endRow = 100
    )
    Begin {
        If ((Confirm-AutomateNOWSession -IgnoreEmptyDomain -Quiet -DoNotRefresh) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$Instance = $anow_session.Instance
        [hashtable]$parameters = @{}
        If ($LoggedOnUser -eq $true) {
            [string]$command = '/secUser/getUserInfo'
            $parameters.Add('Method', 'GET')
        }
        Else {
            [string]$command = '/secUser/read'
            $parameters.Add('Method', 'POST')
        }
        If ($endRow -lt $startRow) {
            Write-Warning -Message "The endRow must be greater then the startRow"
            Break
        }
        $parameters.Add('Command', $command)
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        $parameters.Add('Instance', $Instance)
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($LoggedOnUser -ne $true) {
            If ($_.Length -gt 0) {
                [string]$id = $_
            }
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            If ($id.Length -gt 0) {
                $BodyMetaData.Add('id', $id )
                [string]$textMatchStyle = 'exactCase'
                $BodyMetaData.Add('_operationId', 'read')
            }
            Else {
                [string]$textMatchStyle = 'exact'
                $BodyMetaData.Add('_componentId', 'SecUserList')
                $BodyMetaData.Add('_startRow', $startRow)
                $BodyMetaData.Add('_endRow', $endRow)
            }
            $BodyMetaData.Add('_operationType', 'fetch')
            $BodyMetaData.Add('_textMatchStyle', $textMatchStyle)
            $BodyMetaData.Add('_dataSource', 'SecUserDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            If ($null -eq $parameters.Body) {
                $parameters.Add('Body', $Body)
            }
            Else {
                $parameters.Body = $Body
            }
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
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
        }
        If ($LoggedOnUser -ne $True) {
            [ANOWUser[]]$Users = ForEach ($User in $results.response.data) {
                [string]$User_Id = $User.Id
                If ($null -eq $User.defaultTimeZone) {
                    [ANOWTimeZone]$defaultTimeZone = $anow_session.server_timezone
                }
                Else {
                    [ANOWTimeZone]$defaultTimeZone = Get-AutomateNOWTimeZone -Id ($User.defaultTimeZone)
                }
                If ($Null -eq $User.defaultTimeZone) {
                    $User | Add-Member -MemberType NoteProperty -Name defaultTimeZone -Value $defaultTimeZone
                }
                Else {
                    $User.defaultTimeZone = $defaultTimeZone
                }
                [ANOWSecurityRole[]]$secRoles2 = ForEach ($secRole in $User.secRoles) {
                    [ANOWDomainRole[]]$domain_roles = $secRole.domainRoles
                    If($User_Id -ne 'Administrator'){
                        $secRole.domainRoles = $domain_roles
                    }
                    $secRole
                }
                $User.secRoles = $secRoles2
                [ANOWUser]$FormattedUser = New-Object -TypeName ANOWUser
                $Error.Clear()
                # Note: I'm not sure why routine this was needed
                Try {
                    ForEach ($Property in ($FormattedUser | Get-Member -MemberType Property | Select-Object -ExpandProperty Name)) {
                        If ($null -eq $User.$Property) {
                            If ($Property -in @('lastAccountExpired')) {
                                $FormattedUser.$Property = Get-Date -Date '1970-01-01'
                            }
                        }
                        Else {
                            $FormattedUser.$Property = $User.$Property
                        }
                    }
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to convert the returned [ANOWUser] object from response data for [$User_id] under Get-AutomateNOWUser due to [$Message]."
                    Break
                }
                If ($FormattedUser -is [ANOWUser]) {
                    Write-Verbose -Message "User $User_id was successfully updated"
                }
                Else {
                    Write-Warning -Message "Somehow the modified [ANOWUser] object under Get-AutomateNOWUser in invalid!"
                    Break
                }
                $FormattedUser
            }
            If ($Users.Count -gt 0) {
                Return $Users
            }
            Else {
                Write-Warning -Message "Somehow there were 0 users returned, this cannot be correct"
                Break
            }
        }
        Else {
            [string]$id = $results.id
            If ($null -ne $results.defaultTimeZone) {
                [ANOWTimeZone]$defaultTimeZone = Get-AutomateNOWTimeZone -Id ($results.defaultTimeZone)
            }
            Else {
                [ANOWTimeZone]$defaultTimeZone = $anow_session.server_timezone
            }
            $results.'defaultTimeZone' = $defaultTimeZone
            $results.'secRoles' = @()
            $Error.Clear()
            If ($LoggedOnUser -eq $true) {
                Try {
                    [ANOWUserInfo]$ANOWUserInfo = $results
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to convert the returned [ANOWUserInfo] object from direct data for [$id] due to [$Message]."
                    Break
                }
                If ($ANOWUserInfo.id.Length -gt 0) {
                    Return $ANOWUserInfo
                }
                Else {
                    Write-Warning -Message "Somehow the [ANOWUser] object appears to be empty"
                    Break
                }
            }
            Else {
                Try {
                    [ANOWUser]$ANOWUser = $results
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Failed to convert the returned [ANOWUser] object from direct data for [$id] due to [$Message]."
                    Break
                }
                If ($ANOWUser.id.Length -gt 0) {
                    Return $ANOWUser
                }
                Else {
                    Write-Warning -Message "Somehow the [ANOWUser] object appears to be empty"
                    Break
                }
            }
        }
    }
    End {

    }
}

Function Set-AutomateNOWUser {
    <#
    .SYNOPSIS
    Changes the settings of a User from an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of a User from an AutomateNOW! instance

    .PARAMETER User
    An [ANOWUser] object representing the User to be changed.

    .PARAMETER skinThemeType
    A string representing the theme. Valid choice are: LIGHT, GRAY, DARK, CONTRAST_ULTRA

    .PARAMETER skinDensityType
    A string representing the theme. Valid choice are: DENSE, COMPACT, STANDARD, EXPANDED, SPACIOUS

    .PARAMETER admin
    A boolean parameter representing administrative privileges. Use this with caution!

    .PARAMETER ResetDefaultTimeZone
    Switch parameter that will blank out the user accounts default timezone.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the extraneous output that this outputs by default

    .INPUTS
    ONLY [ANOWUser] objects are accepted (including from the pipeline)

    .OUTPUTS
    The updated [ANOWUser] object will be returned

    .EXAMPLE
    Get-AutomateNOWUser -Id 'user01' | Set-AutomateNOWUser -skinTheme 'DARK'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    There's at least 2 missing properties: Admin, OAuth_clientid

    This function does not support any roles. It is only to be used for the basic user properties.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWUser]$User,
        [AllowEmptyString()]
        [ValidateLength(0, 255)]
        [Parameter(Mandatory = $false)]
        [string]$FirstName,
        [AllowEmptyString()]
        [ValidateLength(0, 255)]
        [Parameter(Mandatory = $false)]
        [string]$LastName,
        [AllowEmptyString()]
        [ValidateLength(0, 255)]
        [Parameter(Mandatory = $false)]
        [string]$Department,
        [AllowEmptyString()]
        [ValidateLength(0, 255)]
        [Parameter(Mandatory = $false)]
        [string]$Location,
        [ValidateScript({ $_ -match '^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$' })]
        [Parameter(Mandatory = $false, HelpMessage = 'Enter a valid email address')]
        [string]$Email,
        [AllowEmptyString()]
        [ValidateScript({ $_ -match '^[\d]{0,255}$' })]
        [Parameter(Mandatory = $false, HelpMessage = 'Enter numbers only')]
        [string]$PhoneNumber,
        [Parameter(Mandatory = $false)]
        [datetime]$AccountValidUntil,
        [Parameter(Mandatory = $false)]
        [ANOWTimeZone]$DefaultTimeZone,
        [Parameter(Mandatory = $false)]
        [ANOWUser_skinThemeType]$skinThemeType,
        [Parameter(Mandatory = $false)]
        [ANOWUser_skinDensityType]$skinDensityType,
        [Parameter(Mandatory = $false, HelpMessage = 'Set this to true to promote the user to full admin privileges')]
        [boolean]$admin,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$ResetDefaultTimeZone
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/secUser/update'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess("$($User.id)")) -eq $true) {
            If ($_.id.Length -gt 0) {
                [string]$User_id = $_.id
            }
            ElseIf ($User.id.Length -gt 0) {
                [string]$User_id = $User.id
            }
            Else {
                [string]$User_id = $Id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [ANOWUser]$User = Get-AutomateNOWUser -Id $User_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWUser failed to check if the User [$User_id] already existed under Set-AutomateNOWUser due to [$Message]."
                Break
            }
            [boolean]$User_exists = ($User.Id.Length -gt 0)
            If ($User_exists -eq $false) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a User named [$User_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [boolean]$account_has_changed = $false
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $User.id
            If ($FirstName.Length -gt 0) {
                $BodyMetaData.'firstName' = $FirstName
                $BodyMetaData.'firstLastName' = ($FirstName + ' ' + $User.LastName)
                [boolean]$account_has_changed = $true
            }
            If ($LastName.Length -gt 0) {
                $BodyMetaData.'lastName' = $LastName
                $BodyMetaData.'firstLastName' = ($User.FirstName + ' ' + $LastName)
                [boolean]$account_has_changed = $true
            }
            If ($FirstName.Length -gt 0 -and $LastName.Length -gt 0) {
                $BodyMetaData.'firstLastName' = ($FirstName + ' ' + $LastName)
            }
            If ($Department.Length -gt 0) {
                $BodyMetaData.'department' = $Department
                [boolean]$account_has_changed = $true
            }
            If ($Location.Length -gt 0) {
                $BodyMetaData.'location' = $Location
                [boolean]$account_has_changed = $true
            }
            If ($Email.Length -gt 0) {
                $BodyMetaData.'email' = $Email
                [boolean]$account_has_changed = $true
            }
            If ($PhoneNumber.Length -gt 0) {
                $BodyMetaData.'phone' = $PhoneNumber
                [boolean]$account_has_changed = $true
            }
            If ($null -ne $AccountValidUntil) {
                $BodyMetaData.'accountValidUntil' = Get-Date -Date $AccountValidUntil -Format 'yyyy-MM-ddTHH:mm:ss.fff'
                [boolean]$account_has_changed = $true
            }

            If ($null -ne $DefaultTimeZone) {
                $BodyMetaData.'defaultTimeZone' = ($DefaultTimeZone.Id)
                [boolean]$account_has_changed = $true
            }
            If ($ResetDefaultTimeZone -eq $true) {
                $BodyMetaData.'defaultTimeZone' = ''
                [boolean]$account_has_changed = $true
            }

            If ($skinThemetype.Length -gt 0) {
                $BodyMetaData.'skinThemeType' = $skinThemeType
                [boolean]$account_has_changed = $true
            }
            If ($skinThemetype.Length -gt 0) {
                $BodyMetaData.'skinDensityType' = $skinDensityType
                [boolean]$account_has_changed = $true
            }
            If ($account_has_changed -eq $false) {
                Write-Warning -Message "There must be at least 1 change to use Set-AutomateNOWUser"
                Break
            }
            $BodyMetaData.'createdBy' = $User.createdBy
            $BodyMetaData.'lastAccountExpired' = $User.lastAccountExpired
            $BodyMetaData.'languageCode' = $User.languageCode
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_oldValues' = $User.CreateOldValues()
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_componentId' = 'SecUserEditForm'
            $BodyMetaData.'_dataSource' = 'SecUserDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$User_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            [PSCustomObject]$results_response_data = $results.response.data
            If ($null -eq $results_response_data.defaultTimeZone) {
                [ANOWTimeZone]$defaultTimeZone = $anow_session.server_timezone
            }
            Else {
                [ANOWTimeZone]$defaultTimeZone = Get-AutomateNOWTimeZone -Id ($results_response_data.defaultTimeZone)
                [PSCustomObject]$results_response_data = $results_response_data | Select-Object -ExcludeProperty defaultTimeZone
            }
            $Error.Clear()
            Try {
                [PSCustomObject]$results_response_data | Add-Member -MemberType NoteProperty -Name defaultTimeZone -Value $defaultTimeZone
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Add-Member failed to add the defaultTimeZone member under Set-AutomateNOWUser due to [$Message]."
                Break
            }
            [ANOWUser]$ModifiedUser = New-Object -TypeName ANOWUser
            $Error.Clear()
            # Note: I'm not sure why routine this was needed
            Try {
                ForEach ($Property in ($ModifiedUser | Get-Member -MemberType Property | Select-Object -ExpandProperty Name)) {
                    $ModifiedUser.$Property = $results_response_data.$Property
                }
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to convert the returned [ANOWUser] object from response data for [$User_id] under Set-AutomateNOWUser due to [$Message]."
                Break
            }
            If ($ModifiedUser -is [ANOWUser]) {
                Write-Verbose -Message "User $User_id was successfully updated"
            }
            Else {
                Write-Warning -Message "Somehow the modified [ANOWUser] object in invalid!"
                Break
            }
            If ($Quiet -ne $true) {
                Return $ModifiedUser
            }
        }
    }
    End {
    }
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

    .PARAMETER Type
    Optional string containing the type of workflow. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

    .PARAMETER startRow
    Integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 100.

    .INPUTS
    Accepts a string representing the simple id of the workflow from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWWorkflow] class objects

    .EXAMPLE
    Get-AutomateNOWWorkflowTempate

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'workflow_01'

    .EXAMPLE
    Get-AutomateNOWWorkflow -WorkflowType TRIGGER

    .EXAMPLE
    @( 'workflow_01', 'workflow_02' ) | Get-AutomateNOWWorkflow

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the workflows.

    #>
    #[OutputType([ANOWWorkflow[]])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflow_workflowType]$Type,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'id'
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
            Break
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Method', 'POST')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
        $Body.'_constructor' = 'AdvancedCriteria'
        $Body.'operator' = 'and'
        If ($_.Length -gt 0 -or $Id.Length -gt 0) {
            If ($_.Length -gt 0 ) {
                $Body.'id' = $_
            }
            Else {
                $Body.'id' = $Id
            }
            $Body.'_operationId' = 'ProcessingDataSource_fetch'
            $Body.'criteria1' = '{"__normalized":true,"fieldName":"archived","operator":"equals","value":false}'
            $Body.'criteria2' = '{"fieldName":"parent","value":"' + $Id + '","operator":"equals"}'
        }
        Else {
            $Body.'criteria1' = '{"fieldName":"archived","operator":"equals","value":false}'
            $Body.'criteria2' = '{"fieldName":"isProcessing","operator":"equals","value":true}'
            If (($Type.Length -gt 0)) {
                $Body.'criteria3' = '{"fieldName":"itemType","operator":"equals","value":"' + $Type + '"}'
            }
            Else {
                $Error.Clear()
                Try {
                    [string]$all_workflow_types = ([ANOWWorkflow_workflowType].GetEnumNames() | ForEach-Object { '"' + $_ + '"' }) -join ','
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWWorkflow was unable to enumerate the object class [ANOWWorkflow_workflowType] due to [$Message]."
                    Break
                }
                $Body.'criteria3' = '{"fieldName":"itemType","operator":"inSet","value":[' + $all_workflow_types + ']}'
            }
            $Body.'_startRow' = $startRow
            $Body.'_endRow' = $endRow
            $Body.'_sortBy' = $sortBy
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_textMatchStyle' = 'substring'
        $Body.'_componentId' = 'ProcessingList'
        $Body.'_dataSource' = 'ProcessingDataSource'
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/processing/read?' + $Body)
        If ($null -eq $parameters["Command"]) {
            $parameters.Add('Command', $command)
        }
        Else {
            $parameters.Command = $command
        }
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
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

    .PARAMETER Workflow
    Mandatory [ANOWWorkflow] object (Use Get-AutomateNOWWorkflow to retrieve them)

    .PARAMETER Type
    Mandatory string containing the type of workflow. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

    .INPUTS
    ONLY [ANOWWorkflow] objects from the pipeline are accepted

    .OUTPUTS
    The [ANOWWorkflow] objects are exported to the local disk in CSV format

    .EXAMPLE
    Get-AutomateNOWWorkflow | Export-AutomateNOWWorkflow -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflow -Type STANDARD | Export-AutomateNOWWorkflow -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01' | Export-AutomateNOWWorkflow -Type FOR_EACH

    .EXAMPLE
    @( 'Workflow01', 'Workflow02', 'Workflow03' ) | Get-AutomateNOWWorkflow | Export-AutomateNOWWorkflow -Type STANDARD

    .EXAMPLE
    Get-AutomateNOWWorkflow | Where-Object { $_.id -like '*MyWorkflow*' } | Export-AutomateNOWWorkflow -Type STANDARD

    .NOTES
	You must present [ANOWWorkflow] objects to the pipeline to use this function.

    The -Type parameter is mandatory here!
    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflow_workflowType]$Type
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
            [ANOWWorkflow]$workflow_ = $_
        }
        $Error.Clear()
        Try {
            $workflow_ | Export-CSV @parameters
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

Function Remove-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Archives a Workflow from an AutomateNOW! instance

    .DESCRIPTION
    Archives a Workflow from an AutomateNOW! instance

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow Template to be archived.

    .PARAMETER Force
    Force the archiving without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Archives a single workflow

    Get-AutomateNOWWorkflow -Id 'Workflow01' | Remove-AutomateNOWWorkflow 

    .EXAMPLE
    Archives a series of workflows without prompting

    @( 'Workflow1', 'Workflow2', 'Workflow3') | Remove-AutomateNOWWorkflow -Force

    .EXAMPLE
    Archives all for_each workflows

    Get-AutomateNOWWorkflow | ? { $_.serverWorkflowType -eq 'FOR_EACH' } | Remove-AutomateNOWWorkflow 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The term Remove and Archive are synonymous from the API perspective. In ANOW parlance, Templates are 'Deleted' and Workflows are 'Archived'.
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
        [string]$command = '/processing/delete'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Workflow_id = $_.id
        }
        ElseIf ($Workflow.id.Length -gt 0) {
            [string]$Workflow_id = $Workflow.id
        }
        Else {
            [string]$Workflow_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($Workflow_id, 'Archive')) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$Body = [System.Collections.Specialized.OrderedDictionary]@{}
            $Body.Add('id', $Workflow_id)
            $Body.Add('_operationType', 'remove')
            $Body.Add('_operationId', 'delete')
            $Body.Add('_textMatchStyle', 'exact')
            $Body.Add('_dataSource', 'ProcessingDataSource')
            $Body.Add('isc_metaDataPrefix', '_')
            $Body.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $Body
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
                Break
            }
            Write-Verbose -Message "Workflow $Workflow_id successfully archived"
        }
    }
    End {

    }
}

Function Restart-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Restarts a Workflow from an AutomateNOW! instance

    .DESCRIPTION
    Restarts a Workflow from an AutomateNOW! instance

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow to be restarted

    .PARAMETER Quiet
    Switch parameter to omit the informational message if the Restart was successful

    .PARAMETER Force
    Force the restart without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    An informational message is written to the screen unless -Quiet is used

    .EXAMPLE
    Restarts a single Workflow

    Get-AutomateNOWWorkflow -Id 'Workflow_01' | Restart-AutomateNOWWorkflow

    .EXAMPLE
    Quietly restarts multiple Workflows

    @('Workflow1', 'Workflow2') | Get-AutomateNOWWorkflow | Restart-AutomateNOWWorkflow -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/restart'
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
            If ($_.id -gt 0) {
                [int64]$Workflow_id = $_.id
            }
            Else {
                [int64]$Workflow_id = $Workflow.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWWorkflow]$current_workflow = Get-AutomateNOWWorkflow -Id $Workflow_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkflow failed to check if the Workflow [$Workflow_id] existed under Restart-AutomateNOWWorkflow due to [$Message]."
                Break
            }
            If ($current_workflow.id.length -eq 0) {
                Write-Warning "The Workflow you specified does not seem to exist (Restart-AutomateNOWWorkflow)"
                Break
            }
            [string]$current_workflow_status = $current_workflow.processingStatus
            If ($current_workflow_status -notin [ANOWWorkflow_processingStatus].GetEnumNames()) {
                Write-Warning -Message "Somehow the processing status of the Workflow [$Workflow_id] cannot be read (Restart-AutomateNOWWorkflow)"
                Break
            }
            If ($current_workflow_status -notin @('COMPLETED', 'FAILED')) {
                Write-Warning -Message "[$Workflow_id] cannot be restarted as it currently in [$current_workflow_status] processing status"
                Break
            }
            Else {
                Write-Verbose -Message "[$Workflow_id] had a status of $current_workflow_status"
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('restartType', 'RESTART_FROM_BEGINNING')
            $BodyMetaData.Add('restartFailedOnly', 'false' ) # Note this value is currently not available in the console
            $BodyMetaData.Add('id', $Workflow_id )
            $BodyMetaData.Add('_operationType', 'custom')
            $BodyMetaData.Add('_operationId', 'restart')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            If ($Quiet -ne $true) {
                Write-Information -MessageData "Workflow $Workflow_id was successfully restarted"
            }
        }
    }
    End {

    }
}

Function Stop-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Stops a Workflow on an AutomateNOW! instance

    .DESCRIPTION
    Stops a Workflow on an AutomateNOW! instance with either a soft or hard stop

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow to be stopped

    .PARAMETER Kill
    Switch parameter to indicate 'Hard kill' of the Workflow. You must include either this parameter or -Abort

    .PARAMETER Abort
    Switch parameter to indicate 'Soft abort' of the Workflow. You must include either this parameter or -Kill

    .PARAMETER Quiet
    Switch parameter to omit the informational message if the stop was successful

    .PARAMETER Force
    Force the stoppage without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    An informational message is written to the screen unless -Quiet is used

    .EXAMPLE
    Stops a single Workflow

    Get-AutomateNOWWorkflow -Id 'Workflow_01' | Stop-AutomateNOWWorkflow -Abort

    .EXAMPLE
    Quietly stops multiple Workflows

    @('Workflow1', 'Workflow2') | Get-AutomateNOWWorkflow | Stop-AutomateNOWWorkflow -Kill -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $true, ParameterSetName = 'Kill')]
        [switch]$Kill,
        [Parameter(Mandatory = $true, ParameterSetName = 'Abort')]
        [switch]$Abort,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($Kill -eq $true) {
            [string]$operation_id = 'kill'
        }
        Else {
            [string]$operation_id = 'abort'
        }
        [string]$command = ('/processing/' + $operation_id)
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
            If ($_.id -gt 0) {
                [int64]$Workflow_id = $_.id
            }
            Else {
                [int64]$Workflow_id = $Workflow.id
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWWorkflow]$current_workflow = Get-AutomateNOWWorkflow -Id $Workflow_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkflow failed to check if the Workflow [$Workflow_id] existed under Restart-AutomateNOWWorkflow due to [$Message]."
                Break
            }
            If ($current_workflow.id.length -eq 0) {
                Write-Warning "The Workflow you specified does not seem to exist (Stop-AutomateNOWWorkflow)"
                Break
            }
            [string]$current_workflow_status = $current_workflow.processingStatus
            If ($current_workflow_status -notin [ANOWWorkflow_processingStatus].GetEnumNames()) {
                Write-Warning -Message "Somehow the processing status of the Workflow [$Workflow_id] cannot be read (Stop-AutomateNOWWorkflow)"
                Break
            }
            If ($current_workflow_status -in @('COMPLETED', 'FAILED')) {
                Write-Warning -Message "[$Workflow_id] cannot be stopped as it currently in [$current_workflow_status] processing status"
                Break
            }
            Else {
                Write-Verbose -Message "[$Workflow_id] had a status of $current_workflow_status"
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Workflow_id )
            $BodyMetaData.Add('_operationType', 'custom')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
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
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            If ($Quiet -ne $true) {
                Write-Information -MessageData "Workflow $Workflow_id was successfully stopped"
            }
        }
    }
    End {

    }
}

Function Resume-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Resumes a Workflow that is on hold (suspended) on an AutomateNOW! instance

    .DESCRIPTION
    Resumes a Workflow that is on hold (suspended) on an AutomateNOW! instance

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow to be resumed

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    A verbose information message will be sent indicating success

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01' | Resume-AutomateNOWWorkflow -Force

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01', 'Workflow02' | Resume-AutomateNOWWorkflow 

    .EXAMPLE
    @( 'Workflow1', 'Workflow2', 'Workflow3') | Resume-AutomateNOWWorkflow 

    .EXAMPLE
    Get-AutomateNOWWorkflow | ? { $_.serverWorkflowType -eq 'LINUX' } | Resume-AutomateNOWWorkflow

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/resume'
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
                [int64]$Workflow_id = $_.id
            }
            ElseIf ($Workflow.id.Length -gt 0) {
                [int64]$Workflow_id = $Workflow.id
            }
            Else {
                Write-Warning -Message "Unable to determine the Id of the Workflow."
                Break
            }
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWWorkflow]$current_workflow = Get-AutomateNOWWorkflow -Id $Workflow_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkflow failed to check if the Workflow [$Workflow_id] existed under Resume-AutomateNOWWorkflow due to [$Message]."
                Break
            }
            If ($current_workflow.id.length -eq 0) {
                Write-Warning "The Workflow you specified does not seem to exist (Resume-AutomateNOWWorkflow)"
                Break
            }
            [boolean]$current_workflow_hold_status = $current_workflow.onHold
            If ($current_workflow_hold_status -eq $false) {
                Write-Warning -Message "[$Workflow_id] cannot be resumed as it is not currently suspended (on hold)"
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Workflow_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'resume')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Workflow $Workflow_id successfully resumed"
        }
    }
    End {

    }
}

Function Suspend-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Places a Workflow on hold (suspend) from execution on an AutomateNOW! instance

    .DESCRIPTION
    Places a Workflow on hold (suspend) from execution on an AutomateNOW! instance

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow to be suspended (placed on hold)

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    A verbose information message will be sent indicating success

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01' | Suspend-AutomateNOWWorkflow -Force

    .EXAMPLE
    Get-AutomateNOWWorkflow -Id 'Workflow01', 'Workflow02' | Suspend-AutomateNOWWorkflow 

    .EXAMPLE
    @( 'Workflow1', 'Workflow2', 'Workflow3') | Suspend-AutomateNOWWorkflow 

    .EXAMPLE
    Get-AutomateNOWWorkflow | ? { $_.serverWorkflowType -eq 'LINUX' } | Suspend-AutomateNOWWorkflow 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/hold'
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
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
            $Error.Clear()
            Try {
                [ANOWWorkflow]$current_workflow = Get-AutomateNOWWorkflow -Id $Workflow_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkflow failed to check if the Workflow [$Workflow_id] existed under Resume-AutomateNOWWorkflow due to [$Message]."
                Break
            }
            If ($current_workflow.id.length -eq 0) {
                Write-Warning "The Workflow you specified does not seem to exist (Resume-AutomateNOWWorkflow)"
                Break
            }
            [boolean]$current_workflow_hold_status = $current_workflow.onHold
            If ($current_workflow_hold_status -eq $true) {
                Write-Warning -Message "[$Workflow_id] cannot be suspended (placed on hold) as it is already suspended (on hold)"
                Break
            }
            ## End warning ##
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Workflow_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'hold')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Workflow $Workflow_id successfully suspended (placed on hold)"
        }
    }
    End {

    }
}

Function Skip-AutomateNOWWorkflow {
    <#
    .SYNOPSIS
    Sets or unsets the Skip flag on a Workflow on an AutomateNOW! instance

    .DESCRIPTION
    Sets or unsets the Skip flag on a Workflow on an AutomateNOW! instance

    .PARAMETER Workflow
    An [ANOWWorkflow] object representing the Workflow to be set to skipped or unskipped

    .PARAMETER UnSkip
    Removes the skip flag from an [ANOWWorkflow] object. This is the opposite of the default behavior.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWWorkflow] object

    .INPUTS
    ONLY [ANOWWorkflow] objects are accepted (including from the pipeline)

    .OUTPUTS
    The skipped/unskipped [ANOWWorkflow] object will be returned

    .EXAMPLE
    Sets a Workflow to Skip (bypass)

    Get-AutomateNOWWorkflow -Id 'Workflow01' | Skip-AutomateNOWWorkflow -Force

    .EXAMPLE
    Unsets the Skip (bypass) flag on a Workflow

    Get-AutomateNOWWorkflow | Skip-AutomateNOWWorkflow -UnSkip

    .EXAMPLE
    Sets an array of Workflows to Skip (bypass)

    @( 1234567, 2345678, 34567890) | Skip-AutomateNOWWorkflow 

    .EXAMPLE
    Get-AutomateNOWWorkflow | ? { $_.workflowType -eq 'FOR_EACH' } | Skip-AutomateNOWWorkflow -UnSkip -Force -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflow]$Workflow,
        [Parameter(Mandatory = $false)]
        [switch]$UnSkip,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnSkip -ne $True) {
            [string]$skip_flag_status = 'On'
            [string]$operation_id = 'passByOn'
            [string]$ProcessDescription = 'Add the Skip flag'
        }
        Else {
            [string]$skip_flag_status = 'Off'
            [string]$operation_id = 'passByOff'
            [string]$ProcessDescription = 'Remove the Skip flag'
        }
        [string]$command = ('/processing/' + $operation_id)
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$Workflow_id = $_.id
        }
        ElseIf ($Workflow.id.Length -gt 0) {
            [string]$Workflow_id = $Workflow.id
        }
        Else {
            [string]$Workflow_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($Workflow_id, $ProcessDescription)) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $Workflow_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
            $Error.Clear()
            Try {
                [PSCustomObject]$results = Invoke-AutomateNOWAPI @parameters
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$Workflow_id] due to [$Message]."
                Break
            }
            [int32]$response_code = $results.response.status
            If ($response_code -ne 0) {
                [string]$full_response_display = $results.response | ConvertTo-Json -Compress
                Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
            }
            Write-Verbose -Message "Successfully set the skip flag to [$skip_flag_status] on [$Workflow_id]"
        }
    }
    End {

    }
}

#endregion

#Region - WorkflowTemplates

Function Get-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Gets the Workflow Templates from an AutomateNOW! instance

    .DESCRIPTION
    Gets the Workflow Templates from an AutomateNOW! instance

    .PARAMETER Id
    Mandatory string containing the simple id of the Workflow Template to fetch or you can pipeline a series of simple id strings. You may not enter an array here.

    .PARAMETER Type
    Mandatory string containing the type of Workflow Template. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

    .PARAMETER sortBy
    Optional string parameter to sort the results by. Valid choices are: id {To be continued...}

    .PARAMETER Descending
    Optional switch parameter to sort in descending order

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the Workflow Template from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWWorkflowTemplate] class objects

    .EXAMPLE
    Get-AutomateNOWWorkflowTempate

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'workflow_01'

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Type FOR_EACH

    .EXAMPLE
    @( 'workflow_01', 'workflow_02' ) | Get-AutomateNOWWorkflowTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the workflows.

    #>
    [OutputType([ANOWWorkflowTemplate[]])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflowTemplate_workflowType]$Type,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'processingType'
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($endRow -le $startRow) {
            Write-Warning -Message "The endRow must be greater than the startRow. Please try again."
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
        $Body.'_startRow' = $startRow
        $Body.'_endRow' = $endRow
        $Body.'_textMatchStyle' = 'exact'
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
        Else {
            If ( $Type.length -eq 0) {
                [string]$fieldName = 'processingType'
                [string]$value = 'WORKFLOW'
            }
            Else {
                [string]$fieldName = 'workflowType'
                [string]$value = $Type
            }
            $Body.'criteria' = ('{"fieldName":"' + $fieldName + '","operator":"equals","value":"' + $value + '"}')
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
            [ANOWWorkflowTemplate[]]$WorkflowTemplates = $results.response.data
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Failed to parse the response into a series of [ANOWWorkflowTemplate] objects due to [$Message]."
            Break
        }
        If ($WorkflowTemplates.Count -gt 0) {
            If ($WorkflowTemplates.Count -eq 1 -and $WorkflowTemplates.processingType -ne 'WORKFLOW') {
                [string]$processingType = $WorkflowTemplates.processingType
                If ($processingType -eq 'TASK') {
                    Write-Warning -Message "$Id is actually a task template. Please use Get-AutomateNOWTaskTemplate to retrieve this item."
                }
                Else {
                    Write-Warning -Message "$Id is not actually a workflow template, it is a $processingType template."
                }
                Break
            }
            Return $WorkflowTemplates
        }
    }
    End {

    }
}

Function Set-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Changes the settings of a Workflow Template on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of a Workflow Template on an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be changed.

    .PARAMETER Description
    Optional description of the Workflow Template (may not exceed 255 characters).

    .PARAMETER Workspace
    A string representing the name of the Workspace you wish to move this Workflow Template into.

    .PARAMETER UnsetWorkspace
    A switch parameter that will move the Workflow Template out of its current Workspace.

    .PARAMETER Folder
    A string representing the name of the Folder to move the Workflow Template into.

    .PARAMETER UnsetFolder
    A switch parameter that will move the Workflow Template out of its current folder.

    .PARAMETER Tags
    Optional array of strings representing the Tags to include with this object.

    .PARAMETER UnsetTags
    A switch parameter that will the Tags from the Workflow Template

    .PARAMETER Title
    A string representing the "alias" of the Workflow Template (this property needs a better explanation)

    .PARAMETER ResultMapping
    An [ResultMapping] object representing the Result Mapping object to set on the Workflow Template.

    .PARAMETER UnsetResultMapping
    A switch parameter that will remove the Result Mapping assignment from the Workflow Template.

    .PARAMETER Calendar
    A [ANOWCalendar] object representing the Calendar object to set on the Workflow Template.

    .PARAMETER UnsetCalendar
    A switch parameter that will remove the Calendar assignment from the Workflow Template.

    .PARAMETER Approval
    A [ANOWApproval] object representing the Approval object to set on the Workflow Template.

    .PARAMETER UnsetApproval
    A switch parameter that will remove the Approval assignment from the Workflow Template.

    .PARAMETER Weight
    An integer representing a logical measure of resources required to process the item by the Server Node. Each Server Node has [a] maximum weight capacity[.] Weight determines [the] number of parallel processes that can run simultaneously. Default processing Weight is 1. Minimal Weight is 0.

    .PARAMETER Priority
    An integer representing the items priority which determines the order when queuing for resources (Stock and Locks) and [for] being executed by Server Nodes. Default Priority is 0. Minimal Priority is 0.

    .PARAMETER Owner
    A string which appears to represent the user who owns the object. In practice, it is just a string. This particular property does not appear to be explained anywhere in the documentation.

    .PARAMETER LazyLoad
    A boolean to enable the Workflow Template on Lazy Load status. You must specify $true or $false here.

    .PARAMETER OnHold
    A boolean to put the Workflow Template on Hold status. You must specify $true or $false here. When $true, it's the same as the Suspend-AutomateNOWWorkflowTemplate function. When $false, Resume-AutomateNOWWorkflowTemplate function.

    .PARAMETER Skip
    A boolean to put the Workflow Template on Skip status. You must specify $true or $false here. When $true, it's the same as the Skip-AutomateNOWWorkflowTemplate function. When $false, Skip-AutomateNOWWorkflowTemplate with -UnSkip parameter.

    .PARAMETER AutoArchive
    A boolean that causes the Workflows from this Workflow Template to be archived immediately after execution. You must specify $true or $false here.

    .PARAMETER PassResources
    A boolean that indicates if the Workflow Template should pass its Resources to its children.

    .PARAMETER PassActions
    A boolean that indicates if the Workflow Template should pass its Actions to its children.

    .PARAMETER KeepResources
    A boolean that indicates if the Workflow Template should keep its Resources (Stocks and Locks) even if it fails to execute.

    .PARAMETER UseScripts
    A boolean that indicates if the Workflows from this Workflow Template should ?

    .PARAMETER EagerScriptExecution
    A boolean that indicates if the scripts from the Workflows from this Workflow Template should use "Eager" load strategy. In orderto use this parameter, you must include -UseScripts $true.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWWorkflowTemplate] object will be returned

    .EXAMPLE
    $workflow_template = Get-AutomateNOWWorkflowTemplate -Id 'workflow_01'
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Description 'Description!' -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetDescription -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Title 'title!' -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetTags -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Tags 'Tag1' -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetFolder -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Folder 'Folder1' -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -title 'Title1' -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -ResultMapping (Get-AutomateNOWResultMapping -Id 'result_mapping1') -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetResultMapping -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Calendar (Get-AutomateNOWCalendar -Id 'calendar1') -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetCalendar -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Approval (Get-AutomateNOWApproval -Id 'approval1') -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UnsetApproval -Force
    Set-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -Priority 1 -Weight 1 -LazyLoad $true -OnHold $true -Skip $true -AutoArchive $true -PassResources $true -PassActions $true -KeepREsources $true -UseScripts $true -EagerScriptExecution $true -Owner 'owner' -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.
    #>
    [Cmdletbinding(SupportsShouldProcess, DefaultParameterSetName = 'Default', ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false, ParameterSetName = 'SetDescription')]
        [string]$Description,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetDescription')]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetWorkspace')]
        [string]$Workspace,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetWorkspace')]
        [switch]$UnsetWorkspace,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetFolder')]
        [string]$Folder,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetFolder')]
        [switch]$UnsetFolder,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTags')]
        [string[]]$Tags,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTags')]
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTitle')]
        [string]$Title,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTitle')]
        [switch]$UnsetTitle,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetResultMapping')]
        [ANOWResultMapping]$ResultMapping,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetResultMapping')]
        [switch]$UnsetResultMapping,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetCalendar')]
        [ANOWCalendar]$Calendar,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetCalendar')]
        [switch]$UnsetCalendar,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetApproval')]
        [ANOWApproval]$Approval,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetApproval')]
        [switch]$UnsetApproval,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [int32]$Priority,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [int32]$Weight,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$LazyLoad,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$OnHold,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$Skip,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$AutoArchive,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$PassResources,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$PassActions,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$KeepResources,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$UseScripts,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [boolean]$EagerScriptExecution,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string]$Owner,
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnsetFolder -eq $true -or $Folder.Length -gt 0) {
            [string]$command = '/processingTemplate/setFolder'
            [string]$operationId = 'setFolder'
        }
        Else {
            [string]$command = '/processingTemplate/update'
            [string]$componentId = 'ProcessingTemplateValuesManager'
        }
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
        If ($Description.Length -gt 0 -and $UnsetDescription -eq $true) {
            Write-Warning -Message 'You cannot set the Description and unset it at the same time. Please choose one or the other.'
            Break
        }
        If ($Title.Length -gt 0 -and $UnsetTitle -eq $true) {
            Write-Warning -Message 'You cannot set the Title and unset it at the same time. Please choose one or the other.'
            Break
        }
        If ($EagerScriptExecution -eq $true -and $UseScripts -ne $true) {
            Write-Warning -Message 'To use -EagerScriptExecution, you must include -UseScripts $true'
            Break
        }
        If ($UnsetWorkspace -eq $true -and $Workspace.Length -gt 0) {
            Write-Warning -Message "You cannot set the Workspace and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($UnsetFolder -eq $true -and $Folder.Length -gt 0) {
            Write-Warning -Message "You cannot set the Folder and unset it at the same time. Please choose one or the other."
            Exit
        }
        If ($Tags.count -gt 0 -and $UnsetTags -eq $true) {
            Write-Warning -Message "You cannot set the tags and unset them at the same time. Please choose one or the other."
        }
        If ($UnsetApproval -eq $true -and $Approval.id.Length -gt 0) {
            Write-Warning -Message "You cannot set the Approval and unset it at the same time. Please choose one or the other."
            Exit
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
            ## Begin warning ##
            ## Do not tamper with this below code which makes sure that the object exists before attempting to change it.
            $Error.Clear()
            Try {
                [boolean]$WorkflowTemplate_exists = ($null -eq (Get-AutomateNOWWorkflowTemplate -Id $WorkflowTemplate_id))
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the Workflow Template [$WorkflowTemplate_id] already existed due to [$Message]."
                Break
            }
            If ($WorkflowTemplate_exists -eq $true) {
                [string]$current_domain = $anow_session.header.domain
                Write-Warning "There is not a Workflow Template named [$WorkflowTemplate_id] in the [$current_domain]. Please check into this."
                Break
            }
            ## End warning ##
            [System.Collections.ArrayList]$include_properties = [System.Collections.ArrayList]@()
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $WorkflowTemplate_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($UnsetDescription -eq $true) {
                $BodyMetaData.'description' = $null
                $include_properties += 'description'
            }
            If ($Workspace.Length -gt 0) {
                $Error.Clear()
                Try {
                    [ANOWWorkspace]$workspace_object = Get-AutomateNOWWorkspace -Id $Workspace
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWWorkspace failed to confirm that the workspace [$Workspace] actually existed while running under Set-AutomateNOWWorkflowTemplate due to [$Message]"
                    Break
                }
                If ($workspace_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWWorkspace failed to locate the Workspace [$Workspace] running under Set-AutomateNOWWorkflowTemplate. Please check again."
                    Break
                }
                [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding workspace $workspace_display to [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'workspace' = $Workspace
                $include_properties += 'workspace'
            }
            ElseIf ($UnsetWorkspace -eq $true) {
                [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWWorkflowTemplate] [$WorkflowTemplate_id] from Workspace $workspace_display"
                $BodyMetaData.'workspace' = $null
                $include_properties += 'workspace'
            }
            If ($Folder.Length -gt 0) {
                $Error.Clear()
                Try {
                    [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the Folder [$Folder] actually existed while running under Set-AutomateNOWWorkflowTemplate due to [$Message]"
                    Break
                }
                If ($folder_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] running under Set-AutomateNOWWorkflowTemplate. Please check again."
                    Break
                }
                [string]$folder_display = $folder_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Folder $folder_display to [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'folder' = $Folder
                $include_properties += 'folder'
            }
            ElseIf ($UnsetFolder -eq $true) {
                [string]$folder_display = $folder_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWWorkflowTemplate] [$WorkflowTemplate_id] from Folder $folder_display"
                $BodyMetaData.'folder' = $null
                $include_properties += 'folder'
            }
            If ($Tags.Count -gt 0) {
                [int32]$total_tags = $Tags.Count
                [int32]$current_tag = 1
                ForEach ($tag_id in $Tags) {
                    $Error.Clear()
                    Try {
                        [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under New-AutomateNOWWorkflowTemplate due to [$message]"
                        Break
                    }
                    If ($tag_object.simpleId.length -eq 0) {
                        Throw "New-AutomateNOWWorkflowTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                        Break
                    }
                    [string]$tag_display = $tag_object | ConvertTo-Json -Compress
                    Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
                    [string]$tag_name_sequence = ('tags' + $current_tag)
                    $BodyMetaData.Add($tag_name_sequence, $tag_id)
                    $include_properties += $tag_name_sequence
                    $current_tag++
                }
            }
            ElseIf ($UnsetTags -eq $true) {
                [string]$tags_display = ($Calendar.tags) | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing tags [$tags_display] from [$WorkflowTemplate_id]"
                $BodyMetaData.'tags' = $null
                $include_properties += 'tags'
            }
            If ($Title.Length -gt 0) {
                $BodyMetaData.'title' = $Title
            }
            ElseIf ( $UnsetTitle -eq $true) {
                $BodyMetaData.'title' = $null
            }
            If ($ResultMapping.simpleId.Length -gt 0) {
                [string]$ResultMapping_id = $ResultMapping.simpleId
                $Error.Clear()
                Try {
                    [ANOWResultMapping]$rm_object = Get-AutomateNOWResultMapping -Id $ResultMapping_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWResultMapping failed to confirm that the Result Mapping [$ResultMapping_id] actually existed while running under Set-AutomateNOWWorkflowTemplate due to [$Message]"
                    Break
                }
                If ($rm_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWResultMapping failed to locate the Result Mapping [$ResultMapping_id] running under Set-AutomateNOWWorkflowTemplate. Please check again."
                    Break
                }
                [string]$rm_display = $rm_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding Result Mapping $rm_display to [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'resultMapping' = $ResultMapping_id
                $include_properties += 'resultMapping'
            }
            ElseIf ($UnsetResultMapping -eq $true) {
                [string]$rm_display = $rm_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Removing [ANOWWorkflowTemplate] [$ResultMapping_id] from Result Mapping $rm_display"
                $BodyMetaData.'resultMapping' = $null
                $include_properties += 'resultMapping'
            }
            If ($Calendar.Id.Length -gt 0) {
                [string]$Calendar_id = $Calendar.simpleId
                $Error.Clear()
                Try {
                    [ANOWCalendar]$Calendar_object = Get-AutomateNOWCalendar -Id $Calendar_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWCalendar failed to confirm that the Calendar object [$Calendar_id] actually existed while running under Set-AutomateNOWWorkflowTemplate due to [$Message]"
                    Break
                }
                If ($Calendar_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWCalendar failed to locate the Calendar object [$Calendar_id] running under Set-AutomateNOWWorkflowTemplate. Please check again."
                    Break
                }
                Write-Verbose -Message "Adding Calendar object [$Calendar_id] to [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'calendar' = $Calendar_id
                $include_properties += 'calendar'
            }
            ElseIf ($UnsetCalendar -eq $true) {
                [string]$Calendar_id = $Calendar.simpleId
                Write-Verbose -Message "Removing [ANOWCalendar] [$Calendar_id] from [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'calendar' = $null
                $include_properties += 'calendar'
            }
            If ($Approval.Id.Length -gt 0) {
                [string]$Approval_id = $Approval.simpleId
                $Error.Clear()
                Try {
                    [ANOWApproval]$Approval_object = Get-AutomateNOWApproval -Id $Approval_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWApproval failed to confirm that the Approval object [$Approval_id] actually existed while running under Set-AutomateNOWWorkflowTemplate due to [$Message]"
                    Break
                }
                If ($Approval_object.simpleId.Length -eq 0) {
                    Throw "Get-AutomateNOWApproval failed to locate the Approval object [$Approval_id] running under Set-AutomateNOWWorkflowTemplate. Please check again."
                    Break
                }
                Write-Verbose -Message "Adding Approval object [$Approval_id] to [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'approvalConfiguration' = $Approval_id
                $include_properties += 'approvalConfiguration'
            }
            ElseIf ($UnsetApproval -eq $true) {
                [string]$Approval_id = $Approval.simpleId
                Write-Verbose -Message "Removing [ANOWApproval] [$Approval_id] from [ANOWWorkflowTemplate] [$WorkflowTemplate_id]"
                $BodyMetaData.'approvalConfiguration' = $null
                $include_properties += 'approvalConfiguration'
            }
            If ($Weight -ge 0) {
                $BodyMetaData.'weight' = $Weight
            }
            If ($Priority -ge 0) {
                $BodyMetaData.'priority' = $Priority
            }
            If ($Owner.Length -gt 0) {
                $BodyMetaData.'owner' = $Owner
            }
            If ($LazyLoad -eq $false) {
                $BodyMetaData.'lazyLoad' = 'false'
            }
            ElseIf ($LazyLoad -eq $true) {
                $BodyMetaData.'lazyLoad' = 'true'
            }
            If ($OnHold -eq $false) {
                $BodyMetaData.'onHold' = 'false'
            }
            ElseIf ($OnHold -eq $true) {
                $BodyMetaData.'onHold' = 'true'
            }
            If ($Skip -eq $false) {
                $BodyMetaData.'passBy' = 'false'
            }
            ElseIf ($Skip -eq $true) {
                $BodyMetaData.'passBy' = 'true'
            }
            If ($AutoArchive -eq $false) {
                $BodyMetaData.'autoArchive' = 'false'
            }
            ElseIf ($Skip -eq $true) {
                $BodyMetaData.'autoArchive' = 'true'
            }
            If ($PassResources -eq $false) {
                $BodyMetaData.'passResourceDependenciesToChildren' = 'false'
            }
            ElseIf ($PassResources -eq $true) {
                $BodyMetaData.'passResourceDependenciesToChildren' = 'true'
            }
            If ($PassActions -eq $false) {
                $BodyMetaData.'passActionsToChildren' = 'false'
            }
            ElseIf ($PassActions -eq $true) {
                $BodyMetaData.'passActionsToChildren' = 'true'
            }
            If ($KeepResources -eq $false) {
                $BodyMetaData.'keepResourcesOnFailure' = 'false'
            }
            ElseIf ($KeepResources -eq $true) {
                $BodyMetaData.'keepResourcesOnFailure' = 'true'
            }
            If ($UseScripts -eq $false) {
                $BodyMetaData.'useScripts' = 'false'
            }
            ElseIf ($UseScripts -eq $true) {
                $BodyMetaData.'useScripts' = 'true'
            }
            If ($EagerScriptExecution -eq $false) {
                $BodyMetaData.'eagerScriptExecution' = 'false'
            }
            ElseIf ($EagerScriptExecution -eq $true) {
                $BodyMetaData.'eagerScriptExecution' = 'true'
            }
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_oldValues' = $WorkflowTemplate.CreateOldValues()
            If ($componentId.Length -gt 0) {
                $BodyMetaData.'_componentId' = $componentId
            }
            If ($operationId.Length -gt 0) {
                $BodyMetaData.'_operationId' = $operationId
            }
            $BodyMetaData.'_dataSource' = 'ProcessingTemplateDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties $include_properties
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
                If ($null -eq $results.response.status) {
                    Write-Warning -Message "Received an empty response when invoking the [$command] endpoint. Please look into this."
                    Break
                }
                Else {
                    [string]$results_response = $results.response
                    Write-Warning -Message "Received status code [$response_code] instead of 0. Something went wrong. Here's the full response: $results_response"
                    Break
                }
            }
            $Error.Clear()
            Try {
                [ANOWWorkflowTemplate]$UpdatedWorkflowTemplate = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to parse the response into a [ANOWWorkflowTemplate] object (under Set-AutomateNOWWorkflowTemplate) due to [$Message]."
                Break
            }
            If ($UpdatedWorkflowTemplate.id -eq $WorkflowTemplate_id) {
                Write-Verbose -Message "Workflow Template $WorkflowTemplate_id was successfully updated"
                Return $UpdatedWorkflowTemplate
            }
            Else {
                Write-Warning -Message "Somehow the returned Workflow Template (under Set-AutomateNOWWorkflowTemplate) has an error. Please look into this."
            }
        }
    }
    End {
    }
}

Function Export-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Exports the Workflow Templates from an instance of AutomateNOW!

    .DESCRIPTION
    Exports the Workflow Templates from an instance of AutomateNOW! to a local .csv file

    .PARAMETER WorkflowTemplate
    Mandatory [ANOWWorkflowTemplate] object (Use Get-AutomateNOWWorkflowTemplate to retrieve them)

    .PARAMETER Type
    Mandatory string containing the type of Workflow Template. Valid choices are STANDARD, BROADCAST, FOR_EACH, TIME_SERIES, SWITCH, CYCLE, INFORMATICA

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

    #>

    [Cmdletbinding(DefaultParameterSetName = 'Pipeline')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Pipeline')]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $False)]
        [ANOWWorkflowTemplate_workflowType]$Type
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
            [ANOWWorkflowTemplate]$WorkflowTemplate = $_
        }
        $Error.Clear()
        Try {
            $WorkflowTemplate | Export-CSV @parameters
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
    Creates a Workflow Template within an AutomateNOW! instance

    .DESCRIPTION
    Creates a Workflow Template within an AutomateNOW! instance and returns back the newly created [ANOWWorkflowTemplate] object

    .PARAMETER WorkflowType
    Required type of the Workflow Template.

    .PARAMETER Id
    Mandatory "name" of the Workflow Template. For example: 'WorkflowTemplate1'. This value may not contain the domain in brackets. This is the unique key of this object.

    .PARAMETER Description
    Optional description of the Workflow Template (may not exceed 255 characters).

    .PARAMETER Tags
    Optional array of strings representing the Tags to include with this object.

    .PARAMETER Folder
    Optional string representing the Folder to place this object into.

    .PARAMETER DesignTemplate
    Optional string representing the Design Template to place this object into.

    .PARAMETER Workspace
    Optional string representing the Workspace to place this object into.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Workflow into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWWorkflowTemplate.

    .OUTPUTS
    An [ANOWWorkflowTemplate] object representing the newly created Workflow Template. Use the -Quiet parameter to suppress this.

    .EXAMPLE
    Creates a new "For Each" Workflow Template
    New-AutomateNOWWorkflowTemplate -WorkflowType FOR_EACH -Id 'WorkflowTemplate01' -Description 'Description text' -Tags 'Tag01', 'Tag02' -Folder 'Folder01' -Workspace 'Workspace01' -CodeRepository 'CodeRepository01'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Workflow Template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    #>
    [OutputType([ANOWWorkflowTemplate])]
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ANOWWorkflowTemplate_workflowType]$WorkflowType,
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [ValidateScript({ $_.Length -le 255 })]
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder,
        [Parameter(Mandatory = $false)]
        [string]$DesignTemplate,
        [Parameter(Mandatory = $false)]
        [string]$Workspace,
        [Parameter(Mandatory = $false)]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
        Write-Warning -Message "Somehow there is not a valid token confirmed."
        Break
    }
    ## Begin warning ##
    ## Do not tamper with this below code which makes sure that the object does not previously exist before attempting to create it. This is a critical check with the console handles for you.
    $Error.Clear()
    Try {
        [boolean]$WorkflowTemplate_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $Id))
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the Workflow Template [$Id] already existed due to [$Message]."
        Break
    }
    If ($WorkflowTemplate_exists -eq $true) {
        [string]$current_domain = $anow_session.header.domain
        Write-Warning "There is already a Workflow Template named [$Id] in [$current_domain]. Please check into this."
        Break
    }
    ## End warning ##
    [System.Collections.Specialized.OrderedDictionary]$ANOWWorkflowTemplate = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWWorkFlowTemplate.Add('id', $Id)
    $ANOWWorkflowTemplate.Add('processingType', 'WORKFLOW')
    $ANOWWorkFlowTemplate.Add('workflowType', $Type)
    [string[]]$include_properties = 'id', 'processingType', 'workflowType'
    If ($Description.Length -gt 0) {
        $ANOWWorkflowTemplate.Add('description', $Description)
        $include_properties += 'description'
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] under New-AutomateNOWWorkflowTemplate due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWWorkflowTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWWorkflowTemplate.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] actually existed while running under New-AutomateNOWWorkflowTemplate due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] running under New-AutomateNOWWorkflowTemplate. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWWorkflowTemplate.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($DesignTemplate.Length -gt 0) {
        $ANOWWorkflowTemplate.Add('designTemplate', $DesignTemplate)
        $include_properties += 'designTemplate'
    }
    If ($Workspace.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWWorkspace]$workspace_object = Get-AutomateNOWWorkspace -Id $Workspace
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkspace failed to confirm that the workspace [$Workspace] actually existed while running under New-AutomateNOWWorkflowTemplate due to [$Message]"
            Break
        }
        If ($workspace_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWWorkspace failed to locate the Workspace [$Workspace] running under New-AutomateNOWWorkflowTemplate. Please check again."
            Break
        }
        [string]$workspace_display = $workspace_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding workspace $workspace_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWWorkflowTemplate.Add('workspace', $Workspace)
        $include_properties += 'workspace'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] actually existed while running under New-AutomateNOWWorkflowTemplate due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] running under New-AutomateNOWWorkflowTemplate. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWWorkflowTemplate.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
    }
    [string]$BodyObject = ConvertTo-QueryString -InputObject $ANOWWorkflowTemplate -IncludeProperties $include_properties
    [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
    $BodyMetaData.'_textMatchStyle' = 'exact'
    $BodyMetaData.'_operationType' = 'add'
    $BodyMetaData.'_oldValues' = '{"processingType":"WORKFLOW","workflowType":"' + $Type + '","workspace":null}'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
        Write-Warning -Message "Failed to create Workflow Template [$Id] of type [$Type] due to $results_display. The parameters used: $parameters_display"
        Break
    }
    ElseIf ($null -eq $results.response.status) {
        Write-Warning -Message "Failed to create Workflow Template [$Id] of type [$Type] due to [an empty response]. The parameters used: $parameters_display"
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
        Write-Warning -Message "Somehow the newly created [ANOWWorkflowTemplate] is empty!"
        Break
    }
    $Error.Clear()
    Try {
        [ANOWWorkflowTemplate]$WorkflowTemplate = Get-AutomateNOWWorkflowTemplate -Id $Id
    }
    Catch {
        [string]$Message = $_.Exception.Message
        Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to confirm that the [ANOWWorkflowTemplate] object [$Id] was created due to [$Message]."
        Break
    }
    If ($Quiet -ne $true) {
        Return $WorkflowTemplate
    }
}

Function Remove-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Removes a Workflow Template from an AutomateNOW! instance

    .DESCRIPTION
    Removes a Workflow Template from an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWworkflowTemplate] object representing the Workflow Template to be deleted.

    .PARAMETER Force
    Force the removal without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    None. The status will be written to the console with Write-Verbose.

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'Workflow01' | Remove-AutomateNOWWorkflowTemplate

    .EXAMPLE
    Get-AutomateNOWWorkTemplate -Id 'Workflow01', 'Workflow02' | Remove-AutomateNOWWorkflowTemplate

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
    Copies a Workflow Template from an AutomateNOW! instance

    .DESCRIPTION
    Copies a Workflow Template from an AutomateNOW! instance. AutomateNOW object id can never be changed, but we can copy the object to a new id and it will include all of the items therein.

    .PARAMETER WorkflowTemplate
    Mandatory [ANOWworkflowTemplate] object to be copied.

    .PARAMETER NewId
    Mandatory string indicating the new id or name of the Workflow Template. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

    .PARAMETER UnsetTags
    Optional switch that will purposely omit the previously existing tags on the new copy of the Workflow Template. You can still specify new tags with -Tags but the old previous ones will not be carried over. In the UI, this is accomplished by clicking the existing tags off.

    .PARAMETER NoFolder
    Optional switch that will ensure that the newly created Workflow Template will not be placed in a folder.

    .PARAMETER UnsetDescription
    Optional switch that will ensure that the newly created Workflow Template will not carry over its previous description.

    .PARAMETER Description
    Optional description of the Workflow Template (may not exceed 255 characters). You may send an empty string here to ensure that the description is blanked out. Do not use this parameter if your intention is to keep the description from the previous Workflow Template.

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new Workflow Template. The UnsetTags DOES NOT influence this parameter.

    .PARAMETER Folder
    Optional name of the folder to place the Workflow Template into. The NoFolder parameter overrides this setting.

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

    The new id (name) of the Workflow Template must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.
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
        [switch]$UnsetTags,
        [Parameter(Mandatory = $false)]
        [switch]$UnsetDescription,
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
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the Workflow Template [$NewId] already existed due to [$Message]."
            Break
        }
        If ($Workflow_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a Workflow Template named [$NewId] in [$current_domain]. You may not proceed."
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
            If ($UnsetDescription -ne $true) {
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
            If ($UnsetTags -ne $true) {
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
    Renames a Workflow Template from an AutomateNOW! instance

    .DESCRIPTION
    Performs a psuedo-rename operations of a Workflow Template from an AutomateNOW! instance by copying it first and then deleting the source. This function merely combines Copy-AutomateNOWWorkflowTemplate and Remove-AutomateNOWWorkflowTemplate therefore it is to be considered destructive.

    .PARAMETER WorkflowTemplate
    An [ANOWworkflowTemplate] object representing the Workflow Template to be renamed.

    .PARAMETER NewId
    Mandatory string indicating the new id or name of the Workflow Template. Please remember that the Id is the same as a primary key, it must be unique. The console will provide the old Id + '_COPY' in the UI when making a copy. The Id is limited to 1024 characters.

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

    When renaming, you may only specify a different Id (name).

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
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the Workflow Template [$NewId] already existed due to [$Message]."
            Break
        }
        If ($new_Workflow_template_exists -eq $true) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is already a Workflow Template named [$NewId] in [$current_domain]. You may not proceed."
            [boolean]$PermissionToProceed = $false
        }
        [string]$WorkflowTemplate_id = $WorkflowTemplate.id
        $Error.Clear()
        Try {
            [boolean]$old_Workflow_template_exists = ($null -ne (Get-AutomateNOWWorkflowTemplate -Id $WorkflowTemplate_id))
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWWorkflowTemplate failed to check if the Workflow Template [$WorkflowTemplate_id] already existed due to [$Message]."
            Break
        }
        If ($old_Workflow_template_exists -eq $false) {
            [string]$current_domain = $anow_session.header.domain
            Write-Warning "There is not a Workflow Template named [$WorkflowTemplate_id] in [$current_domain]. You may not proceed."
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
            Write-Warning -Message "Find-AutomateNOWObjectReferral failed to extract the referrals on Workflow Template [$WorkflowTemplate_id] due to [$Message]."
            Break
        }
        If ($referrals_count -gt 0) {
            Write-Warning -Message "Unfortunately, you cannot rename a Workflow Template that has referrals. This is because the rename is not actually renaming but copying anew and deleting the old. Please, use the Find-AutomateNOWObjectReferral function to identify referrals and remove them."
            Break
        }
        Else {
            Write-Verbose -Message "The Workflow Template [$WorkflowTemplate_id] does not have any referrals. It is safe to proceed."
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
                    Write-Warning -Message "Copy-AutomateNOWWorkflowTemplate failed to create a new Workflow Template [$NewId] as Part 1 of the renaming process due to [$Message]."
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

Function Start-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Starts a Workflow Template from an AutomateNOW! instance

    .DESCRIPTION
    Starts a Workflow Template from an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be started.

    .PARAMETER UseAutomaticName
    A switch parameter that is ENABLED BY DEFAULT. You do not need to enable this as it is defaulted to on. This parameter simulates the default format of the executed workflow name (see 'Name' below)

    .PARAMETER Name
    A string representing the name of the running executed workflow. Only use this if you want to OVERRIDE the default naming standard that the console suggests when executing a workflow. The console defaults to a format of "Manual Execution - [Workflow name] - [date utc]".

    .PARAMETER Description
    Optional description of the executed workflow (may not exceed 255 characters).

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new workflow.

    .PARAMETER Folder
    Optional name of the folder to place the executed workflow into.

    .PARAMETER ProcessingTimestamp
    This parameter is -disabled- for now. Instead, the default timestamp will be used to ensure uniqueness. The documentation is unclear or mistaken around this parameter.

    .PARAMETER Priority
    Optional integer between 0 and 1000 to specify the priority of the executed workflow. Defaults to 0.

    .PARAMETER Hold
    Optional switch to set the 'On Hold' property of the executed workflow to enabled. This is $false by default but in the console the checkbox is enabled.

    .PARAMETER ForceLoad
    Optional switch that overrides any 'Ignore Condition' that might exist on the Workflow Template

    .PARAMETER Quiet
    Switch parameter to silence the newly created [ANOWWorkflow] object

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    An [ANOWWorkflow] object representing the started workflow will be returned.

    .EXAMPLE
    Starts a Workflow Template with an automatically generated name and otherwise default values.

    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate_01' | Start-AutomateNOWWorkflowTemplate -UseAutomaticName

    .EXAMPLE
    Starts a Workflow Template with a manually entered name, on hold, at priority 42, placed into a Folder and with two tags.

    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate_01' | Start-AutomateNOWWorkflowTemplate -Name 'WorkflowTemplate_01 2024/01/30' -Description 'My executed Workflow' -Folder 'Folder1' -Tags 'Tag1', 'Tag2' -Hold -Priority 42

    .EXAMPLE
    Starts a Workflow Template without using the pipeline

    $workflow_template = Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate_01'
    Start-AutomateNOWWorkflowTemplate -WorkflowTemplate $workflow_template -UseAutomaticName

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    This function is under construction as the [ANOWWorkflow] class object it returns is not defined yet. You can still use this function but the output is experimental.

    Avoid using the -Name parameter unless you really need to use it. If -Name is not supplied, the parameter set will use -UseAutomaticName instead, which simulates the behavior of the console.

    #>
    [Cmdletbinding(DefaultParameterSetName = 'UseAutomaticName')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false, ParameterSetName = 'UseAutomaticName')]
        [switch]$UseAutomaticName,
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecifyNameManually')]
        [string]$Name,
        [Parameter(Mandatory = $false, HelpMessage = "Enter a descriptive string between 0 and 255 characters in length. UTF8 characters are accepted.")]
        [ValidateScript({ $_.Length -le 255 })]
        [string]$Description,
        [Parameter(Mandatory = $false)]
        [string[]]$Tags,
        [Parameter(Mandatory = $false)]
        [string]$Folder = '',
        [ValidateRange(0, 1000)]
        [Parameter(Mandatory = $false)]
        [int32]$Priority = 0,
        [Parameter(Mandatory = $false)]
        [switch]$Hold,
        [Parameter(Mandatory = $false)]
        [switch]$ForceLoad,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processing/executeNow'
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$WorkflowTemplate_id = $_.id
            [string]$WorkflowTemplate_simpleId = $_.simpleId
        }
        Else {
            [string]$WorkflowTemplate_id = $WorkflowTemplate.id
            [string]$WorkflowTemplate_simpleId = $WorkflowTemplate.simpleId
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $WorkflowTemplate_id )
        $BodyMetaData.Add('runId', $WorkflowTemplate_id )
        $BodyMetaData.Add('priority', $priority )
        $BodyMetaData.Add('processingTimestamp', [string](Get-Date -Date ((Get-Date).ToUniversalTime()) -Format 'yyyy-MM-ddTHH:mm:ss.fff'))
        [string[]]$include_properties = 'id', 'runId', 'priority', 'processingTimestamp', 'hold', 'forceLoad', 'name'
        If ($Tags.Count -gt 0) {
            [int32]$total_tags = $Tags.Count
            [int32]$current_tag = 1
            ForEach ($tag_id in $Tags) {
                $Error.Clear()
                Try {
                    [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
                }
                Catch {
                    [string]$Message = $_.Exception.Message
                    Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] under Start-AutomateNOWWorkflowTemplate due to [$message]"
                    Break
                }
                If ($tag_object.simpleId.length -eq 0) {
                    Throw "Start-AutomateNOWWorkflowTemplate has detected that the tag [$tag_id] does not appear to exist. Please check again."
                    Break
                }
                [string]$tag_display = $tag_object | ConvertTo-Json -Compress
                Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
                #>
                [string]$tag_name_sequence = ('tags' + $current_tag)
                $ANOWWorkflowTemplate.Add($tag_name_sequence, $tag_id)
                $include_properties += $tag_name_sequence
                $current_tag++
            }
        }
        If ($folder.Length -gt 0) {
            $Error.Clear()
            Try {
                [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $folder
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWFolder had an error while retrieving the folder [$folder] running under Start-AutomateNOWWorkflowTemplate due to [$message]"
                Break
            }
            If ($folder_object.simpleId.Length -eq 0) {
                Throw "Start-AutomateNOWWorkflowTemplate has detected that the folder [$folder] does not appear to exist. Please check again."
                Break
            }
            $BodyMetaData.Add('folder', $folder)
            $include_properties += $folder
        }
        If ($hold -ne $true) {
            $BodyMetaData.Add('hold', 'false')
        }
        Else {
            $BodyMetaData.Add('hold', 'true')
        }
        If ($forceLoad -ne $true) {
            $BodyMetaData.Add('forceLoad', 'false')
        }
        Else {
            $BodyMetaData.Add('forceLoad', 'true')
        }
        If ($Name.Length -gt 0) {
            $BodyMetaData.Add('name', $Name)
        }
        Elseif ($UseAutomaticName -eq $true) {
            [string]$Name = New-AutomateNOWDefaultProcessingTitle -simpleId $WorkflowTemplate_simpleId
            Write-Verbose -Message "Generated automatic name [$Name] for this Workflow"
        }
        Else {
            Write-Warning -Message "Unable to determine how to name this Workflow that needs to be started"
            Break
        }
        $BodyMetaData.Add('parameters', '{}')
        $BodyMetaData.Add('_operationType', 'add')
        $BodyMetaData.Add('_operationId', 'executeNow')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ProcessingDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
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
            Write-Warning -Message "Invoke-AutomateNOWAPI failed to execute [$command] on [$WorkflowTemplate_id] due to [$Message]."
            Break
        }
        [int32]$response_code = $results.response.status
        If ($response_code -ne 0) {
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "Somehow the response code was not 0 but was [$response_code]. Please look into this. Body: $full_response_display"
        }
        Write-Verbose -Message "Workflow $WorkflowTemplate_id successfully started as [$Name]"
        $Error.Clear()
        Try {
            [ANOWWorkflow]$Workflow = $results.response.data[0]
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Unable to create the [ANOWWorkflow] object under Start-AutomateNOWWorkflowTemplate from the response due to [$Message]."
            Break
        }
        If ($Quiet -ne $true) {
            Return $Workflow
        }
    }
    End {

    }
}

Function Resume-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Resumes a Workflow Template that is on hold (suspended) on an AutomateNOW! instance

    .DESCRIPTION
    Resumes a Workflow Template that is on hold (suspended) on an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be resumed

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWWorkflowTemplate] object

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The resumed [ANOWWorkflowTemplate] object will be returned

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate01' | Resume-AutomateNOWWorkflowTemplate -Force

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate01', 'WorkflowTemplate02' | Resume-AutomateNOWWorkflowTemplate 

    .EXAMPLE
    @( 'WorkflowTemplate1', 'WorkflowTemplate2', 'WorkflowTemplate3') | Resume-AutomateNOWWorkflowTemplate 

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | ? { $_.workflowType -eq 'FOR_EACH' } | Resume-AutomateNOWWorkflowTemplate

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processingTemplate/resume'
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
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $WorkflowTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'resume')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
                [ANOWWorkflowTemplate]$resumed_Workflow_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWWorkflowTemplate] object after resuming [$WorkflowTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Workflow $WorkflowTemplate_id successfully resumed"
            If ($Quiet -ne $true) {
                Return $resumed_Workflow_template
            }
        }
    }
    End {

    }
}

Function Suspend-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Places a Workflow Template on hold (suspend) from execution on an AutomateNOW! instance

    .DESCRIPTION
    Places a Workflow Template on hold (suspend) from execution on an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be suspended (placed on hold)

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWWorkflowTemplate] object

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The suspended [ANOWWorkflowTemplate] object will be returned

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'Workflow01' | Suspend-AutomateNOWWorkflowTemplate -Force

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate -Id 'Workflow01', 'Workflow02' | Suspend-AutomateNOWWorkflowTemplate 

    .EXAMPLE
    @( 'Workflow1', 'Workflow2', 'Workflow3') | Suspend-AutomateNOWWorkflowTemplate 

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | ? { $_.serverWorkflowType -eq 'LINUX' } | Suspend-AutomateNOWWorkflowTemplate 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        [string]$command = '/processingTemplate/hold'
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
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $WorkflowTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', 'hold')
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
                [ANOWWorkflowTemplate]$suspended_Workflow_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWWorkflowTemplate] object after suspending [$WorkflowTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Workflow $WorkflowTemplate_id successfully suspended (placed on hold)"
            If ($Quiet -ne $true) {
                Return $suspended_Workflow_template
            }
        }
    }
    End {

    }
}

Function Skip-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Sets or unsets the Skip flag on a Workflow Template on an AutomateNOW! instance

    .DESCRIPTION
    Sets or unsets the Skip flag on a Workflow Template on an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be set to skipped or unskipped

    .PARAMETER UnSkip
    Removes the skip flag from an [ANOWWorkflowTemplate] object. This is the opposite of the default behavior.

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .PARAMETER Quiet
    Switch parameter to silence the emitted [ANOWWorkflowTemplate] object

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    The skipped/unskipped [ANOWWorkflowTemplate] object will be returned

    .EXAMPLE
    Sets a Workflow Template to Skip (bypass)

    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate01' | Skip-AutomateNOWWorkflowTemplate -Force

    .EXAMPLE
    Unsets the Skip (bypass) flag on a Workflow Template

    Get-AutomateNOWWorkflowTemplate | Skip-AutomateNOWWorkflowTemplate -UnSkip

    .EXAMPLE
    Sets an array of Workflow Template to Skip (bypass)

    @( 'WorkflowTemplate1', 'WorkflowTemplate2', 'WorkflowTemplate3') | Skip-AutomateNOWWorkflowTemplate 

    .EXAMPLE
    Get-AutomateNOWWorkflowTemplate | ? { $_.workflowType -eq 'FOR_EACH' } | Skip-AutomateNOWWorkflowTemplate -UnSkip -Force -Quiet

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$UnSkip,
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($UnSkip -ne $True) {
            [string]$skip_flag_status = 'On'
            [string]$operation_id = 'passByOn'
            [string]$ProcessDescription = 'Add the Skip flag'
        }
        Else {
            [string]$skip_flag_status = 'Off'
            [string]$operation_id = 'passByOff'
            [string]$ProcessDescription = 'Remove the Skip flag'
        }
        [string]$command = ('/processingTemplate/' + $operation_id)
        [hashtable]$parameters = @{}
        $parameters.Add('Command', $command)
        $parameters.Add('Method', 'POST')
        $parameters.Add('ContentType', 'application/x-www-form-urlencoded; charset=UTF-8')
        If ($anow_session.NotSecure -eq $true) {
            $parameters.Add('NotSecure', $true)
        }
    }
    Process {
        If ($_.id.Length -gt 0) {
            [string]$WorkflowTemplate_id = $_.id
        }
        ElseIf ($WorkflowTemplate.id.Length -gt 0) {
            [string]$WorkflowTemplate_id = $WorkflowTemplate.id
        }
        Else {
            [string]$WorkflowTemplate_id = $Id
        }
        If (($Force -eq $true) -or ($PSCmdlet.ShouldProcess($WorkflowTemplate_id, $ProcessDescription)) -eq $true) {
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.Add('id', $WorkflowTemplate_id )
            $BodyMetaData.Add('_operationType', 'update')
            $BodyMetaData.Add('_operationId', $operation_id)
            $BodyMetaData.Add('_textMatchStyle', 'exact')
            $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
            $BodyMetaData.Add('isc_metaDataPrefix', '_')
            $BodyMetaData.Add('isc_dataFormat', 'json')
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
            $parameters.Add('Body', $Body)
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
                [ANOWWorkflowTemplate]$skipped_workflow_template = $results.response.data[0]
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Failed to create the [ANOWWorkflowTemplate] object after setting the skip flag to [$skip_flag_status] on [$WorkflowTemplate_id] due to [$Message]."
                Break
            }
            Write-Verbose -Message "Successfully set the skip flag to [$skip_flag_status] on [$WorkflowTemplate_id]"
            If ($Quiet -ne $true) {
                Return $skipped_workflow_template
            }
        }
    }
    End {

    }
}

Function Confirm-AutomateNOWWorkflowTemplate {
    <#
    .SYNOPSIS
    Validates (confirms) a Workflow Template on an AutomateNOW! instance

    .DESCRIPTION
    Validates (confirms) a Workflow Template on an AutomateNOW! instance

    .PARAMETER WorkflowTemplate
    An [ANOWWorkflowTemplate] object representing the Workflow Template to be set to confirmed (verified)

    .PARAMETER Quiet
    Returns a boolean $true or $false based on the result of the validation check

    .INPUTS
    ONLY [ANOWWorkflowTemplate] objects are accepted (including from the pipeline)

    .OUTPUTS
    A string with the results from the API will returned.

    .EXAMPLE
    Validates a single Workflow Template

    Get-AutomateNOWWorkflowTemplate -Id 'WorkflowTemplate01' | Confirm-AutomateNOWWorkflowTemplate

    .EXAMPLE
    Validates a series of Workflow Templates

    @( 'WorkflowTemplate1', 'WorkflowTemplate2', 'WorkflowTemplate3') | Confirm-AutomateNOWWorkflowTemplate 

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    #>
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [ANOWWorkflowTemplate]$WorkflowTemplate,
        [Parameter(Mandatory = $false)]
        [switch]$Quiet
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
        If ($_.id.Length -gt 0) {
            [string]$WorkflowTemplate_id = $_.id
        }
        ElseIf ($WorkflowTemplate.id.Length -gt 0) {
            [string]$WorkflowTemplate_id = $WorkflowTemplate.id
        }
        Else {
            [string]$WorkflowTemplate_id = $Id
        }
        [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
        $BodyMetaData.Add('id', $WorkflowTemplate_id )
        $BodyMetaData.Add('_operationType', 'custom')
        $BodyMetaData.Add('_operationId', 'validate')
        $BodyMetaData.Add('_textMatchStyle', 'exact')
        $BodyMetaData.Add('_dataSource', 'ProcessingTemplateDataSource')
        $BodyMetaData.Add('isc_metaDataPrefix', '_')
        $BodyMetaData.Add('isc_dataFormat', 'json')
        [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData
        [string]$command = ('/processingTemplate/validate?' + $Body)
        $parameters.Add('Command', $command)
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
            If ($Quiet -eq $true) {
                Return $false
            }
            [string]$full_response_display = $results.response | ConvertTo-Json -Compress
            Write-Warning -Message "The response code was [$response_code] instead of 0. The Workflow Template $WorkflowTemplate_id is not validated. Please see the full response $full_response_display"
        }
        Else {
            If ($Quiet -eq $true) {
                Return $true
            }
            Else {
                Write-Information -MessageData "The Workflow Template $WorkflowTemplate_id is confirmed as valid."
            }
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

    .PARAMETER sortBy
    Optional string parameter to sort the results by. Valid choices are: id {To be continued...}

    .PARAMETER Descending
    Optional switch parameter to sort in descending order

    .PARAMETER startRow
    Optional integer to indicate the row to start from. This is intended for when you need to paginate the results. Default is 0.

    .PARAMETER endRow
    Optional integer to indicate the row to stop on. This is intended for when you need to paginate the results. Default is 2000.

    .INPUTS
    Accepts a string representing the simple id of the Workspace from the pipeline or individually (but not an array).

    .OUTPUTS
    An array of one or more [ANOWWorkspace] class objects

    .EXAMPLE
    Gets all Workspaces

    Get-AutomateNOWWorkspace

    .EXAMPLE
    Gets a single Workspace

    Get-AutomateNOWWorkspace -Id 'Workspace1'

    .EXAMPLE
    Gets a series of Workspaces from an array of strings sent across the pipeline

    @( 'Workspace1', 'Workspace2' ) | Get-AutomateNOWWorkspace

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    Run this function without parameters to retrieve all of the Workspaces.

    #>
    [OutputType([ANOWWorkspace[]])]
    [Cmdletbinding()]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$Id,
        [Parameter(Mandatory = $False)]
        [int32]$startRow = 0,
        [Parameter(Mandatory = $False)]
        [int32]$endRow = 100,
        [Parameter(Mandatory = $False)]
        [string]$sortBy = 'id',
        [Parameter(Mandatory = $False)]
        [switch]$Descending
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
                [string]$Workspacename = $_
            }
            Else {
                [string]$Workspacename = $Id
            }
            [string]$textMatchStyle = 'exact'
            $Body.'id' = $Workspacename
        }
        Else {
            [string]$textMatchStyle = 'substring'
            $Body.'_constructor' = 'AdvancedCriteria'
            $Body.'operator' = 'and'
        }
        $Body.'_operationType' = 'fetch'
        $Body.'_startRow' = $startRow
        $Body.'_endRow' = $endRow
        $Body.'_textMatchStyle' = $textMatchStyle
        $Body.'_componentId' = 'WorkspaceList'
        $Body.'_dataSource' = 'workspace'
        If ($Descending -eq $true) {
            $Body.'_sortBy' = '-' + $sortBy
        }
        Else {
            $Body.'_sortBy' = $sortBy
        }
        $Body.'isc_metaDataPrefix' = '_'
        $Body.'isc_dataFormat' = 'json'
        [string]$Body = ConvertTo-QueryString -InputObject $Body
        [string]$command = ('/workspace/read?' + $Body)
        $parameters.Add('command', $command)
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
    Changes the settings of a Workspace on an AutomateNOW! instance

    .DESCRIPTION
    Changes the settings of a Workspace on an AutomateNOW! instance

    .PARAMETER Workspace
    An [ANOWWorkspace] object representing the Workspace to be changed.

    .PARAMETER Description
    A text description of at least 1 character.

    .PARAMETER RemoveIcon
    Switch parameter that will remove the icon configured for this workspace.

    .PARAMETER iconSet
    The name of the icon library (if you choose to use one). Possible choices are: FAT_COW, FUGUE (note that FONT_AWESOME is not an actual icon library)

    .PARAMETER iconCode
    The name of the icon which matches the chosen library. To see the list of available iconCodes, use Import-AutomateNOWIcon (or Import-AutomateNOWLocalIcon) then try $anow_assets.icon_library."FUGUE"[0..10] to see the names of the first 10 icons from the Fugue library.

    .PARAMETER UnsetFolder
    Switch parameter that will unset the folder configuration. This is equivalent to unticking the box for 'Automatically set folder to workspace template'

    .PARAMETER SetFolderType
    Enables the 'Automatically set tags to workspace template'. Valid choices are: SET_WORKSPACE_FOLDER, SET_SPECIFIC_FOLDER, CREATE_SUB_FOLDER_PER_WORKFLOW. Note, if you specify SET_SPECIFIC_FOLDER then you must include the -Folder parameter as well with the name (string) of the Folder object.

    .PARAMETER Folder
    String that specifies the name of the folder object that you are specifying with the SET_SPECIFIC_FOLDER folder type. Do not use this parameter with the other two folder types.

    .PARAMETER UnsetTags
    Switch parameter that will unset the tag configuration. If this is the SET_SPECIFIC_TAGS type, the tags set will be removed. This is equivalent to unticking the box for 'Automatically set tags to workspace templates'

    .PARAMETER SetTagType
    Enables the 'Automatically set tags to workspace template'. Valid choices are: SET_WORKSPACE_TAGS, SET_SPECIFIC_TAGS. Note, if you specify SET_SPECIFIC_TAGS then you must include the -Tag parameter as well with the names (string array) of the Tag objects.

    .PARAMETER Tag
    String array that specifies the name(s) of the Tag objects that you are specifying with the SET_SPECIFIC_TAGS tag type. Do not use this parameter with the other tag type.

    .PARAMETER Folder
    String that specifies the name of the folder object that you are specifying with the SET_SPECIFIC_FOLDER folder type. Do not use this parameter with the other two folder types.

    .PARAMETER SetPrefix
    String that enables the 'Add prefix to workspace template' and sets the prefix to the string provided. Unlike the console, a default suggested prefix will not be made for you.

    .PARAMETER UnsetPrefix
    Switch parameter that will unset the prefix configuration. This is equivalent to unticking the box for 'Add prefix to workspace template'

    .PARAMETER Force
    Force the change without confirmation. This is equivalent to -Confirm:$false

    .INPUTS
    ONLY [ANOWWorkspace] objects are accepted (including from the pipeline)

    .OUTPUTS
    The modified [ANOWWorkspace] object will be returned

    .EXAMPLE
    Sets the description on a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -Description 'My Description' -Force

    .EXAMPLE
    Unsets the description on a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -UnsetDescription -Force

    .EXAMPLE
    Unsets the icon on a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -RemoveIcon -Force

    .EXAMPLE
    Sets the icon on a Workspace (example 1)
    Import-AutomateNOWLocalIcon
    Set-AutomateNOWWorkspace -Workspace $workspace -iconSet FUGUE -iconCode address-book -Force

    .EXAMPLE
    Sets the icon on a Workspace (example 2)
    Import-AutomateNOWLocalIcon
    Set-AutomateNOWWorkspace -Workspace $workspace -iconSet FAT_COW -iconCode abacus -Force

    .EXAMPLE
    Unsets the folder configuration for a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -UnsetFolder -Force

    .EXAMPLE
    Sets the folder configuration for a Workspace (example 1)
    Set-AutomateNOWWorkspace -Workspace $workspace -SetFolderType CREATE_SUB_FOLDER_PER_WORKFLOW -Force

    .EXAMPLE
    Sets the folder configuration for a Workspace (example 2)
    Set-AutomateNOWWorkspace -Workspace $workspace -SetFolderType SET_WORKSPACE_FOLDER -Force

    .EXAMPLE
    Sets the folder configuration for a Workspace (example 3) note the -Folder parameter
    Set-AutomateNOWWorkspace -Workspace $workspace -SetFolderType SET_SPECIFIC_FOLDER -Folder 'MJS'

    .EXAMPLE
    Unsets the tag configuration for a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -UnsetTags -Force

    .EXAMPLE
    Sets the tag configuration for a Workspace (example 1)
    Set-AutomateNOWWorkspace -Workspace $workspace -SetTagType 'SET_WORKSPACE_TAGS' -Force

    .EXAMPLE
    Sets the tag configuration for a Workspace (example 2) note the -Tags parameter adding multiple tags
    Set-AutomateNOWWorkspace -Workspace $workspace -SetTagType 'SET_SPECIFIC_TAGS' -Tags Tag1, Tag2 -Force

    .EXAMPLE
    Sets a prefix on a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -SetPrefix 'prefix01_' -Force

    .EXAMPLE
    Unsets the prefix on a Workspace
    Set-AutomateNOWWorkspace -Workspace $workspace -UnsetPrefix -Force

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    You may only make 1 change a time! That's why there are so many parameter sets. This is done out of caution.

    The -iconSet and -iconCode parameter set requires that you import the local icon names with Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon. This is only to check that the name of the icon being sent to the API is valid.

    If you have three tags on a Workspace and wanted to remove one then use the -SetTags parameter to apply the 2 that you want to keep. If you want to remove all tags then use -UnsetTags.

    #>
    [Cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [ANOWWorkspace]$Workspace,
        [AllowEmptyString()]
        [ValidateScript({ $_.Length -ge 1 -and $_.Length -le 255 })]
        [Parameter(Mandatory = $true, ParameterSetName = 'SetDescription', HelpMessage = "Enter a descriptive string between 1 and 255 characters in length. UTF8 characters are accepted.")]
        [string]$Description,
        [Parameter(Mandatory = $true, ParameterSetName = 'ResetDescription')]
        [switch]$UnsetDescription,
        [Parameter(Mandatory = $true, ParameterSetName = 'SetIcon')]
        [ANOWiconSetIconsOnly]$iconSet,
        [Parameter(Mandatory = $true, ParameterSetName = 'SetIcon')]
        [string]$iconCode,
        [Parameter(Mandatory = $true, ParameterSetName = 'RemoveIcon')]
        [switch]$RemoveIcon,
        [Parameter(Mandatory = $true, ParameterSetName = 'UnsetFolder')]
        [switch]$UnsetFolder,
        [Parameter(Mandatory = $true, ParameterSetName = 'SetFolder')]
        [ANOWWorkspace_workspaceSetFolderType]$SetFolderType,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetFolder')]
        [string]$Folder,
        [Parameter(Mandatory = $true, ParameterSetName = 'UnsetTags')]
        [switch]$UnsetTags,
        [Parameter(Mandatory = $true, ParameterSetName = 'SetTags')]
        [ANOWWorkspace_workspaceSetTagType]$SetTagType,
        [Parameter(Mandatory = $false, ParameterSetName = 'SetTags')]
        [string[]]$Tags,
        [ValidateScript({ $_.Length -ge 1 -and $_.Length -le 255 })]
        [Parameter(Mandatory = $true, ParameterSetName = 'SetPrefix', HelpMessage = "Enter a descriptive string between 1 and 255 characters in length. UTF8 characters are accepted. Example 'MyWorkspace_'")]
        [string]$SetPrefix,
        [Parameter(Mandatory = $true, ParameterSetName = 'UnsetPrefix')]
        [switch]$UnsetPrefix,
        [Parameter(Mandatory = $true, ParameterSetName = 'UnsetWorkspace')]
        [switch]$UnsetWorkspace,
        [Parameter(Mandatory = $true, ParameterSetName = 'AddWorkspace')]
        [string]$AddToWorkspace,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    Begin {
        If ((Confirm-AutomateNOWSession -Quiet) -ne $true) {
            Write-Warning -Message "Somehow there is not a valid token confirmed."
            Break
        }
        If ($iconSet.length -gt 0 ) {
            If ($anow_assets.icon_library.length -eq 0) {
                Write-Warning -Message "Please import the ANOW icons into your session with Import-AutomateNOWIcon or Import-AutomateNOWLocalIcon"
                Break
            }
            If ($iconCode -notin ($anow_assets.icon_library."$iconSet")) {
                Write-Warning -Message "The icon [$iconCode] does not appear to exist within the [$iconSet] icon set. Please check again."
                Break
            }
        }
        ElseIf ($AddPrefix -eq $true -and $Prefix.Length -eq 0) {
            Write-Warning -Message 'You must include the -Prefix parameter when specifying -AddPrefix. Please refer to the help.'
            Break
        }
        ElseIf ($SetFolderType -eq 'SET_SPECIFIC_FOLDER' -and $Folder.Length -eq 0) {
            Write-Warning -Message 'You must include the name of the folder with -Folder if you are specifying the ''SET_SPECIFIC_FOLDER'' folder type. Please try again.'
            Break
        }
        ElseIf ($SetFolderType -in ('SET_WORKSPACE_FOLDER', 'CREATE_SUB_FOLDER_PER_WORKFLOW') -and $Folder.Length -gt 0) {
            Write-Warning -Message 'Please do not include the -Folder parameter if you are not specifying the ''SET_SPECIFIC_FOLDER'' folder type. This is not compatible.'
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
            [System.Collections.ArrayList]$include_properties = [System.Collections.ArrayList]@()
            [System.Collections.Specialized.OrderedDictionary]$BodyMetaData = [System.Collections.Specialized.OrderedDictionary]@{}
            $BodyMetaData.'id' = $Workspace_id
            If ($Description.Length -gt 0) {
                $BodyMetaData.'description' = $Description
            }
            ElseIf ($UnsetDescription -eq $true) {
                $BodyMetaData.'description' = $null
            }
            ElseIf ($RemoveIcon -eq $true) {
                $BodyMetaData.'iconSet' = $null
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($iconCode.Length -gt 0) {
                $BodyMetaData.'iconCode' = $iconCode
                $BodyMetaData.'iconSet' = $iconSet
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'_componentId' = 'WorkspaceEditForm'
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($UnsetFolder -eq $true) {
                $BodyMetaData.'setFolder' = 'false'
                $BodyMetaData.'workspaceSetFolderType' = $null
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($SetFolderType.Length -gt 0) {
                $BodyMetaData.'setFolder' = 'true'
                $BodyMetaData.'workspaceSetFolderType' = $SetFolderType
                If ($Folder.Length -gt 0) {
                    $Error.Clear()
                    Try {
                        [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
                    }
                    Catch {
                        [string]$Message = $_.Exception.Message
                        Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] actually existed under Set-AutomateNOWWorkspace due to [$Message]"
                        Break
                    }
                    If ($folder_object.simpleId.Length -eq 0) {
                        Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under Set-AutomateNOWWorkspace. Please check again."
                        Break
                    }
                    [string]$folder_display = $folder_object | ConvertTo-Json -Compress
                    Write-Verbose -Message "Adding folder $folder_display to [ANOWWorkflowTemplate] [$Workspace_id]"
                    $BodyMetaData.'setWorkspaceFolder' = $Folder
                    [void]$include_properties.Add('setWorkspaceFolder')
                }
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'setWorkspaceTags' = $Workspace.setWorkspaceTags
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($UnsetTags -eq $true) {
                $BodyMetaData.'setTags' = 'false'
                $BodyMetaData.'workspaceSetTagType' = $null
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('workspaceSetTagType')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($SetTagType.Length -gt 0) {
                $BodyMetaData.'setTags' = 'true'
                $BodyMetaData.'workspaceSetTagType' = $SetTagType
                If ($Tags.Count -gt 0 -and $SetTagType -eq 'SET_SPECIFIC_TAGS') {
                    [int32]$total_tags = $Tags.Count
                    [int32]$current_tag = 1
                    ForEach ($tag_id in $Tags) {
                        $Error.Clear()
                        Try {
                            [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
                        }
                        Catch {
                            [string]$Message = $_.Exception.Message
                            Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] running under Set-AutomateNOWWorkspace due to [$message]"
                            Break
                        }
                        If ($tag_object.simpleId.length -eq 0) {
                            Throw "New-AutomateNOWTaskTemplate has detected that the tag [$tag_id] does not appear to exist running under Set-AutomateNOWWorkspace. Please check again."
                            Break
                        }
                        [string]$tag_display = $tag_object | ConvertTo-Json -Compress
                        Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
                        [string]$tag_name_sequence = ('setWorkspaceTags' + $current_tag)
                        $BodyMetaData."$tag_name_sequence" = $tag_id
                        $include_properties += $tag_name_sequence
                        $current_tag++
                    }
                }
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($SetPrefix.Length -gt 0) {
                $BodyMetaData.'addPrefix' = 'true'
                $BodyMetaData.'prefix' = $SetPrefix
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            ElseIf ($UnsetPrefix -eq $true) {
                $BodyMetaData.'addPrefix' = 'false'
                $BodyMetaData.'iconCode' = $Workspace.iconCode
                $BodyMetaData.'iconSet' = $Workspace.iconSet
                $BodyMetaData.'fugueIcon' = $null
                $BodyMetaData.'fatCowIcon' = $null
                $BodyMetaData.'_componentId' = 'WorkspaceVM'
                $BodyMetaData.'codeRepository' = $Workspace.codeRepository
                $BodyMetaData.'_oldValues' = $Workspace.CreateOldValues()
                [void]$include_properties.Add('iconSet')
                [void]$include_properties.Add('setWorkspaceTags')
                [void]$include_properties.Add('fugueIcon')
                [void]$include_properties.Add('fatCowIcon')
                [void]$include_properties.Add('codeRepository')
            }
            $BodyMetaData.'_operationType' = 'update'
            $BodyMetaData.'_textMatchStyle' = 'exact'
            $BodyMetaData.'_dataSource' = 'WorkspaceDataSource'
            $BodyMetaData.'isc_metaDataPrefix' = '_'
            $BodyMetaData.'isc_dataFormat' = 'json'
            [string]$Body = ConvertTo-QueryString -InputObject $BodyMetaData -IncludeProperties $include_properties
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

    .PARAMETER Tags
    Optional string array containing the id's of the tags to assign to the new DataSource.

    .PARAMETER Folder
    Optional name of the folder to place the DataSource into.

    .PARAMETER iconSet
    Mandatory string representing a choice between three icon sets. Valid choices are: FAT_COW, FUGUE, FONT_AWESOME

    .PARAMETER iconCode
    The name of the icon which matches the chosen library.

    .PARAMETER CodeRepository
    Optional name of the code repository to place the Workspace into.

    .PARAMETER Quiet
    Optional switch to suppress the return of the newly created object

    .INPUTS
    None. You cannot pipe objects to New-AutomateNOWWorkspace.

    .OUTPUTS
    An [ANOWWorkspace] object representing the newly created Workspace

    .EXAMPLE
    New-AutomateNOWWorkspace -Id 'Workspace1' -Description 'Workspace1 description' -Tags 'Tag1', 'Tag2' -Folder 'Folder1' -iconSet 'FAT_COW' -iconCode 'paper_airplane' -codeRepository 'Repository1'

    .NOTES
    You must use Connect-AutomateNOW to establish the token by way of global variable.

    The name (id) of the Workspace must be unique (per domain). It may consist only of letters, numbers, underscore, dot or hypen.

    The names of the icon is not enforced here! If you want to know the names of the available icons try: Import-AutomateNOWLocalIcon; $anow_assets.icon_library.FUGUE;

    #>

    [OutputType([ANOWWorkspace])]
    [Cmdletbinding(DefaultParameterSetName = 'Default')]
    Param(
        [ValidateScript({ $_ -match '^[0-9a-zA-z_.-]{1,}$' })]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'iconSet')]
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
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet')]
        [string]$CodeRepository,
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'iconSet')]
        [switch]$Quiet
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
    [System.Collections.Specialized.OrderedDictionary]$ANOWWorkspace = [System.Collections.Specialized.OrderedDictionary]@{}
    $ANOWWorkspace.Add('id', $Id)
    If ($Description.Length -gt 0) {
        $ANOWWorkspace.Add('description', $Description)
    }
    If ($Tags.Count -gt 0) {
        [int32]$total_tags = $Tags.Count
        [int32]$current_tag = 1
        ForEach ($tag_id in $Tags) {
            $Error.Clear()
            Try {
                [ANOWTag]$tag_object = Get-AutomateNOWTag -Id $tag_id
            }
            Catch {
                [string]$Message = $_.Exception.Message
                Write-Warning -Message "Get-AutomateNOWTag had an error while retrieving the tag [$tag_id] under New-AutomateNOWWorkspace due to [$message]"
                Break
            }
            If ($tag_object.simpleId.length -eq 0) {
                Throw "New-AutomateNOWWorkspace has detected that the tag [$tag_id] does not appear to exist. Please check again."
                Break
            }
            [string]$tag_display = $tag_object | ConvertTo-Json -Compress
            Write-Verbose -Message "Adding tag $tag_display [$current_tag of $total_tags]"
            [string]$tag_name_sequence = ('tags' + $current_tag)
            $ANOWWorkspace.Add($tag_name_sequence, $tag_id)
            $include_properties += $tag_name_sequence
            $current_tag++
        }
    }
    If ($Folder.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWFolder]$folder_object = Get-AutomateNOWFolder -Id $Folder
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWFolder failed to confirm that the folder [$tag_id] actually existed under New-AutomateNOWWorkspace due to [$Message]"
            Break
        }
        If ($folder_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWFolder failed to locate the Folder [$Folder] under New-AutomateNOWWorkspace. Please check again."
            Break
        }
        [string]$folder_display = $folder_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding folder $folder_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWWorkspace.Add('folder', $Folder)
        $include_properties += 'folder'
    }
    If ($CodeRepository.Length -gt 0) {
        $Error.Clear()
        Try {
            [ANOWCodeRepository]$code_repository_object = Get-AutomateNOWCodeRepository -Id $CodeRepository
        }
        Catch {
            [string]$Message = $_.Exception.Message
            Write-Warning -Message "Get-AutomateNOWCodeRepository failed to confirm that the code repository [$CodeRepository] actually existed under New-AutomateNOWWorkspace due to [$Message]"
            Break
        }
        If ($code_repository_object.simpleId.Length -eq 0) {
            Throw "Get-AutomateNOWCodeRepository failed to locate the Code Repository [$CodeRepository] under New-AutomateNOWWorkspace. Please check again."
            Break
        }
        [string]$code_repository_display = $code_repository_object | ConvertTo-Json -Compress
        Write-Verbose -Message "Adding code repository $code_repository_display to [ANOWWorkflowTemplate] [$Id]"
        $ANOWWorkspace.Add('codeRepository', $CodeRepository)
        $include_properties += 'codeRepository'
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
    $BodyMetaData.'isc_dataFormat' = 'json'
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
    If ($results.response.status -lt 0 -or $results.response.status -gt 0) {
        [string]$results_display = $results.response.errors | ConvertTo-Json -Compress
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

#Region Lookup Tables

Function Resolve-AutomateNOWTaskType2ServerNodeType {
    [OutputType([string[]])]
    [CmdletBinding(DefaultParameterSetName = 'TaskType')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'TaskType')]
        [string]$TaskType,
        [Parameter(Mandatory = $true, ParameterSetName = 'NodeType')]
        [string]$ServerNodeType,
        [Parameter(Mandatory = $true, ParameterSetName = 'All')]
        [switch]$All
    )
    [System.Collections.ArrayList]$ANOWLookupTaskTypeToServerNodeType = [System.Collections.ArrayList]::new()
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AE_SHELL_SCRIPT' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AE_SHELL_SCRIPT' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AMQP_SEND' = 'AMQP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AMQP_SEND' = 'HORNETQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AMQP_SEND' = 'QPID'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AMQP_SEND' = 'RABBIT_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AMQP_SEND' = 'ZERO_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ANSIBLE_PLAYBOOK' = 'ANSIBLE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ANSIBLE_PLAYBOOK_PATH' = 'ANSIBLE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'APACHE_AIRFLOW_RUN_DAG' = 'APACHE_AIRFLOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ARANGO_DB_INSERT' = 'ARANGO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AS400_BATCH_JOB' = 'AS400'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AS400_COMMAND_CALL' = 'AS400'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AS400_PROGRAM_CALL' = 'AS400'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AUTOMATE_NOW_TRIGGER_EVENT' = 'AUTOMATE_NOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AUTOMATION_ANYWHERE_DEPLOY_ROBOT' = 'AUTOMATION_ANYWHERE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AUTOMATION_ANYWHERE_START_ROBOT' = 'AUTOMATION_ANYWHERE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AUTOMATION_ANYWHERE_STOP_ROBOT' = 'AUTOMATION_ANYWHERE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AUTOMATION_ANYWHERE_UNDEPLOY_ROBOT' = 'AUTOMATION_ANYWHERE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_BATCH_JOB' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EC2_DELETE_VOLUME' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EC2_START_INSTANCE' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EC2_STOP_INSTANCE' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EC2_TERMINATE_INSTANCE' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_ADD_STEPS' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_API_COMMAND' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_CANCEL_STEPS' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_GET' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_PUT' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_START_NOTEBOOK_EXECUTION' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_STOP_NOTEBOOK_EXECUTION' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_TERMINATE_JOB_FLOW' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_EMR_WORKFLOW' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_GLUE_CRAWLER' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_GLUE_JOB' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_GLUE_TRIGGER' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_GLUE_WORKFLOW' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_LAMBDA_CREATE_FUNCTION' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_LAMBDA_DELETE_FUNCTION' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_LAMBDA_INVOKE' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_S3_COPY_OBJECT' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_S3_DELETE_OBJECT' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_S3_MOVE_OBJECT' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_S3_RENAME_OBJECT' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_ADD_MODEL' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_API_COMMAND' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_DELETE_MODEL' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_PROCESSING' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_TRAINING' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_TRANSFORM' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_SAGE_MAKER_TUNING' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AWS_START_STEP_FUNCTION_STATE_MACHINE' = 'AWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_BATCH_JOB' = 'AZURE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATA_FACTORY_PIPELINE' = 'AZURE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATA_FACTORY_TRIGGER' = 'AZURE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATA_LAKE_JOB' = 'AZURE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATABRICKS_DELETE_CLUSTER' = 'AZURE_DATABRICKS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATABRICKS_JOB' = 'AZURE_DATABRICKS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATABRICKS_LIST_CLUSTERS' = 'AZURE_DATABRICKS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATABRICKS_START_CLUSTER' = 'AZURE_DATABRICKS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_DATABRICKS_TERMINATE_CLUSTER' = 'AZURE_DATABRICKS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'AZURE_RUN_LOGIC_APP' = 'AZURE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BLUE_PRISM' = 'BLUE_PRISM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BLUE_PRISM_DEPLOY_ROBOT' = 'BLUE_PRISM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BLUE_PRISM_START_ROBOT' = 'BLUE_PRISM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BLUE_PRISM_STOP_ROBOT' = 'BLUE_PRISM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BLUE_PRISM_UNDEPLOY_ROBOT' = 'BLUE_PRISM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'BMC_REMEDY_INCIDENT' = 'BMC_REMEDY'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CA_SERVICE_MANAGEMENT_INCIDENT' = 'CA_SERVICE_MANAGEMENT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CASSANDRA_CQL_SCRIPT' = 'CASSANDRA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'COUCH_BASE_INSERT' = 'COUCH_BASE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'COUCH_DB_INSERT' = 'COUCH_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_ADD_CONDITION' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_CREATE_JOB' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_DELETE_CONDITION' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_ORDER_JOB' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_RESOURCE_TABLE_ADD' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_RESOURCE_TABLE_DELETE' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'CTRLM_RESOURCE_TABLE_UPDATE' = 'CTRL_M'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'DATASOURCE_DELETE_FILE' = 'INTERNAL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'DATASOURCE_DOWNLOAD_FILE' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'DATASOURCE_UPLOAD_FILE' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'DBT_JOB' = 'DBT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'DYNAMO_DB_INSERT' = 'DYNAMO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'EMAIL_CONFIRMATION' = 'EMAIL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'EMAIL_INPUT' = 'EMAIL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'EMAIL_SEND' = 'EMAIL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FACEBOOK_POST' = 'FACEBOOK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FILE_CHECK' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FILE_TRANSFER' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FILE_WATCHER' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FLINK_JAR_DELETE' = 'FLINK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FLINK_JAR_UPLOAD' = 'FLINK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'FLINK_RUN_JOB' = 'FLINK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GO' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GOOGLE_DATA_FLOW_JOB' = 'GOOGLE_DATA_FLOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'GROOVY' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_APPEND_FILE' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_CREATE_DIRECTORY' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_DELETE_DIRECTORY' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_DELETE_FILE' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_DOWNLOAD_FILE' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_RENAME' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HDFS_UPLOAD_FILE' = 'HDFS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HP_OPEN_VIEW_SERVICE_MANAGER_INCIDENT' = 'HP_OPEN_VIEW_SERVICE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'HTTP_REQUEST' = 'HTTP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'IBM_CONTROL_DESK_INCIDENT' = 'IBM_CONTROL_DESK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'IBM_DATASTAGE' = 'IBM_DATASTAGE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'IBM_MQ_SEND' = 'IBM_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'INFORMATICA_CLOUD_TASKFLOW' = 'INFORMATICA_CLOUD'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'INFORMATICA_WORKFLOW' = 'INFORMATICA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'INFORMATICA_WS_WORKFLOW' = 'INFORMATICA_WS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'INSTAGRAM_POST' = 'INSTAGRAM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVA' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JAVASCRIPT' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JIRA_ADD_ISSUE' = 'JIRA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JIRA_CLOSE_ISSUE' = 'JIRA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'ACTIVE_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'HORNETQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'IBM_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'JORAM_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'PULSAR'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'RABBIT_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'SOLACE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'SQS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'SQS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'JMS_SEND' = 'ZERO_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KAFKA_SEND' = 'KAFKA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'KOTLIN' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'LINKED_IN_POST' = 'LINKED_IN'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MICROSOFT_POWER_BI_DATAFLOW_REFRESH' = 'MICROSOFT_POWER_BI'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MICROSOFT_POWER_BI_DATASET_REFRESH' = 'MICROSOFT_POWER_BI'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MONGO_DB_INSERT' = 'MONGO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MQTT_SEND' = 'ACTIVE_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MQTT_SEND' = 'HORNETQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MQTT_SEND' = 'IBM_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MQTT_SEND' = 'RABBIT_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'MS_SSIS' = 'MS_SSIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'NEO4J_INSERT' = 'NEO4J'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ODI_LOAD_PLAN' = 'ODI'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ODI_SESSION' = 'ODI'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'OPENTEXT_DYNAMIC_JCL' = 'OPENTEXT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'OPENTEXT_STORED_JCL' = 'OPENTEXT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ORACLE_EBS_EXECUTE_PROGRAM' = 'ORACLE_EBS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ORACLE_EBS_EXECUTE_REQUEST_SET' = 'ORACLE_EBS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ORACLE_EBS_PROGRAM' = 'ORACLE_EBS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ORACLE_EBS_REQUEST_SET' = 'ORACLE_EBS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ORACLE_SERVICE_CENTER_CASE' = 'ORACLE_SERVICE_CENTER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEGA_DEPLOY_ROBOT' = 'PEGA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEGA_START_ROBOT' = 'PEGA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEGA_STOP_ROBOT' = 'PEGA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEGA_UNDEPLOY_ROBOT' = 'PEGA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_APPLICATION_ENGINE_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_COBOL_SQL_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_CRW_ONLINE_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_CRYSTAL_REPORTS_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_CUBE_BUILDER_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_JOB_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_NVISION_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_SQR_PROCESS_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_SQR_REPORT_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PEOPLESOFT_WINWORD_TASK' = 'PEOPLESOFT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PERL' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'POWERSHELL' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'PYTHON' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RABBIT_MQ_SEND' = 'RABBIT_MQ'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RAINCODE_DYNAMIC_JCL' = 'RAINCODE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RAINCODE_STORED_JCL' = 'RAINCODE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'AZURE_SQL_DATA_WAREHOUSE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'AZURE_SQL_DATABASE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'DASHDB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'DB2'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'GOOGLE_BIG_QUERY'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'H2'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'HIVE_QL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'INFORMIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'MYSQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'NETEZZA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'ORACLE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'POSTGRESQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'PRESTO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'SAP_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'SINGLESTORE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'SNOWFLAKE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'SQL_SERVER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'SYBASE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'TERADATA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL' = 'VERTICA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'AZURE_SQL_DATA_WAREHOUSE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'AZURE_SQL_DATABASE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'DASHDB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'DB2'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'GOOGLE_BIG_QUERY'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'HIVE_QL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'INFORMIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'MYSQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'NETEZZA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'ORACLE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'POSTGRESQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'PRESTO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'SAP_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'SINGLESTORE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'SNOWFLAKE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'SQL_SERVER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'TERADATA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_SQL_STATEMENT' = 'VERTICA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'AZURE_SQL_DATA_WAREHOUSE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'AZURE_SQL_DATABASE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'DASHDB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'DB2'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'GOOGLE_BIG_QUERY'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'INFORMIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'MYSQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'NETEZZA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'ORACLE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'POSTGRESQL'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'PRESTO_DB'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'SAP_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'SINGLESTORE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'SNOWFLAKE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'SQL_SERVER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'TERADATA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RDBMS_STORED_PROCEDURE' = 'VERTICA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REDDIT_POST' = 'REDDIT'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REDIS_CLI' = 'REDIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REDIS_DELETE' = 'REDIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REDIS_GET' = 'REDIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REDIS_SET' = 'REDIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'REST_WEB_SERVICE_CALL' = 'REST_WEB_SERVICE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ROBOT_FRAMEWORK_DEPLOY_ROBOT' = 'ROBOT_FRAMEWORK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ROBOT_FRAMEWORK_START_ROBOT' = 'ROBOT_FRAMEWORK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ROBOT_FRAMEWORK_STOP_ROBOT' = 'ROBOT_FRAMEWORK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'ROBOT_FRAMEWORK_UNDEPLOY_ROBOT' = 'ROBOT_FRAMEWORK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUBY' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'RUST' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_ARCHIVE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_BW_PROCESS_CHAIN' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_CM_PROFILE_ACTIVATE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_CM_PROFILE_DEACTIVATE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_COPY_EXISTING_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_EXPORT_CALENDAR' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_EXPORT_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_FUNCTION_MODULE_CALL' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_GET_APPLICATION_LOG' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_JOB_INTERCEPTOR' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_MODIFY_INTERCEPTION_CRITERIA' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_MONITOR_EXISTING_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_RAISE_EVENT' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_READ_TABLE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_RELEASE_EXISTING_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_START_SCHEDULED_JOB' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_SWITCH_OPERATION_MODE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_VARIANT_COPY' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_VARIANT_CREATE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_VARIANT_DELETE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_4H_VARIANT_UPDATE' = 'SAP_S4_HANA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_ARCHIVE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_BW_PROCESS_CHAIN' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_CM_PROFILE_ACTIVATE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_CM_PROFILE_DEACTIVATE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_EXPORT_CALENDAR' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_EXPORT_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_FUNCTION_MODULE_CALL' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_GET_APPLICATION_LOG' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_IBP_JOB' = 'SAP_S4_HANA_CLOUD'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_MODIFY_INTERCEPTION_CRITERIA' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_ODATA_API_CALL' = 'SAP_S4_HANA_CLOUD'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_COPY_EXISTING_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_JOB_INTERCEPTOR' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_MONITOR_EXISTING_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_RAISE_EVENT' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_RELEASE_EXISTING_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_START_SCHEDULED_JOB' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_VARIANT_COPY' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_VARIANT_CREATE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_VARIANT_DELETE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_R3_VARIANT_UPDATE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_READ_TABLE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_SOLUTION_MANAGER_TICKET' = 'SAP_SOLUTION_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAP_SWITCH_OPERATION_MODE' = 'SAP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAS_4GL' = 'SAS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAS_DI' = 'SAS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAS_JOB' = 'SAS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SAS_VIYA_JOB' = 'SAS_VIYA'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SCALA' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SERVICE_NOW_CLOSE_INCIDENT' = 'SERVICE_NOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SERVICE_NOW_CREATE_INCIDENT' = 'SERVICE_NOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SERVICE_NOW_RESOLVE_INCIDENT' = 'SERVICE_NOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SERVICE_NOW_UPDATE_INCIDENT' = 'SERVICE_NOW'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SH' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SOAP_WEB_SERVICE_CALL' = 'SOAP_WEB_SERVICE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_JAVA' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_PYTHON' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_R' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_RUN_JOB' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_SCALA' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SPARK_SQL' = 'SPARK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'STOMP_SEND' = 'STOMP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SWIFT' = 'IOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'SWIFT' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TABLEAU_REFRESH_EXTRACT' = 'TABLEAU'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TALEND_JOB' = 'TALEND'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TEAMS_CHANNEL_MESSAGE' = 'TEAMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TEAMS_CHAT_MESSAGE' = 'TEAMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TELEGRAM_MESSAGE' = 'TELEGRAM'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TIKTOK_POST' = 'TIKTOK'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TITAN_INSERT' = 'TITAN'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TUMBLR_POST' = 'TUMBLR'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TWITTER_POST' = 'TWITTER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'AIX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'HPUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'LINUX'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'MACOS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'OPENVMS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'SOLARIS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'TYPESCRIPT' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'UI_PATH' = 'UI_PATH'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'UI_PATH_DEPLOY_ROBOT' = 'UI_PATH'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'UI_PATH_START_ROBOT' = 'UI_PATH'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'UI_PATH_STOP_ROBOT' = 'UI_PATH'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'UI_PATH_UNDEPLOY_ROBOT' = 'UI_PATH'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'VBSCRIPT' = 'WINDOWS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'WHATSAPP_MESSAGE' = 'WHATSAPP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'WORK_FUSION_DEPLOY_ROBOT' = 'WORK_FUSION'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'WORK_FUSION_START_ROBOT' = 'WORK_FUSION'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'WORK_FUSION_STOP_ROBOT' = 'WORK_FUSION'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'WORK_FUSION_UNDEPLOY_ROBOT' = 'WORK_FUSION'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'XFTP_COMMAND' = 'FILE_MANAGER'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'XMPP_SEND' = 'XMPP'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'YOUTUBE_POST' = 'YOUTUBE'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'Z_OS_COMMAND' = 'Z_OS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'Z_OS_DYNAMIC_JCL' = 'Z_OS'; })
    [void]$ANOWLookupTaskTypeToServerNodeType.Add([hashtable]@{'Z_OS_STORED_JCL' = 'Z_OS'; })
    If ($TaskType.Length -gt 0) {
        [string[]]$TaskTypes = $ANOWLookupTaskTypeToServerNodeType | Where-Object { $_.keys -eq $TaskType } | Select-Object -ExpandProperty Values
        If ($TaskTypes.Count -gt 0) {
            Return $TaskTypes
        }
        Else {
            Write-Warning -Message "There were no Task Types that match [$TaskType]"
        }
    }
    ElseIf ($ServerNodeType.Length -gt 0) {
        [string[]]$ServerNodeTypes = $ANOWLookupTaskTypeToServerNodeType | Where-Object { $_.values -eq $ServerNodeType } | Select-Object -ExpandProperty Keys
        If ($ServerNodeTypes.Count -gt 0) {
            Return $ServerNodeTypes
        }
        Else {
            Write-Warning -Message "There were no Server Node Types that match [$ServerNodeType]"
        }
    }
    ElseIf ($All -eq $true) {
        Return $ANOWLookupTaskTypeToServerNodeType
    }
    Else {
        Write-Warning -Message "Unable to resolve which output to return!"
        Break
    }
}

#EndRegion
