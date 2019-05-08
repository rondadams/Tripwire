<#
  .SYNOPSIS
    Update Tripwire Enterprise Node Descriptions with the latest version info using API.
  .DESCRIPTION
    This script will:
    1) Prompt for TE user credentials
    2) Connect to the TE API
    3) Query all nodes for the specified name and tag set (optional)
    4) Fetch list of nodes and properties
    5) Update (replace) the description with new version info contained in Make, Model, Version fields.
  
.PARAMETER Nodes
    Name of TE Nodes 
    Can be singular named node or generic
        'nodexyz'
        'odexy'
    
.PARAMETER TagSet 
    Adds Asset Tag filter to use 
    Must include Tag Set:Tag Name
        Ex: 'Operating System:Red Hat Enterprise Linux Server 7'
        
.PARAMETER IncludeDisabled 
    Switches filter to include disabled devices default is 'false'

.PARAMETER AltDesc 
    Provide an alternate description 
        Ex: 'New Description'

.PARAMETER AppendDesc 
    Appends new version information to Description

.PARAMETER TEURI 
    URI for Tripwire Enterprise API

.NOTES
    Name       : Update-TEDescAPI
    Author     : Ron Adams
    Version    : 1.0
    DateCreated: 2019-05-06
    
.EXAMPLE
    TE-Update-Node-Desc -Nodes 'nodename' 
    Updates the description of 'nodename' with the new version info (Make, Model, Version)

.EXAMPLE
    TE-Update-Node-Desc -Nodes 'odenam' 
    Uses generic version to find and update nodes that contain the string 'odenam' 

.EXAMPLE
    TE-Update-Node-Desc -Nodes 'odenam' -Tag 'Operating System:Red Hat Enterprise Linux Server 7'
    Uses generic version to find and update nodes that contain the string 'odenam' and are in the Operating System tag group,
        and tagged 'Red Hat Enterprise Linux Server 7'
    
.EXAMPLE
    TE-Update-Node-Desc -Nodes 'nodename' -AltDesc 'New Description'
    Updates the description of 'nodename' and sets description to specified value. 
        Note: This overrides the Make, Model, Version capture.

.EXAMPLE
    TE-Update-Node-Desc -Nodes 'nodename' -AltDesc 'New Description' -AppendDesc
    Updates the description of 'nodename' and Appends the description with specified value. 
        
.EXAMPLE
    TE-Update-Node-Desc -Nodes 'nodename' -TEURI 'https://tripwire.domain.com/api/v1/'
    Updates the description of 'nodename', overrides default TE API URI to specified value

#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    [Parameter(
        Mandatory = $false,
        Position = 0,
        ParameterSetName = '',
        ValueFromPipeline = $true)]
        [string]$Nodes,
    [Parameter(
        Mandatory = $false,
        Position = 1,
        ParameterSetName = '')]
        [string]$TagSet,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = '')]
        [switch]$IncludeDisabled=$false,
    [Parameter(
        Mandatory = $false,
        Position = 2,
        ParameterSetName = '')]
        [string]$AltDesc=$Null,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = '')]
        [switch]$AppendDesc=$false,
    [Parameter(
        Mandatory = $false,
        ParameterSetName = '')]
        [string]$TEURI="https://tripwire.mydomain.com/api/v1/"
    )


$DebugPreference = "Continue"
$VerbosePreference = "Continue"

# Turn off SSL validation.  (NOT RECOMMEDNED FOR PRODUCTION):
add-type @"
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
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


# 1) Prompt for TE user credentials
$Creds = Get-Credential $null

# Set URI for API connection
$Uri = $TEURI

# 2) Connect to the TE API - and pull down the CSRF token for future POST/PUT/DELETE operations:
$CSRF = Invoke-RestMethod -Uri ($Uri+'csrf-token') -Method Get -Credential $Creds -ContentType 'application/json' -Headers $headers -SessionVariable ActiveSessionVariable

# Build the header for later use
$headers = @{};
$headers.Add($CSRF.tokenName, $CSRF.tokenValue)
# X-Requested-With is required
$headers.Add("X-Requested-With", "XMLHttpRequest")
$headers.Add("User-Agent", "PowerShell Script")

#$headers | Out-String -stream | Write-Debug

# 3) Query nodes 
# Build Query string based on specified parameters
$NodesQry = 'nodes?sub_name=' + $Nodes
if ($TagSet) {
    $NodesQry += '&tag=' + [uri]::EscapeDataString($TagSet)
    }

if ($IncludeDisabled) {
    $NodesQry += '&isDisabled=true'
} else {
    $NodesQry += '&isDisabled=false'
}

$TENodes = Invoke-RestMethod -Uri ($Uri+$NodesQry) -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
Write-Debug "Returned $($TENodes.Count) Nodes"

# 4) Fetch list of nodes and properties    
$TENodes | ForEach-Object {
    $BodyData = ''
    $Node = "`"$($_.Name)`"" 
    Write-Debug $_.Name
    Write-Debug "  Old Desc: $($_.Description)"
    if ($AltDesc -and $AppendDesc -eq $false) {
        $NewDesc = $AltDesc
    } elseif ($AltDesc -and $AppendDesc -eq $true) {
        $NewDesc = "$($_.Description) " + $AltDesc
    } elseif (!$AltDesc -and $AppendDesc -eq $true) {
        $NewDesc = "$($_.Description) $($_.Make) $($_.Model) $($_.Version)"
    } else {
        $NewDesc = "$($_.Make) $($_.Model) $($_.Version)"
    }

    $BodyData = @{ description = $NewDesc }
    Write-Debug "  New Desc: $NewDesc"
    $jsonbody = $BodyData | ConvertTo-Json
    $NodesQry = 'nodes/' + $_.id
  
    #5) Update (replace) the description with new version info contained in Make, Model, Version fields.

    if ($pscmdlet.ShouldProcess($_.Name, "Update Node Desc")){
            Write-Debug  "Invoke-RestMethod"
            $Nodes = Invoke-RestMethod -Uri ($Uri+$NodesQry) -Method Put -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $jsonbody
            }
}


<# OS Version comparison 
    if ($_.Description -match 'Linux' -or $_.Model -match 'Linux') {
        # Parse out Description and Model Release info  
        $DescRls = $_.Description -match 'release\s\d.\d'
        $DescRls = $matches[0]
        $ModRls = '' 
        $ModRls = $_.Model -match 'release\s\d.\d' 
        $ModRls = $matches[0]

        if ($ModRls -ne $DescRls -and $ModRls -ne $Null) {
            
            $Nodes = Invoke-RestMethod -Uri ($Uri+$NodesQry) -Method Put -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $jsonbody
        } elseif ($Force) {
            
            $Nodes = Invoke-RestMethod -Uri ($Uri+$NodesQry) -Method Put -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $jsonbody
        }            

    # https://regex101.com/r/F6VqKw/1
    # Windows Reg Expression should handle all versions of Win7 - Win10
    $WindowsREGX = 'Windows\s\d{1,2}\.?\d?\s\d{1,2}.\d.?\d*'
    if ($_.Description -match $WindowsREGX -or $_.Model -match 'Windows\s\d{1,2}\s\d{1,2}.\d.?\d*') {
        # Parse out Description and Model Release info  
        $DescRls = $_.Description -match '\d+\.\d\.*\d*'
        $DescRls = $matches[0]

        $ModRls = '' 
        $ModRls = $_.Model -match '\d+\.\d\.*\d*' 
        $ModRls = $matches[0]

        if ($ModRls -ne $DescRls -and $ModRls -ne $Null) {        
            $Nodes = Invoke-RestMethod -Uri ($Uri+$NodesQry) -Method Put -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $jsonbody
    }
}

#>