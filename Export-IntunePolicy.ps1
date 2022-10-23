function Export-IntunePolicy {
    <#
        .SYNOPSIS
            Export Intune Policies

        .DESCRIPTION
            Connect using Graph API and export Intune policies of choice

        .PARAMETER LoggingPath
            Logging path

        .PARAMETER ResourceType
            Graph namespace to retrieve

        .PARAMETER SaveResultsToCSV
            Save results to disk in CSV format

        .PARAMETER SaveResultsToJSON
            Save results to disk in JSON format

        .PARAMETER ShowModuleInfoInVerbose
            Used to troubleshoot module install and import

        .PARAMETER ShowFull
            Save results to disk

        .EXAMPLE
            PS C:\Export-IntunePolicy -ResourceType configurationPolicies

            Retrieves Intune configurationPolicies and displays them in a limited custom formatted view

        .EXAMPLE
            PS C:\Export-IntunePolicy -ResourceType configurationPolicies -ShowFull

            Retrieves Intune configurationPolicies and displays them with all policy details to the console

        .EXAMPLE
            PS C:\Export-IntunePolicy -ResourceType configurationPolicies -SaveResultsToCSV

            Retrieves Intune configurationPolicies and saves the policies in csv format

        .EXAMPLE
            PS C:\Export-IntunePolicy -ResourceType configurationPolicies -SaveResultsToJSON

            Retrieves Intune configurationPolicies and saves the policies in json format

        .NOTES
            https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-1.0
   #>

    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    [Alias('ExportIP')]
    param(
        [string]
        $LoggingPath = "$env:Temp\ExportedIntunePolicies",

        [ValidateSet('configurationPolicies', 'deviceCompliancePolicies', 'deviceConfigurations', 'deviceEnrollmentConfigurations', `
                'deviceEnrollmentPlatformRestriction', 'defaultManagedAppProtections', `
                'mdmWindowsInformationProtectionPolicies', 'iosManagedAppProtections', 'managedAppPolicies' )]
        [string]
        $ResourceType = "deviceCompliancePolicies",

        [switch]
        $SaveResultsToCSV,

        [switch]
        $SaveResultsToJSON,

        [switch]
        $ShowModuleInfoInVerbose,

        [switch]
        $ShowFull
    )

    begin {
        Write-Output "Starting Intune policy export"
        $parameters = $PSBoundParameters
        [System.Collections.ArrayList]$configurationPolicies = @()
        $modules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Intune")
        $successful = $false
    }

    process {
        if ($PSVersionTable.PSEdition -ne 'Core') {
            Write-Output "You need to run this script using PowerShell core due to dependencies."
            return
        }

        try {
            if (-NOT(Test-Path -Path $LoggingPath)) {
                if (New-Item -Path $LoggingPath -ItemType Directory -ErrorAction Stop) {
                    Write-Verbose "$LoggingPath directory created!"
                }
            }
            Write-Verbose "$LoggingPath directory already exists!"
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            foreach ($module in $modules) {
                if ($found = Get-Module -Name $module -ListAvailable | Sort-Object Version | Select-Object -First 1) {
                    if (Import-Module -Name $found -ErrorAction Stop -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                        Write-Verbose "$found imported!"
                        $successful = $true
                    }
                    else {
                        Throw "Error importing $($found). Please Run Export-IntunePolicy -Verbose -ShowModuleInfoInVerbose"
                    }
                }
                else {
                    Write-Output "$module not found! Installing module $($module) from the PowerShell Gallery"
                    if (Install-Module -Name $module -Repository PSGallery -Force -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                        Write-Verbose "$module installed successfully! Importing $($module)"
                        if (Import-Module -Name $module -ErrorAction Stop -Verbose:$ShowModuleInfoInVerbose -PassThru) {
                            Write-Verbose "$module imported successfully!"
                            $successful = $true
                        }
                        else {
                            Throw "Error importing $($found). Please Run Export-IntunePolicy -Verbose -ShowModuleInfoInVerbose"
                        }
                    }
                }
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            if ($successful) {
                Select-MgProfile -Name "beta" -ErrorAction Stop
                Write-Verbose "Using MGProfile (Beta)"
                Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All", "DeviceManagementServiceConfig.Read.All" -ForceRefresh -ErrorAction Stop
            }
            else {
                Write-Output "Error: Unable to connect to the Graph endpoint. $_"
                return
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            if (($ResourceType -eq 'iosManagedAppProtections') -or ($ResourceType -eq 'managedAppPolicies')`
                    -or ($ResourceType -eq 'defaultManagedAppProtections') -or ($ResourceType -eq 'mdmWindowsInformationProtectionPolicies')) {
                $uri = "https://graph.microsoft.com/beta/deviceAppManagement/$ResourceType"
            }
            else {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/$ResourceType"
            }

            Write-Output "Querying Graph uri: $($uri)"
            if ($policies = Invoke-MgGraphRequest -Method GET -Uri $uri) {
                foreach ($policy in $policies.value) {
                    $policyFound = [PSCustomObject]@{ PSTypeName = "Intune $ResourceType" }
                    foreach ($policyItem in $policy.GetEnumerator()) {
                        if (($policyItem.Key -eq 'validOperatingSystemBuildRanges') -or ($policyItem.Key -eq 'roleScopeTagIds')) {
                            $policyFound | Add-Member -MemberType NoteProperty -Name $policyItem.key -Value ($policyItem.Value -Join ',')
                        }
                        else {
                            $policyFound | Add-Member -MemberType NoteProperty -Name $policyItem.key -Value $policyItem.value
                        }
                    }
                    $null = $configurationPolicies.add($policyFound)
                }
            }
            else {
                Write-Output "No Graph results returned!"
            }
        }
        catch {
            Write-Output "Error: $_"
        }

        try {
            if ($parameters.ContainsKey('ShowFull')) {
                [PSCustomObject]$configurationPolicies
            }
            else {
                if ($ResourceType -eq 'configurationPolicies') {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'name', 'id', 'createdDateTime', 'lastModifiedDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                }
                if (($ResourceType -eq 'deviceCompliancePolicies') -or
                ($ResourceType -eq 'deviceConfigurations') -or
                (($ResourceType -eq 'deviceEnrollmentConfigurations'))) {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'displayName', 'id', 'createdDateTime', 'lastModifiedDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                }
            }

            if ($parameters.ContainsKey('SaveResultsToCSV')) {
                foreach ($policy in $configurationPolicies) {
                    Write-Verbose "Saving $($policy.displayName + ".csv")"
                    [PSCustomObject]$policy | Export-Csv -Path (Join-Path -Path $LoggingPath -ChildPath $($policy.displayName + ".csv")) -ErrorAction Stop -Encoding UTF8 -NoTypeInformation -Append
                }
            }

            if ($parameters.ContainsKey('SaveResultsToJSON')) {
                foreach ($policy in $configurationPolicies) {
                    Write-Verbose "Saving $($policy.displayName + ".json")"
                    [PSCustomObject]$policy | ConvertTo-Json -Depth 10 | Set-Content (Join-Path -Path $LoggingPath -ChildPath $($policy.displayName + ".json")) -ErrorAction Stop -Encoding UTF8
                }
            }
        }
        catch {
            Write-Output "Error: $_"
        }
    }

    end {
        if (($parameters.ContainsKey('SaveResultsToCSV')) -or ($parameters.ContainsKey('SaveResultsToJSON'))) {
            Write-Output "`nResults exported to: $($LoggingPath)`nCompleted!"
        }
        else {
            Write-Output "`nCompleted!"
        }
    }
}