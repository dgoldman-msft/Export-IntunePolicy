function New-LoggingDirectory {
    <#
        .SYNOPSIS
            Create directories

        .DESCRIPTION
            Create the root and all subfolder needed for logging

        .PARAMETER LoggingPath
            Logging Path

        .PARAMETER SubFolder
            Switch to indicated we are creating a subfolder

        .PARAMETER SubFolderName
            Subfolder Name

        .EXAMPLE
            PS C:\New-LoggingDirectory -SubFolder SubFolderName

        .NOTES
            Internal function
    #>

    [OutputType('System.IO.Folder')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]
        $LoggingPath,

        [switch]
        $SubFolder,

        [string]
        $SubFolderName
    )

    begin {
        if (-NOT($SubFolder)) {
            Write-Verbose "Creating directory: $($LoggingPath)"
        }
        else {
            Write-Verbose "Creating directory: $LoggingPath\$SubFolderName)"
        }
    }

    process {
        try {
            # Leaving this here in case the root directory gets deleted between executions so we will re-create it again
            if (-NOT(Test-Path -Path $LoggingPath)) {
                if (New-Item -Path $LoggingPath -ItemType Directory -ErrorAction Stop) {
                    Write-Verbose "$LoggingPath directory created!"
                }
                else {
                    Write-Verbose "$($LoggingPath) already exists!"
                }
            }
            if ($SubFolder) {
                if (-NOT(Test-Path -Path $LoggingPath\$SubFolderName)) {
                    if (New-Item -Path $LoggingPath\$SubFolderName -ItemType Directory -ErrorAction Stop) {
                        Write-Verbose "$LoggingPath\$SubFolderName directory created!"
                    }
                    else {
                        Write-Verbose "$($SubFolderName) already exists!"
                    }
                }
            }
        }
        catch {
            Write-Output "Error: $_"
            return
        }
    }

}

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
            https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-devicemanagement?view=graph-rest-beta
   #>

    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    [Alias('ExportIP')]
    param(
        [ValidateSet('Global', 'GCC', 'DOD')]
        [parameter(Position = 0)]
        [string]
        $Endpoint = 'Global',

        [parameter(Position = 1)]
        [string]
        $LoggingPath = "$env:Temp\ExportedIntunePolicies",

        [parameter(Position = 2)]
        [ValidateSet('androidManagedAppProtections', 'configurationPolicies', 'deviceManagementScripts', 'deviceCompliancePolicies', 'deviceComplianceScripts', 'deviceConfigurations', `
                'deviceEnrollmentConfigurations', 'defaultManagedAppProtections', 'deviceManagementPartners', 'importedWindowsAutopilotDeviceIdentities', 'iosManagedAppProtections', `
                'iosUpdateStatuses', 'managedAppPolicies', 'managedAppRegistrations', 'mdmWindowsInformationProtectionPolicies', 'roleAssignments', 'roleDefinitions', 'resourceOperations', `
                'softwareUpdateStatusSummary', 'templates', 'vppTokens', 'windowsAutopilotDeviceIdentities' )]
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
        $saveAsJson = $false
    }

    process {
        if ($PSVersionTable.PSEdition -ne 'Core') {
            Write-Output "You need to run this script using PowerShell core due to dependencies."
            return
        }

        try {
            # Create root directory
            New-LoggingDirectory -LoggingPath $LoggingPath
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
                If ($Endpoint -eq 'Global') {
                    Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All", `
                        "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All" -Environment Global -ErrorAction Stop
                }
                if ($Endpoint -eq 'GCC') {
                    Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All", `
                        "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All" -Environment USGov -ErrorAction Stop
                }
                if ($Endpoint -eq 'Dod') {
                    Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All", `
                        "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All" -Environment USGovDoD -ErrorAction Stop
                }
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
            if (($ResourceType -eq 'iosManagedAppProtections') -or ($ResourceType -eq 'managedAppPolicies') -or ($ResourceType -eq 'vppTokens')`
                    -or ($ResourceType -eq 'defaultManagedAppProtections') -or ($ResourceType -eq 'mdmWindowsInformationProtectionPolicies')`
                    -or ($ResourceType -eq 'androidManagedAppProtections') -or $ResourceType -eq 'managedAppRegistrations') {

                switch ($Endpoint) {
                    'Global' {
                        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/$ResourceType"
                        continue
                    }
                    'GCC' {
                        $uri = "https://graph.microsoft.us/beta/deviceAppManagement/$ResourceType"
                        continue
                    }
                    'DoD' {
                        $uri = "https://dod-graph.microsoft.us/beta/deviceAppManagement/$ResourceType"
                        continue
                    }
                }
            }
            else {
                switch ($Endpoint) {
                    'Global' {
                        $uri = "https://graph.microsoft.com/beta/deviceManagement/$ResourceType"
                        continue
                    }
                    'GCC' {
                        $uri = "https://graph.microsoft.us/beta/deviceManagement/$ResourceType"
                        continue
                    }
                    'DoD' {
                        $uri = "https://dod-graph.microsoft.us/beta/deviceManagement/$ResourceType"
                        continue
                    }
                }
            }

            Write-Output "Querying Graph uri: $($uri)"
            if ($policies = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop) {
                foreach ($policy in $policies.value) {
                    $policyFound = [PSCustomObject]@{ PSTypeName = "Intune $ResourceType" }
                    foreach ($policyItem in $policy.GetEnumerator()) {
                        if (($policyItem.Key -eq 'validOperatingSystemBuildRanges') -or ($policyItem.Key -eq 'roleScopeTagIds')) {
                            $policyFound | Add-Member -MemberType NoteProperty -Name $policyItem.key -Value ($policyItem.Value -Join ',') -ErrorAction Stop
                        }
                        else {
                            $policyFound | Add-Member -MemberType NoteProperty -Name $policyItem.key -Value $policyItem.value -ErrorAction Stop
                        }
                    }

                    # Pull the settings catalog for the policies
                    if ($ResourceType -eq "configurationPolicies") {
                        $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.id)')/settings"
                        Write-Output "Querying Graph uri: $($uri) for policy settings"
                        if ($policySettings = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop) {
                            $policyFound | Add-Member -MemberType NoteProperty -Name "Policy Settings" -Value ($policySettings) -ErrorAction Stop
                        }
                    }
                    $null = $configurationPolicies.add($policyFound)
                }
            }
            else {
                Write-Output "No results returned!"
            }
        }
        catch {
            Write-Output "Error: $_"
        }

        try {
            # If no data was found then bail out
            if ($configurationPolicies.count -eq 0) {
                Write-Output "Not data found!"
                return
            }

            if ($parameters.ContainsKey('SaveResultsToCSV')) {
                # These do not format well in CSV and json is a much better choice to get all details
                if ($ResourceType -eq 'configurationPolicies|roleDefinitions|roleAssignments|resourceOperations') {
                    Write-Output "$($ResourceType) need to be saved in json format to retail all formatting and data."
                    $saveAsJson = $true
                }
                else {
                    foreach ($policy in $configurationPolicies) {
                        New-LoggingDirectory -LoggingPath $LoggingPath -SubFolder $ResourceType
                        Write-Verbose "Saving $($policy.description + ".csv")"
                        [PSCustomObject]$policy | Export-Csv -Path (Join-Path -Path $LoggingPath\$ResourceType -ChildPath $($policy.displayName + ".csv")) -Encoding UTF8 -NoTypeInformation -ErrorAction Stop
                    }
                }
            }

            if ($parameters.ContainsKey('SaveResultsToJSON') -or ($saveAsJson)) {
                foreach ($policy in $configurationPolicies) {
                    New-LoggingDirectory -LoggingPath $LoggingPath -SubFolder $ResourceType
                    switch -wildcard ($ResourceType) {
                        'res*' {
                            $policyName = $policy.resourceName
                            [PSCustomObject]$policy | ConvertTo-Json -Depth 10 | Set-Content (Join-Path -Path $LoggingPath\$ResourceType -ChildPath $($policyName + ".json")) -ErrorAction Stop -Encoding UTF8
                            Write-Verbose "Saving $($policyName + ".json")"
                        }

                        Default {
                            [PSCustomObject]$policy | ConvertTo-Json -Depth 10 | Set-Content (Join-Path -Path $LoggingPath\$ResourceType -ChildPath $($policy.description + ".json")) -ErrorAction Stop -Encoding UTF8
                            Write-Verbose "Saving $($policy.description + ".json")"
                        }
                    }

                }
            }

            # Display to the console results
            if ($parameters.ContainsKey('ShowFull')) {
                [PSCustomObject]$configurationPolicies
            }

            # Switch based on resource type and display with a custom view
            switch -Wildcard ($ResourceType) {
                'config*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'name', 'id', 'createdDateTime', 'lastModifiedDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'deviceManagement*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'displayName', 'id', 'partnerAppType', 'isConfigured'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'importedWindowsAutopilot*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'serialNumber', 'id', 'hardwareIdentifier'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'iosUpdateStatuses*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'userName', 'id', 'osVersion', 'deviceModel', 'lastReportedDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'managedApp*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'deviceName', 'deviceTag', 'createdDateTime', 'lastSyncDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'resourceOperations' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'resourceName', 'id', 'actionName'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'role*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'displayName', 'id'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'softwareUpdate*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'displayName', 'id', 'compliantDeviceCount', 'nonCompliantDeviceCount', 'errorDeviceCount'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                'windowsAutopilot*' {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'managedDeviceId', 'id', 'enrollmentState', 'serialNumber'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }

                Default {
                    $TypeData = @{
                        TypeName                  = "Intune $ResourceType"
                        DefaultDisplayPropertySet = 'displayName', 'id', 'createdDateTime', 'lastModifiedDateTime'
                    }
                    Update-TypeData @TypeData
                    [PSCustomObject]$configurationPolicies
                    Remove-TypeData -TypeName "Intune $ResourceType"
                    continue
                }
            }
        }
        catch {
            Write-Output "Error: $_"
        }
    }

    end {
        if (($configurationPolicies.Count -gt 0) -and ($parameters.ContainsKey('SaveResultsToCSV') -or ($parameters.ContainsKey('SaveResultsToJSON')))) {
            Write-Output "`nResults exported to: $($LoggingPath)`nCompleted!"
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
        else {
            Write-Output "Completed!"
        }
    }
}