# Export-IntunePolicy
Exports a number of Intune policies in csv and json format

## Getting Started with Export-IntunePolicy

Running this script you agree to install Microsoft.Graph PowerShell modules and consent to permissions on your system so you can connect to GraphAPI to export Intune policy information

### DESCRIPTION

Connect using Graph API (Beta) and export Intune policies of choice. As of now these are the items that can be exported:

    configurationPolicies
    deviceCompliancePolicies
    deviceConfigurations
    deviceEnrollmentConfigurations
    deviceEnrollmentPlatformRestriction
    defaultManagedAppProtections
    mdmWindowsInformationProtectionPolicies
    iosManagedAppProtections
    managedAppPolicies

- EXAMPLE 1: PS C:\Export-IntunePolicy -ResourceType configurationPolicies

    Retrieves Intune configurationPolicies and displays them in a limited custom formatted view

- EXAMPLE 2: PS C:\Export-IntunePolicy -ResourceType configurationPolicies -ShowFull

    Retrieves Intune configurationPolicies and displays them with all policy details to the console

- EXAMPLE 3: PS C:\Export-IntunePolicy -ResourceType configurationPolicies -SaveResultsToCSV

    Retrieves Intune configurationPolicies and saves the policies in csv format

- EXAMPLE 4: PS C:\Export-IntunePolicy -ResourceType configurationPolicies -SaveResultsToJSON

    Retrieves Intune configurationPolicies and saves the policies in json format

### Note on file export

All policies will be exported in csv or json to "$env:Temp\ExportedIntunePolicies". This path can be changed if necessary.
