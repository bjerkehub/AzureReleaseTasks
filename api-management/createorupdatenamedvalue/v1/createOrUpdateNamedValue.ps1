[CmdletBinding()]
param()

# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

Trace-VstsEnteringInvocation $MyInvocation

    Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_ 
    Install-Module -Name Az.ApiManagement -AllowClobber -Scope CurrentUser -Force
    Install-Module -Name Az.Resources -AllowClobber -Scope CurrentUser -Force
    Import-Module Az.ApiManagement 
    Import-Module Az.Resources

    $ConnectedSubscription = Get-VstsInput -Name ConnectedSubscription -Require
    $endPointRM = Get-VstsEndpoint -Name $ConnectedSubscription -Require

    $subscriptionId = $endPointRM.Data.subscriptionId
    $clientId = $endPointRM.Auth.Parameters.ServicePrincipalId
    $clientSecret = $endPointRM.Auth.Parameters.ServicePrincipalKey
    $tenantId = $endPointRM.Auth.Parameters.TenantId

    $sec = $clientSecret | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $clientid, $sec 
    Connect-AzAccount -Tenant $tenantId -Credential $Credential -Subscription $subscriptionId -ServicePrincipal

    [string]$ApiMRG = Get-VstsInput -Name ResourceGroupName -Require 
    [string]$apimIns = Get-VstsInput -Name APIMInstanceName


    [string]$Id = Get-VstsInput -Name Id
    [string]$Name = Get-VstsInput -Name Name
    [string]$Value = Get-VstsInput -Name Value
    [bool]$IsSecret = [System.Convert]::ToBoolean($(Get-VstsInput -Name IsSecret))
    [string]$Tags = Get-VstsInput -Name Tags

    
    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    Write-Host "Checking if named value: $($Id) exists..."
    try { $existingNamedValue = Get-AzApiManagementNamedValue -Context $apiManagementContext -NamedValueId $Id } catch {$_.Exception.Response.StatusCode.Value__}


    if([string]::IsNullOrWhiteSpace($Tags)){
        $tagArray = @()
    }else{
        $tagArray = $Tags.Split(',')
    }

    if($existingNamedValue){
        Write-Host "Named value $($Id) found...update..."
        if($IsSecret){
            Set-AzApiManagementNamedValue -Context $apiManagementContext -NamedValueId $Id -Name $Name -Value $Value -Tag $tagArray -Secret $True
        }else{
            Set-AzApiManagementNamedValue -Context $apiManagementContext -NamedValueId $Id -Name $Name -Value $Value -Tag $tagArray -Secret $False
        }
        
        Write-Host "Named value $($Id) updated!"
    }
    else{
        Write-Host "Named value $($Id) not found...creating..."
        if($IsSecret){
            New-AzApiManagementNamedValue -Context $apiManagementContext -NamedValueId $Id -Name $Name -Value $Value -Tag $tagArray -Secret
        }else{
            New-AzApiManagementNamedValue -Context $apiManagementContext -NamedValueId $Id -Name $Name -Value $Value -Tag $tagArray
        }
        
        Write-Host "Named value $($Id) created!"
    }
