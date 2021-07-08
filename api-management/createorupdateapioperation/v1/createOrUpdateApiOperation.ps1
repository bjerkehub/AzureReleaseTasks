[CmdletBinding()]
param()

# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

Trace-VstsEnteringInvocation $MyInvocation

    Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_ 
    Install-Module -Name Az.ApiManagement -AllowClobber -Scope CurrentUser -Force
    Import-Module Az.ApiManagement

    $ConnectedSubscription = Get-VstsInput -Name ConnectedSubscription -Require
    $endPointRM = Get-VstsEndpoint -Name $ConnectedSubscription -Require

    $subscriptionId = $endPointRM.Data.subscriptionId
    $clientId = $endPointRM.Auth.Parameters.ServicePrincipalId
    $clientSecret = $endPointRM.Auth.Parameters.ServicePrincipalKey
    $tenantId = $endPointRM.Auth.Parameters.TenantId

    $sec = $clientSecret | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $clientid, $sec 
    Connect-AzAccount -Tenant $tenantId -Credential $Credential -Subscription $subscriptionId -ServicePrincipal

    $ApiMRG = Get-VstsInput -Name ResourceGroupName -Require 
    $apimIns = Get-VstsInput -Name APIMInstanceName



    $ApiName = Get-VstsInput -Name ApiName
    $OperationId = Get-VstsInput -Name OperationId
    $OperationName = Get-VstsInput -Name OperationName
    $OperationDescription = Get-VstsInput -Name OperationDescription
    $Method = Get-VstsInput -Name Method
    $UrlTemplate = Get-VstsInput -Name UrlTemplate
    $ApiCreatedPrevious = Get-VstsInput -Name ApiCreatedPrevious

    
    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    if($ApiCreatedPrevious -eq $true){
        Write-Host 'Checking api created by prevous task'
        $newApi = Get-VstsTaskVariable -Name "NewUpdatedApi"

        if ([string]::IsNullOrWhiteSpace($newApi))
        {
            throw "There was no api created by a previous task"
        }
        
        Write-Host "Api created by a previous task: $newApi"
        Write-Host "Checking if api: $newApi exists"

        try { $api = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $newApi } catch {$_.Exception.Response.StatusCode.Value__}

        if($api){
            Write-Host "Api: '$($api.ApiId)' exists...continue"
        }
        else{
            throw "Could not find any product with id: $($api.ApiId)"
        }

        
    }
    else{
        Write-Host "Checking if api exists"    
        try { $api = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}
            
        if($api)
        {
            Write-Host "Api: '$apiName' exists...continue"
        }
        else 
        {
            throw "Could not find any api with id: $ApiName"   
        } 
    }
    

    try { $operation = Get-AzApiManagementOperation -Context $context -ApiId $api.ApiId -OperationId $operationId } catch {$_.Exception.Response.StatusCode.Value__}

    if($operation){
        Write-host "Updates existing operation with id: $operationId"
        
        Set-AzApiManagementOperation -Context $apiManagementContext -ApiId $api.ApiId -OperationId $OperationId -Name $OperationName -Description $OperationDescription -Method $Method -UrlTemplate $UrlTemplate -TemplateParameters $operation.TemplateParameters -Request $operation.Request -Responses $operation.Responses

        Write-host "Successfully updated operation with id: $operationId"

    }

    else{
        Write-host "Creates new operation with id: $operationId"

        New-AzApiManagementOperation -Context $apiManagementContext -ApiId $api.ApiId -OperationId $OperationId -Name $OperationName -Description $OperationDescription -Method $Method -UrlTemplate $UrlTemplate

        Write-host "Successfully created operation with id: $operationId"
    }

    

    

