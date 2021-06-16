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
    $endPoint = Get-VstsEndpoint -Name $ConnectedSubscription -Require
    $endpointUrl = $endPoint.Url
    $subscriptionId = $endPoint.Data.subscriptionId
    $clientId = $endPoint.Auth.Parameters.ServicePrincipalId
    $clientSecret = $endpoint.Auth.Parameters.ServicePrincipalKey
    $tenantId = $endPoint.Auth.Parameters.TenantId
    $Cloud = "https://login.microsoftonline.com"
    # $sec = $clientSecret | ConvertTo-SecureString -AsPlainText -Force
    # $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $clientid, $sec 
    # Connect-AzAccount -Tenant $tenantId -Credential $Credential -Subscription $subscriptionId -ServicePrincipal

    [string]$ApiMRG = Get-VstsInput -Name ResourceGroupName -Require 
    [string]$apimIns = Get-VstsInput -Name APIMInstanceName


    [string]$Id = Get-VstsInput -Name Id
    [string]$Name = Get-VstsInput -Name Name
    [string]$Value = Get-VstsInput -Name Value
    [bool]$IsSecret = [System.Convert]::ToBoolean($(Get-VstsInput -Name IsSecret))
    [string]$Tags = Get-VstsInput -Name Tags
    [bool]$MultiInsert = [System.Convert]::ToBoolean($(Get-VstsInput -Name MultiInsert))
    [string]$ConfigFilePath = Get-VstsInput -Name ConfigFilePath

    
    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    
    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    Write-Host "Reqesting accessToken"
 
    . "$PSScriptRoot\utility.ps1"
    ##. ".\createorupdatenamedvalue\v1\utility.ps1"

    $accessToken = Get-AccessToken -clientId $clientId -clientSecret $clientSecret
    
    if($MultiInsert){
        Write-Host "Get config..."

        $jsonArr = Get-Content $ConfigFilePath | ConvertFrom-Json
        
        foreach($item in $jsonArr){
            if(-not $item.id -or -not $item.name -or -not $item.displayName){
                throw "$($ConfigFilePath) is not valid! 'id', 'name' and 'displayName' is required properties"
            }

            if(-not $item.value -and -not $item.secretIdentifier){
                throw "$($ConfigFilePath) is not valid! Eather 'value' or 'secretIdentifier' must be set"
            }

            Write-Host "Updates named value: $($item.id) exists..."

            Set-NamedValue -accessToken $accessToken -item $item
            
        }



    }
    else{
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
    }
    
