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
    $endpointUrl = $endPointRM.Url
    $subscriptionId = $endPointRM.Data.subscriptionId
    $clientId = $endPointRM.Auth.Parameters.ServicePrincipalId
    $clientSecret = $endPointRM.Auth.Parameters.ServicePrincipalKey
    $tenantId = $endPointRM.Auth.Parameters.TenantId
    $Cloud = "https://login.microsoftonline.com"
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
    [bool]$MultiInsert = [System.Convert]::ToBoolean($(Get-VstsInput -Name MultiInsert))
    [string]$ConfigFilePath = Get-VstsInput -Name ConfigFilePath

    
    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    $securedClientID = ConvertTo-SecureString $clientId -AsPlainText -Force
    $bstrClientId = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedClientID)
    $plainClienId = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrClientId)

    $securedClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $bstrClientSecret = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedClientSecret)
    $plainClienSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrClientSecret)
    Write-Host "ClientId: $($plainClienId)"
    Write-Host "ClientSecret: $($plainClienSecret)"
    Write-Host "endpointUrl: $($endpointUrl)"

    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    Write-Host "Reqesting accessToken"

    $body="resource=https%3A%2F%2Fmanagement.azure.com%2F"+
            "&client_id=$($clientId)"+
            "&grant_type=client_credentials"+
            "&client_secret=$($clientSecret)"
    try
    {
        $resp=Invoke-WebRequest -UseBasicParsing -Uri "$($Cloud)/$($tenantId)/oauth2/token" `
            -Method POST `
            -Body $body| ConvertFrom-Json    

        Write-Host "Successfully received access-token"
    
    }
    catch [System.Net.WebException] 
    {
        $er=$_.ErrorDetails.Message.ToString()|ConvertFrom-Json
        write-host $er.error.details
        throw
    }
    
    $headers = @{
        Authorization = "Bearer $($resp.access_token)"        
    }
    
    
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

            $baseurl="$($endpointUrl)subscriptions/$($subscriptionId)/resourceGroups/$($ApiMRG)/providers/Microsoft.ApiManagement/service/$($apimIns)"
                                   
		    $targeturl="$($baseurl)/namedValues/$($item.id)?api-version=2021-01-01-preview"	
		
            try
            {
                if($item.secretIdentifier){
                    Write-Host "Adding named value using keyvault"
                    $json = @{
                        properties = [ordered]@{
                            displayName = $item.displayName
                            keyVault = @{
                                secretIdentifier = $item.secretIdentifier
                                identityClientId = $null
                            }
                            tags = $item.tags
                            secret = $item.secret
                        }
                    } | ConvertTo-Json

                }
                else{
                    Write-Host "Adding named value using plain"
                    $json = @{
                        properties = [ordered]@{
                            displayName = $item.displayName
                            value = $item.value
                            tags = $item.tags
                            secret = $item.secret
                        }
                    } | ConvertTo-Json
                }
                Invoke-WebRequest -UseBasicParsing -Uri $targeturl -Body $json -ContentType "application/json" -Headers $headers -Method Put
                
                
            }
            catch [System.Net.WebException] 
            {
                throw
            }
	
            
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
    
