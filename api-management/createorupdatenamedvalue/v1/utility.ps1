
$ConnectedSubscription = Get-VstsInput -Name ConnectedSubscription -Require
$ApiMRG = Get-VstsInput -Name ResourceGroupName -Require 
$apimIns = Get-VstsInput -Name APIMInstanceName
$endPoint = Get-VstsEndpoint -Name $ConnectedSubscription -Require
$endpointUrl = $endPoint.Url
$subscriptionId = $endPoint.Data.subscriptionId
$tenantId = $endPoint.Auth.Parameters.TenantId
$clientId = $endPoint.Auth.Parameters.ServicePrincipalId
$clientSecret = $endpoint.Auth.Parameters.ServicePrincipalKey
$Cloud = "https://login.microsoftonline.com"


function Get-AccessToken{
    [CmdletBinding()]
    param()

    $body = @{
        resource = "https://management.azure.com"
        client_id = "$($clientId)"
        client_secret = "$($clientSecret)"
        grant_type = "client_credentials"
    }

    $conentType = 'application/x-www-form-urlencoded' 

    try
    {
        $resp=Invoke-WebRequest -UseBasicParsing -Uri "$($Cloud)/$($tenantId)/oauth2/token" -Method POST -Body $body -ContentType $conentType | ConvertFrom-Json    

        Write-Host "Successfully received access-token"

        return $resp.access_token
    
    }
    catch [System.Net.WebException] 
    {
        $er=$_.ErrorDetails.Message.ToString()|ConvertFrom-Json
        write-host $er.error.details
        throw
    }
}


function Set-NamedValue{
    [CmdletBinding()]
    param($accessToken, $item)

    $baseurl="$($endpointUrl)subscriptions/$($subscriptionId)/resourceGroups/$($ApiMRG)/providers/Microsoft.ApiManagement/service/$($apimIns)"
                                   
    $targeturl="$($baseurl)/namedValues/$($item.id)?api-version=2021-01-01-preview"	

    
    $headers = @{
        Authorization = "Bearer $($accessToken)"        
    }

    
    

    try
        {
            if($item.secretIdentifier){
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
                $regex = "\$\(([^\)]+)\)" #check if the string is a variable
                $match = [regex]::Match($item.value, $regex)
                if($match.Success){
                    $var = ($item.value).TrimStart('$').TrimStart('(').TrimEnd(')')
                    Write-host "Get Variable:" -ForegroundColor Yellow
                    $varItem = Get-ChildItem "env:$var"
                    $secretVar = "$($var)"
                    Write-host "Get secret Variable:" -ForegroundColor Yellow
                    $secretVar
                    $json = @{
                        properties = [ordered]@{
                            displayName = $item.displayName
                            value = $varItem.Value
                            tags = $item.tags
                            secret = $item.secret
                        }
                    } | ConvertTo-Json    
                }
                else{
                    $json = @{
                        properties = [ordered]@{
                            displayName = $item.displayName
                            value = $item.value
                            tags = $item.tags
                            secret = $item.secret
                        }
                    } | ConvertTo-Json
                }
                
            }
            
            $resp = Invoke-WebRequest -UseBasicParsing -Uri $targeturl -Body $json -ContentType "application/json" -Headers $headers -Method Put 
            
            
            
        }
        catch [System.Net.WebException] 
        {
            $er=$_.ErrorDetails.Message.ToString()|ConvertFrom-Json
            write-host $er.error.details
            throw
        }
}