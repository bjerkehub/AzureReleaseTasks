




function Get-AccessToken{
    [CmdletBinding()]
    param($clientId, $clientSecret)


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