[CmdletBinding()]
param()

# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

Trace-VstsEnteringInvocation $MyInvocation

    Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_ 

    $ValueType = Get-VstsInput -Name ValueType
    $KeyVaultName = Get-VstsInput -Name KeyVaultName
    $KeyVaultSecret = Get-VstsInput -Name KeyVaultSecret

    $Id = Get-VstsInput -Name Id
    $Name = Get-VstsInput -Name Name
    $Value = Get-VstsInput -Name Value
    $Tags = Get-VstsInput -Name Tags
    $MultiInsert = [System.Convert]::ToBoolean($(Get-VstsInput -Name MultiInsert))
    $ConfigFilePath = Get-VstsInput -Name ConfigFilePath

    
    Write-Host "Reqesting accessToken"
 
    . "$PSScriptRoot\utility.ps1"

    $accessToken = Get-AccessToken

    if($MultiInsert){
        Write-Host "Get config..."

        $jsonArr = Get-Content $ConfigFilePath | ConvertFrom-Json
        
        foreach($item in $jsonArr){
            if(-not $item.id -or -not $item.displayName){
                throw "$($ConfigFilePath) is not valid! 'id' and 'displayName' is required properties"
            }

            if(-not $item.value -and -not $item.secretIdentifier){
                throw "$($ConfigFilePath) is not valid! Eather 'value' or 'secretIdentifier' must be set"
            }

            Write-Host "Updates named value: $($item.id)"

            Set-NamedValue -accessToken $accessToken -item $item
            
        }
    }
    else{
        if([string]::IsNullOrWhiteSpace($Tags)){
            $tagArray = @()
        }else{
            $tagArray = $Tags.Split(',')
        }

        $namedValueItem = @{
            id = $Id
            displayName = $Name
            secret = ($ValueType -eq "secret" -or $ValueType -eq "keyVault")
            tags = $tagArray
        }

        if($ValueType -eq "keyVault"){
            $namedValueItem.secretIdentifier = "https://$KeyVaultName.vault.azure.net/secrets/$KeyVaultSecret"
        }
        
        if($ValueType -eq "secret" -or $ValueType -eq "plain"){
            $namedValueItem.value = $Value
        }

        Write-Host "Create or Update Named value: $id"
        Set-NamedValue -accessToken $accessToken -item $namedValueItem
        Write-Host "Create or Update Named value: '$id' successed!!!"
    }
    
