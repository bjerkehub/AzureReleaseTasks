[CmdletBinding()]
param()

# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

Trace-VstsEnteringInvocation $MyInvocation


    

    Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_ 
    Install-Module -Name Az.ApiManagement -AllowClobber -Scope CurrentUser -Force
    Import-Module Az.ApiManagement

    $serviceNameInput = Get-VstsInput -Name ConnectedServiceNameSelector -Require
    $serviceName = Get-VstsInput -Name $serviceNameInput -Require
    $endPointRM = Get-VstsEndpoint -Name $serviceName -Require

    $subscriptionId = $endPointRM.Data.subscriptionId
    $clientId = $endPointRM.Auth.Parameters.ServicePrincipalId
    $clientSecret = $endPointRM.Auth.Parameters.ServicePrincipalKey
    $tenantId = $endPointRM.Auth.Parameters.TenantId

    $sec = $clientSecret | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $clientid, $sec 
    Connect-AzAccount -Tenant $tenantId -Credential $Credential -Subscription $subscriptionId -ServicePrincipal

    [string]$ApiMRG = Get-VstsInput -Name ResourceGroupName -Require 
    [string]$apimIns = Get-VstsInput -Name APIMInstanceName

    [string]$APIMProduct = Get-VstsInput -Name APIMProduct
    [string]$APIMProductDisplayName = Get-VstsInput -Name APIMProductDisplayName
    [string]$APIMProductDescription = Get-VstsInput -Name APIMProductDescription
    $ProductSubscriptionRequiredAsString = Get-VstsInput -Name ProductSubscriptionRequired
    [bool]$ProductSubscriptionRequired = [System.Convert]::ToBoolean($ProductSubscriptionRequiredAsString)
    [int]$ProductSubscriptionsLimit = Get-VstsInput -Name ProductSubscriptionsLimit
    $ProductApprovalRequiredAsString = Get-VstsInput -Name ProductApprovalRequired
    [bool]$ProductApprovalRequired = [System.Convert]::ToBoolean($ProductApprovalRequiredAsString)
    $ProductStateAsString = Get-VstsInput -Name ProductState
    [bool]$ProductState = [System.Convert]::ToBoolean($ProductStateAsString)
    $ProductGroups = $(Get-VstsInput -Name ProductGroups).Split([Environment]::NewLine)
    [string]$ProductPolicyArtifact = Get-VstsInput -Name ProductPolicyArtifact
    Set-VstsTaskVariable -Name "productName" -Value $APIMProduct
    [string]$ProductLegalTerms = Get-VstsInput -Name APIMProductLegalTerms
    Write-Host "ProductLegalTerms: $($ProductLegalTerms)"

    if($ProductState -eq $true)
    {
        $state = "published"
    }
    else 
    {
        $state = "notPublished"
    }

    if($null -eq $ProductSubscriptionsLimit -or $ProductSubscriptionsLimit -eq "")
    {
        $ProductSubscriptionsLimit='null'
    }


    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    Write-Host 'Checking if the product exists'

    $product = Get-AzApiManagementProduct -Context $apiManagementContext -ProductId $APIMProduct
    
    if($product){
        Write-Host 'Product found...Updates product!'

        Set-AzApiManagementProduct -Context $apiManagementContext -ProductId $APIMProduct -Title $APIMProductDisplayName -Description $APIMProductDescription -SubscriptionRequired $ProductSubscriptionRequired -ApprovalRequired $ProductApprovalRequired -SubscriptionsLimit $ProductSubscriptionsLimit -State $state -LegalTerms $ProductLegalTerms

        Write-Host 'Product updated'
    }
    else 
    {
        Write-Host 'Product not found...Creating product!'

        New-AzApiManagementProduct -Context $apiManagementContext -ProductId $APIMProduct -Title $APIMProductDisplayName -Description $APIMProductDescription -SubscriptionRequired $ProductSubscriptionRequired -ApprovalRequired $ProductApprovalRequired -SubscriptionsLimit $ProductSubscriptionsLimit -State $state -LegalTerms $ProductLegalTerms
    
        Write-Host 'Product created'
    }

    #Get product again, to make sure we have the lates version of the product
    $product = Get-AzApiManagementProduct -Context $apiManagementContext -ProductId $APIMProduct
    
    $createdProducts = Get-VstsTaskVariable -Name "NewUpdatedProducts"

    if([string]::IsNullOrWhiteSpace($createdProducts)){
        $createdProducts = "$($product.ProductId)"
    }
    else{
        $createdProducts += ";$($product.ProductId)"
    }

    # Write-Host ("##vso[task.setvariable variable=NewUpdatedProduct;]$product")
    Write-Host "Setting product: $($createdProducts) to variable: NewUpdatedProducts"
    Set-VstsTaskVariable -Name "NewUpdatedProducts" -Value $createdProducts

    Write-Host 'Checking if the groups exists'


    foreach($group in $ProductGroups)
    {
        Write-Host $group
        $groupExists = Get-AzApiManagementGroup -Context $apiManagementContext -GroupId $group

        if($groupExists)
        {
            Write-Host "Group $($group) found...linking to product!"
            Add-AzApiManagementProductToGroup -Context $apiManagementContext -GroupId $group -ProductId $APIMProduct
        }
        else
        {
            Write-Host "Group with name $($group) not found"
        }
    }


    if($ProductPolicyArtifact -ne $env:Build_SourcesDirectory -and !(Test-Path $ProductPolicyArtifact) )
    {
        Write-Host 'Set product policy!'
        Set-AzApiManagementPolicy -Context $apiManagementContext -ProductId $APIMProduct -PolicyFilePath $ProductPolicyArtifact
    }

    

