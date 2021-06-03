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

    [bool]$ProductCreatedPrevious = [System.Convert]::ToBoolean($(Get-VstsInput -Name ProductCreatedPrevious))
    [string]$APIMProducts = Get-VstsInput -Name APIMProducts
    [string]$Authorization = Get-VstsInput -Name Authorization
    [string]$OauthServer = Get-VstsInput -Name oauth
    [string]$OidServer = Get-VstsInput -Name oid
    [string]$ApiName = Get-VstsInput -Name ApiName
    [string]$ApiDisplayName = Get-VstsInput -Name ApiDisplayName
    [string]$ApiDescription = Get-VstsInput -Name ApiDescription
    [string]$BackendUrl = Get-VstsInput -Name BackendUrl
    [string]$ApiUrlSuffix = Get-VstsInput -Name ApiUrlSuffix
    [bool]$ShouldAddVersion =  [System.Convert]::ToBoolean($(Get-VstsInput -Name ShouldAddVersion))
    [bool]$IsSubscriptionRequired = [System.Convert]::ToBoolean($(Get-VstsInput -Name IsSubscriptionRequired))
    [string]$APIPolicy = Get-VstsInput -Name APIPolicy
    [string]$APIOperationPolicies = Get-VstsInput -Name APIOperationPolicies
    [string]$VersionName = Get-VstsInput -Name VersionName
    [string]$OpenAPISpec = Get-VstsInput -Name OpenAPISpec
    [string]$SwaggerPicker = Get-VstsInput -Name SwaggerPicker 
    [string]$SwaggerFilePath = Get-VstsInput -Name SwaggerFilePath
	[string]$SwaggerUrl=Get-VstsInput -Name SwaggerUrl
    
    $apiManagementContextParams = @{
        ResourceGroupName = $ApiMRG
        ServiceName = $apimIns
    }

    $apiManagementContext = New-AzApiManagementContext @apiManagementContextParams

    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

    
    $importSwaggerParams = @{
        Context = $apiManagementContext 
        Path = $apiURLSuffix 
        ServiceUrl = $backendUrl 
        Protocol = "Https" 
        
    }

    switch ($OpenAPISpec) {
        "v2" { 
            Write-Host "Setting specificationFormat = Swagger"
            $importSwaggerParams.SpecificationFormat = "Swagger" 
        }
        "v3" { 
            Write-Host "Setting specificationFormat = OpenApiJson"
            $importSwaggerParams.SpecificationFormat = "OpenApiJson" 
        }
        Default {
            throw "OpenApi version not set. Suported values is: v2 or v3"
        }
    }

    switch($SwaggerPicker)
    {
        "Url"{
            Write-Host "Import openApi from url: $($SwaggerUrl)"
            $importSwaggerParams.SpecificationUrl = $SwaggerUrl
        }
        "File"{
            Write-Host "Import openApi from file: $($SwaggerFilePath)"
            $importSwaggerParams.SpecificationPath = $SwaggerFilePath
        }
        Default{
            throw "OpenApi location not set. Suported values is: Url or Filepath"
        }
    }

    Write-Host "Checking Auth config"

    switch ($Authorization) {
        "OAuth" { 
            try { $oath = Get-AzApiManagementAuthorizationServer -Context $apiManagementContext -ServerId $OauthServer } catch {$_.Exception.Response.StatusCode.Value__}
            if($oath){
                Write-Host "OAuth Server: '$($OauthServer)' exists...continue"
                $authServer = $OauthServer
            }else{
                throw "Could not find any Oauth Server with id: '$($OauthServer)'"
            }
        }
        "OpenID"{
            try { $oath = Get-AzApiManagementAuthorizationServer -Context $apiManagementContext -ServerId $OidServer } catch {$_.Exception.Response.StatusCode.Value__}
            if($oath){
                Write-Host "OAuth Server: '$($OidServer)' exists...continue"
                $authServer = $OidServer
            }else{
                throw "Could not find any Oauth Server with id: '$($OidServer)'"
            }
        }
    }

    $products = $APIMProducts.Trim().Split(",")

    if($ProductCreatedPrevious -eq $true){
        Write-Host 'Checking product(s) created by prevous task'
        $newProducts = Get-VstsTaskVariable -Name "NewUpdatedProducts"

        if ([string]::IsNullOrWhiteSpace($newProducts))
        {
            throw "There was no product created by a previous task"
        }
        
        $products = $newProducts.Split(";")
        Write-Host "Products created by a previous task: $($products | Out-String)"
    }
    else{
        Write-Host "Checking if products exists"    
        foreach($product in $products)
        {
            try { $existingProduct = Get-AzApiManagementProduct -Context $apiManagementContext -ProductId $product } catch {$_.Exception.Response.StatusCode.Value__}

            if($existingProduct)
            {
                Write-Host "Product: '$($product)' exists...continue"
                # Write-Host "Linking API to product: $($product)"
                # Add-AzApiManagementApiToProduct -Context $apiManagementContext -ProductId $product -ApiId $ApiName
            }
            else 
            {
                throw "Could not find any product with name: $($product)"   
            }
        }    
    }

    $versionSetId = $null
    $versionSetName = $null
    $apiVersion = $null


    Write-Host "Checking if versjonset $($ApiName) exists..."
    try { $versionSet = Get-AzApiManagementApiVersionSet -Context $apiManagementContext -ApiVersionSetId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}
    
    if($versionSet){
        Write-Host "VersionSet exists...update"
        $versionSetId = $versionSet.Id
        $versionSet.DisplayName = $ApiDisplayName
        Set-AzApiManagementApiVersionSet -InputObject $versionSet
    }
    
    if($ShouldAddVersion){
        $versionSetId = $ApiName
        $versionSetName = $ApiDisplayName
        
        if($null -eq $versionSet){
            Write-Host "VersionSet not exists...creating"
            $versionSet = New-AzApiManagementApiVersionSet -Context $apiManagementContext -ApiVersionSetId $versionSetId -Name $versionSetName -Scheme Segment
        }
    
        try { $api = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}
    
        if($api){
            $api.ApiVersionSetId = $versionSet.Id
            $api.ApiVersionSetDescription = $versionSet.Description
            Set-AzApiManagementApi -InputObject $api 
        }
    
        $ApiName = "$($ApiName)-$($VersionName)"
        $apiVersion = $VersionName
    
    }
    
    Write-Host "Checking if api $($ApiName) exists"
    try { $existingApi = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}
    
    
    $apiParams = @{
        Context = $apiManagementContext
        Name = $ApiDisplayName 
        Description = $ApiDescription
        Path = $ApiUrlSuffix
        Protocols = "Https"
        ServiceUrl = $BackendUrl
        AuthorizationServerId = $authServer
        SubscriptionRequired = $IsSubscriptionRequired
    }
    
    if($existingApi){
        Write-Host "Api exists...update"
        $apiParams.ApiId = $existingApi.ApiId
        Set-AzApiManagementApi  @apiParams
    }
    
    else{
        Write-Host "Api not exists...creating"
        $apiParams.ApiId = $ApiName
        $apiParams.ApiVersionSetId = $versionSetId
        $apiParams.ApiVersion = $apiVersion
        New-AzApiManagementApi @apiParams
    }
    
    $importSwaggerParams.ApiId = $ApiName
    $importSwaggerParams.ApiVersionSetId = $versionSetId
    $importSwaggerParams.ApiVersion = $apiVersion

    Write-Host "Importing API from OpenApi"
    Import-AzApiManagementApi @importSwaggerParams
    Write-Host "Set api display name: $($ApiDisplayName)"
    Set-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName -Name $ApiDisplayName -Description $ApiDescription
    

    
    foreach($product in $products)
    {
        Write-Host "Linking API to product: $($product)"
        Add-AzApiManagementApiToProduct -Context $apiManagementContext -ProductId $product -ApiId $ApiName
    }    

    
    Write-Host "Setting up diagnostic settings for api..."
    $diagnostic = Get-AzApiManagementDiagnostic -Context $apiManagementContext -DiagnosticId ApplicationInsights 
    $diagnostic.ApiId = $ApiName

    Set-AzApiManagementDiagnostic -InputObject $diagnostic
    
    Write-Host "Diagnostic settings for api successfully configured"

    if($APIPolicy -ne "" -or $null -ne $APIPolicy)
    {
        Write-Host 'Set API policy!'
        Set-AzApiManagementPolicy -Context $apiManagementContext -ApiId $ApiName -PolicyFilePath $APIPolicy -Format RawXml
    }

    if($APIOperationPolicies -ne "" -or $null -ne $APIOperationPolicies)
    {
        Write-Host 'Set Operation policies!'

        $policyFiles = Get-ChildItem -Path $APIOperationPolicies -File

        foreach($file in $policyFiles)
        {
            $fullName = $file.FullName
            $baseName = (Get-Item $fullName).BaseName
            $operation = Get-AzApiManagementOperation -Context $apiManagementContext -ApiId $ApiName -OperationId $baseName 

            if($operation){
                Set-AzApiManagementPolicy -Context $apiManagementContext -ApiId $ApiName -OperationId $operation.OperationId -PolicyFilePath $fullName -Format RawXml
            }

        }
    }

    

