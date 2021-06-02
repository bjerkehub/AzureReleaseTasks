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
    [string]$APIMProducts = $(Get-VstsInput -Name APIMProducts).Split([Environment]::NewLine)
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



    try { $existingApi = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}

    
    if($ShouldAddVersion){

        if($null -ne $existingApi){
            if($null -ne $existingApi.ApiVersionSetId){
                $versionSet = $existingApi.ApiVersionSetId
            }

            
            $existingApi = Get-AzApiManagementApi -Context $apiManagementContext -ApiId 


        }



    }





    Write-Host "Checking Auth config"

    if($Authorization -eq "OAuth")
    {
        $oath = Get-AzApiManagementAuthorizationServer -Context $apiManagementContext -ServerId $OauthServer

        if($oath)
        {
            Write-Host "OAuth Server: '$($OauthServer)' exists...continue"
            $authServer = $OauthServer
        }
        else 
        {
            throw "Could not find any Oauth Server with id: '$($OauthServer)'"
        }
    }

    if($Authorization -eq "OpenID")
    {
        $oath = Get-AzApiManagementAuthorizationServer -Context $apiManagementContext -ServerId $OidServer

        if($oath)
        {
            Write-Host "OAuth Server: '$($OidServer)' exists...continue"
            $authServer = $OidServer
        }
        else 
        {
            throw "Could not find any Oauth Server with id: '$($OidServer)'"
        }
    }

    if($ShouldAddVersion){
        Write-Host "Checking if version-set exists..."
        try { $versionSet = Get-AzApiManagementApiVersionSet -Context $apiManagementContext -ApiVersionSetId $ApiName } catch {$_.Exception.Response.StatusCode.Value__}
        
        if($null -eq $versionSet){

        }


    }





    Write-Host "Checking if the api exists..."

    try { 
        $currentApi = Get-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName 
        $currentApiName = Get-AzApiManagementApi -Context $apiManagementContext -Name $ApiDisplayName
    } catch {
        $_.Exception.Response.StatusCode.Value__
    }

    if($null -ne $currentApi -and $null -ne $currentApiName){
        if($currentApiName.ApiId -ne $currentApi.ApiId){
            throw "Api displayName: $($ApiDisplayName) is associated with another api. Please choose another display name"
        }
    }
    if($null -ne $currentApiName -and $null -eq $currentApi){
        throw "Api displayName: $($ApiDisplayName) is associated with another api. Please choose another display name"
    }

    $importSwaggerParams = @{
        Context = $apiManagementContext 
        ApiId = $apiName 
        Path = $apiURLSuffix 
        ServiceUrl = $backendUrl 
        Protocol = "Https" 
        
    }

    if($OpenAPISpec -eq "v3"){
        Write-Host "Setting specificationFormat = OpenApiJson"
        $importSwaggerParams.SpecificationFormat = "OpenApiJson" 
    }

    else{
        Write-Host "Setting specificationFormat = Swagger"
        $importSwaggerParams.SpecificationFormat = "Swagger" 
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
    }

    if($currentApi)
    {
        Write-Host "API Found...Importing"
        $api = $currentApi
        if($ShouldAddVersion)
        {
            if($currentApi.ApiVersionSetId)
            {
                $apiversionSet = Get-AzResource -ResourceId $currentApi.ApiVersionSetId
            }
            else
            {
                Write-Host "Creating new versionSet..."
                $apiVersionSet = New-AzApiManagementApiVersionSet -Context $apiManagementContext -Name $ApiName -Scheme Segment -ApiVersionSetId $ApiName
            }

            $api.ApiVersionSetId = $apiversionSet.Id
            $api.ApiVersion = $VersionName
            
        }
        $api.Name = $ApiDisplayName
        $api.Description = $ApiDescription
        $api.Path = $ApiUrlSuffix
        $api.Protocols = "Https"
        $api.ServiceUrl = $BackendUrl
        $api.AuthorizationServerId = $authServer
        $api.SubscriptionRequired = $IsSubscriptionRequired
        

        Set-AzApiManagementApi -InputObject $api
        Import-AzApiManagementApi @importSwaggerParams
        Write-Host "Set api display name: $($ApiDisplayName)"
        Set-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName -Name $ApiDisplayName -Description $ApiDescription
    }
    else
    {
        
        $apiParams = @{
            Context = $apiManagementContext
            ApiId = $apiName
            Name = $ApiDisplayName 
            Description = $ApiDescription
            Path = $apiURLSuffix 
            Protocols = "Https" 
            ServiceUrl = $backendUrl
            AuthorizationServerId = $authServer 
            SubscriptionRequired = $IsSubscriptionRequired 
        }

        
        if($ShouldAddVersion)
        {
            Write-Host "Creating new versionSet..."
            $apiVersionSet = New-AzApiManagementApiVersionSet -Context $apiManagementContext -Name $ApiName -Scheme Segment 
            Write-Host "Api not found...Creating..."
            
            $apiParams.ApiVersionSetId = $apiversionSet.ApiVersionSetId 
            $apiParams.ApiVersion = $VersionName
            New-AzApiManagementApi @apiParams
            
            Write-Host "Importing with version..."
            $importSwaggerParams.ApiVersion = $VersionName
            $importSwaggerParams.ApiVersionSetId = $apiversionSet.ApiVersionSetId
            Import-AzApiManagementApi @importSwaggerParams
            Write-Host "Set api display name: $($ApiDisplayName)"
            Set-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName -Name $ApiDisplayName -Description $ApiDescription
        }
        else
        {
            Write-Host "Api not found...Creating..."
            
            New-AzApiManagementApi @apiParams
            Write-Host "Importing without version..."
            Import-AzApiManagementApi @importSwaggerParams
            Write-Host "Set api display name: $($ApiDisplayName)"
            Set-AzApiManagementApi -Context $apiManagementContext -ApiId $ApiName -Name $ApiDisplayName -Description $ApiDescription
        } 
    }

    $products = $APIMProducts;

    if($ProductCreatedPrevious -eq $true){
        Write-Host 'Checking product(s) created by prevous task'
        $newProducts = Get-VstsTaskVariable -Name "NewUpdatedProducts"
        Write-Host "New product: $($newProducts)"

        if ([string]::IsNullOrWhiteSpace($newProducts))
        {
            throw "There was no product created by a previous task"
        }
        
        $products = $newProducts.Split(";")
        Write-Host "Products created by a previous task: $($products | Out-String)"
        Write-Host "Number of products created by a previous task(s): $($products.Length)"
    }

    foreach($product in $products)
    {
        Write-Host "Linking API to product: $($product)"
        try { $existingProduct = Get-AzApiManagementProduct -Context $apiManagementContext -ProductId $product } catch {$_.Exception.Response.StatusCode.Value__}

        if($existingProduct)
        {
            Write-Host "Product: '$($product)' exists...continue"
            Write-Host "Linking API to product: $($product)"
            Add-AzApiManagementApiToProduct -Context $apiManagementContext -ProductId $product -ApiId $ApiName
        }
        else 
        {
            throw "Could not find any product with name: $($product)"   
        }
    }

    Write-Host "Setting up diagnostic settings for api..."
    $diagnostic = Get-AzApiManagementDiagnostic -Context $apiManagementContext -DiagnosticId ApplicationInsights 
    $diagnostic.ApiId = $apiName

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
            $operation = Get-AzApiManagementOperation -Context $apiManagementContext -ApiId $apiName -OperationId $baseName 

            if($operation){
                Set-AzApiManagementPolicy -Context $apiManagementContext -ApiId $ApiName -OperationId $operation.OperationId -PolicyFilePath $fullName -Format RawXml
            }

        }
    }

    

