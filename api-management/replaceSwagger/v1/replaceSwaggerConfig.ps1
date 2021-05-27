[CmdletBinding()]
param()

# For more information on the VSTS Task SDK:
# https://github.com/Microsoft/vsts-task-lib

Trace-VstsEnteringInvocation $MyInvocation

    Import-Module $PSScriptRoot\ps_modules\VstsAzureHelpers_ 
    Import-Module $PSScriptRoot\ps_modules\newtonsoft.json\1.0.1.2\newtonsoft.json.psd1
    Import-Module $PSScriptRoot\ps_modules\newtonsoft.json\1.0.1.2\newtonsoft.json.psm1

    Write-Host "Powershell version: $($PSVersionTable.PSVersion)"
    
    [string]$SwaggerPath = Get-VstsInput -Name SwaggerPath -Require 
    [string]$TitleValue = Get-VstsInput -Name TitleValue
    
    
    Write-Host 'Checking if the swagger exists'

    $pathExists = Test-Path -Path $SwaggerPath -PathType Leaf

    if($pathExists){
        $content = Get-Content $SwaggerPath 
        $jsonobject = [Newtonsoft.Json.JsonConvert]::DeserializeObject($content)
        $jsonobject.info.title = $TitleValue
        $json = [Newtonsoft.Json.JsonConvert]::SerializeObject($jsonobject, [Newtonsoft.Json.Formatting]::Indented)
        Set-Content -Value $json -Path $SwaggerPath
    }
    else{
        throw "Could not find file with path: $(SwaggerPath)"  
    }

    

