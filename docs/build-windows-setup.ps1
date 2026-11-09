# Package fresh Windows agent and tray builds into one per-user setup executable.
param(
    [Parameter(Mandatory=$true)][string]$AgentExe,
    [Parameter(Mandatory=$true)][string]$TrayExe,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$CommandHelperExe,
    [string]$UnattendedServiceExe,
    [string]$GatewayAddress,
    [string]$GatewayTlsName,
    [string]$GatewayCa
)
$ErrorActionPreference = 'Stop'
$agent = (Resolve-Path -LiteralPath $AgentExe).ProviderPath
$tray = (Resolve-Path -LiteralPath $TrayExe).ProviderPath
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'Choose a new output filename.' }
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$source = Join-Path $PSScriptRoot 'WindowsSetup.cs'
$icon = Join-Path $PSScriptRoot '..\src-tauri\icons\icon.ico'
$config = $null
try {
    $resources = @("/resource:$agent,agent", "/resource:$tray,tray")
    if ($UnattendedServiceExe) {
        $systemService=(Resolve-Path -LiteralPath $UnattendedServiceExe).ProviderPath
        $serviceItem=Get-Item -LiteralPath $systemService
        if($serviceItem.Length -eq 0 -or $serviceItem.Length -gt 48MB){
            throw 'Unexpected protected service installer size.'
        }
        $resources += "/resource:$systemService,unattended-service"
    }
    if ($CommandHelperExe) {
        $helper = (Resolve-Path -LiteralPath $CommandHelperExe).ProviderPath
        $item = Get-Item -LiteralPath $helper
        if ($item.Length -eq 0 -or $item.Length -gt 1MB) { throw 'Unexpected administrator helper size.' }
        $resources += "/resource:$helper,command-helper"
    }
    if ($GatewayAddress -or $GatewayTlsName -or $GatewayCa) {
        if ($GatewayAddress -cnotmatch '^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[1-9][0-9]{0,4}$' -or
            [int]($GatewayAddress.Split(':')[-1]) -gt 65535 -or
            $GatewayTlsName -cnotmatch '^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$' -or
            !$GatewayCa) { throw 'Provide the approved gateway address, TLS name, and public CA together.' }
        $ca = (Resolve-Path -LiteralPath $GatewayCa).ProviderPath
        $caText = [IO.File]::ReadAllText($ca)
        if ($caText -cnotmatch '\A\s*-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\z') {
            throw 'Provide exactly one public PEM certificate. Never package keys or credentials.'
        }
        $config = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllLines($config, [string[]]@($GatewayAddress,$GatewayTlsName))
        $resources += @("/resource:$config,gateway", "/resource:$ca,gateway-ca")
    }
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /reference:Microsoft.CSharp.dll /reference:System.Web.Extensions.dll "/win32icon:$icon" @resources "/out:$outputPath" $source
    if ($LASTEXITCODE -ne 0) { throw 'Windows setup build failed.' }
} finally {
    if ($config) { Remove-Item -LiteralPath $config -Force }
}
Get-FileHash -LiteralPath $outputPath -Algorithm SHA256
