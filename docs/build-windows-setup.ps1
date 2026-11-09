# Build a Windows installer. Remote releases MUST include the full protected service
# and a verified, signed WireGuard Windows installer.
param(
    [Parameter(Mandatory=$true)][string]$AgentExe,
    [Parameter(Mandatory=$true)][string]$TrayExe,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$CommandHelperExe,
    [string]$UnattendedServiceExe,
    [string]$WireGuardMsi,
    [switch]$RequireCompleteRemote,
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
if ($RequireCompleteRemote -and (!$UnattendedServiceExe -or !$WireGuardMsi -or
    !$GatewayAddress -or !$GatewayTlsName -or !$GatewayCa)) {
    throw 'Remote installer is incomplete: protected service, signed WireGuard, gateway TLS CA and gateway address are required.'
}
try {
    $resources = @("/resource:$agent,agent", "/resource:$tray,tray")
    if ($UnattendedServiceExe) {
        $systemService=(Resolve-Path -LiteralPath $UnattendedServiceExe).ProviderPath
        $serviceItem=Get-Item -LiteralPath $systemService
        if($serviceItem.Length -eq 0 -or $serviceItem.Length -gt 48MB) {
            throw 'Unexpected protected service installer size.'
        }
        $resources += "/resource:$systemService,unattended-service"
    }
    if ($WireGuardMsi) {
        $wg = (Resolve-Path -LiteralPath $WireGuardMsi).ProviderPath
        $wgItem = Get-Item -LiteralPath $wg
        if ($wgItem.Length -lt 100000 -or $wgItem.Length -gt 32MB -or
            $wgItem.Extension -ne '.msi') { throw 'Unexpected WireGuard MSI size or extension.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $wg
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch 'CN=WireGuard LLC(?:,|$)') {
            throw 'WireGuard MSI is not signed by the approved WireGuard LLC publisher.'
        }
        $resources += "/resource:$wg,wireguard-installer"
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
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /reference:Microsoft.CSharp.dll /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/win32icon:$icon" @resources "/out:$outputPath" $source (Join-Path $PSScriptRoot "GatewayEndpoint.cs") (Join-Path $PSScriptRoot "OfficialWireGuardInstaller.cs")
    if ($LASTEXITCODE -ne 0) { throw 'Windows setup build failed.' }
} finally {
    if ($config) { Remove-Item -LiteralPath $config -Force }
}
Get-FileHash -LiteralPath $outputPath -Algorithm SHA256
