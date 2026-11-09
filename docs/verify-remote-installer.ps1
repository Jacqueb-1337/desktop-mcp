# Strict resource-only validation of a public remote installer. ComponentsOnly
# validates completeness, not installation or a real cross-network handshake.
param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [switch]$ComponentsOnly
)
$ErrorActionPreference = 'Stop'
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Installer).ProviderPath)
$assembly = [Reflection.Assembly]::Load($bytes)
$names = @($assembly.GetManifestResourceNames())
$required = @('agent', 'tray', 'unattended-service', 'gateway', 'gateway-ca', 'wireguard-installer')
foreach ($name in $required) {
    if ($names -cnotcontains $name)
        { throw "INCOMPLETE REMOTE INSTALLER: missing $name." }
    $stream = $assembly.GetManifestResourceStream($name)
    if ($null -eq $stream -or $stream.Length -eq 0)
        { throw "INCOMPLETE REMOTE INSTALLER: empty $name." }
    $stream.Dispose()
}
$serviceStream = $assembly.GetManifestResourceStream('unattended-service')
$serviceMemory = New-Object IO.MemoryStream
$serviceStream.CopyTo($serviceMemory)
$serviceStream.Dispose()
$protected = [Reflection.Assembly]::Load($serviceMemory.ToArray())
$serviceMemory.Dispose()
$nested = @($protected.GetManifestResourceNames())
foreach ($name in @('agent','gateway-ca','gateway','gateway-wg-public')) {
    if($nested -cnotcontains $name)
        { throw "INCOMPLETE PROTECTED SERVICE: missing $name." }
}
if ($null -eq $protected.GetType('WireGuardTunnelInstaller') -or
    $null -eq $assembly.GetType('OfficialWireGuardInstaller') -or
    $null -eq $assembly.GetType('GatewayEndpoint') -or
    $null -eq $assembly.GetType('BinaryUpgradeTransaction') -or
    $null -eq $assembly.GetType('WindowsInPlaceUpgrade') -or
    $null -eq $protected.GetType('BinaryUpgradeTransaction') -or
    $null -eq $protected.GetType('DesktopService').GetMethod('UpgradeMachine',[Reflection.BindingFlags]'NonPublic,Static'))
    { throw 'The required WireGuard, gateway, or protected in-place upgrade code was not included.' }
Write-Output ('COMPONENTS_VERIFIED: '+($names -join ', ') + '; SERVICE: ' + ($nested -join ', '))
if (-not $ComponentsOnly) {
    throw 'Release blocked: live fresh-install, unattended service restart, cross-network WireGuard handshake, revocation, and upgrade acceptance remain unverified.'
}
