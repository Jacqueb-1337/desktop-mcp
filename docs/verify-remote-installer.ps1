# Fail closed: this validates that a Windows release really contains every remote
# component. Run against the actual final EXE before publishing a remote installer.
param([Parameter(Mandatory=$true)][string]$Installer)
$ErrorActionPreference = 'Stop'
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Installer).ProviderPath)
$assembly = [Reflection.Assembly]::Load($bytes)
$names = @($assembly.GetManifestResourceNames())
$required = @('agent', 'tray', 'unattended-service', 'gateway', 'gateway-ca', 'wireguard-installer')
foreach ($name in $required) {
    if ($names -cnotcontains $name) {
        throw "INCOMPLETE REMOTE INSTALLER: missing $name. Do not publish or give to Dad."
    }
    $stream = $assembly.GetManifestResourceStream($name)
    if ($null -eq $stream -or $stream.Length -eq 0) {
        throw "INCOMPLETE REMOTE INSTALLER: embedded $name is empty."
    }
    $stream.Dispose()
}
throw "Resource check passed but Windows WireGuard installation, protected-service startup, persisted gateway reuse, and live remote pairing still require an end-to-end acceptance test. Do not publish an unverified remote installer."
