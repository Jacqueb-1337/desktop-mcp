# Remove the per-user Desktop MCP background task without touching project files.
param([switch]$RemoveInstalledBinary)
$ErrorActionPreference = 'Stop'
$taskNames = @('Desktop MCP Gateway Link', 'Desktop MCP Tray', 'Desktop MCP Local Agent')
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\DesktopMCP'
$exe = Join-Path $installDir 'desktop-mcp-agent.exe'
$launcher = Join-Path $installDir 'start-desktop-mcp-agent.ps1'
foreach ($taskName in $taskNames) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (!$task) { continue }
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Desktop MCP startup task unregistered: $taskName"
}
# Only stop a process when Windows confirms it is our installed executable.
$tray = Join-Path $installDir 'desktop-mcp.exe'
$running = Get-CimInstance Win32_Process -Filter "Name='desktop-mcp-agent.exe' OR Name='desktop-mcp.exe'" -ErrorAction SilentlyContinue
foreach ($proc in $running) {
    if ([string]::Equals($proc.ExecutablePath, $exe, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($proc.ExecutablePath, $tray, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        Write-Host ('Stopped installed Desktop MCP process ' + $proc.ProcessId)
    }
}
if ($RemoveInstalledBinary) {
    Remove-Item -LiteralPath $launcher -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $exe,$tray -Force -ErrorAction SilentlyContinue
    Write-Host 'Removed installed launcher and binaries.'
}
# Keep preferences and other files in %APPDATA%. No Git workspaces are deleted.
Write-Host 'Project files and Desktop MCP preferences were preserved.'
