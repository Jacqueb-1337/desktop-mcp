# Print only the public identity for gateway enrollment.
$ErrorActionPreference = 'Stop'
$agent = Join-Path $env:LOCALAPPDATA 'Programs\DesktopMCP\desktop-mcp-agent.exe'
$state = Join-Path $env:APPDATA 'com.jacqueb.desktopmcp'
$statusJson = & $agent --local-status --state-dir $state
if ($LASTEXITCODE -ne 0 -or !$statusJson) { throw 'Start the Desktop MCP Local Agent task first.' }
$identity = ($statusJson | ConvertFrom-Json).identity
if ($identity.host_id -cnotmatch '^[a-f0-9]{32}$' -or $identity.public_key -cnotmatch '^[a-f0-9]{64}$') {
    throw 'The agent returned an invalid public identity.'
}
[ordered]@{ host_id = $identity.host_id; public_key = $identity.public_key } | ConvertTo-Json -Compress
