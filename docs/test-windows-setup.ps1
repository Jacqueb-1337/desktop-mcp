# Disposable non-elevated first-install smoke test for the Windows setup internals.
# Does not install the protected service or WireGuard, and does not change
# the user's existing Desktop MCP tasks.
param([Parameter(Mandatory=$true)][string]$AgentExe)
$ErrorActionPreference = 'Stop'
$tag = [Guid]::NewGuid().ToString('N')
$fixture = Join-Path $env:LOCALAPPDATA "DesktopMCP-test-$tag"
$agentTask = "Desktop MCP installer test agent $tag"
$trayTask = "Desktop MCP installer test tray $tag"
$gatewayTask = "Desktop MCP installer test gateway $tag"
New-Item -ItemType Directory $fixture | Out-Null
try {
    $setup = Join-Path $fixture 'setup.exe'
    & "$PSScriptRoot\build-windows-setup.ps1" -AgentExe $AgentExe -TrayExe "$env:WINDIR\System32\whoami.exe" -Output $setup | Out-Null
    if($LASTEXITCODE -ne 0) {throw 'Cannot create isolated installer'}
    $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($setup))
    $type = $assembly.GetType('WindowsSetup')
    $endpointType = $assembly.GetType('GatewayEndpoint')
    $parse = $endpointType.GetMethod('Parse',[Reflection.BindingFlags]'Public,NonPublic,Static')
    $endpoint = $parse.Invoke($null,[object[]]@('gateway.example.org:51820'))
    $install = $type.GetMethod('Install',[Reflection.BindingFlags]'NonPublic,Static')
    if (!$install) { throw 'WindowsSetup.Install method missing' }
    $app = Join-Path $fixture 'app'
    $state = Join-Path $fixture 'com.jacqueb.desktopmcp'
    $installParams = [object[]]@([string]$app,[string]$state,[string]$agentTask,[string]$trayTask,[string]$gatewayTask,$endpoint.PSObject.BaseObject)
    try { $code = $install.Invoke($null,[object[]]$installParams) } catch { throw $_.Exception.GetBaseException() }
    if($code -cnotmatch '^DM1-[a-f0-9]{64}$'){throw 'Invalid pairing identity'}
    $status = (& "$app\desktop-mcp-agent.exe" --local-status --state-dir $state | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or !$status.running -or $code -cne "DM1-$($status.identity.public_key)") {
        throw 'Agent startup or pairing identity mismatch'
    }
    $saved = Get-Content "$state\gateway-endpoint.json" -Raw | ConvertFrom-Json
    if ($saved.host -ne 'gateway.example.org' -or $saved.udp_port -ne 51820) {
        throw 'Gateway address persistence mismatch'
    }
    if ((Get-Content "$state\connection-code.txt" -Raw).Trim() -cne $code) {
        throw 'Saved enrollment identity mismatch'
    }
    foreach($name in @($agentTask,$trayTask)){
        $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
        if($task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive'){
            throw 'Unexpected task privilege'
        }
    }
    try { $null=$install.Invoke($null,[object[]]$installParams); throw 'Installer overwrote an existing pairing identity' }
    catch {
        if($_.Exception.GetBaseException().Message -notmatch 'fresh installation'){throw}
    }
    Write-Output 'PASS: fresh local installer, tasks, pairing identity, public gateway persistence, safe no-overwrite.'
}
finally {
    foreach($name in @($gatewayTask,$trayTask,$agentTask)){
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
