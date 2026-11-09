# Exercise the fresh-install path with real agent startup and disposable tasks.
param([Parameter(Mandatory=$true)][string]$AgentExe, [string]$GatewayCa)
$ErrorActionPreference = 'Stop'
$tag = [Guid]::NewGuid().ToString('N')
$fixture = Join-Path $env:LOCALAPPDATA "DesktopMCP-test-$tag"
$agentTask = "Desktop MCP installer test agent $tag"
$trayTask = "Desktop MCP installer test tray $tag"
$gatewayTask = "Desktop MCP installer test gateway $tag"
New-Item -ItemType Directory $fixture | Out-Null
try {
    $setup = Join-Path $fixture 'setup.exe'
    $project = Join-Path $fixture 'Git project'
    git init --quiet $project
    if ($LASTEXITCODE -ne 0) { throw 'git init failed' }
    # Substitute a short-lived process for the tray so the test never touches live tray settings.
    $gateway = @{}
    if ($GatewayCa) {
        $gateway = @{ GatewayCa = $GatewayCa; GatewayAddress = '127.0.0.1:1'; GatewayTlsName = 'desktop-mcp-gateway' }
    }
    & "$PSScriptRoot\build-windows-setup.ps1" @gateway -AgentExe $AgentExe -TrayExe "$env:WINDIR\System32\whoami.exe" -Output $setup | Out-Null
    $method = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($setup)).GetType('WindowsSetup').GetMethod('Install',[Reflection.BindingFlags]'NonPublic,Static')
    $app = Join-Path $fixture 'app'
    $state = Join-Path $fixture 'state'
    $setupArgs = [string[]]@($project,$app,$state,$agentTask,$trayTask,$gatewayTask)
    try { $code = $method.Invoke($null,$setupArgs) } catch { throw $_.Exception.GetBaseException() }
    if ($code -cnotmatch '^DM1-[a-f0-9]{64}$') { throw 'Invalid code' }
    $status = (& "$app\desktop-mcp-agent.exe" --local-status --state-dir $state | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or !$status.running -or $code -cne "DM1-$($status.identity.public_key)") { throw 'Installed agent status or code mismatch' }
    $expectedTasks = @($agentTask,$trayTask)
    if ($GatewayCa) {
        $expectedTasks += $gatewayTask
        $link = Get-ScheduledTask -TaskName $gatewayTask
        if ($link.Actions.Arguments -notlike '*--gateway-connect*127.0.0.1:1*' -or
            (Get-FileHash "$app\nas-ca.pem").Hash -ne (Get-FileHash $GatewayCa).Hash) { throw 'Unexpected gateway link settings' }
    }
    foreach ($name in $expectedTasks) {
        $task = Get-ScheduledTask -TaskName $name
        if ($task.Principal.RunLevel -ne 'Limited' -or $task.Principal.LogonType -ne 'Interactive') { throw 'Unexpected task privilege' }
    }
    try { $null = $method.Invoke($null,$setupArgs); throw 'Unexpected overwrite' }
    catch { if ($_.Exception.GetBaseException().Message -notmatch 'fresh installation') { throw } }
    $badProject = Join-Path $fixture 'bad-project'
    New-Item -ItemType Directory "$badProject\.git" | Out-Null
    try {
        $badArgs = [string[]]@($badProject, (Join-Path $fixture 'bad-app'), (Join-Path $fixture 'bad-state'), ($agentTask + '-bad'), ($trayTask + '-bad'), ($gatewayTask + '-bad'))
        $null = $method.Invoke($null,$badArgs)
        throw 'Unexpected invalid project success'
    } catch {
        if ($_.Exception.GetBaseException().Message -notmatch 'could not start') { throw $_.Exception.GetBaseException() }
    }
    if ((Test-Path "$fixture\bad-app") -or (Test-Path "$fixture\bad-state") -or (Get-ScheduledTask -TaskName "$agentTask-bad" -ErrorAction SilentlyContinue)) { throw 'Rollback left files or tasks' }
    Write-Output 'Installer smoke passed: real agent, project path with spaces, limited startup tasks, correct code, overwrite refused, invalid repo rolled back.'
} finally {
    foreach ($name in @($gatewayTask,$trayTask,$agentTask,("$gatewayTask-bad"),("$trayTask-bad"),("$agentTask-bad"))) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
