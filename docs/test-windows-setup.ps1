# Disposable non-elevated first-install smoke test for the Windows setup internals.
# Does not install the protected service or WireGuard, and does not change
# the user's existing Desktop MCP tasks.
param([Parameter(Mandatory=$true)][string]$AgentExe, [string]$UpgradeInstaller, [string]$FaultInstaller)
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
    if($UpgradeInstaller) {
        $beforePair = (Get-Content "$state\pairing-identity.json" -Raw | ConvertFrom-Json).private_key
        $beforeGateway = Get-FileHash "$state\gateway-endpoint.json" -Algorithm SHA256
        $agentDefinition = Get-ScheduledTask -TaskName $agentTask
        $beforeTask = $agentDefinition.Actions.Execute
        $upgradeAssembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes(
            (Resolve-Path -LiteralPath $UpgradeInstaller).ProviderPath))
        $upgradeType=$upgradeAssembly.GetType('WindowsInPlaceUpgrade')
        if(!$upgradeType){throw 'WindowsInPlaceUpgrade was not embedded'}
        $method=$upgradeType.GetMethod('Run',[Reflection.BindingFlags]'NonPublic,Static')
        $endpointTypeNew=$upgradeAssembly.GetType('GatewayEndpoint')
        $getEndpoint=$endpointTypeNew.GetMethod('Load',[Reflection.BindingFlags]'NonPublic,Static')
        $savedEndpoint=$getEndpoint.Invoke($null,[object[]]@([string]$state))
        $upParams=[object[]]@([string]$app,[string]$state,[string]$agentTask,[string]$trayTask,[string]$gatewayTask,$savedEndpoint.PSObject.BaseObject,$null)
        try { $null=$method.Invoke($null,[object[]]$upParams) }
        catch { Write-Output ("UPGRADE_STACK: "+$_.Exception.GetBaseException().ToString()); throw $_.Exception.GetBaseException() }
        if((Get-Content "$state\pairing-identity.json" -Raw | ConvertFrom-Json).private_key -ne $beforePair){
            throw 'Upgrade rotated the signing identity'
        }
        if((Get-FileHash "$state\gateway-endpoint.json" -Algorithm SHA256).Hash -ne $beforeGateway.Hash){
            throw 'Upgrade modified the configured gateway'
        }
        if((Get-ScheduledTask -TaskName $agentTask).Actions.Execute -ne $beforeTask){
            throw 'Upgrade rewrote the registered task'
        }
        if((Get-FileHash "$app\desktop-mcp-agent.exe" -Algorithm SHA256).Hash -ne
           (Get-FileHash $AgentExe -Algorithm SHA256).Hash){
            throw 'Upgraded agent differs from the packaged binary'
        }
        if(!(Test-Path "$app\nas-ca.pem")){throw 'Gateway CA migration component was not installed'}
        $status = (& "$app\desktop-mcp-agent.exe" --local-status --state-dir $state | ConvertFrom-Json)
        if(!$status.running -or $code -cne "DM1-$($status.identity.public_key)") {
            throw 'Upgraded agent did not preserve the active pairing identity'
        }
        Write-Output 'PASS: real in-place agent/tray upgrade, running tasks, gateway and pairing preserved.'
        if($FaultInstaller) {
            $beforeAgentHash=(Get-FileHash "$app\desktop-mcp-agent.exe").Hash
            $beforeTrayHash=(Get-FileHash "$app\desktop-mcp.exe").Hash
            $beforeIdentity=(Get-Content "$state\pairing-identity.json" -Raw | ConvertFrom-Json).private_key
            $beforeConfig=(Get-FileHash "$state\gateway-endpoint.json").Hash
            $faultAssembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes(
                (Resolve-Path -LiteralPath $FaultInstaller).ProviderPath))
            $faultMethod=$faultAssembly.GetType('WindowsInPlaceUpgrade').GetMethod('Run',[Reflection.BindingFlags]'NonPublic,Static')
            $faultEndpointType=$faultAssembly.GetType('GatewayEndpoint')
            $faultEndpoint=$faultEndpointType.GetMethod('Load',[Reflection.BindingFlags]'NonPublic,Static').Invoke($null,[object[]]@([string]$state))
            $inject=[Action]{throw [InvalidOperationException]::new('INTENTIONAL_FAULT_TEST')}
            $faultParams=[object[]]@([string]$app,[string]$state,[string]$agentTask,[string]$trayTask,[string]$gatewayTask,$faultEndpoint.PSObject.BaseObject,$inject)
            $failedAsPlanned=$false
            try{ $null=$faultMethod.Invoke($null,[object[]]$faultParams) }
            catch{ $failedAsPlanned=$_.Exception.GetBaseException().Message -match 'INTENTIONAL_FAULT_TEST' }
            if(!$failedAsPlanned){throw 'Intentional upgrade failure did not propagate correctly'}
            if((Get-FileHash "$app\desktop-mcp-agent.exe").Hash -ne $beforeAgentHash -or
               (Get-FileHash "$app\desktop-mcp.exe").Hash -ne $beforeTrayHash){
                throw 'Rollback failed to restore the previous executable bytes'
            }
            if((Get-Content "$state\pairing-identity.json" -Raw | ConvertFrom-Json).private_key -ne $beforeIdentity -or
               (Get-FileHash "$state\gateway-endpoint.json").Hash -ne $beforeConfig){
                throw 'Rollback modified pairing or saved public endpoint'
            }
            $status=(& "$app\desktop-mcp-agent.exe" --local-status --state-dir $state | ConvertFrom-Json)
            if(!$status.running -or $code -cne "DM1-$($status.identity.public_key)"){
                throw 'Rollback did not restore the local agent'
            }
            Write-Output 'PASS: injected protected-service failure restores local binaries, running agent, identity and endpoint.'
        }

    }

}
finally {
    foreach($name in @($gatewayTask,$trayTask,$agentTask)){
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
