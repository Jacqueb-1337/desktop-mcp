# Per-user scheduled task. No administrator rights or unrestricted shell tools.
param(
    [Parameter(Mandatory=$true)][string]$AgentExe,
    [Parameter(Mandatory=$true)][string]$Workspace,
    [switch]$AllowWrites,
    [switch]$AllowRemoteReadonly
)
$ErrorActionPreference='Stop'
$exe=(Resolve-Path -LiteralPath $AgentExe).ProviderPath
$workspaceRoot=(Resolve-Path -LiteralPath $Workspace).ProviderPath
$gitRoot=(& git -C $workspaceRoot rev-parse --show-toplevel)
if($LASTEXITCODE -ne 0 -or !$gitRoot){throw 'Workspace is not a Git repository.'}
if(![string]::Equals([IO.Path]::GetFullPath($gitRoot.Trim()).TrimEnd('\'),[IO.Path]::GetFullPath($workspaceRoot).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Select exactly the repository root.'}
$installDir=Join-Path $env:LOCALAPPDATA 'Programs\DesktopMCP'
$configDir=Join-Path $env:APPDATA 'com.jacqueb.desktopmcp'
New-Item -ItemType Directory -Path $installDir,$configDir -Force | Out-Null
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
function Protect-AppPath([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'Application paths cannot be reparse points.'}
    $allowed=@($user.Value,'S-1-5-18','S-1-5-32-544')
    $current=Get-Acl -LiteralPath $Path
    $rules=@($current.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $unexpected=@($rules | Where-Object {$allowed -notcontains $_.IdentityReference.Value -or $_.AccessControlType -ne 'Allow' -or $_.FileSystemRights -ne 'FullControl'})
    if($current.AreAccessRulesProtected -and $current.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $user.Value -and $rules.Count -eq 3 -and $unexpected.Count -eq 0){return}
    $acl=if($item.PSIsContainer){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $acl.SetOwner($user);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($user,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
        $rule=if($item.PSIsContainer){[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')}
        $acl.AddAccessRule($rule)
    }
    if($item.PSIsContainer){[IO.Directory]::SetAccessControl($item.FullName,$acl)}else{[IO.File]::SetAccessControl($item.FullName,$acl)}
}
# Tighten only the application's dedicated directories and direct files.
foreach($dir in @($installDir,$configDir)){
    Protect-AppPath $dir
    foreach($item in Get-ChildItem -LiteralPath $dir -Force){
        if($item.PSIsContainer){throw 'Unexpected nested application state. Review before installing.'}
        Protect-AppPath $item.FullName
    }
}
$taskName='Desktop MCP Local Agent'
$installedExe=Join-Path $installDir 'desktop-mcp-agent.exe'
$previous=$null
if(Test-Path -LiteralPath $installedExe){
    $statusJson=& $installedExe --local-status --state-dir $configDir 2>$null
    if($LASTEXITCODE -eq 0 -and $statusJson){$previous=$statusJson | ConvertFrom-Json}
}
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
# Older installers registered a wrapper that could leave its exact service child
# alive. Stop only the authenticated local-service PID if it uses this binary.
if($previous -and $previous.running){
    $oldAgent=Get-Process -Id $previous.pid -ErrorAction SilentlyContinue
    if($oldAgent -and [string]::Equals($oldAgent.Path,$installedExe,[StringComparison]::OrdinalIgnoreCase)){
        Stop-Process -Id $oldAgent.Id -ErrorAction Stop
        $oldAgent.WaitForExit(5000) | Out-Null
    }
}
if(![string]::Equals($exe,$installedExe,[StringComparison]::OrdinalIgnoreCase)){Copy-Item -LiteralPath $exe -Destination $installedExe -Force}
Protect-AppPath $installedExe
$flags=if($AllowWrites){' --allow-writes'}else{''}
if($AllowRemoteReadonly){
    $flags+=' --allow-remote-readonly'
    $remoteGate=Join-Path $configDir 'remote-readonly.enabled'
    if(!(Test-Path -LiteralPath $remoteGate)){
        [IO.File]::WriteAllText($remoteGate,"enabled`n",[Text.UTF8Encoding]::new($false))
        Protect-AppPath $remoteGate
    }
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$taskArgs='--serve-local --workspace "'+$workspaceRoot+'" --state-dir "'+$configDir+'"'+$flags
$action=New-ScheduledTaskAction -Execute $installedExe -Argument $taskArgs -WorkingDirectory $installDir
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Desktop MCP scoped local agent, no administrator tools' -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed unprivileged local agent for $identity. Project: $workspaceRoot"
Write-Host "Remote read-only launch capability: $([bool]$AllowRemoteReadonly). Every remote operation requires exact approval."
