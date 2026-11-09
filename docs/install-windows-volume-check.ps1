# Run once in a locally approved, elevated Windows PowerShell.
param(
    [Parameter(Mandatory=$true)][string]$HelperExe,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$Sha256,
    [ValidateSet('VolumeCheck.exe','CommandRunner.exe')][string]$Name='VolumeCheck.exe'
)
$ErrorActionPreference='Stop'
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
if (![Security.Principal.WindowsPrincipal]::new($current).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use an elevated Windows PowerShell after approving this installation.'
}
$source=(Resolve-Path -LiteralPath $HelperExe).ProviderPath
$file=Get-Item -LiteralPath $source
if ($file.Length -gt 1MB -or $file.Length -eq 0) { throw 'Unexpected helper size.' }
$bytes=[IO.File]::ReadAllBytes($source)
$hash=[Security.Cryptography.SHA256]::Create()
try { $digest=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','') }
finally { $hash.Dispose() }
if ($digest -ne $Sha256) { throw 'Helper checksum did not match.' }

$programFiles=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$dir=Join-Path $programFiles 'DesktopMCP'
$admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($admin)
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($admin,$system,$users)) {
    $access=if ($sid -eq $users) { 'ReadAndExecute' } else { 'FullControl' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,$access,'ContainerInherit,ObjectInherit','None','Allow'))
}
if (Test-Path -LiteralPath $dir) {
    $item=Get-Item -LiteralPath $dir -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected protected helper folder' }
    $existing=Get-Acl -LiteralPath $dir
    if ($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admin.Value -or
        $existing.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -ne
        $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)) { throw 'Unexpected helper directory ACL' }
} else {
    [IO.Directory]::CreateDirectory($dir,$acl) | Out-Null
}
$target=Join-Path $dir $Name
$stream=[IO.File]::Open($target,'CreateNew','Write','None')
try { $stream.Write($bytes,0,$bytes.Length) }
finally { $stream.Dispose() }
$installedAcl=Get-Acl -LiteralPath $target
$installedAcl.SetOwner($admin)
Set-Acl -LiteralPath $target -AclObject $installedAcl
if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $digest) { throw 'Installed helper did not verify.' }
Write-Output 'Installed the verified Desktop MCP helper.'
