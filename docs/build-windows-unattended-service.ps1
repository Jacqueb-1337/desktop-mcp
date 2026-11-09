param(
  [Parameter(Mandatory=$true)][string]$AgentExe,
  [Parameter(Mandatory=$true)][string]$GatewayCa,
  [Parameter(Mandatory=$true)][string]$GatewayAddress,
  [Parameter(Mandatory=$true)][string]$GatewayTlsName,
  [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$agent=(Resolve-Path -LiteralPath $AgentExe).ProviderPath
$ca=(Resolve-Path -LiteralPath $GatewayCa).ProviderPath
$out=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if(Test-Path -LiteralPath $out){throw 'Installer already exists'}
if($GatewayAddress -notmatch '^[A-Za-z0-9.:-]+$' -or $GatewayTlsName -notmatch '^[a-zA-Z0-9.-]+$'){ throw 'Invalid gateway configuration' }
$cert=[IO.File]::ReadAllText($ca)
if($cert -notmatch '-----BEGIN CERTIFICATE-----' -or $cert -notmatch '-----END CERTIFICATE-----'){throw 'Invalid PEM certificate'}
$config=[IO.Path]::GetTempFileName()
try{
 [IO.File]::WriteAllLines($config,[string[]]@($GatewayAddress,$GatewayTlsName))
 $compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 $source=(Resolve-Path (Join-Path $PSScriptRoot 'WindowsUnattendedService.cs')).ProviderPath
 $options=@('/nologo','/target:winexe','/platform:x64','/optimize+','/warnaserror+',
  '/reference:System.ServiceProcess.dll','/reference:System.Web.Extensions.dll',
  '/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll',
  "/resource:$agent,agent","/resource:$ca,gateway-ca","/resource:$config,gateway",
  "/out:$out",$source)
 & $compiler @options
 if($LASTEXITCODE -ne 0){throw 'Service packaging failed'}
}finally{
 Remove-Item -LiteralPath $config -Force -ErrorAction SilentlyContinue
}
Get-FileHash -LiteralPath $out -Algorithm SHA256
