param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$outputPath=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'Choose a new output filename.' }
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /reference:System.Web.Extensions.dll "/out:$outputPath" (Join-Path $PSScriptRoot 'WindowsCommandRunner.cs')
if ($LASTEXITCODE -ne 0) { throw 'Windows command helper build failed.' }
Get-FileHash -LiteralPath $outputPath -Algorithm SHA256
