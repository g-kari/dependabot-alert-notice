# Trial only. Compatible with Windows PowerShell 5.1 and PowerShell 7.
[CmdletBinding()]
param([ValidateSet('Version', 'WebURL', 'Start')][string]$Mode = 'Version')
$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'dependabot-alert-notice.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Extract the Windows trial binary next to Trial.ps1 first.' }
$trial = Join-Path ([IO.Path]::GetTempPath()) ('devsecops-trial-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $trial) { throw 'Trial directory already exists.' }
$homeDir = Join-Path $trial 'home'
foreach ($path in @($trial, $homeDir, "$homeDir/bin", "$homeDir/config", "$homeDir/gh", "$homeDir/codex", "$homeDir/appdata", "$homeDir/localappdata", "$trial/tmp")) {
    New-Item -ItemType Directory -Path $path | Out-Null
}
$config = Join-Path $trial 'config.yaml'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'trial-config.yaml') -Destination $config
$info = New-Object System.Diagnostics.ProcessStartInfo
$info.FileName = $binary
$info.WorkingDirectory = $trial
$info.UseShellExecute = $false
$info.EnvironmentVariables.Clear()
$info.EnvironmentVariables['SystemRoot'] = [Environment]::GetEnvironmentVariable('SystemRoot')
$info.EnvironmentVariables['WINDIR'] = [Environment]::GetEnvironmentVariable('SystemRoot')
$info.EnvironmentVariables['HOME'] = $homeDir
$info.EnvironmentVariables['USERPROFILE'] = $homeDir
$info.EnvironmentVariables['APPDATA'] = "$homeDir/appdata"
$info.EnvironmentVariables['LOCALAPPDATA'] = "$homeDir/localappdata"
$info.EnvironmentVariables['XDG_CONFIG_HOME'] = "$homeDir/config"
$info.EnvironmentVariables['GH_CONFIG_DIR'] = "$homeDir/gh"
$info.EnvironmentVariables['CODEX_HOME'] = "$homeDir/codex"
$info.EnvironmentVariables['PATH'] = "$homeDir/bin"
$info.EnvironmentVariables['TMP'] = "$trial/tmp"
$info.EnvironmentVariables['TEMP'] = "$trial/tmp"
$info.EnvironmentVariables['SECURITY_NOTICE_AUTO_UPDATE'] = '0'
$info.EnvironmentVariables['SECURITY_NOTICE_NO_BROWSER'] = '1'
$info.Arguments = '--config "' + $config + '" --auto-update=false'
if ($Mode -eq 'Start') {
    Write-Host "Trial data: $trial"
    Write-Host 'Offline/empty trial UI: http://127.0.0.1:18999/settings. Do not enter credentials or enable external integrations. Stop with Ctrl+C.'
} else {
    $info.RedirectStandardOutput = $true
    if ($Mode -eq 'Version') { $info.Arguments += ' --version' } else { $info.Arguments += ' --web-url' }
}
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $info
try {
    if (-not $process.Start()) { throw 'Trial process did not start.' }
    if ($Mode -ne 'Start') { $output = $process.StandardOutput.ReadToEnd() }
    $process.WaitForExit()
    $global:LASTEXITCODE = $process.ExitCode
    if ($process.ExitCode -ne 0) { throw "Trial process failed: $($process.ExitCode)" }
    if ($Mode -ne 'Start') {
        if (Test-Path -LiteralPath (Join-Path $trial 'store.db')) { throw 'Read-only smoke unexpectedly created a database.' }
        Write-Output $output.TrimEnd([char[]]"`r`n")
    }
} finally {
    $process.Dispose()
}
