[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Find-Go {
    $command = Get-Command go -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $knownPaths = @(
        'C:\Program Files\Go\bin\go.exe',
        (Join-Path $env:LOCALAPPDATA 'Programs\Go\bin\go.exe')
    )
    return $knownPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

$go = Find-Go
if (-not $go) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'Go が見つかりません。https://go.dev/dl/ から Go 1.26 以降を導入してください。'
    }

    Write-Host 'Go を WinGet で導入します...'
    & $winget.Source install --id GoLang.Go --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) {
        throw "Go の導入に失敗しました (exit code: $LASTEXITCODE)"
    }

    $go = Find-Go
    if (-not $go) {
        throw 'Go は導入されましたが、このプロセスから見つけられません。PowerShell を開き直して再実行してください。'
    }
}

Push-Location $repoRoot
try {
    & $go version
    & $go mod download
    if ($LASTEXITCODE -ne 0) {
        throw "Go モジュールの取得に失敗しました (exit code: $LASTEXITCODE)"
    }
    Write-Host 'セットアップが完了しました。次に .\scripts\check.ps1 を実行できます。'
}
finally {
    Pop-Location
}
