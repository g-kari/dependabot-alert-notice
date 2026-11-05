[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Find-GoTool([string]$name) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $goBin = @(
        'C:\Program Files\Go\bin',
        (Join-Path $env:LOCALAPPDATA 'Programs\Go\bin')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($goBin) {
        $candidate = Join-Path $goBin "$name.exe"
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    throw "$name が見つかりません。.\scripts\setup.ps1 を先に実行してください。"
}

function Invoke-Checked([string]$label, [scriptblock]$action) {
    Write-Host "==> $label"
    & $action
    if ($LASTEXITCODE -ne 0) {
        throw "$label に失敗しました (exit code: $LASTEXITCODE)"
    }
}

$go = Find-GoTool 'go'
$gofmt = Find-GoTool 'gofmt'

Push-Location $repoRoot
try {
    Write-Host '==> gofmt'
    $unformatted = & $gofmt -l .
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt に失敗しました (exit code: $LASTEXITCODE)"
    }
    if ($unformatted) {
        $unformatted | ForEach-Object { Write-Host "  $_" }
        throw 'gofmt が必要な Go ファイルがあります。'
    }

    Invoke-Checked 'go vet' { & $go vet ./... }

    $cgoEnabled = (& $go env CGO_ENABLED).Trim() -eq '1'
    $hasCompiler = (Get-Command gcc -ErrorAction SilentlyContinue) -or
        (Get-Command clang -ErrorAction SilentlyContinue) -or
        (Get-Command cl -ErrorAction SilentlyContinue)
    if ($cgoEnabled -and $hasCompiler) {
        Invoke-Checked 'go test (race)' { & $go test ./... -race -count=1 }
    }
    else {
        Write-Host '==> race detector は利用できないため、通常の全テストを実行します。'
        Invoke-Checked 'go test' { & $go test ./... -count=1 }
    }
    Invoke-Checked 'go build' { & $go build ./... }
    Write-Host 'すべてのチェックに成功しました。'
}
finally {
    Pop-Location
}
