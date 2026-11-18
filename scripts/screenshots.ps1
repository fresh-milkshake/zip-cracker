param(
    [string]$BinaryPath = "target/release/zip-cracker.exe",
    [string]$FreezePath = "target/freeze/freeze.exe",
    [string]$BkcrackPath = "target/bkcrack-1.8.1/bkcrack.exe"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$escape = [string][char]27

function Quote-Argument([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

function Color([string]$Text, [string]$Code) {
    return "$escape[$($Code)m$Text$escape[0m"
}

function Read-CapturedText([string]$Path) {
    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $rows = $document.SelectNodes("//*[local-name()='text']") | ForEach-Object { $_.InnerText }
    return $rows -join "`n"
}

function Find-Progress([string]$Text) {
    # Freeze captures the real ConPTY stream. A cursor rewind can append the next
    # bar to the preceding count row, so match bars by their braille spinner.
    $pattern = '(?<bar>[\u2800-\u28ff]\s+[^\r\n]*?\]\s+(?<percent>\d+)%)\r?\n\s*(?<counts>[^\r\n]*?checked\s+·\s+[^\r\n]*?ETA\s+\S+)'
    $frames = @([regex]::Matches($Text, $pattern))
    if ($frames.Count -eq 0) { throw "The terminal capture contains no progress frames" }
    $preferred = @($frames | Where-Object { [int]$_.Groups['percent'].Value -ge 35 -and [int]$_.Groups['percent'].Value -le 75 })
    if ($preferred.Count -gt 0) {
        return $preferred | Sort-Object { [Math]::Abs([int]$_.Groups['percent'].Value - 60) } | Select-Object -First 1
    }
    return $frames | Select-Object -Last 1
}

function Capture-Run([string]$Name, [string]$WorkingDirectory, [string[]]$Arguments) {
    $wrapper = Join-Path $captureDirectory "$Name.ps1"
    $argumentsText = ($Arguments + @('--color', 'always') | ForEach-Object { Quote-Argument $_ }) -join ' '
    $wrapperText = @"
[Environment]::SetEnvironmentVariable('NO_COLOR',`$null,'Process')
[Environment]::SetEnvironmentVariable('TERM','xterm-256color','Process')
Set-Location -LiteralPath $(Quote-Argument $WorkingDirectory)
& $(Quote-Argument $binary) $argumentsText
`$status = `$LASTEXITCODE
# Let ConPTY flush the final result before Freeze closes the pseudoconsole.
Start-Sleep -Milliseconds 700
exit `$status
"@
    [IO.File]::WriteAllText($wrapper, $wrapperText, [Text.UTF8Encoding]::new($false))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& $(Quote-Argument $wrapper)"))
    $capturePath = Join-Path $captureDirectory "$Name.capture.svg"
    & $freeze --execute.timeout 2m --execute "pwsh -NoLogo -NoProfile -EncodedCommand $encoded" --output $capturePath --window=false --font.size 13 --padding 20 --background '#161616' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Terminal capture failed: $Name" }
    return Read-CapturedText $capturePath
}

function Save-Image([string]$Name, [string[]]$Lines) {
    $transcript = $Lines -join "`n"
    [IO.File]::WriteAllText((Join-Path $captureDirectory "$Name.ansi"), $transcript, [Text.UTF8Encoding]::new($false))
    $transcript | & $freeze - --language ansi --output (Join-Path $imageDirectory "$Name.png") --window=false --font.size 13 --line-height 1.2 --padding 20 --margin 32 --border.radius 8 --shadow.blur 0 --background '#161616'
    if ($LASTEXITCODE -ne 0) { throw "Rendering failed: $Name" }
}

Push-Location $projectRoot
try {
    $binary = (Resolve-Path -LiteralPath $BinaryPath).Path
    $freeze = (Resolve-Path -LiteralPath $FreezePath).Path
    $backend = (Resolve-Path -LiteralPath $BkcrackPath).Path
    $captureDirectory = Join-Path $projectRoot 'target/readme'
    $imageDirectory = Join-Path $projectRoot 'assets/screenshots'
    New-Item -ItemType Directory -Force -Path $captureDirectory, $imageDirectory | Out-Null
    # A fresh output directory prevents overwriting recovered archives on reruns.
    $runDirectory = Join-Path $captureDirectory ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $runDirectory | Out-Null
    Copy-Item -LiteralPath 'tests/fixtures/abcde12.bin' -Destination (Join-Path $runDirectory 'demo.zip')
    Copy-Item -LiteralPath 'tests/fixtures/known-content.bin' -Destination (Join-Path $runDirectory 'known.zip')
    Copy-Item -LiteralPath 'tests/fixtures/bkcrack-known.txt' -Destination (Join-Path $runDirectory 'bkcrack-known.txt')

    $mask = '?l?l?l?l?l?a?a'
    $raw = Capture-Run 'mask-search' $runDirectory @('demo.zip', '-g', '--mask', $mask, '--limit', '200000000')
    $progress = Find-Progress $raw
    $result = [regex]::Match($raw, 'Password found:\s+(?<password>\S+)')
    $statistics = [regex]::Match($raw, 'Checked\s+\d+\s+passwords in\s+[0-9.]+s\s+·\s+\d+\s+passwords/s')
    if (-not $result.Success -or -not $statistics.Success -or -not $raw.Contains('Full entry verification passed.')) { throw 'Mask recovery was not captured completely' }
    Save-Image 'mask-search' @(
        (Color "`$ zip-cracker demo.zip -g --mask '$mask' --limit 200000000" '38;5;183'),
        '',
        ((Color '  ZIP CRACKER' '38;5;183') + '  Password mask'),
        (Color '    demo.zip  ·  5 lowercase letters + 2 printable characters' '38;5;245'),
        '',
        (Color '  DURING SEARCH — captured from this run' '38;5;245'),
        (Color "  $([regex]::Replace($progress.Groups['bar'].Value, '^[\u2800-\u28ff]', '>'))" '35'),
        (Color "    $($progress.Groups['counts'].Value.Trim())" '36'),
        '',
        (Color '  VERIFIED RESULT' '38;5;245'),
        ((Color '  ✓' '32') + ' Password found: ' + (Color $result.Groups['password'].Value '38;5;158')),
        ('  ' + $statistics.Value),
        (Color '    Full entry verification passed.' '38;5;245')
    )

    $raw = Capture-Run 'automatic-recovery' $runDirectory @('known.zip', '--bkcrack', '--bkcrack-path', $backend, '--decrypt', 'recovered.zip')
    $progress = Find-Progress $raw
    $keys = [regex]::Match($raw, 'Recovered keys:\s+(?<keys>[0-9a-f]{8}\s+[0-9a-f]{8}\s+[0-9a-f]{8})')
    $duration = [regex]::Match($raw, 'Completed in\s+[0-9.]+s without password candidates')
    if (-not $keys.Success -or -not $duration.Success -or -not $raw.Contains('Decrypted and verified:')) { throw 'Automatic recovery was not captured completely' }
    Save-Image 'automatic-preview' @(
        (Color '$ zip-cracker known.zip --bkcrack --decrypt recovered.zip' '38;5;183'),
        '',
        ((Color '  ZIP CRACKER' '38;5;183') + '  Automatic recovery'),
        (Color '    known.zip  ·  ZipCrypto / Store' '38;5;245'),
        '',
        (Color '  DISCOVERED AUTOMATICALLY' '38;5;245'),
        (Color '  1. bkcrack-known.txt' '36'),
        (Color '    Matching open copy · size and CRC32 verified' '38;5;245'),
        (Color '    271 known bytes · no password or mask supplied to the attack' '38;5;245'),
        '',
        (Color '  RECOVERING KEYS — captured from this run' '38;5;245'),
        (Color "  $([regex]::Replace($progress.Groups['bar'].Value, '^[\u2800-\u28ff]', '>'))" '35'),
        (Color "    $($progress.Groups['counts'].Value.Trim())" '36'),
        '',
        (Color '  VERIFIED OUTPUT' '38;5;245'),
        ((Color '  ✓' '32') + ' Decrypted and verified: ' + (Color 'recovered.zip' '38;5;158')),
        (Color "    $($keys.Value)" '38;5;245'),
        ('  ' + $duration.Value)
    )
} finally {
    Pop-Location
}
