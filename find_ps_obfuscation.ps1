# Read-only heuristic scanner for PowerShell scripts and PSReadLine history in an
# authorized lab. Reports paths, line numbers, and indicator names only. It does
# not decode, execute, modify, or upload files. Matches require manual review.

$ErrorActionPreference = 'SilentlyContinue'
# Common OSCP-style script locations, plus custom folders found on this host.
# C:\Users includes profile AppData and PSReadLine history. Panther is omitted
# because it primarily contains setup/configuration files, not PowerShell scripts.
# Broad Program Files trees are omitted by default; add a specific app folder if relevant.
$roots = @(
    'C:\Scripts',
    'C:\Troubleshooting',
    'C:\Users',
    'C:\ProgramData',
    'C:\Temp',
    'C:\Windows\Temp',
    'C:\Windows\System32\GroupPolicy',
    'C:\inetpub\wwwroot'
)
$patterns = [ordered]@{
    'Base64 decode'       = '(?i)FromBase64String'
    'Encoded command'     = '(?i)\bEncodedCommand\b|\s-enc(?:odedcommand)?\b'
    'Dynamic invocation'  = '(?i)\bIEX\b|\bInvoke-Expression\b'
    'Download at runtime' = '(?i)\bDownloadString\b|\bDownloadData\b'
    'Compression stream'  = '(?i)\bGzipStream\b|\bDeflateStream\b'
    'Numeric char build'  = '(?i)\[char\]\s*\d+'
}
$longLinePattern = '.{500,}'

Write-Output 'Static scan only. Matches are indicators for review, not proof of maliciousness.'
Write-Output 'No file contents are printed; nothing is decoded or executed.'

$files = Get-ChildItem -Path $roots -Recurse -File -Include *.ps1,*.psm1,*.psd1,*_history.txt -ErrorAction SilentlyContinue
if (-not $files) {
    Write-Output 'No readable PowerShell scripts or matching history files found in the configured locations.'
    return
}

$results = foreach ($file in $files) {
    $foundIndicators = @()
    $lineNumbers = @()

    foreach ($indicator in $patterns.Keys) {
        $hits = Select-String -LiteralPath $file.FullName -Pattern $patterns[$indicator] -ErrorAction SilentlyContinue
        if ($hits) {
            $foundIndicators += $indicator
            $lineNumbers += $hits | ForEach-Object { $_.LineNumber }
        }
    }

    $longLines = Select-String -LiteralPath $file.FullName -Pattern $longLinePattern -ErrorAction SilentlyContinue
    if ($longLines) {
        $foundIndicators += 'Long line (500+ characters)'
        $lineNumbers += $longLines | ForEach-Object { $_.LineNumber }
    }

    if ($foundIndicators.Count -gt 0) {
        [PSCustomObject]@{
            Path        = $file.FullName
            Indicators  = ($foundIndicators | Select-Object -Unique) -join '; '
            LineNumbers = ($lineNumbers | Sort-Object -Unique) -join ', '
        }
    }
}

Write-Output "`n===== Files with indicators ====="
if ($results) {
    $results | Format-Table -Wrap -AutoSize
    Write-Output "`n===== Manual review commands ====="
    Write-Output 'Review one reported file as text (do not execute it):'
    Write-Output "  Get-Content -LiteralPath '<reported path>'"
    Write-Output 'Inspect its ACL and signature:'
    Write-Output "  icacls '<reported path>'"
    Write-Output "  Get-AuthenticodeSignature -LiteralPath '<reported path>' | Format-List"
    Write-Output 'For a specific suspicious line, show nearby lines without running the file:'
    Write-Output "  Select-String -LiteralPath '<reported path>' -Pattern '<indicator>' -Context 3,3"
} else {
    Write-Output 'No configured indicators found in readable files. This does not prove scripts are benign.'
}

Write-Output "`nReview flagged files as text only. Legitimate scripts may use these techniques; do not execute unknown content."
