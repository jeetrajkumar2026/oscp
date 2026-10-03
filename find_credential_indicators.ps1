# Read-only credential and PowerShell obfuscation indicator scan for an authorized lab.
# Reports paths, line numbers, counts, and registry value-name presence only.
# It never prints matched line contents or password values, decodes, executes,
# modifies, or uploads files.

$ErrorActionPreference = 'SilentlyContinue'

# Targeted Windows/OSCP-relevant locations. Add a specific application directory
# here if enumeration identifies one. Broad full-disk scanning is intentionally omitted.
$roots = @(
    'C:\Users',
    'C:\ProgramData',
    'C:\Scripts',
    'C:\Troubleshooting',
    'C:\Temp',
    'C:\Windows\Temp',
    'C:\Windows\Panther',
    'C:\inetpub\wwwroot'
)

$textExtensions = @(
    '*.config', '*.xml', '*.ini', '*.conf', '*.cfg', '*.json', '*.yaml', '*.yml',
    '*.env', '*.properties', '*.txt', '*.ps1', '*.psm1', '*.psd1', '*.bat',
    '*.cmd', '*.vbs', '*.sql', '*.rdp'
)

# Specific secret-field labels and PowerShell CLIXML credential markers.
# Generic "user" labels are omitted because they caused many benign XML matches.
$credentialPatterns = @(
    '(?i)(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|credential|connectionstring|user\s*id|uid)["'']?\s*[:=]',
    '(?i)<\s*(password|passwd|pwd|secret|token|credential)\b',
    '(?i)System\.Management\.Automation\.PSCredential|<SS\s+N=["'']Password'
)
$obfuscationPatterns = @(
    '(?i)FromBase64String',
    '(?i)\bEncodedCommand\b|\s-enc(?:odedcommand)?\b',
    '(?i)\bIEX\b|\bInvoke-Expression\b',
    '(?i)\bDownloadString\b|\bDownloadData\b',
    '(?i)\bGzipStream\b|\bDeflateStream\b',
    '(?i)\[char\]\s*\d+'
)
$keyVaultExtensions = @('*.kdbx', '*.pfx', '*.p12', '*.pem', '*.ppk', '*.key', 'id_rsa*', 'id_ed25519*')
$credentialNamePatterns = @('*pass*.xml', '*pass*.txt', '*pass*.ini', '*pass*.config', '*cred*.*', '*vnc*.*', '*.rdp')

Write-Output 'Read-only scan: values and file contents are not printed or executed.'
Write-Output 'Matches are review leads, not proof that a usable credential exists.'

$scanErrors = @()
$textFiles = @(Get-ChildItem -Path $roots -Recurse -File -Include $textExtensions `
    -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)

$textFindings = foreach ($file in $textFiles) {
    # Ignore this scanner and named enumeration utilities to reduce self-matches;
    # review those tools separately if their provenance is uncertain.
    if ($file.Name -match '(?i)^find_(credential_indicators|ps_obfuscation)\.ps1$|^win_enum.*\.ps1$|^winpeas\.ps1$') {
        continue
    }

    $credentialHits = @(Select-String -LiteralPath $file.FullName -Pattern $credentialPatterns `
        -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)
    $isPowerShellText = $file.Extension -in @('.ps1', '.psm1', '.psd1', '.txt')
    $obfuscationHits = @()
    $longLineHits = @()
    if ($isPowerShellText) {
        $obfuscationHits = @(Select-String -LiteralPath $file.FullName -Pattern $obfuscationPatterns `
            -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)
        $longLineHits = @(Select-String -LiteralPath $file.FullName -Pattern '.{500,}' `
            -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)
    }

    if ($credentialHits.Count -gt 0 -or $obfuscationHits.Count -gt 0 -or $longLineHits.Count -gt 0) {
        $signals = @()
        if ($credentialHits.Count -gt 0) { $signals += 'credential-like field label' }
        if ($obfuscationHits.Count -gt 0) { $signals += 'PowerShell obfuscation indicator' }
        if ($longLineHits.Count -gt 0) { $signals += 'long line (500+ chars)' }
        $lines = @($credentialHits + $obfuscationHits + $longLineHits |
            ForEach-Object { $_.LineNumber } | Sort-Object -Unique)

        [PSCustomObject]@{
            Path        = $file.FullName
            Signals     = $signals -join '; '
            LineNumbers = $lines -join ', '
        }
    }
}

Write-Output "`n===== Text/config/script findings ====="
if ($textFindings) {
    $textFindings | Format-Table -Wrap -AutoSize
} else {
    Write-Output 'No configured indicators found in readable text files.'
}

Write-Output "`n===== Potential key or vault files (names only) ====="
$keyFiles = @(Get-ChildItem -Path $roots -Recurse -File -Include $keyVaultExtensions `
    -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)
if ($keyFiles) {
    $keyFiles | Select-Object -ExpandProperty FullName
} else {
    Write-Output 'No matching key/vault filenames found in readable locations.'
}

Write-Output "`n===== Credential-named files (names only) ====="
$credentialNamedFiles = @(Get-ChildItem -Path $roots -Recurse -File -Include $credentialNamePatterns `
    -ErrorAction SilentlyContinue -ErrorVariable +scanErrors)
if ($credentialNamedFiles) {
    $credentialNamedFiles | Select-Object -ExpandProperty FullName
} else {
    Write-Output 'No matching credential-style filenames found in readable locations.'
}

Write-Output "`n===== Saved credential/autologon artifact presence ====="
try {
    $credentialManagerOutput = & cmdkey.exe /list 2>&1
    $credentialTargetCount = @($credentialManagerOutput | Select-String -Pattern '^\s*Target:' ).Count
    Write-Output "Credential Manager target entries: $credentialTargetCount (names/passwords not displayed)"
} catch {
    Write-Output "Credential Manager query unavailable: $($_.Exception.Message)"
}

try {
    $winlogonKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', $false)
    if ($winlogonKey) {
        $winlogonNames = @($winlogonKey.GetValueNames())
        $autoLogonNamePresent = $winlogonNames -contains 'DefaultUserName'
        $autoLogonPasswordPresent = $winlogonNames -contains 'DefaultPassword'
        $autoLogonEnabledPresent = $winlogonNames -contains 'AutoAdminLogon'
        Write-Output "Winlogon value names present: DefaultUserName=$autoLogonNamePresent; DefaultPassword=$autoLogonPasswordPresent; AutoAdminLogon=$autoLogonEnabledPresent (values not displayed)"
        $winlogonKey.Close()
    } else {
        Write-Output 'Winlogon registry key could not be opened.'
    }
} catch {
    Write-Output "Winlogon registry check unavailable: $($_.Exception.Message)"
}

try {
    $puttySessions = @(Get-ChildItem -Path 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction Stop)
    Write-Output "PuTTY saved-session registry keys: $($puttySessions.Count) (values not displayed)"
} catch {
    Write-Output 'No readable PuTTY saved-session key found for this account.'
}

Write-Output "`n===== Manual review ====="
Write-Output 'These commands reproduce the checks. Content searches can display sensitive values; keep output local.'
Write-Output 'Search filenames in a selected root:'
Write-Output "  Get-ChildItem C:\Users,C:\ProgramData,C:\Scripts,C:\Troubleshooting -Recurse -File -Include *pass*.xml,*pass*.txt,*pass*.ini,*cred*.* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"
Write-Output 'Search text files for credential labels (matching lines may contain secrets):'
Write-Output "  Get-ChildItem C:\Users,C:\ProgramData,C:\Scripts,C:\Troubleshooting -Recurse -File -Include *.config,*.xml,*.ini,*.json,*.txt,*.ps1,*.rdp -ErrorAction SilentlyContinue | Select-String -Pattern 'password|passwd|pwd|secret|token|api[_-]?key|credential|connectionstring|PSCredential'"
Write-Output 'Search PowerShell scripts/history for common obfuscation indicators (show path and line only):'
Write-Output "  Get-ChildItem C:\Users,C:\ProgramData,C:\Scripts,C:\Troubleshooting -Recurse -File -Include *.ps1,*.psm1,*.psd1,*_history.txt -ErrorAction SilentlyContinue | Select-String -Pattern 'FromBase64String|EncodedCommand|Invoke-Expression|DownloadString|GzipStream|DeflateStream|\[char\]\s*\d+' | Select-Object Path,LineNumber"
Write-Output 'List saved Credential Manager targets (does not display passwords):'
Write-Output '  cmdkey.exe /list'
Write-Output 'List Winlogon value names only (does not display values):'
Write-Output "  (Get-Item 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Property"
Write-Output 'List PuTTY saved-session key names only:'
Write-Output "  Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName"
Write-Output 'Inspect a reported file without executing it; review output locally:'
Write-Output "  Get-Content -LiteralPath '<path>'"
Write-Output 'Check its permissions and signature:'
Write-Output "  icacls '<path>'"
Write-Output "  Get-AuthenticodeSignature -LiteralPath '<path>' | Format-List"
Write-Output 'Matches can be placeholders, field names, or documentation rather than usable credentials.'

if ($scanErrors.Count -gt 0) {
    Write-Output "`nINCOMPLETE: $($scanErrors.Count) read/permission errors occurred; inaccessible paths were skipped."
} else {
    Write-Output "`nScan completed for the configured roots and file types. This is not proof no credentials exist elsewhere."
}
