# Read-only triage for an authorized Windows lab.
# Prompts for a file/folder path, displays icacls output, and checks service
# ImagePath registry values for direct references. Matching services are
# inspected with sc.exe qc/query. This script makes no system changes.

$ErrorActionPreference = 'Continue'

function Write-CheckSection {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Output "`n===== $Title ====="
}

$enteredPath = (Read-Host 'Enter a full file or folder path to inspect').Trim().Trim('"')
if ([string]::IsNullOrWhiteSpace($enteredPath)) {
    Write-Error 'A path is required.'
    return
}

$expandedPath = [Environment]::ExpandEnvironmentVariables($enteredPath)
try {
    $targetPath = [System.IO.Path]::GetFullPath($expandedPath)
} catch {
    Write-Error "Could not parse the path: $($_.Exception.Message)"
    return
}

Write-CheckSection 'Target path'
Write-Output $targetPath
if (-not (Test-Path -LiteralPath $targetPath)) {
    Write-Output 'The path does not currently exist or is not visible to this account.'
}

Write-CheckSection 'Target ACL (icacls)'
if (Test-Path -LiteralPath $targetPath) {
    & icacls.exe $targetPath
} else {
    Write-Output 'Skipped: target path is unavailable.'
}

$parentPath = Split-Path -LiteralPath $targetPath -Parent
if ($parentPath -and (Test-Path -LiteralPath $parentPath)) {
    Write-CheckSection 'Parent directory ACL (icacls)'
    & icacls.exe $parentPath
}

Write-CheckSection 'Services whose configured ImagePath directly contains the target path'
$serviceRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$matchedServices = @()

try {
    $serviceKeys = Get-ChildItem -LiteralPath $serviceRoot -ErrorAction Stop
    foreach ($serviceKey in $serviceKeys) {
        try {
            $serviceProperties = Get-ItemProperty -LiteralPath $serviceKey.PSPath -ErrorAction Stop
            $imagePath = [string]$serviceProperties.ImagePath

            if ($imagePath -and $imagePath.IndexOf(
                $targetPath,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -ge 0) {
                $matchedServices += [PSCustomObject]@{
                    Name      = $serviceKey.PSChildName
                    ImagePath = $imagePath
                }
            }
        } catch {
            # Skip individual service registry keys that are not readable.
        }
    }
} catch {
    Write-Output "Could not read service configuration registry keys: $($_.Exception.Message)"
}

if ($matchedServices.Count -eq 0) {
    Write-Output 'No direct service ImagePath reference to this target path was found.'
} else {
    foreach ($service in $matchedServices) {
        Write-Output "`nService: $($service.Name)"
        Write-Output "Registry ImagePath: $($service.ImagePath)"
        Write-Output 'sc.exe qc:'
        & sc.exe qc $service.Name
        Write-Output 'sc.exe query:'
        & sc.exe query $service.Name
    }
}

Write-CheckSection 'Interpretation'
Write-Output 'Review ACL entries for your account/groups and effective write or modify rights.'
Write-Output 'A writable path is only a lead; confirm a privileged service actually uses it.'
Write-Output 'This checks direct service ImagePath references only; it does not inspect scheduled tasks or indirect script launches.'
