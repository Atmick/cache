<#
  Adam McNelis - VULNOPS
  Vulnerability Toolkit (VTK)
  2026-04-03
  v1.2
  Purpose: Remove the CME Word VSTO add-in from loaded and unloaded user profiles.
  Logs: C:\ProgramData\DeptOfVeteransAffairs\logs
#>

param(
    [string[]]$SkipProfiles = @(
        'Public','Default','Default User','All Users','defaultuser0',
        'systemprofile','LocalService','NetworkService','WDAGUtilityAccount',
        'zero','Administrator'
    ),
    [string[]]$NamePatterns = @(
        'CMEWordAddIn',
        'WordAddIn1',
        'VACMEAddin',
        'BoozAllen CMEWordAddIn',
        'BoozAllen'
    ),
    [string]$RelativeInstallFolder = 'AppData\Local\CMEWordAddIn',
    [bool]$Echo = $true
)

$ErrorActionPreference = 'Stop'
$global:ErrorCounter = 0
$script:LogRoot = 'C:\ProgramData\DeptOfVeteransAffairs\logs'
$script:LogFile = Join-Path $script:LogRoot ('Remove_CMEWordAddIn_AllProfiles_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Add-Content -Path $script:LogFile -Value $line -Encoding ASCII
    if ($Echo) { Write-Output $line }
    if ($Level.ToUpper() -eq 'ERROR') { $global:ErrorCounter++ }
}

function Close-Log {
    if ($global:ErrorCounter -gt 0) {
        exit (1000 + $global:ErrorCounter)
    }
    exit 0
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-RegCommand {
    param([string[]]$Arguments)

    $text = & reg.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = (($text | Out-String).Trim())
    }
}

function Test-PatternMatch {
    param(
        [string]$Text,
        [string[]]$Patterns
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    foreach ($pattern in $Patterns) {
        if ($Text -like ('*' + $pattern + '*')) { return $true }
    }
    return $false
}

function Remove-KeyTree {
    param(
        [string]$Path,
        [string]$Reason
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed ${Reason}: ${Path}"
        return $true
    }
    catch {
        Write-Log "Failed to remove ${Reason}: ${Path}. $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Remove-WordAddinKeys {
    param(
        [string]$Root,
        [string[]]$Patterns
    )

    $removed = 0
    $paths = @(
        (Join-Path $Root 'Software\Microsoft\Office\Word\Addins'),
        (Join-Path $Root 'Software\Microsoft\Office\16.0\Word\Addins')
    )

    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($child in @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
            $nameHit = Test-PatternMatch -Text $child.PSChildName -Patterns $Patterns
            $manifestHit = $false
            $friendlyHit = $false
            if ($props) {
                $manifestHit = Test-PatternMatch -Text ([string]$props.Manifest) -Patterns $Patterns
                $friendlyHit = Test-PatternMatch -Text ([string]$props.FriendlyName) -Patterns $Patterns
                if (-not $friendlyHit) {
                    $friendlyHit = Test-PatternMatch -Text ([string]$props.Description) -Patterns $Patterns
                }
            }
            if ($nameHit -or $manifestHit -or $friendlyHit) {
                if (Remove-KeyTree -Path $child.PSPath -Reason 'Word add-in key') { $removed++ }
            }
        }
    }

    return $removed
}

function Remove-UninstallKeys {
    param(
        [string]$Root,
        [string[]]$Patterns
    )

    $removed = 0
    $path = Join-Path $Root 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    if (-not (Test-Path -LiteralPath $path)) { return $removed }

    foreach ($child in @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
        $displayName = ''
        $publisher = ''
        $uninstallString = ''
        $urlInfo = ''
        if ($props) {
            $displayName = [string]$props.DisplayName
            $publisher = [string]$props.Publisher
            $uninstallString = [string]$props.UninstallString
            $urlInfo = [string]$props.UrlUpdateInfo
        }

        $hit = $false
        if (Test-PatternMatch -Text $child.PSChildName -Patterns $Patterns) { $hit = $true }
        if (-not $hit -and (Test-PatternMatch -Text $displayName -Patterns $Patterns)) { $hit = $true }
        if (-not $hit -and (Test-PatternMatch -Text $publisher -Patterns $Patterns)) { $hit = $true }
        if (-not $hit -and (Test-PatternMatch -Text $uninstallString -Patterns $Patterns)) { $hit = $true }
        if (-not $hit -and (Test-PatternMatch -Text $urlInfo -Patterns $Patterns)) { $hit = $true }

        if ($hit) {
            if (Remove-KeyTree -Path $child.PSPath -Reason 'HKCU uninstall key') { $removed++ }
        }
    }

    return $removed
}

function Remove-VstoInclusionKeys {
    param(
        [string]$Root,
        [string[]]$Patterns
    )

    $removed = 0
    $path = Join-Path $Root 'Software\Microsoft\VSTO\Security\Inclusion'
    if (-not (Test-Path -LiteralPath $path)) { return $removed }

    foreach ($child in @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $hit = $false
        if (Test-PatternMatch -Text $child.PSChildName -Patterns $Patterns) { $hit = $true }
        if (-not $hit) {
            foreach ($grandChild in @(Get-ChildItem -LiteralPath $child.PSPath -ErrorAction SilentlyContinue)) {
                if (Test-PatternMatch -Text $grandChild.PSChildName -Patterns $Patterns) {
                    $hit = $true
                    break
                }
            }
        }
        if ($hit) {
            if (Remove-KeyTree -Path $child.PSPath -Reason 'VSTO inclusion key') { $removed++ }
        }
    }

    return $removed
}

function Remove-InstallFolder {
    param(
        [string]$ProfilePath,
        [string]$RelativePath
    )

    $fullPath = Join-Path $ProfilePath $RelativePath
    if (-not (Test-Path -LiteralPath $fullPath)) { return 0 }
    if (Remove-KeyTree -Path $fullPath -Reason 'Install folder') { return 1 }
    return 0
}

function Invoke-ProfileCleanup {
    param(
        [string]$Root,
        [string]$ProfileName,
        [string]$ProfilePath,
        [string[]]$Patterns
    )

    $wordAddins = Remove-WordAddinKeys -Root $Root -Patterns $Patterns
    $uninstallKeys = Remove-UninstallKeys -Root $Root -Patterns $Patterns
    $vstoKeys = Remove-VstoInclusionKeys -Root $Root -Patterns $Patterns
    $folders = Remove-InstallFolder -ProfilePath $ProfilePath -RelativePath $RelativeInstallFolder

    Write-Log "Summary for ${ProfileName}: WordAddins=${wordAddins} UninstallKeys=${uninstallKeys} VSTOInclusion=${vstoKeys} InstallFolders=${folders}"
}

if (-not (Test-Path -LiteralPath $script:LogRoot)) {
    New-Item -Path $script:LogRoot -ItemType Directory -Force | Out-Null
}

Write-Log 'Starting direct CME Word add-in cleanup'
Write-Log ('SkipProfiles=' + ($SkipProfiles -join ','))
Write-Log ('NamePatterns=' + ($NamePatterns -join ','))

if (-not (Test-Admin)) {
    Write-Log 'This script must be run elevated.' 'ERROR'
    Close-Log
}

try {
    Get-Process WINWORD -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Log 'Stopped WINWORD if it was running'
}
catch {
    Write-Log "Failed to stop WINWORD. $($_.Exception.Message)" 'WARN'
}

$profileRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profiles = @()

foreach ($item in @(Get-ChildItem -LiteralPath $profileRoot -ErrorAction Stop)) {
    try {
        $sid = $item.PSChildName
        if ($sid -notmatch '^S-1-5-21-') { continue }

        $props = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction Stop
        $profilePath = [Environment]::ExpandEnvironmentVariables([string]$props.ProfileImagePath)
        if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
        if (-not (Test-Path -LiteralPath $profilePath)) { continue }

        $profileName = Split-Path $profilePath -Leaf
        if ([string]::IsNullOrWhiteSpace($profileName)) { continue }
        if ($SkipProfiles -contains $profileName) { continue }

        $ntUserDat = Join-Path $profilePath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $ntUserDat)) { continue }

        $profiles += [pscustomobject]@{
            Sid         = $sid
            ProfileName = $profileName
            ProfilePath = $profilePath
            NtUserDat   = $ntUserDat
        }
    }
    catch {
        Write-Log "Failed to inspect profile list entry $($item.PSChildName). $($_.Exception.Message)" 'WARN'
    }
}

Write-Log ('Profiles queued=' + $profiles.Count)

foreach ($profile in $profiles) {
    Write-Log "Processing profile ${($profile.ProfileName)} [${($profile.Sid)}]"

    $loadedRoot = 'Registry::HKEY_USERS\' + $profile.Sid
    if (Test-Path -LiteralPath $loadedRoot) {
        try {
            Invoke-ProfileCleanup -Root $loadedRoot -ProfileName $profile.ProfileName -ProfilePath $profile.ProfilePath -Patterns $NamePatterns
        }
        catch {
            Write-Log "Profile cleanup failed for ${($profile.ProfileName)} [${($profile.Sid)}]. $($_.Exception.Message)" 'ERROR'
        }
        continue
    }

    $tempHive = 'VTK_' + ($profile.Sid -replace '[^A-Za-z0-9]', '_')
    $load = Invoke-RegCommand -Arguments @('load', ('HKU\' + $tempHive), $profile.NtUserDat)
    if ($load.ExitCode -ne 0) {
        Write-Log "reg load failed for ${($profile.ProfileName)} [${($profile.Sid)}]. ${($load.Output)}" 'WARN'
        continue
    }

    try {
        $baseRoot = 'Registry::HKEY_USERS\' + $tempHive
        Invoke-ProfileCleanup -Root $baseRoot -ProfileName $profile.ProfileName -ProfilePath $profile.ProfilePath -Patterns $NamePatterns
    }
    catch {
        Write-Log "Profile cleanup failed for ${($profile.ProfileName)} [${($profile.Sid)}]. $($_.Exception.Message)" 'ERROR'
    }
    finally {
        $unload = Invoke-RegCommand -Arguments @('unload', ('HKU\' + $tempHive))
        if ($unload.ExitCode -ne 0) {
            Write-Log "reg unload failed for ${($profile.ProfileName)} [${($profile.Sid)}]. ${($unload.Output)}" 'WARN'
        }
    }
}

Write-Log 'Finished direct CME Word add-in cleanup'
Close-Log
