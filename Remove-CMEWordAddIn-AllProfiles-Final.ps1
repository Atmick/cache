<#!
  Adam McNelis - VULNOPS
  Vulnerability Toolkit (VTK)
  2026-04-03
  v1.0
  Purpose: Remove the CME Word VSTO add-in from loaded and unloaded user profiles by deleting registry entries and per-user files.
  Logs: C:\ProgramData\DeptOfVeteransAffairs\logs
#>

param(
    [bool]$Echo = $true,
    [string[]]$SkipProfiles = @(
        'Public','Default','Default User','All Users','defaultuser0','systemprofile',
        'LocalService','NetworkService','WDAGUtilityAccount','zero','Administrator'
    ),
    [string[]]$NamePatterns = @('CMEWordAddIn','WordAddIn1','VACMEAddin','BoozAllen CMEWordAddIn'),
    [string]$RelativeInstallFolder = 'AppData\Local\CMEWordAddIn'
)

$LogRoot = 'C:\ProgramData\DeptOfVeteransAffairs\logs'
$LogFile = Join-Path $LogRoot 'Remove-CMEWordAddIn-AllProfiles.log'
$global:ErrorCounter = 0

if (-not (Test-Path $LogRoot)) {
    New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message,[string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpper(), $Message
    Add-Content -Path $LogFile -Value $line
    if ($Echo) { Write-Host $line }
    if ($Level -eq 'ERROR') { $global:ErrorCounter++ }
}

function Close-Log {
    if ($global:ErrorCounter -gt 0) {
        exit (1000 + $global:ErrorCounter)
    }
    exit 0
}

function Test-NameMatch {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    foreach ($pattern in $NamePatterns) {
        if ($Text -like "*$pattern*" -or $Text -match [regex]::Escape($pattern)) { return $true }
    }
    return $false
}

function Remove-RegistryKeySafe {
    param([string]$Path,[string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed $Reason: $Path"
        return $true
    }
    catch {
        Write-Log "Failed to remove $Reason: $Path. $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Remove-FilePathSafe {
    param([string]$Path,[string]$Reason)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed $Reason: $Path"
        return $true
    }
    catch {
        Write-Log "Failed to remove $Reason: $Path. $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Stop-Word {
    try {
        $procs = Get-Process -Name WINWORD -ErrorAction SilentlyContinue
        if ($procs) {
            $procs | Stop-Process -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-Log 'Stopped WINWORD.EXE'
        }
    }
    catch {
        Write-Log "Failed stopping WINWORD.EXE. $($_.Exception.Message)" 'ERROR'
    }
}

function Get-ProfileCandidates {
    $items = @()
    try {
        $profileKeys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop
        foreach ($key in $profileKeys) {
            try {
                $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                $profilePath = $props.ProfileImagePath
                if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
                $expandedPath = [Environment]::ExpandEnvironmentVariables($profilePath)
                if ([string]::IsNullOrWhiteSpace($expandedPath)) { continue }
                $leaf = Split-Path -Path $expandedPath -Leaf
                if ([string]::IsNullOrWhiteSpace($leaf)) { continue }
                if ($SkipProfiles -contains $leaf) { continue }
                if (-not (Test-Path -LiteralPath $expandedPath)) { continue }
                $sid = Split-Path -Path $key.Name -Leaf
                if ([string]::IsNullOrWhiteSpace($sid)) { continue }
                $items += [pscustomobject]@{
                    Sid = $sid
                    ProfileName = $leaf
                    ProfilePath = $expandedPath
                    HivePath = Join-Path $expandedPath 'NTUSER.DAT'
                    IsLoaded = Test-Path -LiteralPath ("Registry::HKEY_USERS\$sid")
                }
            }
            catch {
                Write-Log "Skipping profile list entry $($key.Name). $($_.Exception.Message)" 'WARN'
            }
        }
    }
    catch {
        Write-Log "Failed reading ProfileList. $($_.Exception.Message)" 'ERROR'
    }
    return $items | Sort-Object ProfileName -Unique
}

function Invoke-HiveCommand {
    param([string[]]$Arguments)
    $output = & reg.exe @Arguments 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $code; Output = ($output -join ' ') }
}

function Remove-MatchingWordAddins {
    param([string]$BaseRoot)
    $count = 0
    $addinsPath = Join-Path $BaseRoot 'Software\Microsoft\Office\Word\Addins'
    if (Test-Path -LiteralPath $addinsPath) {
        foreach ($sub in (Get-ChildItem -LiteralPath $addinsPath -ErrorAction SilentlyContinue)) {
            $nameHit = Test-NameMatch $sub.PSChildName
            $manifestHit = $false
            try {
                $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                if ($p) {
                    foreach ($propName in @('Manifest','FriendlyName','Description')) {
                        $value = $p.$propName
                        if (Test-NameMatch ([string]$value)) { $manifestHit = $true; break }
                        if ([string]$value -match '\.vsto') { $manifestHit = $true; break }
                    }
                }
            }
            catch {}
            if ($nameHit -or $manifestHit) {
                if (Remove-RegistryKeySafe -Path $sub.PSPath -Reason 'Word add-in key') { $count++ }
            }
        }
    }
    return $count
}

function Remove-MatchingUninstallKeys {
    param([string]$BaseRoot)
    $count = 0
    $uninstallRoot = Join-Path $BaseRoot 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    if (Test-Path -LiteralPath $uninstallRoot) {
        foreach ($sub in (Get-ChildItem -LiteralPath $uninstallRoot -ErrorAction SilentlyContinue)) {
            $hit = Test-NameMatch $sub.PSChildName
            if (-not $hit) {
                try {
                    $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                    foreach ($propName in @('DisplayName','DisplayIcon','InstallLocation','UninstallString')) {
                        if (Test-NameMatch ([string]$p.$propName)) { $hit = $true; break }
                    }
                }
                catch {}
            }
            if ($hit) {
                if (Remove-RegistryKeySafe -Path $sub.PSPath -Reason 'HKCU uninstall key') { $count++ }
            }
        }
    }
    return $count
}

function Remove-MatchingVstoSecurityKeys {
    param([string]$BaseRoot)
    $count = 0
    $securityRoot = Join-Path $BaseRoot 'Software\Microsoft\VSTO\Security\Inclusion'
    if (Test-Path -LiteralPath $securityRoot) {
        foreach ($sub in (Get-ChildItem -LiteralPath $securityRoot -ErrorAction SilentlyContinue)) {
            $hit = Test-NameMatch $sub.PSChildName
            if (-not $hit) {
                try {
                    $values = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in $values.PSObject.Properties) {
                        if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                        if (Test-NameMatch ([string]$prop.Value)) { $hit = $true; break }
                        if ([string]$prop.Value -match '\.vsto') { $hit = $true; break }
                    }
                }
                catch {}
            }
            if ($hit) {
                if (Remove-RegistryKeySafe -Path $sub.PSPath -Reason 'VSTO security inclusion key') { $count++ }
            }
        }
    }
    return $count
}

function Remove-MatchingResiliencyKeys {
    param([string]$BaseRoot)
    $count = 0
    $resiliencyRoot = Join-Path $BaseRoot 'Software\Microsoft\Office'
    if (-not (Test-Path -LiteralPath $resiliencyRoot)) { return 0 }
    foreach ($officeVer in (Get-ChildItem -LiteralPath $resiliencyRoot -ErrorAction SilentlyContinue)) {
        $wordResiliency = Join-Path $officeVer.PSPath 'Word\Resiliency'
        if (-not (Test-Path -LiteralPath $wordResiliency)) { continue }
        foreach ($branchName in @('DisabledItems','StartupItems')) {
            $branchPath = Join-Path $wordResiliency $branchName
            if (-not (Test-Path -LiteralPath $branchPath)) { continue }
            try {
                $item = Get-Item -LiteralPath $branchPath -ErrorAction Stop
                $props = Get-ItemProperty -LiteralPath $branchPath -ErrorAction SilentlyContinue
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                    $text = ''
                    if ($prop.Value -is [byte[]]) {
                        $text = [System.Text.Encoding]::Unicode.GetString($prop.Value)
                    }
                    else {
                        $text = [string]$prop.Value
                    }
                    if (Test-NameMatch $text -or $text -match '\.vsto') {
                        try {
                            Remove-ItemProperty -LiteralPath $branchPath -Name $prop.Name -Force -ErrorAction Stop
                            Write-Log "Removed resiliency value: $branchPath\$($prop.Name)"
                            $count++
                        }
                        catch {
                            Write-Log "Failed removing resiliency value: $branchPath\$($prop.Name). $($_.Exception.Message)" 'ERROR'
                        }
                    }
                }
                foreach ($sub in ($item | Get-ChildItem -ErrorAction SilentlyContinue)) {
                    $subHit = Test-NameMatch $sub.PSChildName
                    if (-not $subHit) {
                        try {
                            $subProps = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
                            foreach ($prop in $subProps.PSObject.Properties) {
                                if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                                if (Test-NameMatch ([string]$prop.Value) -or [string]$prop.Value -match '\.vsto') { $subHit = $true; break }
                            }
                        }
                        catch {}
                    }
                    if ($subHit) {
                        if (Remove-RegistryKeySafe -Path $sub.PSPath -Reason 'Word resiliency subkey') { $count++ }
                    }
                }
            }
            catch {}
        }
    }
    return $count
}

function Invoke-ProfileCleanup {
    param(
        [string]$Root,
        [string]$ProfileName,
        [string]$ProfilePath
    )

    $wordAddins = Remove-MatchingWordAddins -BaseRoot $Root
    $uninstallKeys = Remove-MatchingUninstallKeys -BaseRoot $Root
    $vstoSecurity = Remove-MatchingVstoSecurityKeys -BaseRoot $Root
    $resiliency = Remove-MatchingResiliencyKeys -BaseRoot $Root

    $fileHits = 0
    $installFolder = Join-Path $ProfilePath $RelativeInstallFolder
    if (Remove-FilePathSafe -Path $installFolder -Reason 'add-in folder') { $fileHits++ }

    $clickOncePath = Join-Path $ProfilePath 'AppData\Local\Apps\2.0'
    if (Test-Path -LiteralPath $clickOncePath) {
        foreach ($pattern in $NamePatterns) {
            try {
                $matches = Get-ChildItem -LiteralPath $clickOncePath -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -like "*$pattern*" }
                foreach ($match in $matches) {
                    if (Remove-FilePathSafe -Path $match.FullName -Reason 'ClickOnce/VSTO leftover') { $fileHits++ }
                }
            }
            catch {}
        }
    }

    Write-Log "Summary for $ProfileName: WordAddins=$wordAddins UninstallKeys=$uninstallKeys VSTOSecurity=$vstoSecurity Resiliency=$resiliency FilePaths=$fileHits"
}

Write-Log 'Starting direct CME Word add-in cleanup'
Write-Log ('SkipProfiles=' + ($SkipProfiles -join ','))
Write-Log ('NamePatterns=' + ($NamePatterns -join ','))

Stop-Word

$profiles = Get-ProfileCandidates
Write-Log ('Profiles queued: ' + $profiles.Count)

foreach ($profile in $profiles) {
    Write-Log ("Processing profile $($profile.ProfileName) [$($profile.Sid)]")
    if (-not (Test-Path -LiteralPath $profile.HivePath)) {
        Write-Log "Skipping $($profile.ProfileName). Missing NTUSER.DAT at $($profile.HivePath)" 'WARN'
        continue
    }

    if ($profile.IsLoaded) {
        try {
            $baseRoot = "Registry::HKEY_USERS\$($profile.Sid)"
            Invoke-ProfileCleanup -Root $baseRoot -ProfileName $profile.ProfileName -ProfilePath $profile.ProfilePath
        }
        catch {
            Write-Log "Profile cleanup failed for $($profile.ProfileName) [$($profile.Sid)]. $($_.Exception.Message)" 'ERROR'
        }
        continue
    }

    $tempHive = 'VTK_' + ($profile.Sid -replace '[^A-Za-z0-9]','_')
    $load = Invoke-HiveCommand -Arguments @('load',"HKU\$tempHive",$profile.HivePath)
    if ($load.ExitCode -ne 0) {
        Write-Log "Skipping $($profile.ProfileName). reg load failed: $($load.Output)" 'WARN'
        continue
    }

    try {
        $baseRoot = "Registry::HKEY_USERS\$tempHive"
        Invoke-ProfileCleanup -Root $baseRoot -ProfileName $profile.ProfileName -ProfilePath $profile.ProfilePath
    }
    catch {
        Write-Log "Profile cleanup failed for $($profile.ProfileName) [$($profile.Sid)]. $($_.Exception.Message)" 'ERROR'
    }
    finally {
        $unload = Invoke-HiveCommand -Arguments @('unload',"HKU\$tempHive")
        if ($unload.ExitCode -ne 0) {
            Write-Log "reg unload failed for $($profile.ProfileName): $($unload.Output)" 'WARN'
        }
    }
}

Write-Log 'Finished direct CME Word add-in cleanup'
Close-Log
