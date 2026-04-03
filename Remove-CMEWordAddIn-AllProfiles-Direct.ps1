<#
  Adam McNelis - VULNOPS
  Vulnerability Toolkit (VTK)
  2026-04-03
  v1.0
  Purpose: Remove the CME Word add-in from loaded and unloaded user profiles by deleting matching HKCU registry entries and per-user files
  Logs: C:\ProgramData\DeptOfVeteransAffairs\logs
#>

[CmdletBinding()]
param(
    [bool]$Echo = $true,
    [string[]]$SkipProfiles = @('Public','Default','Default User','All Users','defaultuser0','systemprofile','LocalService','NetworkService','WDAGUtilityAccount','zero'),
    [string[]]$NamePatterns = @('CMEWordAddIn','WordAddIn1','VACMEAddin','BoozAllen CMEWordAddIn'),
    [string[]]$InstallRelativePaths = @('AppData\Local\CMEWordAddIn'),
    [string[]]$ManifestRelativePaths = @('AppData\Local\CMEWordAddIn\WordAddIn1.vsto')
)

$ErrorActionPreference = 'Stop'
$global:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$global:LogRoot = 'C:\ProgramData\DeptOfVeteransAffairs\logs'
$global:LogFile = Join-Path $global:LogRoot ($global:ScriptName + '.log')
$global:ErrorCounter = 0
$global:RegExe = Join-Path $env:WINDIR 'System32\reg.exe'

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysNativeReg = Join-Path $env:WINDIR 'SysNative\reg.exe'
    if (Test-Path -LiteralPath $sysNativeReg) {
        $global:RegExe = $sysNativeReg
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    try {
        if (-not (Test-Path -LiteralPath $global:LogRoot)) {
            New-Item -Path $global:LogRoot -ItemType Directory -Force | Out-Null
        }

        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        Add-Content -Path $global:LogFile -Value $line -Encoding ASCII
        if ($Echo) {
            Write-Output $line
        }

        if ($Level -eq 'ERROR') {
            $global:ErrorCounter++
        }
    }
    catch {
        $fallback = '{0} [ERROR] Logging failure: {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.Exception.Message
        if ($Echo) {
            Write-Output $fallback
        }
        $global:ErrorCounter++
    }
}

function Close-Log {
    Write-Log -Message ('Finished. Total errors: ' + $global:ErrorCounter)
}

function Invoke-Reg {
    param(
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $output = & $global:RegExe @Arguments 2>&1
    $code = $LASTEXITCODE
    if (($code -ne 0) -and (-not $AllowFailure)) {
        throw ('reg.exe failed [' + $code + '] ' + (($output | Out-String).Trim()))
    }

    return [pscustomobject]@{
        ExitCode = $code
        Output   = (($output | Out-String).Trim())
    }
}

function Test-MatchText {
    param(
        [AllowNull()][string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    foreach ($pattern in $NamePatterns) {
        if ($Text -match [Regex]::Escape($pattern)) {
            return $true
        }
    }

    if ($Text -match '(?i)\.vsto|CMEWordAddIn|WordAddIn1|VACMEAddin') {
        return $true
    }

    return $false
}

function Stop-TargetProcesses {
    foreach ($name in @('WINWORD','VACMEAddin')) {
        try {
            $items = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($items) {
                foreach ($item in $items) {
                    Stop-Process -Id $item.Id -Force -ErrorAction Stop
                    Write-Log -Message ('Stopped process ' + $item.ProcessName + ' PID=' + $item.Id)
                }
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Unable to stop process ' + $name + ': ' + $_.Exception.Message)
        }
    }
}

function Remove-RegistryKeySafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force
        Write-Log -Message ('Removed registry key: ' + $Label)
        return $true
    }
    catch {
        Write-Log -Level 'ERROR' -Message ('Failed removing registry key: ' + $Label + ' - ' + $_.Exception.Message)
        return $false
    }
}

function Remove-RegistryValueSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
            Write-Log -Message ('Removed registry value: ' + $Label)
            return $true
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message ('Failed removing registry value: ' + $Label + ' - ' + $_.Exception.Message)
    }

    return $false
}

function Remove-FilePathSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force
        Write-Log -Message ('Removed path: ' + $Label)
        return $true
    }
    catch {
        Write-Log -Level 'ERROR' -Message ('Failed removing path: ' + $Label + ' - ' + $_.Exception.Message)
        return $false
    }
}

function Get-ProfileList {
    $profiles = @()
    $profileRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    foreach ($item in Get-ChildItem -Path $profileRoot -ErrorAction Stop) {
        try {
            $sid = $item.PSChildName
            if ($sid -notmatch '^S-1-5-21-') { continue }

            $props = Get-ItemProperty -Path $item.PSPath -ErrorAction Stop
            $profilePath = [Environment]::ExpandEnvironmentVariables($props.ProfileImagePath)
            if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
            if (-not (Test-Path -LiteralPath $profilePath)) { continue }

            $leaf = Split-Path -Path $profilePath -Leaf
            if ($SkipProfiles -contains $leaf) {
                Write-Log -Message ('Skipping profile by name: ' + $leaf)
                continue
            }

            if ($profilePath -match '\\Windows\\System32\\config\\systemprofile$') {
                Write-Log -Message ('Skipping system profile path: ' + $profilePath)
                continue
            }

            $profiles += [pscustomobject]@{
                Sid         = $sid
                UserName    = $leaf
                ProfilePath = $profilePath
                NtUserDat   = Join-Path $profilePath 'NTUSER.DAT'
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Skipping one profile list entry: ' + $_.Exception.Message)
        }
    }

    return $profiles | Sort-Object -Property ProfilePath -Unique
}

function Open-UserHive {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile
    )

    if (Test-Path -LiteralPath ('Registry::HKEY_USERS\' + $Profile.Sid)) {
        return [pscustomobject]@{
            RootKey     = 'Registry::HKEY_USERS\' + $Profile.Sid
            NativeKey   = 'HKEY_USERS\' + $Profile.Sid
            IsTemporary = $false
        }
    }

    if (-not (Test-Path -LiteralPath $Profile.NtUserDat)) {
        Write-Log -Level 'WARN' -Message ('NTUSER.DAT not found for ' + $Profile.UserName + ': ' + $Profile.NtUserDat)
        return $null
    }

    $tempHiveName = 'HKU\VTK_' + ($Profile.Sid -replace '[^A-Za-z0-9]','_')
    $result = Invoke-Reg -Arguments @('load', $tempHiveName, $Profile.NtUserDat) -AllowFailure
    if ($result.ExitCode -ne 0) {
        Write-Log -Level 'WARN' -Message ('reg load failed for ' + $Profile.UserName + ' [' + $Profile.Sid + ']: ' + $result.Output)
        return $null
    }

    Write-Log -Message ('Loaded hive for ' + $Profile.UserName + ' [' + $Profile.Sid + '] into ' + $tempHiveName)
    return [pscustomobject]@{
        RootKey     = ('Registry::' + $tempHiveName.Replace('HKU','HKEY_USERS'))
        NativeKey   = ('HKEY_USERS\' + $tempHiveName.Substring(4))
        IsTemporary = $true
    }
}

function Close-UserHive {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Hive,
        [Parameter(Mandatory=$true)][pscustomobject]$Profile
    )

    if (-not $Hive.IsTemporary) {
        return
    }

    $result = Invoke-Reg -Arguments @('unload', $Hive.NativeKey) -AllowFailure
    if ($result.ExitCode -ne 0) {
        Write-Log -Level 'WARN' -Message ('reg unload failed for ' + $Profile.UserName + ' [' + $Profile.Sid + ']: ' + $result.Output)
        return
    }

    Write-Log -Message ('Unloaded hive for ' + $Profile.UserName + ' [' + $Profile.Sid + ']')
}

function Remove-WordAddinKeys {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    $removed = 0
    $wordAddinsRoot = Join-Path $Hive.RootKey 'Software\Microsoft\Office\Word\Addins'
    if (-not (Test-Path -LiteralPath $wordAddinsRoot)) {
        return $removed
    }

    foreach ($subKey in Get-ChildItem -LiteralPath $wordAddinsRoot -ErrorAction SilentlyContinue) {
        try {
            $props = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction SilentlyContinue
            $blob = @(
                $subKey.PSChildName,
                '' + $props.Manifest,
                '' + $props.FriendlyName,
                '' + $props.Description,
                '' + $props.LoadBehavior,
                '' + $props.CommandLineSafe
            ) -join ' '

            if (Test-MatchText -Text $blob) {
                if (Remove-RegistryKeySafe -Path $subKey.PSPath -Label ($Profile.UserName + ' Word Addin ' + $subKey.PSChildName)) {
                    $removed++
                }
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Unable to inspect Word add-in key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
        }
    }

    return $removed
}

function Remove-UninstallKeys {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    $removed = 0
    $uninstallRoot = Join-Path $Hive.RootKey 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    if (-not (Test-Path -LiteralPath $uninstallRoot)) {
        return $removed
    }

    foreach ($subKey in Get-ChildItem -LiteralPath $uninstallRoot -ErrorAction SilentlyContinue) {
        try {
            $props = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction SilentlyContinue
            $blob = @(
                $subKey.PSChildName,
                '' + $props.DisplayName,
                '' + $props.Publisher,
                '' + $props.DisplayIcon,
                '' + $props.InstallLocation,
                '' + $props.UninstallString,
                '' + $props.QuietUninstallString
            ) -join ' '

            if (Test-MatchText -Text $blob) {
                if (Remove-RegistryKeySafe -Path $subKey.PSPath -Label ($Profile.UserName + ' Uninstall ' + $subKey.PSChildName)) {
                    $removed++
                }
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Unable to inspect uninstall key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
        }
    }

    return $removed
}

function Remove-VstoSecurityKeys {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    $removed = 0
    $base = Join-Path $Hive.RootKey 'Software\Microsoft\VSTO\Security\Inclusion'
    if (-not (Test-Path -LiteralPath $base)) {
        return $removed
    }

    $targets = @()
    foreach ($subKey in Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue) {
        $targets += $subKey
        foreach ($child in Get-ChildItem -LiteralPath $subKey.PSPath -Recurse -ErrorAction SilentlyContinue) {
            $targets += $child
        }
    }

    foreach ($item in ($targets | Sort-Object -Property PSPath -Unique | Sort-Object -Property PSPath -Descending)) {
        try {
            $blob = @($item.Name, $item.PSChildName, $item.PSPath) -join ' '
            if (Test-MatchText -Text $blob) {
                if (Remove-RegistryKeySafe -Path $item.PSPath -Label ($Profile.UserName + ' VSTO Security ' + $item.PSChildName)) {
                    $removed++
                }
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Unable to inspect VSTO security key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
        }
    }

    return $removed
}

function Remove-OfficeResiliencyArtifacts {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    $removed = 0
    $officeBase = Join-Path $Hive.RootKey 'Software\Microsoft\Office'
    if (-not (Test-Path -LiteralPath $officeBase)) {
        return $removed
    }

    foreach ($versionKey in Get-ChildItem -LiteralPath $officeBase -ErrorAction SilentlyContinue) {
        try {
            $resiliencyRoot = Join-Path $versionKey.PSPath 'Word\Resiliency'
            if (-not (Test-Path -LiteralPath $resiliencyRoot)) {
                continue
            }

            foreach ($sub in @('DisabledItems','DoNotDisableAddinList','StartupItems')) {
                $subPath = Join-Path $resiliencyRoot $sub
                if (-not (Test-Path -LiteralPath $subPath)) {
                    continue
                }

                foreach ($property in (Get-Item -LiteralPath $subPath).Property) {
                    $valueText = '' + (Get-ItemProperty -LiteralPath $subPath -Name $property -ErrorAction SilentlyContinue).$property
                    $blob = $property + ' ' + $valueText
                    if (Test-MatchText -Text $blob) {
                        if (Remove-RegistryValueSafe -Path $subPath -Name $property -Label ($Profile.UserName + ' Resiliency ' + $sub + ' ' + $property)) {
                            $removed++
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Unable to inspect Office resiliency for ' + $Profile.UserName + ': ' + $_.Exception.Message)
        }
    }

    return $removed
}

function Remove-ProfileFiles {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile
    )

    $removed = 0

    foreach ($relativePath in $InstallRelativePaths) {
        $candidate = Join-Path $Profile.ProfilePath $relativePath
        if (Remove-FilePathSafe -Path $candidate -Label ($Profile.UserName + ' ' + $candidate)) {
            $removed++
        }
    }

    foreach ($relativePath in $ManifestRelativePaths) {
        $candidate = Join-Path $Profile.ProfilePath $relativePath
        if (Test-Path -LiteralPath $candidate) {
            if (Remove-FilePathSafe -Path $candidate -Label ($Profile.UserName + ' ' + $candidate)) {
                $removed++
            }
        }
    }

    return $removed
}

function Process-Profile {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    Write-Log -Message ('Processing profile ' + $Profile.UserName + ' [' + $Profile.Sid + ']')

    $wordRemoved = Remove-WordAddinKeys -Profile $Profile -Hive $Hive
    $uninstallRemoved = Remove-UninstallKeys -Profile $Profile -Hive $Hive
    $vstoRemoved = Remove-VstoSecurityKeys -Profile $Profile -Hive $Hive
    $resiliencyRemoved = Remove-OfficeResiliencyArtifacts -Profile $Profile -Hive $Hive
    $fileRemoved = Remove-ProfileFiles -Profile $Profile

    Write-Log -Message (
        'Summary for ' + $Profile.UserName + ': ' +
        ' WordAddins=' + $wordRemoved +
        ' UninstallKeys=' + $uninstallRemoved +
        ' VSTOSecurity=' + $vstoRemoved +
        ' Resiliency=' + $resiliencyRemoved +
        ' FilePaths=' + $fileRemoved
    )
}

Write-Log -Message 'Starting direct CME Word add-in cleanup.'
Write-Log -Message ('SkipProfiles=' + ($SkipProfiles -join ','))
Write-Log -Message ('NamePatterns=' + ($NamePatterns -join ','))

Stop-TargetProcesses

$profiles = Get-ProfileList
if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Log -Level 'ERROR' -Message 'No eligible user profiles were found.'
    Close-Log
    exit 1
}

Write-Log -Message ('Profiles queued: ' + $profiles.Count)

foreach ($profile in $profiles) {
    $hive = $null
    try {
        $hive = Open-UserHive -Profile $profile
        if ($null -eq $hive) {
            continue
        }

        Process-Profile -Profile $profile -Hive $hive
    }
    catch {
        Write-Log -Level 'ERROR' -Message ('Profile cleanup failed for ' + $profile.UserName + ' [' + $profile.Sid + ']: ' + $_.Exception.Message)
    }
    finally {
        if ($null -ne $hive) {
            Close-UserHive -Hive $hive -Profile $profile
        }
    }
}

Close-Log
if ($global:ErrorCounter -gt 0) {
    exit (1000 + $global:ErrorCounter)
}

exit 0
