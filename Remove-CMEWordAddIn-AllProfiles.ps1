<#
  Adam McNelis - VULNOPS
  Vulnerability Toolkit (VTK)
  2026-04-03
  v1.0
  Purpose: Remove the CME Word VSTO add-in from all local user profiles by cleaning per-user registry hives and files
  Logs: C:\ProgramData\DeptOfVeteransAffairs\logs
#>

[CmdletBinding()]
param(
    [string]$AddInRegKeyName = 'WordAddIn1',
    [string]$ProductNamePattern = 'CMEWordAddIn*',
    [string]$RelativeInstallFolder = 'AppData\Local\CMEWordAddIn',
    [bool]$Echo = $true
)

$ErrorActionPreference = 'Stop'
$global:ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$global:LogRoot = 'C:\ProgramData\DeptOfVeteransAffairs\logs'
$global:LogFile = Join-Path $global:LogRoot ($global:ScriptName + '.log')
$global:ErrorCounter = 0
$global:RegExe = Join-Path $env:WINDIR 'System32\reg.exe'
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysNativeReg = Join-Path $env:WINDIR 'SysNative\reg.exe'
    if (Test-Path $sysNativeReg) {
        $global:RegExe = $sysNativeReg
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    try {
        if (-not (Test-Path $global:LogRoot)) {
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

function Remove-RegistryKeySafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (Test-Path -LiteralPath $Path) {
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

    Write-Log -Message ('Registry key not found: ' + $Label)
    return $true
}

function Remove-FilePathSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (Test-Path -LiteralPath $Path) {
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

    Write-Log -Message ('Path not found: ' + $Label)
    return $true
}

function Get-ProfileList {
    $profiles = @()
    $profileRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    foreach ($item in Get-ChildItem -Path $profileRoot -ErrorAction Stop) {
        try {
            $sid = $item.PSChildName
            $props = Get-ItemProperty -Path $item.PSPath -ErrorAction Stop
            $profilePath = [Environment]::ExpandEnvironmentVariables($props.ProfileImagePath)
            if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
            if ($sid -notmatch '^S-1-5-21-') { continue }

            $leaf = Split-Path -Path $profilePath -Leaf
            if ($leaf -in @('Public','Default','Default User','All Users')) { continue }
            if ($profilePath -match '\Windows\System32\config\systemprofile$') { continue }
            if (-not (Test-Path -LiteralPath $profilePath)) { continue }

            $profiles += [pscustomobject]@{
                Sid         = $sid
                ProfilePath = $profilePath
                NtUserDat    = Join-Path $profilePath 'NTUSER.DAT'
                UserName     = $leaf
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
        Write-Log -Message ('Hive already loaded for ' + $Profile.UserName + ' [' + $Profile.Sid + ']')
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
    $arguments = @('load', $tempHiveName, $Profile.NtUserDat)
    $output = & $global:RegExe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Level 'ERROR' -Message ('reg load failed for ' + $Profile.UserName + ' [' + $Profile.Sid + ']: ' + (($output | Out-String).Trim()))
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

    $arguments = @('unload', $Hive.NativeKey)
    $output = & $global:RegExe @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Level 'ERROR' -Message ('reg unload failed for ' + $Profile.UserName + ' [' + $Profile.Sid + ']: ' + (($output | Out-String).Trim()))
        return
    }

    Write-Log -Message ('Unloaded hive for ' + $Profile.UserName + ' [' + $Profile.Sid + ']')
}

function Remove-CMEAddInFromHive {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Profile,
        [Parameter(Mandatory=$true)][pscustomobject]$Hive
    )

    $root = $Hive.RootKey
    $wordAddinsRoot = Join-Path $root 'Software\Microsoft\Office\Word\Addins'
    $uninstallRoot = Join-Path $root 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $vstoSecurityRoot = Join-Path $root 'Software\Microsoft\VSTO\Security\Inclusion'

    Write-Log -Message ('Processing profile ' + $Profile.UserName + ' [' + $Profile.Sid + ']')

    if (Test-Path -LiteralPath $wordAddinsRoot) {
        foreach ($subKey in Get-ChildItem -LiteralPath $wordAddinsRoot -ErrorAction SilentlyContinue) {
            try {
                $props = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction SilentlyContinue
                $manifest = '' + $props.Manifest
                $friendlyName = '' + $props.FriendlyName
                $description = '' + $props.Description
                $keyName = '' + $subKey.PSChildName
                $matchFound = $false

                if ($keyName -ieq $AddInRegKeyName) { $matchFound = $true }
                if ($manifest -match '(?i)CMEWordAddIn|WordAddIn1\.vsto|WordAddIn1\.dll') { $matchFound = $true }
                if ($friendlyName -match '(?i)CMEWordAddIn|WordAddIn1') { $matchFound = $true }
                if ($description -match '(?i)CMEWordAddIn|WordAddIn1') { $matchFound = $true }

                if ($matchFound) {
                    [void](Remove-RegistryKeySafe -Path $subKey.PSPath -Label ($Profile.UserName + ' Word Addin ' + $keyName))
                }
            }
            catch {
                Write-Log -Level 'WARN' -Message ('Unable to inspect add-in key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
            }
        }
    }
    else {
        Write-Log -Message ('Word add-ins root not found for ' + $Profile.UserName)
    }

    if (Test-Path -LiteralPath $uninstallRoot) {
        foreach ($subKey in Get-ChildItem -LiteralPath $uninstallRoot -ErrorAction SilentlyContinue) {
            try {
                $props = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction SilentlyContinue
                $displayName = '' + $props.DisplayName
                $keyName = '' + $subKey.PSChildName
                if ($displayName -like $ProductNamePattern -or $keyName -like $ProductNamePattern) {
                    [void](Remove-RegistryKeySafe -Path $subKey.PSPath -Label ($Profile.UserName + ' Uninstall ' + $keyName))
                }
            }
            catch {
                Write-Log -Level 'WARN' -Message ('Unable to inspect uninstall key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
            }
        }
    }
    else {
        Write-Log -Message ('Uninstall root not found for ' + $Profile.UserName)
    }

    if (Test-Path -LiteralPath $vstoSecurityRoot) {
        foreach ($subKey in Get-ChildItem -LiteralPath $vstoSecurityRoot -Recurse -ErrorAction SilentlyContinue) {
            try {
                $candidate = '' + $subKey.Name
                if ($candidate -match '(?i)CMEWordAddIn|WordAddIn1') {
                    [void](Remove-RegistryKeySafe -Path $subKey.PSPath -Label ($Profile.UserName + ' VSTO Inclusion ' + $candidate))
                }
            }
            catch {
                Write-Log -Level 'WARN' -Message ('Unable to inspect VSTO inclusion key for ' + $Profile.UserName + ': ' + $_.Exception.Message)
            }
        }
    }

    $installFolder = Join-Path $Profile.ProfilePath $RelativeInstallFolder
    [void](Remove-FilePathSafe -Path $installFolder -Label ($Profile.UserName + ' ' + $installFolder))
}

Write-Log -Message 'Starting CME Word add-in cleanup.'
Write-Log -Message ('AddInRegKeyName=' + $AddInRegKeyName + '; ProductNamePattern=' + $ProductNamePattern + '; RelativeInstallFolder=' + $RelativeInstallFolder)

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

        Remove-CMEAddInFromHive -Profile $profile -Hive $hive
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
