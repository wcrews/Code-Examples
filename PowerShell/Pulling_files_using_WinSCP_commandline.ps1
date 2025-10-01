<#
.SYNOPSIS
    Download selected files from a remote server using WinSCP .NET assembly.

.DESCRIPTION
    - Supports multiple file masks (e.g. "*.zip","*.txt")
    - Filters files by name patterns (e.g. "*LETR*","*BILL*")
    - Uses safer local path handling (Join-Path)
    - Correct property name for SSH private key passphrase (SshPrivateKeyPassphrase)
    - Attempts to locate WinSCPnet.dll and gives a helpful error if missing
    - Creates local download folder if it doesn't exist
    - Uses verbose/warning messages for clarity

.EXAMPLE
    .\Download-From-SFTP.ps1 `
      -LocalPath "C:\Downloads" `
      -RemotePath "/incoming" `
      -FileMask "*.zip","*.txt" `
      -HostName "sftp.example.com" `
      -UserName "bob" `
      -Password "hunter2" `
      -IncludeNamePatterns "*LETR*","*BILL*" -Verbose

.NOTES
    - You must have WinSCP installed and the WinSCP .NET assembly available.
    - If you use key-based auth, populate -SshPrivateKeyPath and (if needed) -SshPrivateKeyPassphrase.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LocalPath = "C:\Downloads",

    [Parameter(Mandatory=$false)]
    [string]$RemotePath = "/",

    [Parameter(Mandatory=$false)]
    [string[]]$FileMask = @("*.zip"),

    [Parameter(Mandatory=$true)]
    [string]$HostName = "TODO#",

    [Parameter(Mandatory=$true)]
    [string]$UserName = "TODO#",

    [Parameter(Mandatory=$false)]
    [string]$Password = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Sftp","Scp","Ftp","Webdav")]
    [string]$Protocol = "Sftp",

    [Parameter(Mandatory=$false)]
    [string]$SshPrivateKeyPath = "",

    [Parameter(Mandatory=$false)]
    [string]$SshPrivateKeyPassphrase = "",   # <-- corrected property name

    [Parameter(Mandatory=$false)]
    [string]$SshHostKeyFingerprint = "",

    [Parameter(Mandatory=$false)]
    [string[]]$IncludeNamePatterns = @("*LETR*"),

    [Parameter(Mandatory=$false)]
    [string]$WinSCPnetPath = "C:\Program Files (x86)\WinSCP\WinSCPnet.dll"
)

function Join-RemotePath {
    param(
        [string]$BasePath,
        [string]$Name
    )
    if ([string]::IsNullOrEmpty($BasePath)) { return $Name }
    if ($BasePath.EndsWith("/")) { return $BasePath + $Name }
    return $BasePath + "/" + $Name
}

# Try to find WinSCP .NET assembly if default not present
$possiblePaths = @(
    $WinSCPnetPath,
    "C:\Program Files (x86)\WinSCP\WinSCPnet.dll",
    "C:\Program Files\WinSCP\WinSCPnet.dll"
) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique

$winScpFound = $null
foreach ($p in $possiblePaths) {
    if (Test-Path -Path $p) {
        $winScpFound = $p
        break
    }
}

if (-not $winScpFound) {
    Write-Error "WinSCP .NET assembly (WinSCPnet.dll) not found. Install WinSCP and/or set -WinSCPnetPath to the DLL path."
    Write-Error "Common install locations: 'C:\Program Files (x86)\WinSCP\WinSCPnet.dll' or 'C:\Program Files\WinSCP\WinSCPnet.dll'"
    exit 2
}

try {
    Add-Type -Path $winScpFound -ErrorAction Stop
}
catch {
    Write-Error "Failed to load WinSCP .NET assembly from '$winScpFound': $($_.Exception.Message)"
    exit 2
}

# Basic validation for auth
if ([string]::IsNullOrEmpty($Password) -and [string]::IsNullOrEmpty($SshPrivateKeyPath)) {
    Write-Error "Authentication not provided. Either supply -Password or -SshPrivateKeyPath."
    exit 3
}

# Ensure local folder exists
try {
    if (-not (Test-Path -Path $LocalPath)) {
        Write-Verbose "Local path $LocalPath does not exist. Creating..."
        New-Item -ItemType Directory -Path $LocalPath -Force | Out-Null
    }
}
catch {
    Write-Error "Failed to ensure local folder exists: $($_.Exception.Message)"
    exit 4
}

$sessionOptions = New-Object WinSCP.SessionOptions
$sessionOptions.Protocol = [WinSCP.Protocol]::$Protocol
$sessionOptions.HostName = $HostName
$sessionOptions.UserName = $UserName
$sessionOptions.Timeout = New-TimeSpan -Minutes 5

if (-not [string]::IsNullOrEmpty($Password)) {
    $sessionOptions.Password = $Password
}
if (-not [string]::IsNullOrEmpty($SshPrivateKeyPath)) {
    $sessionOptions.SshPrivateKeyPath = $SshPrivateKeyPath
}
if (-not [string]::IsNullOrEmpty($SshPrivateKeyPassphrase)) {
    $sessionOptions.SshPrivateKeyPassphrase = $SshPrivateKeyPassphrase
}
if (-not [string]::IsNullOrEmpty($SshHostKeyFingerprint)) {
    $sessionOptions.SshHostKeyFingerprint = $SshHostKeyFingerprint
}

$session = New-Object WinSCP.Session

try {
    Write-Verbose "Opening session to $HostName..."
    $session.Open($sessionOptions)

    # Collect remote file names from all provided masks
    $remoteFilesFound = @()
    foreach ($mask in $FileMask) {
        Write-Verbose "Enumerating remote files in '$RemotePath' matching '$mask'..."
        try {
            $items = $session.EnumerateRemoteFiles($RemotePath, $mask, [WinSCP.EnumerationOptions]::None)
            foreach ($it in $items) {
                # Only collect files (not directories)
                if (-not $it.IsDirectory) {
                    $remoteFilesFound += $it.Name
                }
            }
        }
        catch {
            Write-Warning "Enumeration for mask '$mask' failed: $($_.Exception.Message)"
        }
    }

    $remoteFilesFound = $remoteFilesFound | Sort-Object -Unique

    if ($remoteFilesFound.Count -eq 0) {
        Write-Host "No remote files found matching masks: $($FileMask -join ', ') in $RemotePath"
        return
    }

    Write-Verbose "Remote files discovered: $($remoteFilesFound -join ', ')"

    # Filter by IncludeNamePatterns (if provided)
    $filesToDownload = @()
    foreach ($f in $remoteFilesFound) {
        foreach ($pat in $IncludeNamePatterns) {
            if ($f -like $pat) {
                $filesToDownload += $f
                break
            }
        }
    }

    if ($filesToDownload.Count -eq 0) {
        Write-Host "No files matched include name patterns: $($IncludeNamePatterns -join ', ')"
        return
    }

    Write-Host "Files to download: $($filesToDownload -join ', ')"

    foreach ($file in $filesToDownload) {
        $remoteFilePath = Join-RemotePath -BasePath $RemotePath -Name $file
        $localFilePath = Join-Path -Path $LocalPath -ChildPath $file

        Write-Host "Downloading: $remoteFilePath -> $localFilePath"
        try {
            $transferResult = $session.GetFiles($remoteFilePath, $localFilePath)
            # Throw on any transfer error
            $transferResult.Check()
            Write-Host "Successfully downloaded: $file"
        }
        catch {
            Write-Warning "Failed to download '$file': $($_.Exception.Message)"
        }
    }
}
catch {
    Write-Error "Session error: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($session -ne $null) {
        try { $session.Dispose() } catch {}
    }
}
