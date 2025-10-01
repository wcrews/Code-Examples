README - WinSCP SFTP Download Script

Overview

This PowerShell script automates downloading files from an SFTP (or
SCP/FTP/WebDAV) server using the WinSCP .NET assembly. It supports
multiple file masks and flexible include-name patterns, and ensures
safer path handling and better error reporting.

Requirements

1.  Windows PowerShell 5.1 or PowerShell 7+.
2.  WinSCP installed.
    -   Ensure WinSCPnet.dll (the .NET assembly) is available.
    -   Common locations:
        -   C:\Program Files (x86)\WinSCP\WinSCPnet.dll
        -   C:\Program Files\WinSCP\WinSCPnet.dll
3.  Network access to the target server (firewall/SFTP open).

Parameters

-   -LocalPath
    Local folder where files will be downloaded.
    Example: C:\Downloads

-   -RemotePath
    Remote directory path on the SFTP server.
    Example: /incoming

-   -FileMask
    One or more file patterns to match. Default is "*.zip".
    Example: "*.zip","*.txt"

-   -HostName
    Hostname or IP of the remote server.
    Example: sftp.example.com

-   -UserName
    Username for authentication.

-   -Password
    Password for authentication (omit if using key-based
    authentication).

-   -Protocol
    Protocol type. Default: Sftp. Options: Sftp, Scp, Ftp, Webdav.

-   -SshPrivateKeyPath
    Path to private key file for authentication (if using keys).

-   -SshPrivateKeyPassphrase
    Passphrase for the private key (if required).

-   -SshHostKeyFingerprint
    The SSH host key fingerprint to validate the remote server identity.

-   -IncludeNamePatterns
    One or more wildcard patterns to filter which files to download.
    Example: "*LETR*","*BILL*"

-   -WinSCPnetPath
    Optional: Path to the WinSCP .NET assembly. Defaults to typical
    install location.

Usage Example

Run the script from PowerShell:

    .\Download-From-SFTP.ps1 `
      -LocalPath "C:\Downloads" `
      -RemotePath "/incoming" `
      -FileMask "*.zip","*.txt" `
      -HostName "sftp.example.com" `
      -UserName "bob" `
      -Password "hunter2" `
      -IncludeNamePatterns "*LETR*","*BILL*" -Verbose

Notes

-   If no files match the filters, the script exits without errors.
-   If the local path does not exist, it will be created automatically.
-   If transfers fail, warnings are logged but other files will continue
    to download.
-   Use -Verbose for detailed output.

Author

Will Crews

