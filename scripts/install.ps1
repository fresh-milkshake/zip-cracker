# Zip Cracker - Automatic Installation Script for Windows PowerShell
# Usage: Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fresh-milkshake/zip-cracker/master/scripts/install.ps1" -UseBasicParsing | Invoke-Expression

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\zip-cracker",
    [switch]$Force
)

# Configuration
$RepoOwner = "fresh-milkshake"
$RepoName = "zip-cracker"
$BinaryName = "zip-cracker.exe"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Cyan"
    White = "White"
}

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "arm64" }
        default { 
            Write-ColorMessage "Error: Unsupported architecture: $arch" "Red"
            exit 1
        }
    }
}

function Get-LatestVersion {
    Write-ColorMessage "Fetching latest release information..." "Blue"
    
    try {
        $apiUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $version = $response.tag_name
        
        if (-not $version) {
            throw "Could not fetch latest version"
        }
        
        Write-ColorMessage "Latest version: $version" "Green"
        return $version
    }
    catch {
        Write-ColorMessage "Error: Could not fetch latest version - $($_.Exception.Message)" "Red"
        exit 1
    }
}

function Install-Binary {
    param(
        [string]$Version,
        [string]$Architecture
    )
    
    $downloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$Version/zip-cracker-$Version-windows-$Architecture.zip"
    $tempDir = [System.IO.Path]::GetTempPath()
    $tempFile = Join-Path $tempDir "zip-cracker-$Version.zip"
    $extractDir = Join-Path $tempDir "zip-cracker-extract"
    
    Write-ColorMessage "Downloading zip-cracker from $downloadUrl..." "Blue"
    
    try {
        # Download the binary
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        
        if (-not (Test-Path $tempFile)) {
            throw "Download failed: File not found"
        }
        
        Write-ColorMessage "Extracting archive..." "Blue"
        
        # Create extraction directory
        if (Test-Path $extractDir) {
            Remove-Item $extractDir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
        
        # Extract the archive
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Expand-Archive -Path $tempFile -DestinationPath $extractDir -Force
        } else {
            # Fallback for older PowerShell versions
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($tempFile, $extractDir)
        }
        
        # Create install directory
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-ColorMessage "Created installation directory: $InstallDir" "Blue"
        }
        
        # Find and move the binary
        $binaryPath = Get-ChildItem -Path $extractDir -Name $BinaryName -Recurse | Select-Object -First 1
        if ($binaryPath) {
            $sourcePath = Join-Path $extractDir $binaryPath
            $destPath = Join-Path $InstallDir $BinaryName
            
            if ((Test-Path $destPath) -and -not $Force) {
                $response = Read-Host "Binary already exists at $destPath. Overwrite? (y/N)"
                if ($response -notmatch '^[Yy]') {
                    Write-ColorMessage "Installation cancelled by user." "Yellow"
                    return $false
                }
            }
            
            Copy-Item $sourcePath $destPath -Force
            Write-ColorMessage "Binary installed to $destPath" "Green"
        } else {
            throw "Binary not found in archive"
        }
        
        return $true
    }
    catch {
        Write-ColorMessage "Error during installation: $($_.Exception.Message)" "Red"
        return $false
    }
    finally {
        # Clean up temporary files
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        if (Test-Path $extractDir) {
            Remove-Item $extractDir -Recurse -Force
        }
    }
}

function Add-ToPath {
    Write-ColorMessage "Configuring PATH environment variable..." "Blue"
    
    # Get current user PATH
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    
    if ($currentPath -and $currentPath.Split(';') -contains $InstallDir) {
        Write-ColorMessage "$InstallDir is already in PATH" "Yellow"
        return
    }
    
    try {
        # Add to user PATH
        $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        
        # Update current session PATH
        $env:PATH = "$env:PATH;$InstallDir"
        
        Write-ColorMessage "Added $InstallDir to user PATH" "Green"
        Write-ColorMessage "PATH will be available in new terminal sessions" "Blue"
    }
    catch {
        Write-ColorMessage "Warning: Could not update PATH environment variable - $($_.Exception.Message)" "Yellow"
        Write-ColorMessage "Please manually add $InstallDir to your PATH" "Yellow"
    }
}

function Test-Installation {
    $binaryPath = Join-Path $InstallDir $BinaryName
    
    if (Test-Path $binaryPath) {
        Write-ColorMessage "Installation successful!" "Green"
        Write-ColorMessage "Binary location: $binaryPath" "Blue"
        
        # Test if binary works
        try {
            & $binaryPath --help | Out-Null
            Write-ColorMessage "Binary is working correctly" "Green"
            Write-ColorMessage "You can now run: zip-cracker --help" "Blue"
        }
        catch {
            Write-ColorMessage "Warning: Binary installed but may not be working correctly" "Yellow"
        }
        
        return $true
    }
    else {
        Write-ColorMessage "Installation failed: Binary not found" "Red"
        return $false
    }
}

function Show-Usage {
    Write-ColorMessage "Zip Cracker Installation Script for Windows" "Green"
    Write-ColorMessage ""
    Write-ColorMessage "Usage:" "Blue"
    Write-ColorMessage "  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/fresh-milkshake/zip-cracker/master/scripts/install.ps1' -UseBasicParsing | Invoke-Expression" "White"
    Write-ColorMessage ""
    Write-ColorMessage "Parameters:" "Blue"
    Write-ColorMessage "  -InstallDir    Directory to install binary (default: %LOCALAPPDATA%\zip-cracker)" "White"
    Write-ColorMessage "  -Force         Overwrite existing installation without prompting" "White"
    Write-ColorMessage ""
    Write-ColorMessage "Examples:" "Blue"
    Write-ColorMessage "  # Install with custom directory" "White"
    Write-ColorMessage "  & .\install.ps1 -InstallDir 'C:\Tools\zip-cracker'" "White"
    Write-ColorMessage ""
    Write-ColorMessage "  # Force reinstall" "White"
    Write-ColorMessage "  & .\install.ps1 -Force" "White"
}

function Main {
    Write-ColorMessage "=== Zip Cracker Installation Script ===" "Green"
    Write-ColorMessage "This script will download and install zip-cracker to $InstallDir" "Blue"
    Write-ColorMessage ""
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-ColorMessage "Error: PowerShell 3.0 or higher is required" "Red"
        exit 1
    }
    
    # Check if running as Administrator for system-wide installation
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-ColorMessage "Running as Administrator - installing for current user only" "Yellow"
    }
    
    try {
        $architecture = Get-Architecture
        Write-ColorMessage "Detected architecture: $architecture" "Blue"
        
        $version = Get-LatestVersion
        $success = Install-Binary -Version $version -Architecture $architecture
        
        if ($success) {
            Add-ToPath
            Test-Installation
            
            Write-ColorMessage "" "White"
            Write-ColorMessage "=== Installation Complete ===" "Green"
            Write-ColorMessage "Documentation: https://github.com/$RepoOwner/$RepoName" "Blue"
            Write-ColorMessage ""
            Write-ColorMessage "Note: You may need to restart your terminal for PATH changes to take effect" "Yellow"
        }
        else {
            exit 1
        }
    }
    catch {
        Write-ColorMessage "Unexpected error: $($_.Exception.Message)" "Red"
        exit 1
    }
}

# Check if script is being piped from web or run locally
if ($MyInvocation.MyCommand.Path) {
    # Script is being run locally, show usage if no parameters
    if (-not $PSBoundParameters.Count -and -not $args.Count) {
        Show-Usage
        return
    }
}

# Run the installer
Main