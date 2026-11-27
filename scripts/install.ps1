param(
    [string]$InstallDir = "$env:LOCALAPPDATA\zip-cracker",
    [switch]$Force
)

$RepoOwner = "fresh-milkshake"
$RepoName = "zip-cracker"
$BinaryName = "zip-cracker.exe"

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
        default { 
            Write-ColorMessage "Error: Unsupported architecture: $arch" "Red"
            Write-ColorMessage "Only x86_64/AMD64 architecture is supported" "Red"
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
    
    $ErrorActionPreference = "Stop"
    $downloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$Version/zip-cracker-windows-x64.exe"
    $tempFile = Join-Path $InstallDir ".zip-cracker-$([guid]::NewGuid()).exe"
    $destPath = Join-Path $InstallDir $BinaryName
    $expectedVersion = "zip-cracker $($Version -creplace '^v', '')"
    
    try {
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-ColorMessage "Created installation directory: $InstallDir" "Blue"
        }
        
        if ((Test-Path -LiteralPath $destPath -PathType Leaf) -and -not $Force) {
            try {
                $installedVersion = & $destPath --version
                if ($LASTEXITCODE -eq 0 -and ($installedVersion -join "`n") -ceq $expectedVersion) {
                    Write-ColorMessage "zip-cracker $Version is already installed" "Green"
                    return $true
                }
            }
            catch {
                Write-ColorMessage "The existing binary could not run. Reinstalling..." "Yellow"
            }
        }
        
        Write-ColorMessage "Downloading zip-cracker from $downloadUrl..." "Blue"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
        $downloadedVersion = & $tempFile --version
        if ($LASTEXITCODE -ne 0) {
            throw "Downloaded binary exited with code $LASTEXITCODE"
        }
        if (($downloadedVersion -join "`n") -cne $expectedVersion) {
            throw "Downloaded binary did not report version $Version"
        }

        if (Test-Path -LiteralPath $destPath -PathType Leaf) {
            [IO.File]::Replace($tempFile, $destPath, [NullString]::Value)
        }
        else {
            [IO.File]::Move($tempFile, $destPath)
        }
        Write-ColorMessage "Binary installed to $destPath" "Green"
        
        return $true
    }
    catch {
        Write-ColorMessage "Error during installation: $($_.Exception.Message)" "Red"
        return $false
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Add-ToPath {
    Write-ColorMessage "Configuring PATH environment variable..." "Blue"
    
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    
    if ($currentPath -and $currentPath.Split(';') -contains $InstallDir) {
        Write-ColorMessage "$InstallDir is already in PATH" "Yellow"
        return
    }
    
    try {
        $newPath = if ($currentPath) { "$currentPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        $env:PATH = "$env:PATH;$InstallDir"
        Write-ColorMessage "Added $InstallDir to user PATH" "Green"
        Write-ColorMessage "PATH will be available in new terminal sessions" "Blue"
    }
    catch {
        Write-ColorMessage "Warning: Could not update PATH environment variable - $($_.Exception.Message)" "Yellow"
        Write-ColorMessage "Please manually add $InstallDir to your PATH" "Yellow"
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
    Write-ColorMessage "  -Force         Reinstall even if the latest version is already installed" "White"
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
    
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-ColorMessage "Error: PowerShell 3.0 or higher is required" "Red"
        exit 1
    }
    
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
            Write-ColorMessage "You can now run: zip-cracker --help" "Blue"
            
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

if ($MyInvocation.MyCommand.Path) {
    if (-not $PSBoundParameters.Count -and -not $args.Count) {
        Show-Usage
        return
    }
}

Main
