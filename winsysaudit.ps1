# Function to Temporarily Set Execution Policy
function Set-ExecutionPolicyTemporarily {
    param (
        [string]$policy = 'RemoteSigned'
    )
    
    try {
        # Get current policy
        $currentPolicy = Get-ExecutionPolicy
        # Set new policy
        Set-ExecutionPolicy $policy -Scope CurrentUser -Force
        Write-Host "Execution policy set to $policy temporarily." -ForegroundColor Green
        
        # Return the old policy to be restored later
        return $currentPolicy
    } catch {
        Write-Host "Failed to set execution policy. Ensure you are running this script with administrative privileges." -ForegroundColor Red
        exit
    }
}

# Function to Restore Execution Policy
function Restore-ExecutionPolicy {
    param (
        [string]$policy
    )
    
    try {
        Set-ExecutionPolicy $policy -Scope CurrentUser -Force
        Write-Host "Execution policy restored to $policy." -ForegroundColor Green
    } catch {
        Write-Host "Failed to restore execution policy. Ensure you have the necessary permissions." -ForegroundColor Red
    }
}

# Check and set Execution Policy to RemoteSigned temporarily
$currentPolicy = Set-ExecutionPolicyTemporarily

# Your existing script functionality...

# Check for Administrative Permissions
function Check-AdminRights {
    try {
        net session | Out-Null
        return $true
    } catch {
        Write-Host "You do not have administrative privileges. Some actions may fail." -ForegroundColor Red
        return $false
    }
}

$adminRights = Check-AdminRights

# Prompt for Output Location
$outputFile = Read-Host "Enter output file path (leave blank for default: C:\SystemInfoReport_yyyyMMdd_HHmmss.txt)"
if ([string]::IsNullOrWhiteSpace($outputFile)) {
    $outputFile = "C:\SystemInfoReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
}

# Validate Output Directory
$outputDirectory = Split-Path $outputFile -Parent
if (-not (Test-Path $outputDirectory)) {
    Write-Host "Directory does not exist. Creating directory..." -ForegroundColor Yellow
    try {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    } catch {
        Write-Host "Failed to create directory. Please check permissions." -ForegroundColor Red
        exit
    }
}

# Initialize Error Log
$errorLog = @()

function Log-Error($message) {
    $errorLog += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR: $message"
}

function Write-OutputToFile($message) {
    Add-Content -Path $outputFile -Value $message
}

function Show-Progress($message) {
    Write-Host $message -ForegroundColor Green
}

function Capture-Error {
    param($block)
    try {
        & $block
    } catch {
        Log-Error "Error: $_"
    }
}

function Gather-SystemInfo {
    Show-Progress "Gathering System Information..."
    Write-OutputToFile "=== SYSTEM INFORMATION ==="
    Write-OutputToFile "========================="
    Capture-Error {
        $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        Write-OutputToFile "OS Version: $osVersion"
    }
    Capture-Error {
        Write-OutputToFile "`nSystem Information:"
        systeminfo | Out-File -Append -FilePath $outputFile
    }
}

function Gather-TasklistAndServices {
    Show-Progress "Gathering Tasklist and Services..."
    Capture-Error {
        Write-OutputToFile "`nTasklist and Services:"
        tasklist /svc | Out-File -Append -FilePath $outputFile
    }
}

function Gather-UserGroupInfo {
    Show-Progress "Gathering User and Group Information..."
    Write-OutputToFile "`n=== USER AND GROUP INFORMATION ==="
    Write-OutputToFile "========================================"
    Capture-Error {
        Write-OutputToFile "`nCurrent Users:"
        net user | Out-File -Append -FilePath $outputFile
    }
    Capture-Error {
        Write-OutputToFile "`nLocal Administrators:"
        net localgroup "Administrators" | Out-File -Append -FilePath $outputFile
    }
}

function Gather-DomainInfo {
    if ($adminRights -and (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History")) {
        Show-Progress "Gathering Domain Information..."
        Write-OutputToFile "`n=== DOMAIN INFORMATION ==="
        Write-OutputToFile "========================================"
        Capture-Error {
            Write-OutputToFile "`nDomain Information:"
            net view /domain | Out-File -Append -FilePath $outputFile
            net user /domain | Out-File -Append -FilePath $outputFile
            net group "Domain Admins" /domain | Out-File -Append -FilePath $outputFile
        }
    } else {
        Write-Host "Domain-specific commands skipped. The system is not part of a domain." -ForegroundColor Yellow
    }
}

function Gather-StorageInfo {
    Show-Progress "Gathering Storage and File Information..."
    Write-OutputToFile "`n=== STORAGE AND FILE INFORMATION ==="
    Write-OutputToFile "========================================"
    Capture-Error {
        Write-OutputToFile "`nList of Drives:"
        fsutil fsinfo drives | Out-File -Append -FilePath $outputFile
    }
    Capture-Error {
        Write-OutputToFile "`nCurrent SMB Shares:"
        net share | Out-File -Append -FilePath $outputFile
    }
    Capture-Error {
        Write-OutputToFile "`nSearching for PDF Files:"
        dir C:\*.pdf -Recurse -ErrorAction SilentlyContinue | Out-File -Append -FilePath $outputFile
    }
    Capture-Error {
        Write-OutputToFile "`nDirectory Listing (C:\):"
        tree C:\ -F -A | Out-File -Append -FilePath $outputFile
    }
}

function Compress-Output {
    $compressReport = Read-Host "Would you like to compress the report into a ZIP file? (Y/N; default is Y if blank)"
    if ([string]::IsNullOrWhiteSpace($compressReport)) {
        $compressReport = "Y"
    }

    if ($compressReport -eq "Y") {
        Show-Progress "Compressing the report..."
        $zipFile = "$outputFile.zip"
        Capture-Error {
            Compress-Archive -Path $outputFile -DestinationPath $zipFile
            Write-Host "Report compressed into $zipFile." -ForegroundColor Green
            Remove-Item -Path $outputFile -Force
        }
    } else {
        Write-Host "Compression skipped." -ForegroundColor Yellow
    }
}

# Start processing all sections
Show-Progress "Starting system information collection..."
Gather-SystemInfo
Gather-TasklistAndServices
Gather-UserGroupInfo
Gather-DomainInfo
Gather-StorageInfo

# Consolidated Error Log
Write-OutputToFile "`n=== ERROR LOG ==="
Write-OutputToFile "========================================"
if ($errorLog.Count -gt 0) {
    Write-OutputToFile ($errorLog -join "`n")
} else {
    Write-OutputToFile "No errors encountered."
}

# Final Message
Show-Progress "System information collection complete. Report saved to $outputFile."
Write-OutputToFile "`n==============================="
Write-OutputToFile "System information collection complete."
Write-OutputToFile "Report saved to $outputFile."
Write-OutputToFile "==============================="

# Open the output file if it exists
if (Test-Path $outputFile) {
    Invoke-Item $outputFile
} elseif (Test-Path "$outputFile.zip") {
    Invoke-Item "$outputFile.zip"
} else {
    Show-Progress "Failed to create the report file." -ForegroundColor Red
}

# Restore the original execution policy
Restore-ExecutionPolicy $currentPolicy
