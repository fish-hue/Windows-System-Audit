---

# System Information Collection Script

## Overview
This PowerShell script collects detailed system information, including OS version, currently running tasks and services, user and group info, domain details, storage information, and generates a report in text format. Optionally, it can compress the report into a ZIP file for easier sharing.

## Prerequisites
- This script requires you to run PowerShell.
- You may need to run PowerShell as an administrator, especially for system and domain-related queries.

## Setting Execution Policy
Before running the script, you must set the execution policy for the current session to allow script execution. Open a PowerShell window and execute the following command:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

This command sets the execution policy to `RemoteSigned`, allowing you to run scripts that you create locally or scripts that are signed by a trusted publisher.

## Running the Script
1. **Open PowerShell:**
   - Press `Win + X`, then select `Windows PowerShell (Admin)`.

2. **Navigate to the Script Directory:**
   Change the directory to where the script is located. For example:
   ```powershell
   cd "C:\Path\To\Windows-System-Audit\"
   ```

3. **Run the Script:**
   Execute the script by typing its name:
   ```powershell
   .\winsysaudit.ps1
   ```

4. **Follow Prompts:**
   The script will prompt you for the output location for the report. You can either specify a file path or leave it blank to use the default location.

5. **Review the Output:**
   After the script executes, it will generate a report with system information, which can be found at the specified output location.

## Features
- **System Information**: Captures OS version and system info using `systeminfo`.
- **Tasklists and Services**: Gathers currently running tasks and associated services.
- **User and Group Information**: Provides details about local users and administrators.
- **Domain Information**: If applicable, retrieves domain info and group memberships.
- **Storage Information**: Lists drives, current SMB shares, and searches for specific file types (e.g., PDF).
- **Compression**: Optionally compress the report into a ZIP file.

## Error Logging
Any errors encountered during the execution of the script will be logged. At the end of the script, a consolidated error log will be added to the output report for review.

## Important Notes
- Running the script may require administrative privileges for certain operations.
- Always check the output directory to ensure the report is saved as expected.

--- 
