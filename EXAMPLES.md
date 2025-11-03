# Usage Examples

## Basic Examples

### 1. Quick Audit (Console Only)
```powershell
.\Audit-AzureStorageSecurity.ps1
```

**Output:** Console output only, no HTML report

---

### 2. Audit with HTML Report
```powershell
.\Audit-AzureStorageSecurity.ps1 -ExportReport
```

**Output:** Console output + HTML report in current directory

---

### 3. Detailed Audit (Scan for Backup Files)
```powershell
.\Audit-AzureStorageSecurity.ps1 -Detailed -ExportReport
```

**Additional checks:**
- Scans all containers for .bak, .sql, .dump, .backup files
- Reports file sizes
- Flags as warnings

---

## Advanced Examples

### 4. Audit Specific Subscriptions
```powershell
$subs = @(
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
)

.\Audit-AzureStorageSecurity.ps1 -SubscriptionIds $subs -ExportReport
```

---

### 5. Custom Report Location
```powershell
$reportPath = "C:\AuditReports\storage-audit-$(Get-Date -Format 'yyyyMMdd').html"
.\Audit-AzureStorageSecurity.ps1 -ExportReport -ReportPath $reportPath
```

---

### 6. Scheduled Audit (Task Scheduler)
```powershell
# Create scheduled task to run daily at 2 AM
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Audit-AzureStorageSecurity.ps1 -ExportReport"

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

Register-ScheduledTask -TaskName "Azure Storage Security Audit" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

---

### 7. CI/CD Integration (Azure DevOps)
```yaml
# azure-pipelines.yml
steps:
- task: AzurePowerShell@5
  inputs:
    azureSubscription: 'YourServiceConnection'
    ScriptType: 'FilePath'
    ScriptPath: '$(System.DefaultWorkingDirectory)/Audit-AzureStorageSecurity.ps1'
    ScriptArguments: '-ExportReport -ReportPath "$(Build.ArtifactStagingDirectory)/audit-report.html"'
    azurePowerShellVersion: 'LatestVersion'
    
- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)'
    ArtifactName: 'SecurityAuditReports'
    
- script: |
    if [ $? -eq 2 ]; then
      echo "##vso[task.logissue type=error]Critical security issues found!"
      exit 1
    fi
  displayName: 'Check for Critical Issues'
```

---

### 8. Email Report Automatically
```powershell
# Run audit
.\Audit-AzureStorageSecurity.ps1 -ExportReport -ReportPath ".\audit.html"

# Email report
$params = @{
    From = "security@company.com"
    To = "it-team@company.com"
    Subject = "Azure Storage Security Audit - $(Get-Date -Format 'yyyy-MM-dd')"
    Body = "Please find attached the latest Azure Storage security audit report."
    Attachments = ".\audit.html"
    SmtpServer = "smtp.company.com"
}

Send-MailMessage @params
```

---

### 9. Check Specific Storage Account
```powershell
# Get subscription ID where storage account exists
$subId = (Get-AzStorageAccount -Name "mystorageaccount" `
    -ResourceGroupName "myrg").Id.Split('/')[2]

.\Audit-AzureStorageSecurity.ps1 -SubscriptionIds $subId -ExportReport
```

---

### 10. Compare Audit Results Over Time
```powershell
# Run weekly audits with dated filenames
$date = Get-Date -Format 'yyyyMMdd'
$reportPath = "C:\AuditReports\audit-$date.html"

.\Audit-AzureStorageSecurity.ps1 -Detailed -ExportReport -ReportPath $reportPath

# Track issues over time
Write-Host "This week's report: $reportPath"
Write-Host "Compare with previous reports in C:\AuditReports\"
```

---

## Output Examples

### Console Output (Success)
```
Azure Storage Security Audit - All Subscriptions
Started: 2025-11-03 14:30:00

[OK] Authenticated as: admin@company.com

=================================================================
OVERALL SUMMARY
=================================================================

Subscriptions Scanned: 2
Total Storage Accounts: 8
Critical Issues: 0
Warnings: 0

[OK] All checks passed across all subscriptions!

Completed: 2025-11-03 14:32:15
```

### Console Output (Issues Found)
```
Storage Account: proddata
-----------------------------------------------------------------

CHECK 1: Public Blob Access...
   [FAIL] ENABLED - CRITICAL

CHECK 6: Containers...
      [FAIL] backups: PUBLIC (Blob) - CRITICAL
      [PASS] logs: Private
      [PASS] config: Private

=================================================================
OVERALL SUMMARY
=================================================================

Critical Issues: 3
Warnings: 5

[WARNING] Issues found - review and remediate
```

---

## Exit Code Usage
```powershell
.\Audit-AzureStorageSecurity.ps1 -ExportReport

switch ($LASTEXITCODE) {
    0 { Write-Host "Success: No issues found" -ForegroundColor Green }
    1 { Write-Host "Warning: Minor issues found" -ForegroundColor Yellow }
    2 { Write-Host "Critical: Immediate action required!" -ForegroundColor Red }
}
```

---

## Troubleshooting

### Error: Not authenticated
```powershell
# Solution: Login first
Connect-AzAccount

# Then run audit
.\Audit-AzureStorageSecurity.ps1
```

### Error: Module not found
```powershell
# Solution: Install required modules
Install-Module -Name Az.Storage -Scope CurrentUser -Force
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
```

### Error: Insufficient permissions
```powershell
# Solution: Check your Azure role
Get-AzRoleAssignment -SignInName (Get-AzContext).Account.Id

# You need at least "Reader" role on subscriptions
```
