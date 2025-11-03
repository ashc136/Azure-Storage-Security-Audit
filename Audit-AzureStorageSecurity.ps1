<#
.SYNOPSIS
    Azure Storage Account Security Audit - All Subscriptions
    
.DESCRIPTION
    Audits Azure Storage Accounts across ALL subscriptions for security misconfigurations.
    This is a READ-ONLY audit script - no changes are made to your environment.
    
.PARAMETER ExportReport
    Generate an HTML report of the audit findings
    
.PARAMETER Detailed
    Perform detailed scan including backup file detection
    
.PARAMETER ReportPath
    Custom path for the HTML report (default: current directory with timestamp)
    
.PARAMETER SubscriptionIds
    Optional array of specific subscription IDs to audit (default: all accessible subscriptions)
    
.EXAMPLE
    .\Audit-AzureStorageSecurity.ps1
    Basic audit across all subscriptions
    
.EXAMPLE
    .\Audit-AzureStorageSecurity.ps1 -ExportReport
    Audit with HTML report generation
    
.EXAMPLE
    .\Audit-AzureStorageSecurity.ps1 -Detailed -ExportReport
    Detailed audit including backup file scan with HTML report
    
.EXAMPLE
    .\Audit-AzureStorageSecurity.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -ExportReport
    Audit specific subscriptions only
    
.NOTES
    Author: Ash C
    Date: 2025-11-03
    Version: 1.0
    Requires: Az.Storage, Az.Accounts PowerShell modules
    Permissions: Reader role on subscriptions being audited
#>

[CmdletBinding()]
param(
    [switch]$ExportReport,
    [switch]$Detailed,
    [string]$ReportPath = ".\storage-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').html",
    [string[]]$SubscriptionIds
)

$ErrorActionPreference = "Continue"

# Results tracking
$script:CriticalIssues = 0
$script:WarningIssues = 0
$script:Results = @()
$script:SubscriptionResults = @()

function Write-Status {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Details = "")
    $status = if($Passed){"[PASS]"}else{"[FAIL]"}
    $color = if($Passed){"Green"}else{"Red"}
    Write-Host "   $status $Name" -ForegroundColor $color
    if($Details) { Write-Host "      $Details" -ForegroundColor Gray }
}

Write-Status "`nAzure Storage Security Audit - All Subscriptions" -Color Cyan
Write-Status "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -Color Gray

# Check modules
if (-not (Get-Module -ListAvailable -Name Az.Storage)) {
    Write-Status "Installing Az.Storage module..." -Color Yellow
    Install-Module -Name Az.Storage -Scope CurrentUser -Force -AllowClobber
}
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Write-Status "Installing Az.Accounts module..." -Color Yellow
    Install-Module -Name Az.Accounts -Scope CurrentUser -Force -AllowClobber
}
Import-Module Az.Storage, Az.Accounts -ErrorAction Stop

# Check authentication
$context = Get-AzContext
if (-not $context) {
    Write-Status "Not authenticated. Logging in..." -Color Yellow
    Connect-AzAccount
    $context = Get-AzContext
}

Write-Status "[OK] Authenticated as: $($context.Account.Id)`n" -Color Green

# Get all subscriptions
Write-Status "Discovering subscriptions..." -Color Yellow

if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    $subscriptions = @()
    foreach ($subId in $SubscriptionIds) {
        try {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
            $subscriptions += $sub
        } catch {
            Write-Status "[WARNING] Could not access subscription: $subId" -Color Yellow
        }
    }
} else {
    $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
}

if ($subscriptions.Count -eq 0) {
    Write-Status "[ERROR] No accessible subscriptions found" -Color Red
    exit 1
}

Write-Status "[OK] Found $($subscriptions.Count) subscription(s)`n" -Color Green

$totalStorageAccounts = 0

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    Write-Status "=================================================================" -Color Magenta
    Write-Status "SUBSCRIPTION: $($subscription.Name)" -Color Magenta
    Write-Status "ID: $($subscription.Id)" -Color Gray
    Write-Status "=================================================================`n" -Color Magenta
    
    # Switch to subscription
    try {
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        Write-Status "[OK] Switched to subscription`n" -Color Green
    } catch {
        Write-Status "[ERROR] Failed to switch to subscription: $($_.Exception.Message)`n" -Color Red
        continue
    }
    
    # Get storage accounts in this subscription
    try {
        $storageAccounts = Get-AzStorageAccount -ErrorAction Stop
    } catch {
        Write-Status "[WARNING] Could not retrieve storage accounts: $($_.Exception.Message)`n" -Color Yellow
        continue
    }
    
    if ($storageAccounts.Count -eq 0) {
        Write-Status "[INFO] No storage accounts in this subscription`n" -Color Gray
        
        $script:SubscriptionResults += @{
            Name = $subscription.Name
            Id = $subscription.Id
            StorageAccountCount = 0
            Critical = 0
            Warnings = 0
        }
        continue
    }
    
    Write-Status "Found $($storageAccounts.Count) storage account(s) in this subscription`n" -Color White
    $totalStorageAccounts += $storageAccounts.Count
    
    $subCritical = 0
    $subWarnings = 0
    
    # Audit each storage account
    foreach ($sa in $storageAccounts) {
        Write-Status "-----------------------------------------------------------------" -Color Cyan
        Write-Status "Storage Account: $($sa.StorageAccountName)" -Color Cyan
        Write-Status "-----------------------------------------------------------------`n" -Color Cyan
        
        $accountResult = @{
            Name = $sa.StorageAccountName
            ResourceGroup = $sa.ResourceGroupName
            Location = $sa.Location
            Subscription = $subscription.Name
            SubscriptionId = $subscription.Id
            Checks = @()
            ContainerDetails = @()
            BackupFiles = @()
            Critical = 0
            Warnings = 0
        }
        
        # CHECK 1: Public Blob Access
        Write-Status "CHECK 1: Public Blob Access..." -Color Yellow
        $publicAccess = $sa.AllowBlobPublicAccess
        $passed = -not $publicAccess
        Write-Check -Name $(if($passed){"Disabled"}else{"ENABLED - CRITICAL"}) -Passed $passed
        if(-not $passed) { 
            $script:CriticalIssues++
            $accountResult.Critical++
            $subCritical++
        }
        $accountResult.Checks += @{Name="Public Blob Access"; Status=if($passed){"PASS"}else{"CRITICAL"}; Value=if($publicAccess){"Enabled"}else{"Disabled"}}
        
        # CHECK 2: HTTPS Only
        Write-Status "`nCHECK 2: HTTPS Enforcement..." -Color Yellow
        $httpsOnly = $sa.EnableHttpsTrafficOnly
        Write-Check -Name $(if($httpsOnly){"Enforced"}else{"NOT enforced - CRITICAL"}) -Passed $httpsOnly
        if(-not $httpsOnly) { 
            $script:CriticalIssues++
            $accountResult.Critical++
            $subCritical++
        }
        $accountResult.Checks += @{Name="HTTPS Only"; Status=if($httpsOnly){"PASS"}else{"CRITICAL"}; Value=if($httpsOnly){"Yes"}else{"No"}}
        
        # CHECK 3: TLS Version
        Write-Status "`nCHECK 3: Minimum TLS Version..." -Color Yellow
        $tlsVersion = $sa.MinimumTlsVersion
        $tlsOk = $tlsVersion -eq "TLS1_2" -or $tlsVersion -eq "TLS1_3"
        Write-Check -Name "TLS $tlsVersion $(if(-not $tlsOk){'- Upgrade to 1.2+'})" -Passed $tlsOk
        if(-not $tlsOk) { 
            $script:WarningIssues++
            $accountResult.Warnings++
            $subWarnings++
        }
        $accountResult.Checks += @{Name="TLS Version"; Status=if($tlsOk){"PASS"}else{"WARNING"}; Value=$tlsVersion}
        
        # CHECK 4: Encryption
        Write-Status "`nCHECK 4: Encryption..." -Color Yellow
        $blobEnc = $sa.Encryption.Services.Blob.Enabled
        $fileEnc = $sa.Encryption.Services.File.Enabled
        $encOk = $blobEnc -and $fileEnc
        Write-Check -Name $(if($encOk){"Enabled"}else{"NOT fully enabled - CRITICAL"}) -Passed $encOk -Details "Blob: $blobEnc, File: $fileEnc"
        if(-not $encOk) { 
            $script:CriticalIssues++
            $accountResult.Critical++
            $subCritical++
        }
        $accountResult.Checks += @{Name="Encryption"; Status=if($encOk){"PASS"}else{"CRITICAL"}; Value="Blob: $blobEnc, File: $fileEnc"}
        
        # CHECK 5: Network Rules
        Write-Status "`nCHECK 5: Network Firewall..." -Color Yellow
        $defaultAction = $sa.NetworkRuleSet.DefaultAction
        $firewallOk = $defaultAction -eq "Deny"
        Write-Check -Name "Default: $defaultAction $(if(-not $firewallOk){'- WARNING'})" -Passed $firewallOk
        if(-not $firewallOk) { 
            $script:WarningIssues++
            $accountResult.Warnings++
            $subWarnings++
        }
        $accountResult.Checks += @{Name="Network Firewall"; Status=if($firewallOk){"PASS"}else{"WARNING"}; Value="Default: $defaultAction"}
        
        # CHECK 6: Container Public Access
        Write-Status "`nCHECK 6: Containers..." -Color Yellow
        try {
            $ctx = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -UseConnectedAccount
            $containers = Get-AzStorageContainer -Context $ctx
            
            if($containers.Count -eq 0) {
                Write-Status "   No containers found" -Color Gray
                $accountResult.ContainerDetails += @{Name="(none)"; Status="No containers"; PublicAccess="N/A"}
            } else {
                $publicContainers = @()
                foreach($c in $containers) {
                    $isPublic = $c.PublicAccess -and $c.PublicAccess -ne "Off" -and $c.PublicAccess -ne "None"
                    
                    if($isPublic) {
                        Write-Host "      [FAIL] $($c.Name): PUBLIC ($($c.PublicAccess)) - CRITICAL" -ForegroundColor Red
                        $publicContainers += $c.Name
                        $script:CriticalIssues++
                        $accountResult.Critical++
                        $subCritical++
                        $accountResult.ContainerDetails += @{Name=$c.Name; Status="CRITICAL"; PublicAccess=$c.PublicAccess}
                    } else {
                        Write-Host "      [PASS] $($c.Name): Private" -ForegroundColor Green
                        $accountResult.ContainerDetails += @{Name=$c.Name; Status="PASS"; PublicAccess="Private"}
                    }
                }
                $accountResult.Checks += @{Name="Container Public Access"; Status=if($publicContainers.Count -eq 0){"PASS"}else{"CRITICAL"}; Value="$($publicContainers.Count) public container(s)"}
            }
        } catch {
            Write-Status "   Unable to check containers: $($_.Exception.Message)" -Color Yellow
            $accountResult.ContainerDetails += @{Name="Error"; Status="Unable to check"; PublicAccess=$_.Exception.Message}
        }
        
        # CHECK 7: Backup Files (if Detailed)
        if($Detailed) {
            Write-Status "`nCHECK 7: Backup Files..." -Color Yellow
            $backupExts = @(".bak", ".sql", ".dump", ".backup")
            $backupFilesFound = @()
            
            try {
                foreach($c in $containers) {
                    try {
                        $blobs = Get-AzStorageBlob -Container $c.Name -Context $ctx -ErrorAction SilentlyContinue
                        foreach($blob in $blobs) {
                            $ext = [System.IO.Path]::GetExtension($blob.Name).ToLower()
                            if($backupExts -contains $ext) {
                                $sizeGB = [math]::Round($blob.Length / 1GB, 2)
                                $sizeMB = [math]::Round($blob.Length / 1MB, 2)
                                $displaySize = if($sizeGB -gt 0.1) { "$sizeGB GB" } else { "$sizeMB MB" }
                                
                                Write-Host "      [WARNING] $($c.Name)/$($blob.Name) - $displaySize" -ForegroundColor Yellow
                                
                                $backupFilesFound += @{
                                    Container = $c.Name
                                    FileName = $blob.Name
                                    Size = $displaySize
                                    SizeBytes = $blob.Length
                                }
                                
                                $script:WarningIssues++
                                $accountResult.Warnings++
                                $subWarnings++
                            }
                        }
                    } catch {}
                }
                
                if($backupFilesFound.Count -eq 0) {
                    Write-Status "   [PASS] No backup files found" -Color Green
                } else {
                    $accountResult.BackupFiles = $backupFilesFound
                }
                $accountResult.Checks += @{Name="Backup Files"; Status=if($backupFilesFound.Count -eq 0){"PASS"}else{"WARNING"}; Value="$($backupFilesFound.Count) backup file(s) found"}
            } catch {
                Write-Status "   Unable to scan for backup files" -Color Yellow
            }
        }
        
        # CHECK 8: Soft Delete
        Write-Status "`nCHECK 8: Soft Delete..." -Color Yellow
        try {
            $blobProps = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName
            $softDelete = $blobProps.DeleteRetentionPolicy.Enabled
            $days = $blobProps.DeleteRetentionPolicy.Days
            Write-Check -Name $(if($softDelete){"Enabled ($days days)"}else{"Disabled - WARNING"}) -Passed $softDelete
            if(-not $softDelete) { 
                $script:WarningIssues++
                $accountResult.Warnings++
                $subWarnings++
            }
            $accountResult.Checks += @{Name="Soft Delete"; Status=if($softDelete){"PASS"}else{"WARNING"}; Value=if($softDelete){"Enabled ($days days)"}else{"Disabled"}}
        } catch {
            Write-Status "   Unable to check" -Color Gray
            $accountResult.Checks += @{Name="Soft Delete"; Status="INFO"; Value="Unable to check"}
        }
        
        # CHECK 9: Diagnostic Logging
        Write-Status "`nCHECK 9: Diagnostic Logging..." -Color Yellow
        try {
            $diag = Get-AzDiagnosticSetting -ResourceId $sa.Id -ErrorAction SilentlyContinue
            $diagEnabled = $diag -and $diag.Count -gt 0
            Write-Check -Name $(if($diagEnabled){"Configured"}else{"Not configured - WARNING"}) -Passed $diagEnabled
            if(-not $diagEnabled) { 
                $script:WarningIssues++
                $accountResult.Warnings++
                $subWarnings++
            }
            $accountResult.Checks += @{Name="Diagnostic Logging"; Status=if($diagEnabled){"PASS"}else{"WARNING"}; Value=if($diagEnabled){"Configured"}else{"Not configured"}}
        } catch {
            Write-Status "   Unable to check" -Color Gray
            $accountResult.Checks += @{Name="Diagnostic Logging"; Status="INFO"; Value="Unable to check"}
        }
        
        $script:Results += $accountResult
        Write-Host ""
    }
    
    # Add subscription summary
    $script:SubscriptionResults += @{
        Name = $subscription.Name
        Id = $subscription.Id
        StorageAccountCount = $storageAccounts.Count
        Critical = $subCritical
        Warnings = $subWarnings
    }
    
    Write-Status "Subscription Summary: $subCritical Critical, $subWarnings Warnings`n" -Color $(if($subCritical -gt 0){"Red"}elseif($subWarnings -gt 0){"Yellow"}else{"Green"})
}

# Overall Summary
Write-Status "=================================================================" -Color Cyan
Write-Status "OVERALL SUMMARY" -Color Cyan
Write-Status "=================================================================`n" -Color Cyan

Write-Status "Subscriptions Scanned: $($subscriptions.Count)" -Color White
Write-Status "Total Storage Accounts: $totalStorageAccounts" -Color White
Write-Status "Critical Issues: $script:CriticalIssues" -Color $(if($script:CriticalIssues -gt 0){"Red"}else{"Green"})
Write-Status "Warnings: $script:WarningIssues`n" -Color $(if($script:WarningIssues -gt 0){"Yellow"}else{"Green"})

# Subscription breakdown
Write-Status "By Subscription:" -Color Cyan
foreach ($subResult in $script:SubscriptionResults) {
    $statusColor = if($subResult.Critical -gt 0){"Red"}elseif($subResult.Warnings -gt 0){"Yellow"}else{"Green"}
    Write-Status "   - $($subResult.Name): $($subResult.StorageAccountCount) accounts, $($subResult.Critical) critical, $($subResult.Warnings) warnings" -Color $statusColor
}
Write-Host ""

if($script:CriticalIssues -eq 0 -and $script:WarningIssues -eq 0) {
    Write-Status "[OK] All checks passed across all subscriptions!" -Color Green
} else {
    Write-Status "[WARNING] Issues found - review and remediate" -Color Red
}

# Export report
if($ExportReport) {
    Write-Status "`nGenerating HTML report..." -Color Yellow
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Storage Security Audit Report</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { margin: 0 0 15px 0; font-size: 28px; }
        .header p { margin: 5px 0; opacity: 0.9; }
        
        .summary { background: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary h2 { margin-top: 0; color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #0078d4; }
        .stat-card.critical { border-left-color: #d32f2f; background: #ffebee; }
        .stat-card.warning { border-left-color: #f57c00; background: #fff3e0; }
        .stat-card.success { border-left-color: #388e3c; background: #e8f5e9; }
        .stat-card h3 { margin: 0 0 5px 0; font-size: 14px; color: #666; }
        .stat-card .value { font-size: 32px; font-weight: bold; margin: 0; }
        
        .subscription { background: #e3f2fd; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #0078d4; }
        .subscription h2 { margin-top: 0; color: #0078d4; }
        
        .account { background: white; padding: 25px; border-radius: 10px; margin: 15px 0 15px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .account h3 { margin-top: 0; color: #333; font-size: 20px; }
        .account-meta { color: #666; margin: 10px 0; font-size: 14px; }
        .account-status { margin: 15px 0; }
        
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: #0078d4; color: white; font-weight: 600; position: sticky; top: 0; }
        tr:hover { background: #f5f5f5; }
        
        .critical { color: #d32f2f; font-weight: bold; }
        .warning { color: #f57c00; font-weight: bold; }
        .pass { color: #388e3c; font-weight: bold; }
        .info { color: #666; }
        
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin: 0 5px; }
        .badge-critical { background: #d32f2f; color: white; }
        .badge-warning { background: #f57c00; color: white; }
        .badge-pass { background: #388e3c; color: white; }
        
        .container-list, .backup-list { margin: 15px 0; }
        .container-item, .backup-item { padding: 8px 12px; margin: 5px 0; border-radius: 5px; background: #f8f9fa; border-left: 3px solid #ccc; }
        .container-item.public { background: #ffebee; border-left-color: #d32f2f; }
        .container-item.private { background: #e8f5e9; border-left-color: #388e3c; }
        .backup-item { background: #fff3e0; border-left-color: #f57c00; }
        
        .sub-summary { background: #fff3cd; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #f57c00; }
        
        @media print {
            body { background: white; }
            .account, .summary, .subscription { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure Storage Security Audit Report</h1>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Audited By:</strong> $($context.Account.Id)</p>
        <p><strong>Tenant:</strong> $($context.Tenant.Id)</p>
    </div>
    
    <div class="summary">
        <h2>Overall Summary</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>Subscriptions Scanned</h3>
                <p class="value">$($subscriptions.Count)</p>
            </div>
            <div class="stat-card">
                <h3>Storage Accounts</h3>
                <p class="value">$totalStorageAccounts</p>
            </div>
            <div class="stat-card critical">
                <h3>Critical Issues</h3>
                <p class="value">$script:CriticalIssues</p>
            </div>
            <div class="stat-card warning">
                <h3>Warnings</h3>
                <p class="value">$script:WarningIssues</p>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <h2>Subscriptions Breakdown</h2>
"@

    foreach ($subResult in $script:SubscriptionResults) {
        $html += @"
        <div class="sub-summary">
            <strong>$($subResult.Name)</strong><br>
            <span style="color: #666;">Storage Accounts: $($subResult.StorageAccountCount)</span> | 
            <span class="critical">Critical: $($subResult.Critical)</span> | 
            <span class="warning">Warnings: $($subResult.Warnings)</span>
        </div>
"@
    }
    
    $html += "</div>"
    
    # Group results by subscription
    $resultsBySubscription = $script:Results | Group-Object -Property Subscription
    
    foreach ($subGroup in $resultsBySubscription) {
        $html += @"
    <div class="subscription">
        <h2>$($subGroup.Name)</h2>
        <p><strong>Storage Accounts in this subscription:</strong> $($subGroup.Count)</p>
"@
        
        foreach($result in $subGroup.Group) {
            $html += @"
        <div class="account">
            <h3>$($result.Name)</h3>
            <div class="account-meta">
                <strong>Resource Group:</strong> $($result.ResourceGroup) | 
                <strong>Location:</strong> $($result.Location) | 
                <strong>Subscription:</strong> $($result.Subscription)
            </div>
            <div class="account-status">
                <span class="badge badge-critical">Critical: $($result.Critical)</span>
                <span class="badge badge-warning">Warnings: $($result.Warnings)</span>
            </div>
            
            <h4>Security Checks</h4>
            <table>
                <thead>
                    <tr>
                        <th style="width: 30%;">Check</th>
                        <th style="width: 15%;">Status</th>
                        <th style="width: 55%;">Details</th>
                    </tr>
                </thead>
                <tbody>
"@
            foreach($check in $result.Checks) {
                $statusClass = switch($check.Status) {
                    "CRITICAL" {"critical"}
                    "WARNING" {"warning"}
                    "PASS" {"pass"}
                    default {"info"}
                }
                
                $html += @"
                    <tr>
                        <td><strong>$($check.Name)</strong></td>
                        <td class="$statusClass">$($check.Status)</td>
                        <td>$($check.Value)</td>
                    </tr>
"@
            }
            $html += "</tbody></table>"
            
            # Add container details if available
            if($result.ContainerDetails.Count -gt 0) {
                $html += "<h4>Container Details</h4><div class='container-list'>"
                foreach($container in $result.ContainerDetails) {
                    $containerClass = if($container.Status -eq "CRITICAL"){"public"}elseif($container.Status -eq "PASS"){"private"}else{""}
                    $html += "<div class='container-item $containerClass'><strong>$($container.Name)</strong> - $($container.PublicAccess)</div>"
                }
                $html += "</div>"
            }
            
            # Add backup files if found
            if($result.BackupFiles.Count -gt 0) {
                $html += "<h4>Backup Files Found</h4><div class='backup-list'>"
                foreach($backup in $result.BackupFiles) {
                    $html += "<div class='backup-item'><strong>$($backup.Container)/$($backup.FileName)</strong> - Size: $($backup.Size)</div>"
                }
                $html += "</div>"
            }
            
            $html += "</div>"
        }
        
        $html += "</div>"
    }
    
    $html += @"
    <div style="text-align: center; padding: 20px; color: #666; font-size: 14px; margin-top: 30px;">
        <p>Azure Storage Security Audit Report</p>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Status "[OK] Report saved: $ReportPath" -Color Green
    
    # Get file size
    $fileInfo = Get-Item $ReportPath
    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    Write-Status "   File size: $fileSizeMB MB" -Color Gray
    Write-Status "   Location: $($fileInfo.FullName)" -Color Gray
    
    # Open report
    try {
        Start-Process $ReportPath
        Write-Status "   Report opened in default browser" -Color Gray
    } catch {
        Write-Status "   [WARNING] Could not open report automatically" -Color Yellow
    }
}

Write-Status "`nCompleted: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Gray

# Exit codes
if($script:CriticalIssues -gt 0) { exit 2 }
elseif($script:WarningIssues -gt 0) { exit 1 }
else { exit 0 }
