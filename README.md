# Azure-Storage-Security-Audit
PowerShell tool to audit Azure Storage Accounts for security misconfigurations across all subscriptions
# Azure Storage Security Audit Tool

A comprehensive PowerShell tool to audit Azure Storage Accounts for security misconfigurations across all subscriptions. Inspired by real-world breaches like the EY 4TB data exposure incident.

https://www.linkedin.com/pulse/ernst-young-ey-exposes-4tb-database-online-what-qypre/

## Overview

This tool performs a **read-only security audit** of all Azure Storage Accounts in your tenant, checking for common misconfigurations that could lead to data exposure.

## Key Features

- ✅ **Multi-subscription support** - Audits all subscriptions or specific ones
- ✅ **Comprehensive checks** - 9 security checks per storage account
- ✅ **Container-level auditing** - Identifies publicly accessible containers
- ✅ **Backup file detection** - Finds sensitive backup files (.bak, .sql, .dump)
- ✅ **HTML reporting** - Professional audit reports with detailed findings
- ✅ **Exit codes** - Integrate with CI/CD pipelines

## What It Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Public Blob Access | CRITICAL | Account-level public access setting |
| HTTPS Enforcement | CRITICAL | Ensures only HTTPS traffic is allowed |
| TLS Version | WARNING | Minimum TLS version (should be 1.2+) |
| Encryption | CRITICAL | Blob and File encryption status |
| Network Firewall | WARNING | Default network access rules |
| Container Public Access | CRITICAL | Individual container ACLs |
| Backup Files | WARNING | Sensitive backup files in storage |
| Soft Delete | WARNING | Data recovery protection |
| Diagnostic Logging | WARNING | Audit trail configuration |

## Prerequisites

- **PowerShell 5.1** or **PowerShell 7+**
- **Azure PowerShell modules:**
  - `Az.Storage`
  - `Az.Accounts`
- **Azure permissions:** Reader role on subscriptions

## Installation

### Option 1: Clone Repository
```powershell
git clone https://github.com/YOUR-USERNAME/Azure-Storage-Security-Audit.git
cd Azure-Storage-Security-Audit
```

### Option 2: Download Script

Download `Audit-AzureStorageSecurity.ps1` directly from the repository.

### Install Required Modules
```powershell
Install-Module -Name Az.Storage -Scope CurrentUser -Force
Install-Module -Name Az.Accounts -Scope CurrentUser -Force
```

## Usage

### Basic Audit (All Subscriptions)
```powershell
.\Audit-AzureStorageSecurity.ps1
```

### Generate HTML Report
```powershell
.\Audit-AzureStorageSecurity.ps1 -ExportReport
```

### Detailed Scan (Including Backup Files)
```powershell
.\Audit-AzureStorageSecurity.ps1 -Detailed -ExportReport
```

### Audit Specific Subscriptions
```powershell
.\Audit-AzureStorageSecurity.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -ExportReport
```

### Custom Report Path
```powershell
.\Audit-AzureStorageSecurity.ps1 -ExportReport -ReportPath "C:\Reports\audit.html"
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ExportReport` | Switch | No | Generate HTML report |
| `-Detailed` | Switch | No | Include backup file scanning |
| `-ReportPath` | String | No | Custom path for HTML report |
| `-SubscriptionIds` | String[] | No | Specific subscription IDs to audit |

## Output

### Console Output
```
Azure Storage Security Audit - All Subscriptions
Started: 2025-11-03 14:30:00

[OK] Authenticated as: user@company.com

Discovering subscriptions...
[OK] Found 3 subscription(s)

=================================================================
SUBSCRIPTION: Production
ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
=================================================================

Found 5 storage account(s) in this subscription

-----------------------------------------------------------------
Storage Account: mystorageaccount
-----------------------------------------------------------------

CHECK 1: Public Blob Access...
   [FAIL] ENABLED - CRITICAL

CHECK 2: HTTPS Enforcement...
   [PASS] Enforced

...

=================================================================
OVERALL SUMMARY
=================================================================

Subscriptions Scanned: 3
Total Storage Accounts: 12
Critical Issues: 4
Warnings: 7
```

### HTML Report

  HTML report with:
- Executive summary dashboard
- Detailed findings per subscription
- Storage account security checks
- Container-level details
- Backup file listings


## Exit Codes

- `0` - All checks passed
- `1` - Warnings found
- `2` - Critical issues found

Perfect for CI/CD integration:
```powershell
.\Audit-AzureStorageSecurity.ps1 -ExportReport
if ($LASTEXITCODE -eq 2) {
    Write-Error "Critical security issues found!"
    exit 1
}
```

**How attackers find exposed storage:**
```
https://{storage-account-name}.blob.core.windows.net/{container}/{file}
```

Automated scanners find these within seconds using:
- DNS enumeration
- Common naming patterns
- Certificate transparency logs
- GitHub connection string leaks

## Security Best Practices

Based on audit findings, implement these controls:

1. **Disable public blob access** at account level
2. **Set all containers to private** - no exceptions
3. **Enable HTTPS-only** traffic
4. **Use TLS 1.2** or higher
5. **Configure network firewalls** (default action: Deny)
6. **Enable soft delete** (30+ days retention)
7. **Enable diagnostic logging** for audit trails
8. **Never store unencrypted backups** in cloud storage
9. **Use Private Endpoints** for production workloads
10. **Implement Azure Policy** to prevent misconfigurations

## Roadmap

- [ ] Azure Policy export for automatic remediation
- [ ] JSON/CSV export formats
- [ ] Integration with Azure Security Center
- [ ] Slack/Teams notifications
- [ ] Terraform/Bicep templates for fixes
- [ ] Container image scanning
- [ ] SAS token auditing

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Ash C** - Cloud Security Engineer

## Acknowledgments

- Inspired by real-world Azure Storage misconfigurations
- Built to help organizations avoid data exposure incidents
- Community feedback and contributions welcome

## Disclaimer

This tool is provided as-is for security auditing purposes. Always test in non-production environments first. The author assumes no liability for any issues arising from the use of this tool.

---

**⭐ If this tool helped secure your Azure environment, please star the repository!**

## Support

- **Issues:** [GitHub Issues](https://github.com/YOUR-USERNAME/Azure-Storage-Security-Audit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/YOUR-USERNAME/Azure-Storage-Security-Audit/discussions)

## Related Resources

- [Azure Storage Security Guide](https://docs.microsoft.com/azure/storage/common/storage-security-guide)
- [Azure Storage Best Practices](https://docs.microsoft.com/azure/storage/blobs/security-recommendations)
- [Ernst & Young Breach Analysis](https://www.linkedin.com/pulse/ernst-young-ey-exposes-4tb-database-online-what-qypre/)
```

---

### 📄 File 3: `LICENSE`

(GitHub will create this automatically if you selected MIT License during repo creation)

---

### 📄 File 4: `.gitignore`

(GitHub creates this automatically if you selected PowerShell template)

If not, create it:
```
# PowerShell
*.ps1~
*.psm1~

# Audit reports
*.html
storage-audit-*.html

# Azure credentials
*.publishsettings

# Test files
test/
temp/

# OS files
.DS_Store
Thumbs.db
