# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-03-27

### Fixed

- Public blob access check now correctly flags storage accounts where the property returns null, which occurs on accounts created before the setting was introduced
- Container public access comparison updated to reliably handle both None and Off values returned by the Azure SDK
- Removed TLS1_3 from valid TLS version check as this value is not returned by the Azure API
- Initialised containers variable before the try block to prevent null reference errors in backup file scanning when container enumeration fails

### Added

- Az.Monitor added as a required module and explicitly imported to ensure diagnostic logging check works correctly

## [1.0.0] - 2025-11-03

### Added
- Initial release
- Multi-subscription audit support
- 9 comprehensive security checks
- HTML report generation
- Container-level public access detection
- Backup file scanning (detailed mode)
- Exit codes for CI/CD integration
- PowerShell 5.1 and 7+ support

### Security Checks
- Public Blob Access (account-level)
- HTTPS enforcement
- Minimum TLS version
- Encryption status
- Network firewall rules
- Container public access (container-level)
- Backup file detection
- Soft delete configuration
- Diagnostic logging

## [Unreleased]

### Planned
- Azure Policy export
- JSON/CSV export formats
- Slack/Teams notifications
- Private Endpoint detection
- SAS token auditing
