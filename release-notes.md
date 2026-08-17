# Release Notes  

## Version 2.0.0 Free / 2.0.0 Pro

### Major New Features

#### 1. Multi-Brand & Multi-Vendor Network Engine
- **Universal Multi-Vendor Support:** Extended the platform beyond MikroTik to manage diverse network hardware vendors including **Cisco (IOS, IOS-XE, NX-OS), Juniper (JunOS), Huawei (VRP), ArubaOS, Ubiquiti EdgeOS, Linux**, and custom SSH/Telnet appliances powered by unified Netmiko integration and custom connection drivers.
- **Multi-Brand Snippets & Sequences:** Execute commands and snippets across multi-vendor fleets with real-time terminal output streaming, conditional execution, and brand filtering.
- **Template & Brand Manager (rConfig Templates):** Manage vendor command templates with system template protection, custom command section parsing, and automatic brand detection based on device responses.
- **Multi-Vendor Configuration Backups:** Automated configuration retrieval, parsing, and storage for all supported vendor operating systems.

#### 2. Privileged Access Management (PAM) & Database Credential Envelope Encryption
- **Zero-Trust Credential Architecture:** Completely decoupled credential storage from device records into a centralized, dedicated `credentials` repository with granular per-device, per-group, and per-user scoping.
- **Two-Tier Envelope Encryption (DEK / KEK):** 
  - Upgraded database secret storage from legacy single-key encryption to enterprise-grade **Envelope Encryption**.
  - Every individual credential (passwords, passphrases, private keys) is encrypted using its own unique, dynamically generated **Data Encryption Key (DEK)** (AES-256-GCM / Fernet).
  - The DEK itself is encrypted using a Master **Key Encryption Key (KEK)** managed by the KEK provider and persisted securely in `server-conf.json` (`PYSRV_KEK`).
  - Decoupled keys ensure that KEK rotation does not require re-encrypting payload data, and compromise of an individual credential never exposes other credentials.
- **Automated Transparent Data Migration:** Automated migration scripts (`045_devices_alter.py` and `046_password_encryption_migration.py`) automatically decrypt legacy stored device credentials and re-encrypt them into the new envelope-encrypted `credentials` schema upon upgrade with zero manual intervention.
- **Automated Privilege Escalation:** Intelligent credential elevation handling supporting `enable` mode, `sudo`, custom privilege levels, and fallback escalation credentials.
- **PAM Seat Management:** License-enforced seat allocation, multi-worker lock protection, and centralized credential resolution.

#### 3. Terminal Gateway & Session Auditing (Pro)
- **Interactive Browser Terminal Gateway:** High-performance, low-latency WebSocket-driven terminal for direct SSH and Telnet session management from the browser.
- **Live Session Recording & Playback:** Automatically record all terminal and WebFig proxy sessions with timestamped keystroke playback and audit inspection.
- **Session Sharing & Collaboration:** Generate secure, time-limited live session sharing links with configurable read-only or interactive permissions.
- **Terminal Policies & OS-Level Sandboxing:**
  - Configurable enforcement tiers: Linux Kernel level, macOS/FreeBSD Interpreter (Strict), Hook (Compatible), and Gateway Regex backstop.
  - Non-MikroTik device policy overrides with per-OS semantics and capability validation.
- **Command Logs & Audit Trail:** Searchable command execution history with export modals and session attribution.

#### 4. AI Network Assistant & Diagnostic Engine (Pro)
- **Multi-Provider AI Gateway:** Native integration with leading AI providers including **OpenRouter, Google Gemini, OpenAI, and Anthropic Claude** with dynamic model normalization, temperature adjustment, max token limits, and configurable reasoning effort.
- **Context-Aware Device Troubleshooting:** Interactive AI chat assistant accessible directly from device detail pages, capable of analyzing live diagnostics, RouterOS logs, firewall rules, and interface statistics.
- **Intelligent WiFi & Network Optimization:** Automated recommendations for channel allocation, transmit power, interference mitigation, and security configurations.
- **Customer Self-Service AI Widget:** AI-powered assistance embedded in the Customer Portal for guided connectivity troubleshooting.

#### 5. Advanced Multi-Channel Alerting System (Pro)
- **Apprise Universal Notification Catalog:** Dispatch instant notifications across dozens of communication channels including **Telegram, Discord, Slack, Email (SMTP), Pushbullet, Pushover, Microsoft Teams, and Webhooks**.
- **Configurable Alert Rules Engine:** Trigger alerts based on syslog pattern matches, device connectivity status changes, task execution failures, and security anomaly detections.
- **Notification Testing & Delivery Logging:** In-app notification dispatch testing with real-time delivery status feedback and error reporting.

#### 6. Customer Portal & Self-Service Suite (Pro)
- **Redesigned Customer Portal:** Modern, intuitive self-service portal with responsive layout and customizable company branding.
- **Integrated Customer Ticketing System:** Multi-threaded support ticketing workflow with ticket assignment, priorities, status tracking, and direct customer communication.
- **Dual-Mode Speedtest Tool:** Integrated bandwidth testing supporting both browser-based speed tests (WebRTC/HTTP) and router-initiated throughput benchmarks.
- **Customer Device Tools & Firewall Controls:** Delegated firewall management and diagnostic utilities for end customers.
- **User Onboarding & Authentication:** Self-registration, password reset workflows, and role-based portal permission management (`DevUserGroupPermRelPro`).

#### 7. Configuration Versioning & Visual Diff Engine (Pro)
- **Full Configuration Version History:** Track all configuration revisions over time with detailed attribution (manual edit, scheduled task, cloner, snippet run).
- **Interactive Visual Diff Viewer:** Side-by-side and unified diff comparison modal featuring chronological version sorting, column swapping, and syntax-highlighted themes.
- **Regex Diff Exclusions:** Configurable exclusion rules (`diff_exclusions`) to filter out volatile configuration lines (timestamps, uptime, temporary tokens).
- **Enhanced Configuration Cloner:** Streamlined multi-device configuration synchronization with automatic initial `show_config` backup generation and robust JSON parsing.

---

### Frontend UI / UX Improvements

- **Modernized Layout & Navigation:**
  - Connection Manager with auto-hiding sidebar and top navigation for distraction-free full-screen terminal sessions.
  - Active session username badges and persistent connection status indicators.
  - Restyled monitoring status badges, refreshed device detail tabs, and device group filtering.
- **Role-Based Permissions & User Management UI:**
  - Redesigned User & Permission Management interface with reusable role templates and granular feature matrices.
  - License state tracking: real-time license health banner, seat quota counters, over-limit alerts, and Pro pending activation modal on the dashboard.
- **SSL / TLS Certificate Manager UI:**
  - Dedicated SSL Certificate Management page in Settings supporting Let's Encrypt automated issuance, custom certificate/key uploads, and CSR generation.
  - Real-time certificate status inspection (validity, expiry dates, Subject Alternative Names, issuer, fingerprint).
  - Graceful SSL-agent background lifecycle handling during frontend upgrades.
- **Device Management & IP Scanner:**
  - Integrated API-SSL toggle in the Device IP Scanner with automatic default port switching (8729 for SSL, 8728 for API).
  - Multi-brand device support with comprehensive vendor icon library (Cisco, Juniper, Huawei, Aruba, Linux, etc.).
  - Privilege-escalation aware device edit dialog with separate enable password configuration.
  - DHCP Static & Dynamic lease management: add and delete static leases directly from device details.
- **Execution & Output UX:**
  - Interactive terminal-style output capture modals for snippet and sequence execution.
  - Success and error toast notifications across sequence runs, snippet jobs, and user management updates.
  - Persistent sequence device selection and snippet export (CSV / text).
- **UI Stability & Performance Fixes:**
  - Fixed Angular `NG0100` (ExpressionChangedAfterItHasBeenCheckedError) and PrimeNG table `filteredValue` synchronization errors.
  - Configured Nginx SPA fallback routing and `no-cache` headers for `index.html` to eliminate stale browser cache issues after updates.

---

### Backend Core & Infrastructure Enhancements

- **SSL / TLS & Secure Protocol Architecture:**
  - Native MikroTik API-SSL (port 8729) support with automatic port resolution (8729 for SSL, 8728 for plain API).
  - In-app HTTPS SSL certificate automation and Nginx configuration reloader.
  - Enhanced SMTP email configuration supporting `None`, `STARTTLS`, and `SSL/TLS` security modes with step-by-step diagnostic connection logging.
  - Redis password authentication support across all background mules and services.
- **Decoupled Connection Manager:**
  - Introduced dedicated `device_connections` data layer supporting multiple simultaneous protocols per device (API, API-SSL, SSH, Telnet, WebFig).
  - Intelligent server `peer_ip` detection via UDP route inspection for reliable device-side callbacks.
- **Concurrency & Task Execution Modernization:**
  - Replaced custom thread loops with `ThreadPoolExecutor` and async-safe uWSGI mules (`task_run.py`, `bgtasks.py`).
  - Hardened background task lifecycle with robust `try/finally` blocks, preventing task status lockups and orphaned jobs.
  - Database connection pool resets for spool jobs and optimized PostgreSQL connection pooling.
- **Database Architecture & Schema Changes (Migrations 034 – 057):**
  - **Credential Security & PAM Schemas (`044_connection_core.py`, `045_devices_alter.py`, `046_password_encryption_migration.py`, `048_terminal_and_pam_pro.py`, `049_credentials_group_id.py`):**
    - New `credentials` table storing envelope-encrypted secrets (`encrypted_password`, `dek_encrypted`, `encrypted_private_key`, `passphrase_encrypted`).
    - New `device_connections` table decoupling protocols (API, API-SSL, SSH, Telnet, WebFig) from physical device rows.
    - New `connection_sessions` and `credential_rotation_history` tables for full access auditing.
  - **Multi-Brand & Template Schemas (`044_connection_core.py`, `052_rconfig_templates.py`, `053_multi_brand_automation.py`):**
    - New `device_brands` and `device_templates` tables storing brand metadata, prompt patterns, pagination rules, error patterns, and command sections.
    - New `command_expansions` table storing vendor CLI shorthand expansions and full commands.
  - **Terminal Gateway & Session Schemas (`048_terminal_and_pam_pro.py`, `051_terminal_fingerprinting_pro.py`, `055_webfig_session_recording_pro.py`, `056_webfig_sharing_pro.py`):**
    - New tables: `terminal_sessions_pro`, `terminal_commands_pro`, `session_participants_pro`, `terminal_policies_pro`, `terminal_grant_policies_pro`, `terminal_user_settings_pro`, and `terminal_favorites_pro`.
  - **Customer Portal & Alerting Schemas (`035` – `043`):**
    - Added tables for Customer Roles, Support Tickets (`tickets_pro`, `ticket_messages_pro`), Speedtest metrics, Alert Settings, and Apprise dispatch channels.
  - **64-Bit Primary Key Migration (`047_bigint_logs.py`):** Upgraded high-frequency transaction tables (`syslogs`, `user_tasks`, `sequences`, `alert_dispatch_log_pro`) to `BIGINT` to prevent ID overflow in high-traffic environments.
  - **Permissions Taxonomy Migration (`050`, `057_permissions_taxonomy.py`):** Redesigned and consolidated RBAC permission sets with granular scopes for Terminal, PAM, SSL, and Customer Portal features.
  - **Device Partial Unique Index (`054_devices_partial_unique.py`):** Added PostgreSQL partial indexes to handle MAC and IP uniqueness gracefully across routed/tunnel networks.
- **RouterOS Driver Hardening:**
  - Anchored MikroTik prompt regex patterns to eliminate false positive matches on complex RouterOS script operators.
  - Firmware-aware `export_flags` resolution using cached device versions with fallback handling.
  - Optimized RouterOS API interface queries for routers with large interface counts.
  - Fixed total bandwidth calculation and aggregation on dashboard graphs.
- **System Lifecycle & Deployment:**
  - Enhanced updater engine with automated hard restarts, dependency auto-installation, and log rotation.
  - Docker auto-installer improvements and updated dev-mode environments.
  - Graceful handling of empty or missing system configuration keys.
  - Automatic creation of backup and firmware storage directories on startup.

---

### Bug Fixes

- **Authentication & Security:**
  - Fixed an issue where changing user account passwords broke RADIUS authentication.
  - Fixed duplicate session handling and session attribution in Terminal Gateway.
- **Device Management:**
  - Fixed foreign key cascade cleanup on device deletion.
  - Fixed missing values and edit errors for non-MikroTik and SSL-enabled devices in the edit dialog.
  - Resolved device scanner skipping devices in tunnel environments due to MAC duplicate detection.
- **Task Scheduler & Spooler:**
  - Fixed database connection leaks during spooler task execution.
  - Fixed task lockups when handling interrupted or cancelled background tasks.
- **Dashboard & Monitoring:**
  - Fixed incorrect total bandwidth statistics calculation on dashboard charts.
  - Fixed sensor key creation errors in Redis.
  - Fixed MAC partial-index conflict targets during device discovery.

---

## Version 1.3.2
**New Features & Improvements (Pro):**
- **DHCP Manager Enhancements:** Improved DHCP syslog processing to robustly capture all server messages, including pool exhaustion and assignments. Fixed `KeyError` in DHCP lease info for static entries.
- **RADIUS Management:** Optimized RADIUS configuration cleanup and peer identification. Improved "Force RADIUS" functionality to ensure consistent "Single Source of Truth" for device settings.
- **Syslog Reliability:** Enhanced "Force Syslog" logic and regex patterns to handle diverse MikroTik tag formats and ensure critical events are always captured on the Monitoring Wall.

**Bug Fixes:**
- **Scanner Fix:** Resolved an issue where the scanner would skip new devices in tunnel environments due to MAC address duplication detection.
- **API Stability:** Fixed various race conditions in database operations related to device configuration and RADIUS accounting.

---

## Version 1.3.1 (Hotfix)
- **Spooler Fix:** Resolved a critical issue where the Spooler service failed to start or process tasks in version 1.3.0.
- **Minor UI/UX Polish:** Small fixes for license handling and dashboard reporting.

---

## Version 1.3.0 Free / 1.3.0 Pro

### New Features
- **WireGuard VPN Manager (Pro):** Integrated WireGuard server for centralized VPN peer management. Connect MikroTik devices via a dedicated tunnel with easy provisioning (QR code, `.conf` files, or RouterOS scripts). Includes automatic mapping of peers to MikroTik devices.
- **Sequences (Pro):** Chained execution of snippets and code with real-time output monitoring. Supports conditional actions and snippet execution based on output filtering (word filters or regex).
- **Custom Syslog Regex (Pro):** Custom mode for parsing incoming syslog events using a regex builder or custom strings.
- **Custom Alerts (Pro):** Generate fully custom alerts based on execution output or syslog events. Integrated visibility in Device Logs and the Monitoring Wall.
- **Pro License Handling:** Improved expiration warnings and registration workflow.

---

### Improvements & Bug Fixes
- **RADIUS Fix:** Resolved race conditions with RADIUS accounting inserts by introducing optimized processing delays.
- **Health Status Fix:** Improved compatibility with MikroTik devices that do not support standard health data or return non-standard values.
- **Database & API Layer:** Optimized background task execution and optimized backup/restore processes.
- **Security:** Improved duplicate session handling and login stability.
- **Performance:** Enhanced license verification concurrency.
- **System:** Backend support for Angular 18 upgrade and PrimeNG migration.

---

## Version 1.2.0 Free / 1.2.0 Pro

### New Features
- **Web Access Button:** Added a WebFig access button next to each device name in the device list for quick and direct access.
- **Network Map (Pro):** Automatically generates a live network topology map based on MikroTik neighbor discovery.
- **Proxy WebFig (Pro):** Introduced secure proxy functionality that allows WebFig access from anywhere with auto-login configuration.
- **Asyncio Syslog Server:** Complete rewrite of the syslog system using `asyncio` for enhanced performance and scalability.
- **Enhanced DHCP Log Handling:** Improved parsing and interpretation of DHCP logs for more accurate reporting.
- **Firmware Upgrade Tool:** Added the ability to upgrade device firmware directly from MikroWizard.
- **Bulk Device Import:** Devices can now be added in bulk using a CSV file for faster setup.
- **User & Device Group Management:** Assign and manage users directly from the Device Groups page.
- **Device Group Bulk Operations:** Perform bulk firmware upgrades and updates on all devices within a group.
- **Improved Scan/Add History:** Added a **History** button on the Devices page, allowing users to view or download scan/add operation logs directly as a CSV file.
- **Upgradable/Updatable Filter:** The Upgradable/Updatable filter now functions correctly, and previously incorrect upgrade data has been fixed.
- **Cron Selector in Tasks:** Added predefined cron examples with search and list functionality to simplify scheduling in the Tasks page.

---

### Improvements & Bug Fixes
- **Database & API Layer:** Added new migrations for device upgrades and improved API error handling and response formatting.
- **Background Tasks:** Optimized background task execution for better stability and performance.
- **Network Discovery:** Improved device scanner for more accurate detection and mapping.
- **Logging System:** Enhanced log structure and rotation. Logs are now stored in `/opt/mikrowizard/logs` for easier access and management.
- **UI/UX Enhancements:** Refined the interface and improved usability across multiple pages, including Settings, Backups, User Management, Password Vault, Sync & Clone, User Tasks, Device Management, and Device Groups.
- **Performance:** Improved syslog throughput, task cancellation, and database query performance. Introduced configurable thread limits and replaced manual threading with `ThreadPoolExecutor`.
- **Security:** Strengthened input validation and implemented additional security measures throughout the platform.
- **Bug Fixes:**
  - Fixed multiple issues affecting firmware updates and upgrades.
  - Improved error handling in device management modules.
  - Various minor fixes and general performance improvements.

---

### Notes
- This release focuses on **performance, reliability, and scalability**, while introducing several key new features for Pro users.
- Core components have been extensively refactored to improve maintainability and monitoring.
- Enhanced logging and monitoring now provide deeper operational visibility across all modules.

## Version 1.0.8 Free / 1.1.0 Pro

### New Features  
- Router Ping Information: Added ping data to enhance connectivity monitoring.  
- Active User Sessions: Device details page now displays current active users.  
- Session Management: Introduced the ability to terminate active user sessions.  
- Enhanced License Information: Dashboard now provides more detailed license-related insights.  
- MikroTik Configuration Sync & Config Cloner (Pro): Introduced a new menu/page for configuration cloning/sync.  
- DHCP Server & Lease History (Pro): DHCP server details along with historical lease information in device details.  

### Improvements & Bug Fixes  
- Async Syslog Server: The syslog server now utilizes asyncio for improved performance and efficiency.  
- DHCP Log Handling: Enhanced processing of DHCP logs in the syslog system.  
- Firmware Updater Fix: Resolved an issue where the firmware updater failed to retry properly.  
---

## Version 1.0.7 - Fast update
- Firmware updater fix: Fix broken frimware update


## Version 1.0.6 - Firmware upgrade fix  

### Bugs Fixed  

- **Firmware Download:** 
  - Resolved multiple bugs for frimware repository and download
  - Resolved multiple bugs while applying updates to routers
  - Fix CHR firmware updates
- **Device Edit:** Fix password change in edit form when the user the password is not changed
- **Syslog:** Added new regex for new versions of MikroTik the user trace (usernam/ip/connection) is not provided in logs and actions when setup wizards used in winbox/webfig (This is MikroTik bug and Already reported to MikroTik support ,Fix is comming)
- **Dashboard** Fixed showing wrong update information for MikroWizard
### New Features  
- **Firmware Management:** 
  - **Backup** : Now before any firmware update it will try to get a backup of router
  - **Pakages update** : All packages is getting updated and not only the routeros
  - **Wifi package  Update** :Now it should update wifi/radio enabled routers without problem

---
## Version 1.0.5 - Major Improvements and Bug Fixes  

We’re excited to announce the release of version 1.0.5! This update introduces new features, significant enhancements, and essential bug fixes to improve system functionality and user experience.  

### Bugs Fixed  

- **Firmware Download:** Resolved issues with downloading firmware from the MikroTik website when multiple `.npk` files were available.  
- **System Permissions:** Fixed errors when system permissions were set to "None."  
- **Device Group Permissions:** Corrected user device group permissions to function properly.  
- **IP Scanning:**  
  - Fixed issues with single IP scans and ensured the last IP in a range is scanned correctly.
- **Snippets:**  
  - Fixed manual snippet execution issues when device groups were selected.  
- **Backup Visibility:** Resolved problems with MikroTik backups not displaying for larger backup sizes.  
- **Minor UI and Bug Fixes:** Enhanced overall UI consistency and addressed several minor bugs.  

---

### New Features  

- **Background Task Management:** Added the ability to view and stop tasks running in the background, such as IP scanning.  
- **Manual Update Support:** Introduced support for manual MikroWizard updates via the dashboard or settings page.  
- **Firmware Management:** Enabled the option to delete downloaded firmware directly.  

---

### Enhancements  

- **Permission Feedback:** Improved error messages when users lack necessary permissions for specific actions or pages.  
- **Dashboard Improvements:**  
  - Enhanced charts and graphs for better data visualization.  
  - Added detailed version, update, and license information.  
- **Login Page:** Improved error messaging for failed login attempts.  

---

## Version 1.0.1 - Initial Bug Fix Release  

The 1.0.1 update focused on addressing critical issues and improving system stability:  

### Bugs Fixed  

- **Scanning:** Resolved an issue causing scanning failures with tunnel peers and x86 installations.  
- **Syslogs:** Fixed false positive logs and restored accounting functionality.  
- **Updater:** Enhanced security by switching the updater to use HTTPS instead of HTTP.  
- **Firmware Checking:** Resolved issues with automatic firmware checking for free-tier users.  
- **Snippet Execution:** Fixed problems with snippet execution not functioning correctly.  
- **Other Fixes:** Addressed several minor bugs to improve system reliability.  

---

### Upgrade Recommendation  

We strongly recommend upgrading to the latest version to enjoy these new features, improvements, and fixes.  

---

Thank you for your continued trust and feedback! For questions or support, feel free to contact us:  

- **Email:** info[@]mikrowizard[.]com - please replace [@] with @, and [.] with .