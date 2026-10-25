# Release Notes  

## Version 2.1.1 Free / 2.1.1 Pro

> **Upgrade note:** Pro includes database migration `065_pro_schema_backfill_pro.py`. It is safe to run on every Pro install and only adds what is missing.

### Security
- **No secrets in the System Log:** Passwords and other secrets (user passwords, old/new passwords on password change, non-MikroTik device passwords, enable passwords and SSH keys, the RADIUS secret, alert channel tokens) are now replaced with `***` before an event is written. Everything else in the event is stored as before.
- **Cleanup of older entries:** After the update, entries written by 2.1.0 and earlier are cleaned in the background in small batches, without affecting normal operation.
- **Recommendation:** If you entered passwords in user management, non-MikroTik device forms, the RADIUS secret or alert channels on 2.1.0 or earlier, consider changing them.

### Fixes
- **PAM API:** Creating and rotating credentials, listing device connections, setting a credential mapping, and listing or starting PAM sessions failed with a server error. Fixed.
- **Terminal policies after switching from Free to Pro (Pro):** Installs that started on Free and were later switched to Pro could show an error on the terminal policy page (missing Session DLP settings). Migration 065 repairs this and adds a missing history index.
- **MikroTik browser terminal (Pro):** SSH and WebBox to MikroTik log in with your MikroWizard user and a one-time RADIUS password. When the router is not set to use RADIUS, MikroWizard now shows a clear message instead of failing later with "authentication failed".

## Version 2.1.0 Free / 2.1.0 Pro

> **Upgrade note:** This release includes database migrations **058 – 064**. Migration `064_log_tables_scale.py` widens the `account` table to `BIGINT` and builds new indexes on `auth`, `account` and `events`. On large installations this can take several minutes, so do not interrupt the upgrade while migrations run.

### Major New Features

#### 1. RDP, VNC & WebBox Remote Access (Pro)
- **RDP and VNC desktop sessions:** Open Windows RDP and VNC consoles directly in the Connection Manager, alongside SSH, Telnet and WebFig.
- **WebBox (WinBox in the browser):** Launch WinBox sessions from the Connection Manager, device list, device tree and Network Map, with gateway availability checks.
- **RemoteApp publishing:** Publish individual applications from an RDP host as child entries. They appear nested under their parent server and inherit its IP.
- **Separate CLI, RDP and VNC templates:** Templates now carry their own protocol, with display and acceleration settings for graphical sessions. Session options resolve in four tiers: template, host, published app, then DLP policy.
- **Session DLP policies:** Control clipboard, file transfer, watermarking and forensic recording per policy.
- **Recording playback for every protocol:** Graphical sessions are recorded and can be replayed in the browser (Guacamole player for RDP/VNC, MP4 video with seeking for WebBox). Ended WebFig proxy sessions now also appear in session history.
- **Sharing & collaboration:** RDP, VNC and WebBox sessions can be watched or shared like terminal sessions, with protocol badges in the Session Manager. Join and guest links are bound to the authenticated user to block spoofing.

#### 2. Network Map v2 (Pro)
- Rebuilt topology engine with **radial and hierarchical tree layouts**, path finding, and node positions saved per user.
- **Root cause analysis:** A Problems drawer separates the device that actually went down from the devices that are only unreachable because of it.
- Fast SVG icon set with live state rings, link traffic rates, and full theme support.
- **NOC full-screen mode**, search across the map, PNG export and CSV export of the device inventory.
- Device inspection drawer and admin-assigned aliases for neighbours.
- Recognises unmanaged peers through router identity (all interface MACs and IPs), classifies APs and CPEs, and supports bridge ports and RouterOS 7 link-local neighbours.
- The map only shows devices each user is allowed to see.

#### 3. Firmware Upgrade Engine Rewrite (Free + Pro; Pro-only items are marked)
- **Multi-step upgrade planner (Pro):** Upgrades older routers along a safe path (latest v6 → 7.12.1 → 7.13+). In the Free edition, routers are upgraded directly to the selected version.
- **Package checks:** Package names are checked by architecture, and the result is confirmed after the reboot.
- **Restart-safe state machine:** Upgrade progress is stored per device in Redis with leases, so a service restart does not lose track of upgrades and a router is never left halfway through one.
- **Integrity & delivery checks:** Packages are checked against MikroTik's official SHA256 hashes, the router's free storage is checked before upload, a configuration backup is taken before the update (configurable), and RouterBOOT is upgraded after the OS upgrade.
- **Update modes & strategies:** Full (OS + RouterBOOT), OS only, packages only, or bootloader only. Version can come from the server repository, MikroTik's servers directly (native), a specific chosen version, or Auto-Pilot latest.
- **Latest Cloud channel (Pro):** Upgrade to the newest release on the *stable*, *long-term*, *testing* or *development* channel, from single devices, device groups and scheduled tasks.
- **PtP safe ordering (Pro):** On point-to-point wireless links, stations are upgraded before their access points so remote ends do not lose their link.
- **Pro safety rules:** Automatic v6 → v7 upgrades are refused when packages that do not migrate are installed (e.g. multicast, user-manager), and the right wireless driver packages (`wifi-qcom`, `wifi-qcom-ac`) are installed across the 7.13 package split.
- **Live status in the UI:** Updating, rebooting, updated and failed badges; inline *Retry* / *Clear* on failed devices; a *Failed* quick filter; faster polling while updates run.
- Device group firmware updates now have the same options as single-device updates.
- New settings: firmware architecture filter for repository downloads, and **Maximum Update Retries** (1–5, default 2) to prevent reboot loops.
- Upload concurrency scales with fleet size (8–35 parallel transfers) to avoid saturating the WAN link.

#### 4. Workspace Modes
- A global **workspace mode switcher** (MikroTik, PAM, or All) tailors navigation, device tabs and actions to the work you are doing. The current mode is shown as a pill in the header.

#### 5. NATed & Multi-Endpoint Devices
- Several devices can now share one public IP on different ports (e.g. several RDP hosts behind one NAT). Devices are now unique by IP **and** port instead of IP alone.
- Add/Edit dialogs accept the IP and port directly, and protocol badges show the real port (e.g. `RDP:3390`).

---

### Scale & Performance (large fleets)

This release focuses on running reliably with **Many Devices**:

- **Automatic database connection budgeting:** Each process sizes its connection pool from PostgreSQL's real `max_connections` and the running uWSGI layout (web workers, spoolers, poller, firmware and syslog mules, cron). When PostgreSQL is out of connections, processes back off and retry instead of failing. This removes `FATAL: sorry, too many clients already`.
- **Poller scaling:** The worker count adapts to the fleet (15 to 120 workers), work can be split across multiple poller mules (`DATAGRABBER_MULES`), and each cycle has a hard deadline (`DATAGRABBER_CYCLE_DEADLINE`). Large fleets are polled in roughly 30–45 seconds.
- **Lighter router polling:** Interface rates are now calculated from 64-bit counters instead of `monitor-traffic`, rarely-changing information (routerboard, identity, wireless) is cached, and only changed columns are written to the database.
- **RouterOS API transport:** A 64 KB buffered socket read removes the heavy CPU use caused by thousands of tiny `recv()` calls, and broken connections now fail cleanly.
- **Syslog pipeline:** A separate UDP reader process feeds an asyncio pipeline that does not drop messages, can be split across mules (`PYSRV_SYSLOG_MULES`), and retries automatically when the database has a temporary error.
- **Fast SSH exec channel:** Single commands on MikroTik run over SSH in about 0.1 s (`PYSRV_MIKROTIK_EXEC`). SSH connect, auth and command timeouts prevent hung workers.
- **Pooled Redis connections**, and charts are aligned to a regular time grid so outages show as zero instead of misleading jumps.
- **Pro:** Neighbour discovery skips database writes when the topology has not changed, radio telemetry writes are throttled, cloner and vault tasks use bounded thread pools, and alert workers only start when alert rules exist.

---

### Background Tasks & Job Control

- **Stopping tasks safely:** *Stop* now asks running tasks to finish their current device and skip the rest. Critical tasks (firmware, scan, download, vault) cannot be force-killed, and other tasks get a 120 s grace period before a force kill.
- **Cluster-safe job locks:** Redis job leases and per-device locks prevent two operations from running against the same router at once. Tasks left marked as running after a crash are reset automatically.
- **No more lost requests:** Firmware, RouterBOOT, backup and snippet requests are queued when a similar job is already running, instead of being dropped.
- **Large payloads:** Bulk add and scan results are kept in Redis, which avoids the 64 KB uWSGI spooler file limit.
- **Backups:** Identical configurations are stored once (volatile export header timestamps are ignored), and each backup is linked to the execution log entry that created it.

---

### Monitoring, Logs & Retention

- **Live device state:** The device list shows *Offline* (in red) for unreachable routers and a live-updating uptime for online ones. Update badges are hidden for offline devices.
- **Reboot detection:** Unexpected reboots are detected and the cause is read from RouterOS logs. Unreachable alerts are suppressed while a device is expected to be offline (updating or rebooting).
- **RADIUS accounting:** `Accounting-On/Off` closes stale login sessions when a router restarts. Interim updates are handled quietly, and identical usernames on different routers no longer conflict.
- **Terminal Gateway logins:** The router's own syslog copies of gateway logins are no longer shown as separate logins. Session durations are calculated correctly, and recordings can be played for every gateway protocol from the auth logs.
- **Log improvements (UI):** Device filter badges can be cleared with one click, and Authentication and Accounting logs can be opened directly from the Connection Manager context menu.
- **Configurable data retention** (runs daily): Resolved events, login history, configuration change history, execution logs, task results, sequence history, config versions and backups are pruned in batches. Unused config blobs are cleaned up afterwards. Unresolved events and logins that have recordings are always kept. New settings: `RETENTION_EVENTS_DAYS`, `RETENTION_AUTH_DAYS`, `RETENTION_ACCOUNT_DAYS` (default 365 days) and related `RETENTION_*` keys.

---

### Multi-Brand & Templates

- Built-in **diff exclusion rules for 10+ vendors**, so volatile lines (timestamps, counters) do not show up as configuration changes.
- Template Manager: regex diff exclusions grouped by section, with a **live regex testing sandbox** that shows which lines are kept or removed. Also adds brand management and JSON editors for pre-connect and post-disconnect hooks.
- Trailing CLI prompts are stripped and CRLF line endings normalised in command output. MikroTik license and terminal prompts are answered automatically.

---

### Connection Manager & UI

- **Custom categories** for the device tree, synced to the server, with JSON import/export. Tree grouping by custom category, admin group, device type, or a flat list, plus search and a favorites filter.
- Context menus stay inside the window and scroll on small screens.
- Device tables no longer jump or lose focus while auto-refreshing.
- Sensor widgets handle missing data without errors.
- Customer and operator device selections are kept separate, and cached customer data is cleared on logout.
- Pro-only protocols and features show a lock badge with an explanation in the Free edition.

---

### Deployment

- New `scripts/hotfix_update.sh` to patch code inside a running container, with rollback instructions (also works when Docker needs `sudo`).
- Nginx gzip level lowered from 9 to 5 to reduce CPU use under load.
- Container entrypoint creates the `/conf` folders and fallback SSL configuration, and the SSL agent recovers more reliably.

---

### Bug Fixes

- Fixed fresh installations failing at migration 046 (it selected columns that are only added by later migrations) and invalid PL/pgSQL syntax in migration 058.
- Fixed event status updates that did not target the correct row.
- Fixed RADIUS session ID collisions that broke unique constraints, and logout matching in auth sessions.
- Fixed the firmware download endpoint returning an error page that RouterOS `/tool/fetch` saved as a package (missing files now return 404).
- RouterOS 7.18+ packages marked *available* are no longer shown as installed.
- Fixed connection pool starvation during long router calls, spooler deadlocks, N+1 queries in task device lookups, and leaked API/SSH sockets (issue #12).
- Fixed `KeyError: 'status'` in task results, and version parsing with `(stable)` / `(testing)` suffixes.
- Passwords are no longer written to syslog audit events for bulk adds or to dev-mode terminal logs.
- WebFig proxy browser tokens are now per session, which fixes conflicts when several tabs are open.
- (Pro) Fixed a `NameError` in vault password rotation tasks, cloner syncing a device twice when it belongs to several groups, and duplicate backup rows from the config runner.

---

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
  - Every individual credential (passwords, passphrases, private keys) is encrypted using its own unique, dynamically generated **Data Encryption Key (DEK)** with Fernet (AES-128-CBC and HMAC-SHA256).
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