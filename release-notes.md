# Release Notes  
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