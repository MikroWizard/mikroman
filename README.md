# MikroMan | MikroWizard

<div align="center">

# 🧙‍♂️ MikroWizard
### Enterprise Network Management, Automation, Monitoring & Security Platform
**Native MikroTik RouterOS (v6 & v7) Deep Integration + Multi-Vendor Backup & Automation (SSH & Telnet)**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Edition: Free & Pro](https://img.shields.io/badge/Edition-Free_%26_Pro-orange.svg)](https://mikrowizard.com/pricing/)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Angular: 18](https://img.shields.io/badge/Frontend-Angular_18-red.svg)](https://angular.dev/)
[![Docker: Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://hub.docker.com/)
[![RouterOS: v6 & v7](https://img.shields.io/badge/MikroTik-RouterOS_v6_%26_v7-purple.svg)](https://mikrotik.com/)

[**Official Website**](https://mikrowizard.com) • [**Documentation**](https://mikrowizard.com/docs) • [**Pro Edition & Pricing**](https://mikrowizard.com/pricing/) • [**Docker Compose Repo**](https://github.com/MikroWizard/docker-compose-deployment)

</div>

---

## 📌 What is MikroWizard?

**MikroWizard** is an enterprise-grade centralized network operations, automation, and security orchestration platform engineered for **Network Administrators, WISPs, MSPs, Data Centers, and Enterprise IT Teams**.

Managing distributed networks with dozens, hundreds, or thousands of edge and core routers presents massive challenges: configuration drift, tedious repetitive tasks, lack of audit trails, compliance risks, and fragmented monitoring. MikroWizard delivers a unified "Single Pane of Glass" to automate provisioning, enforce security baselines, orchestrate mass configuration updates, schedule multi-vendor backups, analyze real-time syslogs, and deliver zero-trust remote access.

### 🌐 Dual Engine: Native MikroTik + Universal Multi-Vendor
- **Deep Native MikroTik Integration:** First-class support for **MikroTik RouterOS (v6 & v7)** via native binary API, MAC-Telnet, RoMON, and WebFig.
- **Universal Multi-Vendor Automation:** Complete backup, scripting, and configuration automation for **all major networking vendors** (Cisco, Huawei, HP/Aruba, Juniper, generic Linux, and custom network appliances) using extensible brand templates over **SSH and Telnet**.

---

## 🧭 Complete Architecture & Feature Catalog (By Menu & Category)

MikroWizard's user interface is logically structured into comprehensive functional domains for administrators and end-users:

```
├── 📊 Operations & NOC Wall (Dashboard, Real-Time Monitoring Wall)
├── 📡 Device Management (Devices, Device Groups, Network Topology Maps, WireGuard VPN)
├── 💾 Backup, Config & Automation (Task Planner, Backups, Executions, Snippets, Sequences, Cloner, Password Vault)
├── 📑 Reports & Logs (Authentication, Accounting, Device Logs, System Logs, Syslog Custom Regex)
├── 👥 User & Customer Management (Users, Permissions, Customer Portals, Customer Tickets)
├── 🛡️ Privileged Access Management & Security (2FA/OTP Panel Login, Device-Level RADIUS OTP, Web Terminal, Session Recording, Policies)
├── 🌐 Customer Self-Service Portal (Client Portal, Tools & Clients, Diagnostics, Port Forwarding, Simple Firewall, Speed Test, Tickets)
└── ⚙️ System Settings (Firmware Lifecycle, System & Network, Email/SMTP, AI Copilot, Speed Test, Alerts Catalog, SSL/Certificates)
```

---

### 1. 🛡️ Privileged Access Management (PAM) & Zero-Trust Security *(Pro)*

MikroWizard features an enterprise-grade Privileged Access Management (PAM) suite specifically tailored for **MikroTik RouterOS** and **Multi-Vendor CLI devices**:

#### 🔐 2FA / TOTP Login for Web Management Panel
- **Time-based One-Time Password (TOTP):** Seamless two-factor authentication compatible with Google Authenticator, Microsoft Authenticator, 1Password, Authy, and hardware tokens.
- **Instant Enrollment:** Built-in QR code generation during user onboarding.
- **Brute-Force & Security Auditing:** Automatic detection and logging of failed OTP verification attempts with source IP tracking.

#### 🔑 Device-Level Dynamic 2FA / OTP for MikroTik Routers *(MikroTik Exclusive)*
- **Zero Static Passwords on Routers:** Eliminate shared passwords and static root credentials across your router fleet.
- **Dynamic TOTP Authentication via RADIUS (Winbox, SSH, WebFig, Telnet, API):** When network engineers connect to a physical or virtual MikroTik router, MikroWizard's embedded RADIUS server dynamically verifies the user's live 6-digit TOTP code (or dynamic MS-CHAPv2 NTLM hash).
- **Enforced Security Policy (`otp_force` & `device-totp`):** Globally or selectively mandate that engineers must provide their live mobile authenticator token to access any router CLI or GUI.
- **IP Whitelisting / Geo-Fencing:** Restrict which source IP addresses or subnets an engineer is permitted to authenticate from.

#### 💻 In-Browser Interactive Web Terminal (SSH & Telnet)
- High-performance, zero-plugin Xterm.js terminal sessions over secure WebSockets supporting both **SSH and Telnet**.
- Access router command lines from anywhere in the world with **zero exposed management ports** to the public internet.

#### 📋 Multi-Brand Templates (`/templates`)
- Pre-built and custom templates for **all major hardware vendors** (Cisco IOS, Huawei VRP, HP/Aruba, Juniper, Linux, MikroTik).
- Configurable prompt regex patterns, paging handlers (`--More--`, `terminal length 0`), and automated `enable` password privilege escalation.

#### 🎥 Session Recording & Audit Playback (`/pam/history`)
- Keystroke-level millisecond recording of every interactive terminal session (VT100 screen buffer and raw keystrokes).
- **Web Session Player:** Interactive web playback with Play/Pause, timeline scrubber, playback speed multiplier (1x, 2x, 4x), and full-text terminal output search.

#### 👥 Live Session Sharing & Shadowing (`/terminal-share`)
- Share active terminal sessions securely with colleagues, team leads, or external tier-3 support engineers.
- Granular permission control: **Observer** (read-only live shadowing) and **Collaborator** (shared interactive typing).

#### 🛑 Terminal Security Policies & Real-Time Command Blocking (`/policies`)
- Real-time inline command inspection engine intercepting input before execution on the router.
- Define regex rules with automated policy actions: **Allow**, **Warn**, **Audit**, or **Deny & Block** (e.g., block destructive commands like `/system reset-configuration`, `reload`, `format`, `rm -rf`, or unauthorized firewall modifications).

#### ⌨️ Active Sessions & Command Audit Logs (`/pam/active`, `/pam/commands`)
- Real-time dashboard of all active administrative sessions across the network with one-click **Remote Session Termination (Kill)**.
- Centralized, tamper-proof searchable log of every command executed across all network devices by all operators.

#### 🔑 RADIUS SSO Terminal Injection
- Passwordless terminal connection: injects dynamic RADIUS session tokens to authenticate sessions without exposing root credentials to operators.

---

### 2. 📊 Operations & NOC Dashboard

#### 📈 Main Dashboard
- High-level network health overview: total routers, online/offline status, RouterOS version distribution (v6 vs v7), upgradable/updatable counters, and background task statuses.
- Real-time CPU, memory, and bandwidth utilization telemetry widgets.
- System update notifications, license status, and quick-action shortcuts.

#### 📺 NOC Monitoring Wall *(Pro)*
- **Fullscreen Operations Wallboard:** Purpose-built for Network Operations Center (NOC) overhead displays.
- **Real-Time Visual Grid:** Color-coded status tiles displaying ping latency, packet loss, active alarms, and immediate visual alerts on link drops or router failures.
- **Instant Triage:** Click any tile on the wallboard to jump directly into device telemetry, logs, or terminal sessions.

---

### 3. 📡 Device Management & Topology

#### 🖧 Device Inventory (`/devices`)
- Comprehensive device table displaying IP, MAC, Model, Architecture, Board Name, Serial Number, OS Version, Group, and Uptime.
- **Smart Filters:** Filter by Online/Offline, RouterOS v6, RouterOS v7, Non-MikroTik (Multi-Vendor), Upgradable, Updatable, or WireGuard Tunnel peers.
- **Automated Network Scanner:** Discover devices via MAC broadcast discovery, IP range/subnet scans, or tunnel scans with automated discovery history and CSV export.
- **Bulk Actions:** Bulk Add via CSV, Bulk Delete, Bulk Firmware Update/Upgrade, Bulk Snippet Execution, Bulk Reboot, and Bulk Group Reassignment.
- **Quick Row Actions:** One-click WebFig, Secure WebFig Proxy *(Pro)*, In-Browser Terminal *(Pro)*, Reboot, and Edit.

#### 🗂️ Device Details Deep-Dive (`/device/{id}`)
- **Device Details Tab:** Live resource monitors (CPU, Memory, HDD, Voltage, Temperature), IP address assignments, interface traffic tables, neighbor lists, and ping latency telemetry.
- **Radio Info Tab *(Pro - MikroTik Only)*:** Real-time RF metrics: Tx/Rx signal strength (dBm), Signal-to-Noise Ratio (SNR), CCQ %, frequency, channel width, noise floor, and active wireless client registration tables.
- **DHCP Server Tab *(Pro)*:** Live DHCP server instances, active IP leases, static lease bindings, historical lease analytics, and pool exhaustion detection.
- **Device Events & Syslog:** Device-isolated log stream with severity indicators.
- **Authentication & Accounting Tabs:** Device-specific RADIUS authentication attempts and accounting session durations.
- **Speed Test Tab *(Pro)*:** Live bidirectional bandwidth test executed from the router against speed test servers.
- **AI Chatbot Audit Logs *(Pro - MikroTik Only)*:** Full history of AI chat interactions and tool executions for this router.
- **Config Versions Tab *(Pro)*:** Historical configuration archive with visual diffing.

#### 🏷️ Device Groups (`/deviceGroup`)
- Organize devices into hierarchical, organizational, or regional groups.
- Group-level bulk operations: execute snippets, schedule backups, and perform group-wide firmware updates.
- Granular Role-Based Access Control (RBAC): assign user permissions per device group (Read, Write, Full).

#### 🗺️ Network Topology Maps (`/maps`) *(Pro)*
- **Dynamic Topology Discovery:** Automatically maps network links using MikroTik Neighbor Discovery Protocol (MNDP), Cisco Discovery Protocol (CDP), and Link Layer Discovery Protocol (LLDP).
- **Interactive Visual Canvas:** Powered by Vis-Network with physics-based layout, draggable nodes, cluster views, link bandwidth tags, and live status coloring.

#### 🔒 WireGuard VPN Manager (`/vpn`) *(Pro)*
- Centralized WireGuard server manager orchestrating secure zero-trust management tunnels.
- Connect remote edge routers behind strict NAT, CGNAT, firewalls, or dynamic 4G/5G mobile uplinks.
- **One-Click Provisioning:** Generates ready-to-run RouterOS setup scripts, `.conf` configuration files, and QR codes.

---

### 4. 💾 Backup, Configuration Lifecycle & Automation

#### 🕒 Task Planner & Cron Engine (`/user_tasks`)
- Visual cron builder and scheduler for recurring network jobs.
- Schedule automatic backups, firmware checks, configuration snippets, and sequence workflows with predefined cron templates.
- Real-time task execution logs, status tracking, and error reporting.

#### 📦 Centralized Backups (`/backups`)
- Multi-vendor configuration backups: Binary backups (`.backup`) and script exports (`.rsc`) for MikroTik, plus CLI configuration exports (`show running-config`, `display current-configuration`) for multi-vendor devices.
- Automated scheduled backups and manual on-demand snapshots with search, download, and storage management.

#### 📜 Config Versioning & Visual Diff Engine *(Pro)*
- **Command Versioning Archive:** Stores timestamped revisions of configuration commands (`show_config`, `show_interfaces`, `show_routing`, `show_arp`, `show_version`, `show_log`).
- **Visual Diff Viewer:** Compare changes between any two historical versions or across different routers using **Unified Diff** or **Side-by-Side Split Diff** modes.
- **Multi-Device Comparator:** Compare configuration baselines across multiple routers to detect drift.

#### ⚡ Executions & Snippets (`/snippets`, `/executions`)
- **Snippets Library:** Reusable batch scripts with variable placeholders, multi-vendor syntax highlighting, and target group selection.
- **Execution Engine:** Concurrent execution across hundreds of routers with real-time output streaming, stdout/stderr capture, and full execution history.

#### 🔀 Sequences (Chained Conditional Workflows) (`/sequences`) *(Pro)*
- Multi-step automation pipelines chaining scripts, snippets, and commands.
- **Real-Time Output Filtering:** Evaluate output at each step using word filters or regular expressions.
- **Conditional Branching:** Define branching logic (on-success, on-failure, on-match) to execute remediation scripts, trigger alerts, or abort safely.

#### 🔄 Sync and Cloner (`/cloner`) *(Pro)*
- Replicate configuration settings from a "Golden Master" router to target routers.
- Selectively choose configuration sections (IP, Firewall, Wireless, Users, Services, Routing).
- Customizable exclusion filters (`diff_exclusions.py`) to prevent overwriting unique parameters like IP addresses, identities, or MACs.

#### 🔐 Password Vault (`/vault`) *(Pro - MikroTik Only)*
- **Automated Password Rotation:** Enforce scheduled password changes for local MikroTik router users.
- **Policy Control:** Random password generation or pre-defined password policies, configurable rotation intervals (Daily, Weekly, Monthly, Custom Cron), and device exception lists.
- **Zero-Knowledge Encryption:** Credentials stored with envelope encryption (Fernet / AES-256 with Key Encryption Keys).

---

### 5. 🤖 MikroWizard AI Copilot & Chat Support *(Pro - MikroTik Only)*

An intelligent AI network engineer assistant natively embedded into your operational workflow:
- **Multi-LLM Provider Engine:** Pluggable AI engine supporting **Google Gemini**, **OpenAI GPT**, **Anthropic Claude**, and **Local LLMs (Ollama / vLLM / Custom Base URLs)**.
- **Autonomous Tool Execution Engine:** The AI copilot performs real-time diagnostic and operational actions:
  - `get_router_status` — Live inspection of CPU, memory, uptime, board model, architecture, and RouterOS version.
  - `list_connected_devices` — Live querying of active DHCP leases and Wi-Fi client registration tables.
  - `change_wifi_credentials` — Version-aware (v6 & v7) safe updates of SSID, passwords, and security profiles.
  - `read_latest_backup_config` — Contextual inspection of configuration exports.
  - `query_routeros_api` — Parameter-bounded diagnostic commands (ping, traceroute, bandwidth tests, traffic monitoring).
  - `execute_routeros_config_command` — Controlled write commands with permission gating and state validation.
  - `get_historical_metrics` — Redis TimeSeries queries for CPU, RAM, and bandwidth trends.
- **AI Chat Audit Logs (`/ai-chat-logs`):** Full enterprise compliance logging recording every prompt, tool call, parameter, output, and user ID.

---

### 6. 🌐 Multi-Tenant Customer Self-Service Portal *(Pro)*

Deliver a branded customer portal for clients, branch offices, and subscribers without giving them administrative router access:

#### 📊 Customer Dashboard (`/customer-portal`)
- Overview of assigned routers, connection health, uptime, and WAN link status.

#### 🔍 Tools & Connected Clients (`/customer-router-tools`)
- Live discovery table of connected Wi-Fi and LAN devices (hostname, IP, MAC address, signal strength).
- Quick tools: Router reboot, DNS flush, and connectivity tests.

#### 🩺 Advanced Diagnostics (`/customer-diagnostics`)
- **1-Click Full Diagnostic Check:** Automated sequence testing gateway ping, DNS resolution, WAN interface status, and public DNS latency (8.8.8.8, 1.1.1.1).
- Interactive Live Ping and Traceroute tools executed directly from the edge router.

#### 🔀 Port Forwarding (`/customer-portforward`)
- Self-service NAT port-forwarding rule creator with port conflict validation and security boundaries.

#### 🛡️ Simple Firewall (`/customer-firewall`)
- **Predefined Security Toggles:** 1-click protection (Block WAN Ping, Block Telnet from WAN, Block DNS requests from WAN, FastTrack connections, Drop invalid connections, Protect Router Services, Guest Wi-Fi isolation).
- **Custom Block Lists:** Block specific IP addresses, subnets, or MAC addresses.
- **Preset IP Lists:** Manage custom address lists for firewall policies.

#### 🚀 Integrated Speed Test (`/customer-speedtest`)
- Real-time bandwidth test against your speed test servers (TCP/UDP, latency, jitter, loss %).

#### 🎫 Customer Support Ticket System (`/customer-tickets`, `/admin-tickets`)
- Two-way ticketing system: customers open tickets with attachments and severity; admins manage, assign, and resolve tickets.

#### 🏷️ Customer Assignments (`/customer-assignments`)
- Granular administrative manager to assign routers and toggle allowed portal tabs per customer.

---

### 7. 🔔 Multi-Channel Alerts & Syslog Engine

#### 📢 Multi-Channel Notifications (Apprise Catalog) (`/alerts`) *(Pro)*
- Deliver instant alert notifications across **10+ supported notification platforms**:
  - **Chat Platforms:** Telegram (bots & channels), Slack (webhooks), Discord (webhooks), Mattermost, Microsoft Teams.
  - **Mobile Push:** Pushover, ntfy, Gotify.
  - **Incident Management:** PagerDuty, Opsgenie.
  - **Custom Webhooks:** Generic HTTP POST / JSON endpoints and raw Apprise URLs.
- **Event-Driven Alert Triggers:** Device offline/ping loss, health threshold violations (voltage, temperature, CPU/RAM spikes), sequence execution failures, DHCP pool exhaustion, or custom syslog patterns.
- **Notification Logs:** Complete delivery audit log with timestamps, destination channels, and delivery statuses.

#### 📝 Syslog Custom Regex Builder (`/syslog-regex`) *(Pro)*
- Visual regex builder to parse arbitrary incoming syslog messages.
- Extract custom parameters (usernames, IPs, interfaces) and classify them into custom alert events.

#### 📡 High-Throughput Async Syslog Server (`/syslog`)
- Ultra-fast asyncio UDP/TCP syslog ingestion engine powered by uvloop.
- Real-time live log stream with full-text search, topic filtering, and device-level drill-down.

#### 🔑 RADIUS Server, Authentication & Accounting Logs (`/authlog`, `/accountlog`)
- Embedded RADIUS server capturing authentication attempts, user sessions, and bandwidth accounting data.
- Live session inspection and remote session termination.

---

### 8. ⚙️ Comprehensive System Settings (`/settings`)

The Settings module is organized into 7 specialized administrative tabs:

| Tab | Key Configurations & Capabilities |
| :--- | :--- |
| **📦 Firmware Management** | Internal repository storage, upstream firmware downloaders (stable, LTS, testing, beta, v6/v7), update behavior strategy (Keep v6 vs. Upgrade to v7), and default firmware versions. |
| **⚙️ System & Network** | Network configuration (Server IP, System URL, Timezone), scanner configuration (MAC vs IP range, intervals, default credentials), policy forcing toggles (Force RADIUS, Force Syslog, Force Permissions, Safe Install), and license management. |
| **📧 Email & SMTP** | SMTP server configuration (host, port, TLS/SSL, authentication, sender address) and test email delivery. |
| **🤖 AI Engine Settings *(Pro)*** | AI provider selection (Google Gemini, OpenAI GPT, Anthropic Claude, Local Ollama/vLLM / Custom Base URLs), API key management, model selection, temperature, max tokens, system prompt overrides, and tool calling toggles. |
| **⚡ Speed Test Endpoints** | Configure distributed remote or local speed test servers (host, port, auth token, local addon flag). |
| **🔔 Pro Alerts Catalog *(Pro)*** | Master configuration for notification services (Telegram bot tokens, Discord server names, Opsgenie regions/keys, PagerDuty keys) and global service activation. |
| **🔒 SSL / TLS Certificates** | **Automated Let's Encrypt:** HTTP-01 and DNS-01 challenges (Cloudflare API token or manual TXT records), **Manual Certificate Upload** (PEM cert, private key, CA intermediate chain), **CSR Generator**, and **Force HTTPS redirection**. |

---

## ⚖️ Free vs. Pro Feature Comparison Matrix

| Feature Category | Capability / Feature | Free Edition (AGPLv3) | Pro Edition (Commercial) |
| :--- | :--- | :---: | :---: |
| **Security & 2FA/OTP**| Web Panel Two-Factor Authentication (2FA / TOTP) | ❌ | ✅ QR Code + Authenticator App |
| | Device-Level Dynamic 2FA / OTP via RADIUS *(MikroTik)* | ❌ | ✅ Winbox, SSH, WebFig, Telnet |
| | Enforced OTP Policy (`otp_force` & IP Whitelisting) | ❌ | ✅ Included |
| **PAM & Web Terminal** | In-Browser Web Terminal (SSH & Telnet via Xterm.js) | ❌ | ✅ Included |
| | Multi-Brand Terminal Templates & Prompt Detection | ❌ | ✅ Included |
| | Keystroke Session Recording & Interactive Playback | ❌ | ✅ Included |
| | Live Session Sharing & Shadowing (Observer / Collaborator) | ❌ | ✅ Included |
| | Active Session Tracking & Remote Session Termination | ❌ | ✅ Included |
| | Terminal Security Policies & Real-Time Command Blocking | ❌ | ✅ Included |
| | RADIUS Single Sign-On (SSO) Terminal Injection | ❌ | ✅ Included |
| **Device Inventory** | Unlimited Device & Group Management | ✅ Included | ✅ Included |
| | Multi-Vendor Support (Cisco, Huawei, Linux via SSH/Telnet) | ✅ Included | ✅ Included |
| | Automated Scanner (MAC, IP Range, Tunnel) | ✅ Included | ✅ Included |
| | Dynamic Network Topology Map (MNDP/CDP/LLDP) | ❌ | ✅ Live Visual Map |
| **Backups & Config** | Scheduled & On-Demand Backups (Binary & RSC Export) | ✅ Included | ✅ Included |
| | Multi-Vendor CLI Configuration Backups (SSH/Telnet) | ✅ Included | ✅ Included |
| | Visual Configuration Diffing & Version History Archive | ❌ | ✅ Included |
| | Config Cloner & Multi-Router Synchronization Engine | ❌ | ✅ Included |
| | Password Vault with Automated Rotation *(MikroTik Only)* | ❌ | ✅ Included |
| **AI Copilot** | AI Network Assistant *(MikroTik Only)* | ❌ | ✅ Gemini, OpenAI, Claude, Local |
| | Live RouterOS Tool Execution & Autonomous Diagnostics | ❌ | ✅ Included |
| | AI Chat & Action Compliance Audit Logs | ❌ | ✅ Included |
| **Automation** | Batch Snippets & Script Execution Engine | ✅ Included | ✅ Included |
| | Task Planner & Visual Cron Scheduler | ✅ Included | ✅ Included |
| | Sequences (Chained Conditional Workflows & Output Triggers) | ❌ | ✅ Included |
| **Monitoring & NOC** | Async High-Throughput Syslog Server | ✅ Included | ✅ Advanced Parsing |
| | RADIUS Authentication & Accounting Event Logs | ✅ Included | ✅ Included |
| | Device Health & Ping Telemetry Tracking | ✅ Included | ✅ Included |
| | Fullscreen NOC Operations Monitoring Wall | ❌ | ✅ Included |
| | Radio & Wireless Link Telemetry (Signal, CCQ, SNR) *(MikroTik)*| ❌ | ✅ Included |
| | DHCP Server Manager & Historical Lease Analytics | ❌ | ✅ Included |
| **Alerting** | Event Alerts (Offline, Voltage, Temp, CPU, Regex) | ❌ | ✅ Included |
| | Multi-Channel Notifications (Telegram, Slack, Discord, etc.) | ❌ | ✅ 10+ Integrations |
| | Syslog Custom Regex Builder & Event Classifier | ❌ | ✅ Included |
| **Remote Access & VPN**| Direct WebFig Access (Local LAN / Public IP) | ✅ Included | ✅ Included |
| | Secure WebFig Reverse Proxy (No Public IP Needed) | ❌ | ✅ Included |
| | WireGuard VPN Manager & Auto-Provisioning | ❌ | ✅ Included |
| **Customer Portal** | Multi-Tenant Client Self-Service Dashboard | ❌ | ✅ Included |
| | Connected Client Discovery Table (Wi-Fi & LAN) | ❌ | ✅ Included |
| | 1-Click Diagnostics, Ping & Traceroute Tools | ❌ | ✅ Included |
| | Self-Service Port Forwarding & Simple Firewall Controls | ❌ | ✅ Included |
| | Integrated Support Ticket System (Admin & Client) | ❌ | ✅ Included |
| | Customer Router & Tab Assignment Manager | ❌ | ✅ Included |
| **Diagnostics & Addons**| Bandwidth Speed Testing (Local / Remote Test Servers) | ❌ | ✅ Included |
| | Support for Pro Addons (Terminal GW, WireGuard, SpeedTest) | ❌ | ✅ Native Integration |

---

## 🧩 Pro Addons Architecture

MikroWizard Pro includes support for three dedicated, decoupled microservice addons designed for maximum performance, isolation, and security:

```
                  ┌────────────────────────────────────────┐
                  │          MikroWizard Platform          │
                  │   MikroMan Backend + Angular Frontend  │
                  └───────┬────────────┬────────────┬──────┘
                          │            │            │
             REST / WS    │  REST / WS │            │ REST / API
                          ▼            ▼            ▼
             ┌─────────────────┐ ┌───────────┐ ┌───────────────┐
             │ Terminal Gateway│ │  MikroWG  │ │  MikroSpeed   │
             │     (Addon)     │ │  (Addon)  │ │    (Addon)    │
             └────────┬────────┘ └─────┬─────┘ └───────┬───────┘
                      │ SSH / Telnet   │ VPN Tunnel    │ Bandwidth Test
                      ▼                ▼               ▼
                 [ Core & Edge Network Devices / MikroTik Routers ]
```

### 1. Terminal Gateway Addon (`mikroman-terminal-gateway`)
* **Repository:** `mikroman-terminal-gateway`
* **What it is:** A standalone, high-concurrency WebSocket-to-SSH/Telnet terminal daemon built specifically for Privileged Access Management (PAM).
* **Key Features:** Handles WebSocket connection multiplexing, SSH/Telnet protocol state machines, RADIUS SSO injection, live session recording with compression, and real-time command policy parsing.

### 2. WireGuard Server Addon (`MikroWG`)
* **Repository:** `MikroWG`
* **What it is:** A dedicated WireGuard VPN orchestration daemon.
* **Key Features:** Centralized WireGuard server managing secure zero-trust VPN tunnels for remote edge routers behind carrier-grade NAT (CGNAT), firewalls, or dynamic 4G/5G mobile uplinks with one-click RouterOS script generation.

### 3. Speed Test Server Addon (`MikroSpeed`)
* **Repository:** `MikroSpeed`
* **What it is:** A high-throughput bandwidth testing engine.
* **Key Features:** Compatible with MikroTik Bandwidth Test (`btest`) and web-based speed tests for customer self-service diagnostics and backbone throughput verification without CPU overloading.

---

## 🛠️ Architecture & Tech Stack

### Backend Engine (`MikroMan`)
* **Core:** Python 3.10+, Flask REST API, uWSGI.
* **Architecture:** Inspired by RESTPie3 with modular blueprint APIs and dedicated asynchronous background mules:
  * `syslog.py` — Asyncio UDP/TCP syslog ingestion daemon.
  * `radius.py` — RADIUS server capturing authentication and accounting data, performing MS-CHAPv2 and dynamic OTP verification.
  * `data_grabber.py` — High-concurrency RouterOS API polling worker.
  * `firmware.py` — Upstream firmware tracker and repository synchronizer.
  * `updater.py` — Safe firmware update execution worker.
* **Storage & Caching:**
  * **PostgreSQL:** Relational database for device inventory, credentials, PAM audit logs, tickets, tasks, and system configs.
  * **Redis & Redis Stack (TimeSeries):** Ultra-fast session management, real-time rate limiting, and metric telemetry.
* **Security:** Fernet symmetric encryption and Key Encryption Key (KEK) envelope encryption for zero-knowledge credential storage.

### Frontend Application (`MikroFront`)
* **Framework:** Angular 18, TypeScript, RxJS.
* **UI & Theme:** CoreUI Admin, PrimeNG component library, FontAwesome Icons.
* **Interactive Components:** Vis-Network (dynamic topology graph), Chart.js (real-time telemetry charts), Xterm.js (PAM terminal emulator).

---

## 💖 Open-Source Credits & Acknowledgements

MikroWizard is built upon and deeply indebted to the open-source community:

* **[RESTPie3](https://github.com/tomimick/restpie3)** — REST API architecture by Tomi Mickelsson.
* **[librouteros](https://github.com/luqsz/librouteros)** — Native Python implementation of the MikroTik RouterOS API protocol.
* **[Peewee](https://github.com/coleifer/peewee)** & **[Peewee-Migrate](https://github.com/klen/peewee_migrate)** — Lightweight Python ORM and migration tool.
* **[Flask](https://flask.palletsprojects.com/)** & **[Flask-Session](https://github.com/fengsp/flask-session)** — Python web framework and session store.
* **[Netmiko](https://github.com/ktbyers/netmiko)** & **[Paramiko](https://www.paramiko.org/)** — Multi-vendor SSH/Telnet automation libraries.
* **[pyrad](https://github.com/pyrad/pyrad)** — Python RADIUS protocol library.
* **[pyotp](https://github.com/pyauth/pyotp)** & **[qrcode](https://github.com/lincolnloop/python-qrcode)** — 2FA / TOTP authentication and QR code provisioning.
* **[redis-py](https://github.com/redis/redis-py)** — Python interface to Redis and Redis TimeSeries.
* **[uvloop](https://github.com/MagicStack/uvloop)** — Ultra-fast asyncio event loop.
* **[cryptography](https://cryptography.io/)** & **[pycryptodome](https://www.pycryptodome.org/)** — Cryptographic primitives and encryption recipes.
* **[BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/)** & **[feedparser](https://github.com/kurtmckee/feedparser)** — Firmware and RSS parsing.
* **[python-crontab](https://gitlab.com/doctormo/python-crontab)** & **[cron-validator](https://github.com/vcoder4c/cron-validator)** — Cron utilities.
* **[pexpect](https://pexpect.readthedocs.io/)** — Pseudo-terminal automation.
* **[Angular](https://angular.dev/)** — Web application framework.
* **[CoreUI for Angular](https://coreui.io/angular/)** — UI layout and administrative components.
* **[PrimeNG](https://primeng.org/)** — UI component suite.
* **[Vis-Network](https://visjs.github.io/vis-network/docs/network/)** — Network topology visualization library.
* **[Chart.js](https://www.chartjs.org/)** — HTML5 canvas charting.
* **[date-fns](https://date-fns.org/)** — Modern JavaScript date utilities.

---

## 📦 Installation & Deployment

### Option 1: One-Line Automated Installer (Ubuntu/Debian)

Run the following command on a clean Ubuntu server (v20.04+) with root privileges:

```bash
sudo su -c "bash <(wget -qO- https://gist.githubusercontent.com/s265925/84f8fdc90c8b330a1501626a50e983a1/raw/b1fc4e0f283fd48d78861fa1a665fd1cb19b734d/installer.sh)" root
```

### Option 2: Docker Compose Deployment

Clone our official **Docker Compose repository** for containerized deployments:

```bash
git clone https://github.com/MikroWizard/docker-compose-deployment.git mikrowizard
cd mikrowizard
chmod +x prepare.sh
./prepare.sh
docker compose up -d
```

---

## ⚙️ Configuration File Overview

Runtime settings are managed in `/opt/mikrowizard/server-conf.json`:

```json
{
    "PYSRV_IS_PRODUCTION": "1",
    "PYSRV_DATABASE_HOST": "127.0.0.1",
    "PYSRV_DATABASE_PORT": "5432",
    "PYSRV_DATABASE_NAME": "MIKROMAN",
    "PYSRV_DATABASE_USER": "mikroman",
    "PYSRV_DATABASE_PASSWORD": "your_db_password",
    "PYSRV_CRYPT_KEY": "base64_encoded_32_byte_key",
    "PYSRV_KEK": "base64_encoded_envelope_key",
    "PYSRV_BACKUP_FOLDER": "/backups/",
    "PYSRV_FIRM_FOLDER": "/firms/",
    "PYSRV_REDIS_HOST": "127.0.0.1:6379",
    "PYSRV_REDIS_PASSWORD": "your_redis_password",
    "terminal_gateway_enabled": true,
    "terminal_gateway_url": "http://127.0.0.1:8201",
    "terminal_gateway_token": "your_addon_token"
}
```

---

## 🌐 Official Links & Support

* 🌍 **Website:** [https://mikrowizard.com](https://mikrowizard.com)
* 📖 **Documentation:** [https://mikrowizard.com/docs](https://mikrowizard.com/docs)
* 💼 **Pro Edition & Pricing:** [https://mikrowizard.com/pricing/](https://mikrowizard.com/pricing/)
* 🐳 **Docker Compose Repository:** [https://github.com/MikroWizard/docker-compose-deployment](https://github.com/MikroWizard/docker-compose-deployment)
* ✉️ **Support & Inquiries:** [info@mikrowizard.com](mailto:info@mikrowizard.com)

---

## 📄 License

* **Core Platform (Free Edition):** Licensed under the **[GNU Affero General Public License v3.0 (AGPL-3.0)](https://www.gnu.org/licenses/agpl-3.0.html)**.
* **Pro Features & Commercial Addons:** Licensed under the **MikroWizard Commercial License**. Visit [mikrowizard.com/pricing](https://mikrowizard.com/pricing/) for licensing details.
