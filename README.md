<img width="1200" height="725" alt="image" src="https://github.com/user-attachments/assets/76ad54b0-18a8-4ace-89c2-2e2c13ca66c9" />

# Threat Hunt Report: Unauthorized TOR Browser Usage
- [Scenario Creation](https://github.com/TerrCyber/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation)

## Overview
This project documents a **threat hunting investigation** performed using **Microsoft Defender for Endpoint and Microsoft Sentinel** to detect unauthorized TOR browser installation and usage on a workstation.

The goal of this investigation was to determine whether TOR was installed or used to bypass organizational security controls and access restricted websites.

---

# Scenario

Management suspected that some employees might be using TOR browsers to bypass network security controls after unusual encrypted traffic patterns and connections to known TOR entry nodes were observed in network logs.

Additionally, anonymous reports suggested that employees had been discussing ways to access restricted websites during work hours.

The objective of this investigation was to detect TOR activity, analyze related telemetry, and determine whether TOR was used on any endpoints.

---

# Target System

Device Name: `terr-main-test-`  
User: `[REDACTED]`  
Investigation Date: `March 11, 2026`

---

# High-Level TOR IoC Discovery Plan

The investigation focused on identifying TOR-related indicators using three primary data sources.

| Log Source | Purpose |
|------------|--------|
| DeviceFileEvents | Detect TOR download and file creation |
| DeviceProcessEvents | Detect TOR installation and execution |
| DeviceNetworkEvents | Detect TOR network communication |

---

# Step 1 — TOR File Discovery

The **DeviceFileEvents** table was queried to identify TOR-related file activity on the endpoint.

```kql
DeviceFileEvents
| where DeviceName == "terr-main-test-"
| where InitiatingProcessAccountName contains "REDACTED"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-11T23:48:11.3476705Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
The results revealed that the user downloaded a TOR browser installer, which resulted in multiple TOR files being extracted onto the system.

Several TOR-related files were copied to the user’s desktop directory, and a file named tor-shopping-list was created.

The file activity began at:

2026-03-11T23:48:11.3476705Z

Step 2 — TOR Installer Execution

The DeviceProcessEvents table was analyzed to determine whether the TOR installer had been executed on the endpoint.
```kql
DeviceProcessEvents
| where DeviceName == "terr-main-test-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
The results confirmed that the TOR browser installer was executed by the user on the workstation.

The process creation event occurred at:

2026-03-11T23:47:59Z

The installer was launched from the user's Downloads directory and included a silent execution flag (/S), indicating the TOR portable package was extracted locally on the system.

Step 3 — TOR Browser Execution

To determine whether the TOR browser was actively used after installation, additional process telemetry was analyzed.
```kql
DeviceProcessEvents
| where DeviceName == "terr-main-test-"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
The results confirmed that the TOR browser was launched at:

2026-03-11T23:48:32.4931799Z

Following the initial launch, several additional processes were spawned including:

tor.exe
firefox.exe

These processes represent the TOR daemon and the modified Firefox browser used by the TOR browser bundle.

Step 4 — TOR Network Activity

The DeviceNetworkEvents table was analyzed to determine whether the TOR browser established outbound network connections.
```kql
DeviceNetworkEvents
| where DeviceName == "terr-main-test-"
| where InitiatingProcessFileName has_any ("tor","firefox")
| where RemotePort in (9001,9030,9050,9051,9150,9151,443)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```
The results confirmed that the TOR process initiated outbound encrypted network connections shortly after execution.

At:

2026-03-11T23:48:55Z

the process tor.exe established encrypted outbound connections over TCP port 443 to external IP addresses including:

64.65.0.98
64.65.62.148
193.124.33.242

Additional activity showed firefox.exe communicating with the TOR proxy service locally via:

127.0.0.1:9150
127.0.0.1:9151

This communication is consistent with TOR browser architecture where the browser connects locally to the TOR daemon before traffic is routed through the TOR network.

Chronological Timeline of Events
Timestamp (UTC)	Event
2026-03-11T23:47:59Z	TOR installer executed
2026-03-11T23:48:11Z	TOR files extracted to system
2026-03-11T23:48:32Z	TOR browser launched
2026-03-11T23:48:46Z	TOR routing service started
2026-03-11T23:48:55Z	TOR external network connections observed
2026-03-11T23:49:02Z	Local TOR proxy communications observed
