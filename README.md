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
User: `[your username]`  
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
| where InitiatingProcessAccountName contains "terrcyber"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-11T23:48:11.3476705Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1347" height="432" alt="image" src="https://github.com/user-attachments/assets/cd5e2a57-155e-4801-9e4a-491ae3068515" />

The results revealed that the user downloaded a TOR browser installer, which resulted in multiple TOR files being extracted onto the system.

Several TOR-related files were copied to the user’s desktop directory, and a file named tor-shopping-list was created.

The file activity began at:

2026-03-11T23:48:11.3476705Z

# Step 2 — TOR Installer Execution

The DeviceProcessEvents table was analyzed to determine whether the TOR installer had been executed on the endpoint.
```kql
DeviceProcessEvents
| where DeviceName == "terr-main-test-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1772" height="406" alt="image" src="https://github.com/user-attachments/assets/af52e52a-ea47-479b-99ca-11a25bebc793" />

The results confirmed that the TOR browser installer was executed by the user on the workstation.

The process creation event occurred at:

2026-03-11T23:47:59Z

The installer was launched from the user's Downloads directory and included a silent execution flag (/S), indicating the TOR portable package was extracted locally on the system.

# Step 3 — TOR Browser Execution

To determine whether the TOR browser was actively used after installation, additional process telemetry was analyzed.
```kql
DeviceProcessEvents
| where DeviceName == "terr-main-test-"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1847" height="745" alt="image" src="https://github.com/user-attachments/assets/3555d4cb-1339-40d2-8e97-41c8ac26ab3e" />

The results confirmed that the TOR browser was launched at:

2026-03-11T23:48:32.4931799Z

Following the initial launch, several additional processes were spawned including:

tor.exe
firefox.exe

These processes represent the TOR daemon and the modified Firefox browser used by the TOR browser bundle.

# Step 4 — TOR Network Activity

The DeviceNetworkEvents table was analyzed to determine whether the TOR browser established outbound network connections.
```kql
DeviceNetworkEvents
| where DeviceName == "terr-main-test-"
| where InitiatingProcessFileName has_any ("tor","firefox")
| where RemotePort in (9001,9030,9050,9051,9150,9151,443)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```
<img width="1620" height="378" alt="image" src="https://github.com/user-attachments/assets/62c40a3a-1a41-40c9-8e10-313b14cce5df" />

The results confirmed that the TOR process initiated outbound encrypted network connections shortly after execution.

At:

2026-03-11T23:48:55Z

the process tor.exe established encrypted outbound connections over TCP port 443 to external IP addresses including:

• 64.65.0.98

• 64.65.62.148

• 193.124.33.242

Additional activity showed firefox.exe communicating with the TOR proxy service locally via:

• 127.0.0.1:9150

• 127.0.0.1:9151

This communication is consistent with TOR browser architecture where the browser connects locally to the TOR daemon before traffic is routed through the TOR network.

| Timestamp (UTC)      | Event                                     |
| -------------------- | ----------------------------------------- |
| 2026-03-11T23:47:59Z | TOR installer executed                    |
| 2026-03-11T23:48:11Z | TOR files extracted to system             |
| 2026-03-11T23:48:32Z | TOR browser launched                      |
| 2026-03-11T23:48:46Z | TOR routing service started               |
| 2026-03-11T23:48:55Z | TOR external network connections observed |
| 2026-03-11T23:49:02Z | Local TOR proxy communications observed   |


# Summary

The investigation confirmed the installation and active usage of the TOR Browser on workstation terr-main-test-.

The activity began when the user executed the portable TOR installer, which resulted in the extraction of multiple TOR components onto the system. Shortly after installation, the TOR browser was launched, spawning both the TOR routing service (tor.exe) and the TOR browser client (firefox.exe).

Network telemetry confirmed TOR usage when outbound encrypted connections were observed from tor.exe to external IP addresses over TCP port 443. Additionally, internal communication between the TOR browser and the local TOR proxy service was observed via localhost ports 9150 and 9151.

These findings demonstrate that the TOR browser was successfully installed, executed, and used to establish anonymized network communications from the endpoint.

# Response Taken

TOR usage was confirmed on endpoint:

terr-main-test-

The device was isolated for further investigation and the user's direct manager was notified.

# MITRE ATT&CK Mapping
Technique	ID
• Proxy	T1090
• Web Protocols	T1071
• Encrypted Channel	T1573
• Ingress Tool Transfer	T1105

#Tools Used

• Microsoft Sentinel

• Microsoft Defender for Endpoint

• Kusto Query Language (KQL)

# Key Takeaways

  • Defender telemetry can detect TOR installation and usage

  • Process telemetry provides strong evidence of TOR browser execution

  • Network telemetry confirms anonymized communication behavior

  • Correlating file, process, and network logs enables effective threat hunting investigations
