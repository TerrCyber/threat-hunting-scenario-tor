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
