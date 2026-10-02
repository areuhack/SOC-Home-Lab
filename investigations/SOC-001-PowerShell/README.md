# SOC-001: PowerShell Execution Investigation

## Overview

A PowerShell process was observed executing with the
`-ExecutionPolicy Bypass` option on the monitored Windows 11
endpoint.

The objective of this investigation was to analyze the event,
reconstruct the process relationship, and determine whether the
activity represented malicious behavior.

## Environment

**Endpoint:** SOC-WIN11  
**Operating System:** Windows 11  
**SIEM:** Wazuh  
**Telemetry:** Sysmon  
**Event Type:** Process Creation (Sysmon Event ID 1)

## Observed Command

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Select-Object -First 5"
