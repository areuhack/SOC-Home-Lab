# SOC Home Lab

A home Security Operations Center (SOC) environment built to
practice security monitoring, detection engineering, threat
hunting, and incident investigation.

## Lab Architecture

- Wazuh SIEM
- Windows 11 monitored endpoint
- Sysmon telemetry
- Windows Server / Active Directory
- Ubuntu Server
- Kali Linux attack simulation

## Objectives

- Collect and analyze endpoint telemetry
- Investigate security alerts
- Correlate events using Sysmon
- Develop custom detection rules
- Map observed activity to MITRE ATT&CK
- Document incident investigations

## Investigations

| ID | Investigation | Status |
|---|---|---|
| SOC-001 | PowerShell Execution Investigation | Completed |
| SOC-002 | Repeated Failed Login Investigation | Planned |
| SOC-003 | Account Creation Investigation | Planned |
| SOC-004 | Persistence Investigation | Planned |
| SOC-005 | Network Reconnaissance | Planned |

## Environment

Host:
- Ubuntu
- KVM/QEMU + libvirt

SIEM:
- Wazuh

Endpoints:
- Windows 11
- Windows Server
- Ubuntu Server

Telemetry:
- Windows Event Logs
- Sysmon

Attack Simulation:
- Kali Linux

## Disclaimer

All attack simulations and security testing documented in this
repository were performed in an isolated home lab environment
against systems owned and controlled by me.
