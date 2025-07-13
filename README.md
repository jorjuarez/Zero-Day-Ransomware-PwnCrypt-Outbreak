# Threat Hunt: Zero-Day Ransomware (PwnCrypt) Outbreak

### 1. Project Objective & Scenario

This project simulates a proactive threat hunt for a new ransomware strain, "PwnCrypt," and details the subsequent incident response according to the NIST 800-61 framework.

* **Scenario:** A new ransomware strain leveraging a PowerShell-based payload (`pwncrypt.ps1`) was reported in the news. The CISO requested a proactive hunt to determine if the organization had been compromised.
* **Objective:** Hunt for known Indicators of Compromise (IoCs) associated with PwnCrypt within the environment and, if found, execute a full incident response to contain, eradicate, and recover from the threat.
* **Hypothesis:** Due to an immature security program, it is plausible that the PwnCrypt ransomware has been introduced to the network, likely through user action. The initial hunt will focus on finding files with the `.pwncrypt` extension.

---

### 2. Investigation & Findings

The investigation began by querying Microsoft Defender XDR logs for IoCs related to the PwnCrypt ransomware on the device `arcwin10`, belonging to the user `arcanalyst1`.

#### Finding 1: Malicious Script Download & Execution
At **2:01 PM on May 10, 2025**, the user account `arcanalyst1` was observed downloading and immediately executing the malicious PowerShell script, `pwncrypt.ps1`. The script was downloaded from a known malicious GitHub repository and saved to the `C:\ProgramData` directory, a common location for attacker tools.

**Supporting Query:**
```kql
// Find network events showing the download of the script from the source URL
let target_device = "arcwin10";
DeviceNetworkEvents
| where DeviceName == target_device and Timestamp == datetime(2025-05-10T19:01:44.3886333Z)
| where isnotempty(RemoteUrl)
| project Timestamp, ActionType, InitiatingProcessCommandLine, RemoteUrl

// Find files being renamed with the PwnCrypt extension by the SYSTEM account
let target_device = "arcwin10";
DeviceFileEvents
| where DeviceName == target_device
| where ActionType == "FileRenamed" and FolderPath contains "pwncrypt" and InitiatingProcessAccountName == "SYSTEM"
| project Timestamp, ActionType, FileName, PreviousFolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc
```
---

#### Finding 2: Ransomware Activity & Privilege Escalation
Once executed, the script began its ransomware routine of enumerating and encrypting files. Further investigation revealed that at approximately 3:13 PM, additional file renaming activity was observed running under the SYSTEM account, indicating the script successfully escalated its privileges to gain full control of the machine.

**Supporting Query:**
```kql
// Find files being renamed with the PwnCrypt extension by the SYSTEM account
let target_device = "arcwin10";
DeviceFileEvents
| where DeviceName == target_device
| where ActionType == "FileRenamed" and FolderPath contains "pwncrypt" and InitiatingProcessAccountName == "SYSTEM"
| project Timestamp, ActionType, FileName, PreviousFolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc
```
### 3. Incident Response
Upon confirming active ransomware and privilege escalation, the following response actions were taken immediately:

* **Containment:** The infected host, `arcwin10`, was isolated from the network using Microsoft Defender for Endpoint to prevent the ransomware from spreading.
* **Communication:** A report was sent to the manager of `arcanalyst1` to initiate an internal investigation into how the malicious command was run under the user's account.
* **Eradication & Recovery:** A ticket was submitted to have the infected machine reimaged and rebuilt, with user files to be restored from clean backups.
---

