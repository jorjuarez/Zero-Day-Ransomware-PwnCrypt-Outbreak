# Threat Hunt: Zero-Day Ransomware (PwnCrypt) Outbreak 💻⚠️

### Executive Summary
A proactive threat hunt, initiated in response to reports of a new ransomware strain named "PwnCrypt," successfully identified an active infection on a corporate device. The investigation traced the attack's full lifecycle, from a malicious PowerShell download to the unauthorized encryption of files. The infected host was immediately contained using Microsoft Defender for Endpoint, and the incident was used to develop strategic recommendations for improving the organization's security posture.

*Full technical details of this hunt, including IoCs and MITRE ATT&CK mapping, are available in the [Project Appendix](https://github.com/jorjuarez/Cybersecurity-Portfolio-Public/tree/main/PwnCrypt%20Ransomware%20Project%20Appendix).*

---

### 1. Project Objective & Scenario

This project simulates a proactive threat hunt for a new ransomware strain, "PwnCrypt," and details the subsequent incident response according to the NIST 800-61 framework.

* **Scenario:** A new ransomware strain leveraging a PowerShell-based payload (`pwncrypt.ps1`) was reported in the news. The CISO requested a proactive hunt to determine if the organization had been compromised.
* **Objective:** Hunt for known Indicators of Compromise (IoCs) associated with PwnCrypt within the environment and, if found, execute a full incident response to contain, eradicate, and recover from the threat.
* **Hypothesis:** Due to an immature security program, it is plausible that the PwnCrypt ransomware has been introduced to the network, likely through user action.

---

### 2. Investigation & Findings

The investigation began by querying Microsoft Defender XDR logs for IoCs related to the PwnCrypt ransomware on the device `arcwin10`, belonging to the user `arcanalyst1`.

#### Finding 1: Malicious Script Download
At **2:01 PM on May 10, 2025**, the user account `arcanalyst1` initiated a PowerShell command to download the malicious script, `pwncrypt.ps1`, from an external GitHub repository and save it to the `C:\programdata` directory.

**Supporting Query:**
```kql
let target_device = "arcwin10";
DeviceNetworkEvents
| where DeviceName == target_device and Timestamp == datetime(2025-05-10T19:01:44.3886333Z)
| project Timestamp, ActionType, InitiatingProcessCommandLine, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileSize
| where isnotempty(RemoteUrl)
```
<img width="912" height="357" alt="image" src="https://github.com/user-attachments/assets/7c1f7754-d348-4596-b730-b3e1bf6b417c" />

---

#### Finding 2: Script Execution via Policy Bypass
Immediately after being downloaded, the script was executed using a command that bypassed the PowerShell Execution Policy, a common defense evasion technique.

**Supporting Query:**
```kql
let target_device = "arcwin10";
let start_time = datetime(2025-05-10T18:50:00Z); //May 10, 2025 1:50:00 PM CDT
let end_time = datetime(2025-05-10T19:21:00Z); //May 10, 2025 2:21:00 PM CDT
DeviceProcessEvents
| where DeviceName == target_device
| where Timestamp between (start_time .. end_time )
| where InitiatingProcessFileName contains "powershell" and AccountName == "arcanalyst1"
| project Timestamp,AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, FileSize, AdditionalFields
| sort by Timestamp desc
```
<img width="1171" height="409" alt="image" src="https://github.com/user-attachments/assets/52f4288c-94d3-4a8f-8515-7a853f632000" />

#### Finding 3: Corroborating the Full Command Line
To get the full, unobfuscated command line used by the attacker, the investigation pivoted to the `DeviceEvents` table. This confirmed the use of `Invoke-WebRequest` to download the file and `cmd.exe` to launch the script, all in one line.
```kql
let target_device = "arcwin10";
let start_time = datetime(2025-05-10T18:50:00Z); //May 10, 2025 1:50:00 PM CDT
let end_time = datetime(2025-05-10T19:21:00Z); //May 10, 2025 2:21:00 PM CDT
DeviceEvents
| where DeviceName == target_device
| where Timestamp between (start_time .. end_time )
| where ActionType contains "PowerShellCommand"
| project Timestamp, ActionType, InitiatingProcessSHA1, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName, AdditionalFields
| sort by Timestamp asc
```
<img width="1676" height="301" alt="image" src="https://github.com/user-attachments/assets/920a649e-6b3d-4526-a740-62923fd9e469" />

#### Finding 4: Ransomware Activity & Privilege Escalation 
Later, at approximately **3:13 PM**, the hunt uncovered evidence of the script's true purpose. File renaming activity consistent with ransomware was observed, and crucially, it was being initiated by the **SYSTEM account**, indicating the script had successfully escalated its privileges.

```kql
let target_device = "arcwin10";
DeviceFileEvents
| where DeviceName == target_device
| where ActionType == "FileRenamed" and FolderPath contains "pwncrypt"
| project Timestamp, ActionType, FileName, PreviousFolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
| sort by Timestamp asc
```

<img width="2094" height="742" alt="image" src="https://github.com/user-attachments/assets/64dc7e4f-8653-43a8-a872-88ff66fd587c" />



#### Key Indicators of Compromise (IoCs)

* **Malware Script (`pwncrypt.ps1`):**
    * **File Path:** `C:\programdata\pwncrypt.ps1`
    * **SHA256:** `739d9923e2ddf467ce9f997c82d36bfb72accc90acc40573eaa5e1abb2097cd8`
* **Delivery & Initial Execution:**
    * **Source URL (Defanged):** `hxxps[://]raw[.]githubusercontent[.]com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt[.]ps1`
    * **Observed Command:** `Invoke-WebRequest ...; cmd /c powershell.exe -ExecutionPolicy Bypass ...`
* **Ransomware Impact:**
    * **Encrypted File Suffix:** `_pwncrypt.csv`
    * **Ransom Note Link:** `__________decryption-instructions.lnk`
* **Initial Compromise Context:**
    * **User / Device:** `arcanalyst1` on `arcwin10`


#### 3. Incident Response
Upon confirming active ransomware behavior, the following response actions were taken immediately:

#### Containment
The infected host, arcwin10, was isolated from the network using Microsoft Defender for Endpoint to prevent the ransomware from spreading.

#### Communication
A report was sent to the manager of arcanalyst1 to initiate an internal investigation into how the malicious command was run under the user's account.

#### Eradication & Recovery
A ticket was submitted to have the infected machine reimaged and rebuilt, with user files to be restored from clean backups.

### 4. MITRE ATT&CK® Framework Mapping
The observed attacker behavior maps to several tactics and techniques. A link to the full mapping is available in the [Project Appendix.](https://github.com/jorjuarez/Cybersecurity-Portfolio-Public/tree/main/PwnCrypt%20Ransomware%20Project%20Appendix#mitre-attck-framework).

---
### 5. Strategic Improvements & Recommendations
This incident revealed opportunities to harden the environment against similar attacks. The following layered security improvements were recommended:

* **User Training:** Implement immediate and recurring user security awareness training, focusing on phishing, malicious file recognition, and safe Browse habits.

* **Endpoint Hardening:**
    * Use Windows Defender Application Control (`WDAC`) or AppLocker to restrict the execution of unauthorized scripts.
    * Enforce stricter PowerShell Execution Policies via Group Policy to prevent bypassing.

* **Detection Engineering:** Create new high-fidelity alerts in Sentinel based on the specific `IoCs` and `TTPs` observed in this attack.

