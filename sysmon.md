# Adversary Emulation and Detection Validation Report

---

## 1. Executive Summary
This project successfully implemented a distributed Adversary Emulation environment to validate the detection capabilities of **Sysmon** against 35 randomized MITRE ATT&CK techniques. By utilizing **Caldera** as the orchestration engine, we demonstrated that a centralized Linux-based Command and Control (C2) server can effectively manage and execute high-fidelity attacks against a Windows endpoint. The primary finding confirms that Sysmon, when configured with the SwiftOnSecurity baseline, provides critical visibility into process lineage and registry-based persistence.

## 2. Environment Architecture
The lab was designed to mimic a real-world "Off-Network" attack scenario using a **Distributed C2 Model**.

*   **C2 Server (The Brain):** Linux VM running MITRE Caldera. Configured to listen on `0.0.0.0:8888`.
*   **Target Host (The Victim):** Windows VM (Administrator) monitored by **Sysmon v15.0**.
*   **Connectivity:** Established via **VirtualBox NAT Port Forwarding** (Host Port 8888 -> Guest Port 8888).
*   **Agent:** Custom-compiled **Sandcat (54ndc47)** Go-binary (`sandcat.exe`).

## 3. Configuration Comparison: Baseline vs. SwiftOnSecurity
A critical component of this research was evaluating the difference between a "Default/Baseline" Sysmon installation and the industry-standard **SwiftOnSecurity** configuration.

| Metric | Baseline Sysmon (Default) | SwiftOnSecurity Config | Improvement |
| :--- | :--- | :--- | :--- |
| **Signal-to-Noise Ratio** | Low (Logs everything) | High (Filtered/Contextual) | **Significant** |
| **T1122 (COM Hijacking)** | **Missed** (No Registry ID 13) | **Caught** (Registry Monitored) | **Critical Gap Fill** |
| **T1071 (C2 Beaconing)** | **Noisy** (Logs every packet) | **Precise** (Excludes known-good) | **Better Triage** |

**Key Takeaway:** The Baseline configuration is a "recorder," while SwiftOnSecurity is a "sensor." Without the advanced filtering and registry monitoring of SwiftOnSecurity, the COM Hijacking persistence attempt would have gone completely undetected.

## 4. Key Technical Findings

### 4.1 Technique Validation: T1122 (COM Hijacking)
*   **Action:** The agent used `reg.exe` to modify `HKCU\Software\Classes\CLSID\{...}\InProcServer32`.
*   **Detection:** Sysmon **Event ID 13 (Registry Value Set)** captured the exact key modification and the malicious payload path (`C:\IDontExist.dll`).
*   **Fidelity:** High. Baseline Sysmon would have missed this entirely as it does not monitor Registry events by default.

### 4.2 Technique Validation: T1059 (Command and Scripting Interpreter)
*   **Action:** Sandcat spawned `powershell.exe` with `-ExecutionPolicy Bypass`.
*   **Detection:** Sysmon **Event ID 1 (Process Create)** captured the full command line, including the attempt to rename malicious files (`mv mission.go mission.exe`).

## 5. Detection Gap Analysis
| Technique | Sysmon ID | Status | Observation |
| :--- | :--- | :--- | :--- |
| **C2 Beaconing** | 3 | **Detected** | High fidelity; caught the remote IP and Port 8888. |
| **COM Hijacking** | 13 | **Detected** | Critical visibility into registry-based persistence. |
| **mDNS Discovery** | 3 | **Noisy** | Caught UDP 5353 traffic, but difficult to distinguish from baseline. |

## 6. Conclusion & Recommendations
The research confirms that **Sysmon is a vital component** of a Windows defense-in-depth strategy, but only when paired with a mature configuration like SwiftOnSecurity. 


---
