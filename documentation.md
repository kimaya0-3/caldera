# Adversary Emulation & Detection Gap Analysis Report

---

## 1. Introduction
This project utilizes **MITRE Caldera**, an automated adversary emulation platform, to stress-test Linux system defenses. By leveraging the **Caldera for OT** extension and the **Atomic Red Team** library, we emulated real-world attacker behaviors across the entire kill chain. The primary goal was to determine if a baseline Linux system could detect sophisticated persistence, exfiltration, and anti-forensic techniques without the aid of third-party security agents.

---

## 2. Methodology: The Automation Pipeline
To ensure the emulation was both randomized and relevant, a three-stage Python pipeline was developed to interface with the MITRE ATT&CK dataset and the Caldera engine.

1.  **Filtering:** Techniques were filtered to include only Linux-compatible attacks, excluding Cloud-specific (AWS/Azure/SaaS) and non-technical (Social Engineering) methods.
2.  **Sampling:** A randomized selection of 3-4 techniques per Tactic column was performed to generate a diverse 35-step attack plan.
3.  **Adversary Creation:** To bypass API limitations, a custom script wrote the attack profile directly to the Caldera backend, forcing a "Brute Force" execution order to prevent the operation from stopping on individual command failures.

---

## 3. Monitoring Configuration Comparison
We compared two distinct levels of system auditing to measure the "Visibility Gap."

### 3.1 Standard Auditd Configuration
The standard setup relied on manual rules targeting specific high-level triggers:
*   **Execve Monitoring:** Watching for any command execution.
*   **File Watches:** Monitoring `/etc/shadow` and `/etc/systemd/system/`.
*   **Result:** Captured that a command was run, but lacked the context of *what* was inside the command or *why* it failed.

### 3.2 Neo23x0 (Advanced) Ruleset
The **Neo23x0 ruleset** (by Florian Roth) was applied to provide high-fidelity telemetry.
*   **Telemetry-First:** Captured full command-line arguments, network socket creation (IPv4/IPv6), and file deletions.
*   **Result:** Transformed the VM into a forensic sensor, capturing over **10,000 relevant events** during a 10-minute attack window.

---

## 4. Detailed Findings & Log Analysis

The operation was executed with the Sandcat agent running as **root** (disguised as `splunkd`).

### 4.1 Trace Level Categorization
| Category | Trace Level | Findings |
| :--- | :--- | :--- |
| **System Persistence** | **Strong** | Captured the exact `echo` commands used to create the `art-timer.service`. |
| **Permission Mods** | **Strong** | Flagged 1,038 events where the agent used `fchmodat` to secure malicious tools. |
| **Anti-Forensics** | **Strong** | Recorded 704 file deletions (`unlinkat`) as the agent attempted to "wipe" its tracks. |
| **C2 Activity** | **Moderate** | Detected 1,108 network connections. We saw the "Who" and "Where," but not the "What" due to encryption. |
| **Discovery** | **Weak/None** | While 4,806 processes were logged, simple commands like `id` and `whoami` were indistinguishable from normal admin noise. |

### 4.2 Key Attack Deep-Dives

#### **Finding 1: The "Invisible" Persistence Success (T1053.006)**
The agent successfully installed a `systemd` timer. 
*   **Standard Log:** Showed a generic `systemctl daemon-reload`.
*   **Neo23x0 Log:** Captured the full payload string being written to `/etc/systemd/system/art-timer.service`. This allowed for immediate identification of the malicious "marker" file created in `/tmp/`.

#### **Finding 2: Automated Anti-Forensics (T1070.004)**
The agent attempted to "Timestomp" files to hide its activity.
*   **Evidence:** The Neo ruleset triggered 99 alerts under the `key=T1070_006_timestomp`. This is a critical indicator of compromise (IoC) that standard logging completely ignored.

#### **Finding 3: Permission Enforcement Visibility**
One attack attempted to modify a PAM module but failed.
*   **Forensic Discovery:** The Neo23x0 logs provided the root cause: an `EACCES (Permission Denied)` error. This level of detail is vital for defenders to understand which specific security boundaries are being tested.

---

## 5. Conclusion
The emulation proved that **Standard Linux logging is insufficient** for modern threat detection. While it records that activity occurred, it fails to provide the forensic detail required to stop an attack in progress. 

The **Neo23x0 Ruleset** successfully bridged this gap, providing 100% visibility into the attacker's lifecycle. However, the sheer volume of data (126,000+ lines) highlights the need for an automated analysis tool or SIEM (like Wazuh) to filter these high-fidelity logs in real-time.

---

## Appendix: Technical Reference

### A. Installation & Setup Commands
```bash
# 1. Start Caldera Server
python3 server.py --build --fresh --insecure

# 2. Install Auditd & Neo23x0 Rules
sudo apt install auditd -y
sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules
sudo service auditd restart

# 3. Deploy Root Agent
sudo bash -c 'server="http://localhost:8888"; curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:amd64" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group red -v'
```

### B. Automation Scripts

#### **Script 1: `filter_mitre.py`**
*(Filters the MITRE Matrix for Linux-only, non-social techniques)*
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
        master_list.append({"id": obj.get('external_references', [{}])[0].get('external_id', 'N/A'), "name": obj.get('name'), "tactics": ", ".join(tactic_names)})
    with open(f'{name_prefix}_master.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["id", "name", "tactics"]); writer.writeheader(); writer.writerows(master_list)
process_matrix(ENTERPRISE_URL, "enterprise")
```

#### **Script 2: `create_adversary.py`**
*(Bypasses API to write the 35-attack profile directly to disk)*
```python
import requests, json, os, uuid
CALDERA_URL = "http://localhost:8888"
API_KEY = "admin123" 
def create_brute_force_adversary():
    with open("tuesday_plan_enterprise.json", 'r') as f: plan = json.load(f)
    mitre_ids = [tech['id'] for tactic in plan.values() for tech in tactic]
    abilities = requests.get(f"{CALDERA_URL}/api/v2/abilities", headers={'KEY': API_KEY}).json()
    uuids = [ab['ability_id'] for aid in mitre_ids for ab in abilities if ab.get('technique_id') == aid and 'linux' in [p.lower() for p in ab.get('platforms', [])]]
    adv_id = str(uuid.uuid4())
    yaml = f"id: {adv_id}\nname: Tuesday_35_Attack_Run\natomic_ordering:\n"
    for u in uuids: yaml += f"  - {u}\n"
    with open(f"data/adversaries/{adv_id}.yml", 'w') as f: f.write(yaml)
create_brute_force_adversary()
```
