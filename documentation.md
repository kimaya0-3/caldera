# Adversary Emulation Report: MITRE ATT&CK & Caldera for OT
 
**Target System:** Linux VM (Ubuntu/Debian)  
**Objective:** Automate randomized attack emulation to identify detection gaps in a baseline Linux environment.

---

## 1. Introduction to MITRE Caldera
MITRE Caldera is an automated adversary emulation platform built on the MITRE ATT&CK framework. It allows security teams to test their defenses by running "operations" that mimic real-world attacker behaviors. 

For this project, we utilized the **Caldera for OT (Operational Technology)** extension, which provides specialized plugins for industrial protocols like Modbus, DNP3, and BACnet, allowing for security testing in Industrial Control Systems (ICS) environments.

---

## 2. Technical Setup & Installation

### 2.1 Starting the Caldera Server
To ensure a clean environment and include all specialized plugins (Atomic & OT), the server was initialized with the following command:

```bash
# Navigate to the caldera directory
cd ~/caldera

# Start the server with a fresh database and insecure mode for API access
python3 server.py --build --fresh --insecure
```

### 2.2 Required Plugins & Dependencies
The following plugins were cloned into the `caldera/plugins/` directory:
*   **Atomic:** Integrates the Red Canary Atomic Red Team library.
*   **Caldera-OT:** Provides Modbus, DNP3, and BACnet capabilities.

**Python Dependencies:**
```bash
pip3 install requests pymodbus scapy pycip
```

---

## 3. Automation Scripts
We developed a three-stage automation pipeline to ensure the attacks were relevant, randomized, and automatically loaded into the Caldera engine.

### 3.1 Stage 1: The Matrix Filter (`filter_mitre.py`)
This script pulls the live MITRE Enterprise and ICS matrices and removes irrelevant techniques (Cloud, SaaS, Social Engineering).

```python
import requests
import json
import csv

ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

EXCLUDED_PLATFORMS = {'salesforce', 'office-365', 'google-workspace', 'saas', 'azure', 'aws', 'gcp'}
EXCLUDED_TACTICS = {'resource-development'}
EXCLUDED_KEYWORDS = {'phishing', 'social engineering', 'user execution'}

def process_matrix(url, name_prefix):
    data = requests.get(url).json()
    master_list = []
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern' or obj.get('revoked'):
            continue
        platforms = [p.lower() for p in obj.get('x_mitre_platforms', [])]
        if any(p in EXCLUDED_PLATFORMS for p in platforms): continue
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

if __name__ == "__main__":
    process_matrix(ENTERPRISE_URL, "enterprise")
    process_matrix(ICS_URL, "ics")
```

### 3.2 Stage 2: The Random Sampler (`pick_samples.py`)
This script reads the vetted CSV files and randomly selects 2-3 techniques per tactic column.

```python
import csv
import json
import random
import os

def pick_random_samples():
    files = ['enterprise_master.csv', 'ics_master.csv']
    for csv_file in files:
        if not os.path.exists(csv_file): continue
        columns = {}
        with open(csv_file, mode='r') as f:
            reader = csv.DictReader(f)
            for tech in reader:
                for tactic in [t.strip() for t in tech['tactics'].split(',')]:
                    if tactic not in columns: columns[tactic] = []
                    columns[tactic].append(tech)
        
        selection = {t: random.sample(techs, min(len(techs), random.randint(2, 3))) 
                     for t, techs in columns.items()}
        
        with open(f'tuesday_plan_{csv_file.replace("_master.csv", "")}.json', 'w') as f:
            json.dump(selection, f, indent=4)

if __name__ == "__main__":
    pick_random_samples()
```

### 3.3 Stage 3: The Adversary Creator (`create_adversary.py`)
To bypass API limitations, this script writes the adversary profile directly to the Caldera data directory.

```python
import requests
import json
import os
import uuid

CALDERA_URL = "http://localhost:8888"
API_KEY = "admin123" 

def create_adversary_file():
    with open("tuesday_plan_enterprise.json", 'r') as f:
        plan = json.load(f)
    mitre_ids = [tech['id'] for tactic in plan.values() for tech in tactic]
    
    resp = requests.get(f"{CALDERA_URL}/api/v2/abilities", headers={'KEY': API_KEY})
    abilities = resp.json()
    
    uuids = []
    for aid in mitre_ids:
        for ab in abilities:
            if ab.get('technique_id') == aid:
                uuids.append(ab['ability_id'])
                break

    adv_id = str(uuid.uuid4())
    yaml_content = f"id: {adv_id}\nname: Tuesday_Random_Final\natomic_ordering:\n"
    for uid in uuids: yaml_content += f"  - {uid}\n"

    with open(f"data/adversaries/{adv_id}.yml", 'w') as f:
        f.write(yaml_content)
    print("Adversary created. Restart Caldera to load.")

if __name__ == "__main__":
    create_adversary_file()
```

---

## 4. Findings & Detection Analysis

### 4.1 Execution Summary
The operation "Tuesday_Random_Final" was executed against a baseline Linux VM with security agents removed.

| Technique | Result | Log Evidence |
| :--- | :--- | :--- |
| **Persistence (Systemd Service)** | Success | `systemd[1]: Created slice...` |
| **Exfiltration (HTTPS/curl)** | Success | None (Blended with web traffic) |
| **Credential Access (PAM)** | Timeout | `polkit-agent-helper` activity |
| **Discovery (Network/Process)** | Success | `systemd-run /usr/bin/bash` |

### 4.2 Key Observations
1.  **Invisible Persistence:** The system allowed the creation of a new `systemd` timer and service. Without File Integrity Monitoring (FIM), this change went un-alerted.
2.  **Log Obfuscation:** While `syslog` captured the execution of `systemd-run`, it did **not** record the specific commands executed within the bash shell.
3.  **Resource Exhaustion:** High-intensity emulation caused the kernel to report "CPU hogging" in the workqueue, indicating that aggressive scanning can be used as a secondary Denial of Service (DoS) vector.

### 4.3 Conclusion
The baseline Linux logging configuration is insufficient for detecting modern adversary techniques. The removal of specialized agents like **Wazuh** created a total blind spot for exfiltration and persistence. To secure this environment, **Auditd** or a similar EDR solution must be implemented to capture command-level telemetry.
````
