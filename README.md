# 🔥 Firewall Policy Engine (FPE)

## Description

The **Firewall Policy Engine (FPE)** is a modern, GUI‑based firewall ruleset management and deployment tool built using **Python**, **CustomTkinter**, **nftables**, and **SQLite**. It provides a controlled, safe, and user‑friendly environment for editing, validating, simulating, versioning, and deploying nftables rulesets.

FPE is designed for **cybersecurity professionals, students, researchers, and developers** who want a practical and safe workflow for managing Linux firewall rules.

This project demonstrates strong skills in:

* Python systems programming
* GUI development (CustomTkinter)
* Firewall automation & scripting
* Secure deployment workflows
* Policy versioning and audit logging

Its goal is to remain **simple, understandable, and effective** — avoiding unnecessary complexity while still providing professional‑grade functionality.

---

## 🚀 Features

### ✔ Policy Editing

* Full ruleset editor with syntax-friendly formatting.
* Real-time preview panel.
* Built-in sample nftables template.

### ✔ Safe Policy Deployment

* **Dry-run validation** using `nft -f -` to catch syntax errors.
* **Safety heuristic** to prevent SSH lockouts (checks for port 22 ACCEPT rules).
* **Simulation mode** (demo): no system changes; safe for testing.
* **Real deployment mode**: applies nftables rules using `sudo`.

### ✔ Policy Versioning

* Automatic policy version saving.
* Load previous rulesets anytime.
* Delete old versions.
* Stored locally in SQLite.

### ✔ Audit Logging

Tracks:

* Policy saves
* Deployments
* Simulations
* Validation attempts
* Deleted versions

### ✔ Modern CustomTkinter GUI

* Dark themed professional UI.
* Resizable panels and scrollable version list.
* Clean layout for easy workflow.

---

## Requirements

Ensure you have the following installed:

* **Python 3.8+**
* **CustomTkinter**
* **nftables** (Linux only; required for real deployment)
* **sudo privileges** (if using deployment mode)

Install dependencies:

```bash
pip install customtkinter
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/firewall-policy-engine.git
cd firewall-policy-engine
```

(Optional) Set up a virtual environment.

---

## Usage

### ▶️ Run in Demo Mode (SAFE)

Recommended for learning/testing:

```bash
python app.py --demo
```

No firewall changes are made.

### ⚠️ Run in Real Deployment Mode

```bash
python app.py
```

This mode uses:

```bash
sudo nft -f -
```

Use only if you understand your ruleset.

---

## Using the Application

### 🔧 Editing Firewall Policies

* Write or paste nftables rules into the editor.
* The preview panel updates automatically.
* Use the **Save Version** button to store the ruleset.

### 🧪 Simulation Mode

Simulates loading your rules without applying them.

* Includes built‑in SSH safety check.
* Logs simulation results.

### ✔ Dry Run Validation

Runs:

```
nft -f -
```

against your ruleset (without sudo).

### 🚀 Deployment

* Prompts safety confirmation.
* Applies ruleset using sudo.
* Saves deployed version with timestamp.
* Logs all deployment actions.

### 📚 Version Management

* Versions appear in the right panel.
* Each entry has **Load** and **Delete** buttons.
* Stored in `policies_customtk.db`.

### 📝 Audit Logging

See all actions in the audit panel:

* Saved policies
* Deleted policies
* Dry-runs
* Simulations
* Deployments

---

## Troubleshooting

### If the application shows errors or fails to run:

1. Use the ZIP-packed release version.
2. Extract all files.
3. Run the executable:

```bash
firewall_policy_engine.exe
```

4. If the database becomes corrupted, delete:

```
policies_customtk.db
```

It will be recreated automatically.

### Linux Issues

* Ensure `nftables` is installed:

```bash
sudo apt install nftables
```

* Confirm `sudo nft` works:

```bash
sudo nft list ruleset
```

* Run demo mode if you're unsure.

---

## Project Structure

```
.
├── app.py                  # Main GUI + logic
├── policies_customtk.db    # SQLite database (auto-created)
├── Firewall_Deployer_README.md
```

---

## How FPE Works Internally

### 1. nftables Integration

FPE interacts with nft using:

* dry-run mode
* simulate mode
* deployment mode

### 2. Safety Heuristic

Checks if:

* Global DROP/deny rules exist
* SSH port 22 has explicit ACCEPT
  Prevents accidental lockouts.

### 3. Versioning System

* Policies stored in SQLite
* Each version includes name, timestamp, content
* Actions written to audit table

### 4. Audit Log Engine

Every action is written with:

* Timestamp
* Policy ID
* Description

---

## Contribution

Contributions are welcome! You can help by:

* Improving safety checks
* Adding rule templates
* Enhancing UI features
* Adding import/export support
---

## License

This project is licensed under the **MIT License**.
