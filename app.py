# ==============================================================
#  Firewall Policy Engine (FPE)
#  Author: Mohammad Shahazaad Ahmed
#
#  LEGAL DISCLAIMER:
#  This software is provided for educational and research use only.
#  It is NOT intended for use on production environments or
#  unauthorized systems.
#
#  Any damage, misconfiguration, or security impact caused by
#  using this tool is solely the user's responsibility.
#
#  Proceed with caution.
# ==============================================================
import os
import sqlite3
import subprocess
import threading
import datetime
import sys
import argparse
import customtkinter as ctk
parser = argparse.ArgumentParser()
parser.add_argument("--demo", action="store_true", help="Run in demo mode (no sudo, simulate deploy).")
args = parser.parse_args()
DEMO_MODE = args.demo
class NFTManager:
    def __init__(self, nft_bin="nft", demo=False):
        self.nft_bin = nft_bin
        self.demo = demo

    def _run(self, args, input_text=None, use_sudo=False):
        if self.demo:
            if "-f" in args:
                return 0, "Simulated nft output (demo mode).", ""
            return 0, "Simulated list ruleset (demo mode).", ""
        cmd = []
        if use_sudo:
            cmd = ["sudo", self.nft_bin] + args
        else:
            cmd = [self.nft_bin] + args
        proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    def list_ruleset(self):
        rc, out, err = self._run(["list", "ruleset"])
        if rc != 0:
            raise RuntimeError(err.strip() or "unknown error listing ruleset")
        return out

    def dry_run(self, ruleset_text):
        rc, out, err = self._run(["-f", "-"], input_text=ruleset_text, use_sudo=False)
        return rc == 0, out if rc == 0 else err

    def apply_ruleset(self, ruleset_text):
        if self.demo:
            return True, "Demo-mode: deploy simulated (no changes)."
        rc, out, err = self._run(["-f", "-"], input_text=ruleset_text, use_sudo=True)
        return rc == 0, out if rc == 0 else err
class PolicyDB:
    def __init__(self, path="policies_customtk.db"):
        self.path = path
        self._ensure()

    def _ensure(self):
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            content TEXT,
            created_at TEXT
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            policy_id INTEGER,
            detail TEXT,
            created_at TEXT
        )""")
        self.conn.commit()

    def save_policy(self, name, content):
        cur = self.conn.cursor()
        now = datetime.datetime.utcnow().isoformat()
        cur.execute("INSERT INTO policies (name, content, created_at) VALUES (?, ?, ?)", (name, content, now))
        pid = cur.lastrowid
        cur.execute("INSERT INTO audit (action, policy_id, detail, created_at) VALUES (?, ?, ?, ?)",
                    ("save", pid, f"Saved policy '{name}'", now))
        self.conn.commit()
        return pid

    def list_policies(self, limit=200):
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, created_at FROM policies ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    def get_policy(self, pid):
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, content, created_at FROM policies WHERE id=?", (pid,))
        return cur.fetchone()

    def log_audit(self, action, policy_id, detail=""):
        cur = self.conn.cursor()
        now = datetime.datetime.utcnow().isoformat()
        cur.execute("INSERT INTO audit (action, policy_id, detail, created_at) VALUES (?, ?, ?, ?)", (action, policy_id, detail, now))
        self.conn.commit()

    def list_audit(self, limit=200):
        cur = self.conn.cursor()
        cur.execute("SELECT id, action, policy_id, detail, created_at FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

def check_ssh_safe(ruleset_text):
    lowered = ruleset_text.lower()
    if "policy drop" not in lowered and "policy deny" not in lowered:
        return True, "No global DROP policy detected — likely safe."
    if ("tcp dport 22 accept" in lowered or
        "tcp dport 22 ct state established,related accept" in lowered or
        ("tcp dport 22" in lowered and "accept" in lowered)):
        return True, "Found explicit accept for SSH port 22."
    if "ct state established,related accept" in lowered:
        return True, "Has 'ct state established,related accept' — established connections allowed."
    return False, "Global DROP/deny policy present and no explicit SSH accept detected. This may lock you out."

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self, manager, db):
        super().__init__()
        self.manager = manager
        self.db = db
        self.title("Firewall Deployer — CustomTkinter")
        self.geometry("1200x720")

        header = ctk.CTkFrame(self, height=80)
        header.pack(fill="x", padx=12, pady=(12,6))
        ctk.CTkLabel(header, text="Firewall Deployer", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=12)
        mode_label = "DEMO MODE" if self.manager.demo else "REAL MODE"
        ctk.CTkLabel(header, text=mode_label, fg_color=("gray20","gray30"), corner_radius=10, padx=10).pack(side="right", padx=12)

        content = ctk.CTkFrame(self)
        content.pack(fill="both", expand=True, padx=12, pady=6)

        left = ctk.CTkFrame(content)
        left.pack(side="left", fill="both", expand=True, padx=(6,6), pady=6)

        ctk.CTkLabel(left, text="Ruleset Editor").pack(anchor="w", padx=6, pady=(6,0))
        self.editor = ctk.CTkTextbox(left, width=1)  # fills container
        sample = (
            "# Sample nftables ruleset\n"
            "table inet filter {\n"
            "  chain input {\n"
            "    type filter hook input priority 0;\n"
            "    policy drop;\n"
            "    ct state established,related accept\n"
            "    iif lo accept\n"
            "    tcp dport 22 accept\n"
            "  }\n"
            "}\n"
        )
        self.editor.insert("0.0", sample)
        self.editor.pack(fill="both", expand=True, padx=6, pady=(4,6))

        btn_frame = ctk.CTkFrame(left, height=44)
        btn_frame.pack(fill="x", padx=6, pady=(0,6))
        ctk.CTkButton(btn_frame, text="Save Version", command=self.save_version, width=120).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(btn_frame, text="Dry Run", command=self.on_dry_run, width=100).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Simulate", command=self.on_simulate, width=100).pack(side="left", padx=6)
        self.deploy_btn = ctk.CTkButton(btn_frame, text="Deploy", command=self.on_deploy, fg_color="red", width=100)
        self.deploy_btn.pack(side="right", padx=6)

        center = ctk.CTkFrame(content, width=420)
        center.pack(side="left", fill="both", padx=(6,6), pady=6, expand=False)

        ctk.CTkLabel(center, text="Preview / Current ruleset").pack(anchor="w", padx=6, pady=(6,0))
        self.preview = ctk.CTkTextbox(center)
        self.preview.configure(state="normal")
        self.preview.insert("0.0", self.editor.get("0.0", "end"))
        self.preview.configure(state="disabled")
        self.preview.pack(fill="both", expand=True, padx=6, pady=(4,6))

        ctk.CTkLabel(center, text="Audit Log").pack(anchor="w", padx=6)
        self.audit = ctk.CTkTextbox(center, height=160)
        self.audit.configure(state="disabled")
        self.audit.pack(fill="both", padx=6, pady=(4,6))

        right = ctk.CTkFrame(content, width=300)
        right.pack(side="right", fill="y", padx=(6,12), pady=6)

        ctk.CTkLabel(right, text="Saved Versions").pack(anchor="w", padx=6, pady=(6,0))
        self.tree = ctk.CTkScrollableFrame(right)
        self.tree.pack(fill="both", expand=True, padx=6, pady=(4,6))
        self._load_version_buttons()

        status = ctk.CTkFrame(self, height=28)
        status.pack(fill="x", side="bottom")
        self.status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(status, textvariable=self.status_var, anchor="w").pack(side="left", padx=8)

        self.editor.bind("<<Modified>>", self._on_edit_modified)

        self._refresh_audit_log()

    def _set_status(self, text):
        self.status_var.set(text)
        self.update_idletasks()

    def _on_edit_modified(self, event=None):
        try:
            self.editor.edit_modified(False)
        except Exception:
            pass
        self.preview.configure(state="normal")
        self.preview.delete("0.0", "end")
        self.preview.insert("0.0", self.editor.get("0.0", "end"))
        self.preview.configure(state="disabled")

    def _load_version_buttons(self):
        for w in self.tree.winfo_children():
            w.destroy()
        rows = self.db.list_policies(limit=100)
        if not rows:
            ctk.CTkLabel(self.tree, text="(no saved versions)").pack(padx=6, pady=6)
            return
        for pid, name, created in rows:
            txt = f"{pid}: {name} ({created.split('T')[0]} {created.split('T')[1][:8]})"
            frame = ctk.CTkFrame(self.tree)
            frame.pack(fill="x", padx=6, pady=4)
            lbl = ctk.CTkLabel(frame, text=txt, anchor="w")
            lbl.pack(side="left", padx=6, fill="x", expand=True)
            ctk.CTkButton(frame, text="Load", width=60, command=lambda p=pid: self.load_policy(p)).pack(side="right", padx=4)
            ctk.CTkButton(frame, text="Del", width=50, command=lambda p=pid: self.delete_policy(p)).pack(side="right", padx=4)

    def _refresh_audit_log(self):
        rows = self.db.list_audit(limit=200)
        self.audit.configure(state="normal")
        self.audit.delete("0.0", "end")
        for id_, action, pid, detail, created in rows:
            self.audit.insert("0.0", f"[{created}] {action} pid={pid} {detail}\n" + self.audit.get("0.0", "end"))
        self.audit.configure(state="disabled")
    def save_version(self):
        content = self.editor.get("0.0", "end").strip()
        if not content:
            ctk.CTkMessagebox(title="Empty", message="Cannot save empty ruleset.") if hasattr(ctk, "CTkMessagebox") else messagebox.showwarning("Empty", "Cannot save empty ruleset.")
            return
        name = f"policy-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        pid = self.db.save_policy(name, content)
        self.db.log_audit("save_ui", pid, "Saved via CustomTk UI")
        self._set_status(f"Saved {pid}")
        self._load_version_buttons()
        self._refresh_audit_log()

    def load_policy(self, pid):
        rec = self.db.get_policy(pid)
        if not rec:
            messagebox.showerror("Not found", "Policy not found")
            return
        _, name, content, created = rec
        self.editor.delete("0.0", "end")
        self.editor.insert("0.0", content)
        self._set_status(f"Loaded {pid}")

    def delete_policy(self, pid):
        cur = self.db.conn.cursor()
        cur.execute("DELETE FROM policies WHERE id=?", (pid,))
        self.db.conn.commit()
        self.db.log_audit("delete_ui", pid, "Deleted via CustomTk UI")
        self._set_status(f"Deleted {pid}")
        self._load_version_buttons()
        self._refresh_audit_log()

    def on_simulate(self):
        content = self.editor.get("0.0", "end")
        safe, reason = check_ssh_safe(content)
        ok, out_err = self.manager.dry_run(content)
        msg = f"Safety: {'PASS' if safe else 'WARN'} — {reason}\n\nDry-run: {'OK' if ok else 'FAILED'}\n\n{out_err}"
        messagebox.showinfo("Simulation", msg)
        pid = self.db.save_policy("sim-" + datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S"), content)
        self.db.log_audit("simulate", pid, reason)
        self._refresh_audit_log()
        self._load_version_buttons()
        self._set_status("Simulation done")

    def on_dry_run(self):
        content = self.editor.get("0.0", "end")
        self._set_status("Running dry-run...")
        def job():
            try:
                ok, out_err = self.manager.dry_run(content)
            except Exception as e:
                ok = False
                out_err = str(e)
            self.after(0, lambda: self._after_dry_run(ok, out_err))
        threading.Thread(target=job, daemon=True).start()

    def _after_dry_run(self, ok, out_err):
        if ok:
            messagebox.showinfo("Dry-run", "Validation OK (nft parsed the ruleset).")
            self._set_status("Dry-run OK")
        else:
            messagebox.showerror("Dry-run failed", f"Validation failed:\n\n{out_err}")
            self._set_status("Dry-run failed")

    def on_deploy(self):
        content = self.editor.get("0.0", "end")
        safe, reason = check_ssh_safe(content)
        if not safe:
            if not messagebox.askyesno("Warning", f"Safety check warns:\n\n{reason}\n\nProceed?"):
                self._set_status("Deploy aborted (safety)")
                return
        if not messagebox.askyesno("Confirm", "This will apply the ruleset (may require sudo). Proceed?"):
            return
        self.deploy_btn.configure(state="disabled")
        self._set_status("Deploying...")
        def job():
            try:
                success, out_err = self.manager.apply_ruleset(content)
            except Exception as e:
                success = False
                out_err = str(e)
            self.after(0, lambda: self._after_deploy(success, out_err, content))
        threading.Thread(target=job, daemon=True).start()

    def _after_deploy(self, success, out_err, content):
        self.deploy_btn.configure(state="normal")
        if success:
            messagebox.showinfo("Deployed", "Ruleset deployed.")
            pid = self.db.save_policy("deployed-" + datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S"), content)
            self.db.log_audit("deploy", pid, "Deployed via CustomTk UI")
            self._set_status("Deployed ✔")
        else:
            messagebox.showerror("Deploy failed", f"Deploy failed:\n\n{out_err}")
            self.db.log_audit("deploy_failed", None, out_err)
            self._set_status("Deploy failed")
        self._refresh_audit_log()
        self._load_version_buttons()

def main():
    manager = NFTManager(demo=DEMO_MODE)
    db = PolicyDB()
    app = App(manager, db)
    app.mainloop()

if __name__ == "__main__":

    main()

