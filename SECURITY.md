# Security Policy

## 📌 Supported Versions

The **SSA (Supra Security Agent)** repository is under active development.

Only the **latest `main` branch** is supported for security updates.

| Version | Supported |
|-------|-----------|
| main  | ✅ Yes    |
| older commits | ❌ No |

---

## 🔐 Reporting a Vulnerability

If you discover a **security vulnerability** in SSA, please **do not open a public GitHub issue**.

Instead, report it responsibly using one of the following channels:

### Preferred
📧 **Email:** security@supravault.io  
(If unavailable, contact the Supra Vault team via official channels.)

### What to include
Please provide as much detail as possible:
- Affected file(s) or module(s)
- Type of vulnerability (e.g. injection, access bypass, logic flaw)
- Steps to reproduce
- Proof-of-concept (if available)
- Impact assessment (what could go wrong)

---

## 🕒 Response Timeline

We aim to:
- Acknowledge reports within **48 hours**
- Provide a remediation plan or status update within **5–7 days**
- Release fixes as soon as reasonably possible

Critical issues may be patched immediately without prior notice.

---

## 🛡️ Scope

### In scope
- SSA scanner logic
- CLI tooling
- View allowlist enforcement
- PDF report generation
- RPC interaction layers
- Server-side API endpoints

### Out of scope
- Third-party infrastructure (Supra RPC, SupraScan, external indexers)
- Misconfiguration of user-deployed environments
- Denial-of-service via excessive RPC usage
- Issues requiring private keys or credentials

---

## ⚠️ Disclaimer

SSA is a **security analysis and reporting tool**.  
It does **not** guarantee correctness, safety, or absence of vulnerabilities in any analyzed project.

Reports are informational and should not be interpreted as:
- Financial advice
- Endorsement
- Formal security certification

---

## 🧠 Responsible Disclosure

We strongly encourage responsible disclosure and will credit researchers who report issues ethically, unless anonymity is requested.

Thank you for helping keep the Supra ecosystem safer.

— **Supra Vault / SSA Team**
