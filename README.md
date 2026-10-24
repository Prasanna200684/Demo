# TrustVault — Secure sharing, Smarter Access, Verifiable Accountability

> **A secure, multi-tenant document-sharing platform that enables organizations to upload, share, and manage confidential documents with strict 3-tier Role-Based Access Control (RBAC) and verifiable audit trails.**

---

## 🌟 Key Features

1. **Strict 3-Tier Role-Based Access Control (RBAC):**
   - **Admin:** Executive dashboard, global document oversight, user administration, and system-wide activity logs.
   - **Document Owner:** Complete ownership over uploaded documents. Can grant/revoke viewer and editor permissions and permanently delete their own files.
   - **Viewer:** Restricted read/download privileges strictly limited to files shared with them. Prevented from modifying access or viewing audit logs.

2. **Executive Admin Dashboard:**
   - Real-time metrics: Total documents uploaded, registered users, documents sharing, records shared.
   - Live Security Status: AES-256 encryption ready, strict RBAC policy active, audit trail integrity checked.
   - Live security feed and registered users breakdown.

3. **Confidential Document Repository ("My Documents"):**
   - Tabular separation of "My Uploaded Documents" and "Documents Shared With Me".
   - Download, preview metadata, grant/revoke permissions, and secure deletion.

4. **Multi-Filter Document Search:**
   - Filter by document title/keyword, category classification, owner, and date range.

5. **Document Categories:**
   - Pre-configured departments: Legal & Compliance, Financial Reports, Executive & Board, Engineering & Tech, Human Resources, and Confidential & Top Secret.

6. **Tamper-Evident Activity Logs (Admin Only):**
   - Immutable audit logging for `LOGIN`, `LOGOUT`, `REGISTER`, `UPLOAD`, `DOWNLOAD`, `DELETE`, `SHARE_GRANTED`, `SHARE_REVOKED`, and `ACCESS_DENIED`.

7. **Profile & Security Settings:**
   - Profile avatar upload and secure password change.

8. **Aesthetic & Responsive Design:**
   - Custom **Black & Emerald Green** corporate cybersecurity dark theme (no mismatched colors).
   - Fully responsive for mobile viewports with an animated slide-in drawer and mobile-friendly tables.

---

## ⚡ Demo Quick-Start Credentials

When running the application, the database is automatically seeded with demo accounts for testing all three roles:

| Role | Username | Password | Access Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | Executive dashboard, all documents, user management, audit logs |
| **Document Owner** | `owner_sarah` | `owner123` | Uploads files, grants/revokes permissions on own files, deletes own files |
| **Viewer** | `viewer_alex` | `viewer123` | Can only view and download files shared with them |

---

## 🚀 How to Run It

### Windows PowerShell:
```powershell
# 1. Open PowerShell and navigate to the project directory
cd "C:\Users\Prasanna\.gemini\antigravity\scratch\trustvault"

# 2. Run the application
python run.py
```

### Browser:
Open your browser and navigate to:  
👉 **`http://127.0.0.1:5000/`**

---

## 🛠️ Technology Stack
- **Backend:** Python 3.11, Flask 3.1, Flask-SQLAlchemy, Werkzeug
- **Database:** SQLite (`trustvault.db`)
- **Frontend:** HTML5, Modern CSS3 (CSS Variables, Flexbox, Grid), Vanilla JavaScript
- **Theme:** Obsidian Black (`#070a08`) & Emerald Green (`#10b981`)
