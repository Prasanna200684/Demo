"""
TrustVault Runner
Secure sharing, Smarter Access, Verifiable Accountability
"""
import sys
from app import app, seed_database

if __name__ == '__main__':
    print("=" * 60)
    print("  🛡️  TRUSTVAULT — SECURE DOCUMENT SHARING PLATFORM")
    print("  Role-Based Access Control (Admin, Owner, Viewer)")
    print("=" * 60)
    print("  [+] Initializing database and verifying security tables...")
    seed_database()
    print("  [+] Seed accounts available:")
    print("      • Admin:  admin       / admin123")
    print("      • Owner:  owner_sarah / owner123")
    print("      • Viewer: viewer_alex / viewer123")
    print("  [+] Starting TrustVault server on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)
