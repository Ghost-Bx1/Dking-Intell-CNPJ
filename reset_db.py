"""
Execute este script para apagar o banco antigo e recriar do zero.
  python reset_db.py
"""
import os, glob

for f in glob.glob("*.db") + glob.glob("instance/*.db"):
    os.remove(f)
    print(f"[OK] Removido: {f}")

print("\n[OK] Banco resetado.")
print("[OK] Execute: python app.py")
print("[OK] Login:   admin / Admin@1234")