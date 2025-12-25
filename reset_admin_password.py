import json
from pathlib import Path
from werkzeug.security import generate_password_hash

NEW_PASSWORD = "Alepe2025"   # simple, sans caractères spéciaux

# Cherche le bon users.json (priorité à app/data/users.json)
candidates = []
for p in Path(".").rglob("users.json"):
    s = str(p).replace("\\", "/")
    if s.endswith("app/data/users.json"):
        candidates.insert(0, p)
    else:
        candidates.append(p)

if not candidates:
    raise SystemExit("Aucun users.json trouvé dans le projet.")

users_file = candidates[0]
users = json.loads(users_file.read_text(encoding="utf-8"))

found = False
for u in users:
    if u.get("username") == "admin":
        u["password_hash"] = generate_password_hash(NEW_PASSWORD, method="scrypt")
        u["is_active"] = True
        u["role"] = "admin"
        found = True
        break

if not found:
    users.append({
        "username": "admin",
        "password_hash": generate_password_hash(NEW_PASSWORD, method="scrypt"),
        "role": "admin",
        "full_name": "Administrateur",
        "contacts": "",
        "polling_station_code": None,
        "center_code": None,
        "is_active": True,
        "election_id": None
    })

users_file.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")

print("OK -> Fichier modifié:", users_file)
print("OK -> admin password =", NEW_PASSWORD)
