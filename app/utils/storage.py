import json
import os
from pathlib import Path
from filelock import FileLock

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
LOCK_PATH = DATA_DIR / ".data.lock"

def _lock() -> FileLock:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return FileLock(str(LOCK_PATH))

def load_json(filename: str, default):
    path = DATA_DIR / filename
    if not path.exists():
        return default
    with _lock():
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

def save_json(filename: str, data) -> None:
    path = DATA_DIR / filename
    tmp = DATA_DIR / (filename + ".tmp")
    with _lock():
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

def touch_last_update() -> None:
    meta = load_json("meta.json", default={})
    meta["last_update_utc"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    save_json("meta.json", meta)
