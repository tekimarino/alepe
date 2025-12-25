from __future__ import annotations

import os
import json
import uuid
import secrets
import shutil
import zipfile
import unicodedata
from pathlib import Path
from datetime import datetime, timezone, timedelta, date
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

import io

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_file,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ----------------------------
# Pagination helper
# ----------------------------

def _paginate(items: List[Any], page: int, per_page: int) -> Dict[str, Any]:
    """Return a slice + metadata. Page is 1-indexed."""
    if per_page <= 0:
        per_page = 10
    try:
        page = int(page)
    except Exception:
        page = 1
    if page < 1:
        page = 1

    total = len(items)
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page
    return {
        "items": items[start:end],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
    }


# ----------------------------
# Configuration
# ----------------------------
APP_NAME = "Recensement Électoral 2028"
APP_VERSION = "10.14"  # cache-busting CSS + UI version

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
ZONES_FILE = os.path.join(DATA_DIR, "zones.json")
REG_FILE = os.path.join(DATA_DIR, "registrations.json")

CENTERS_FILE = os.path.join(DATA_DIR, "centers.json")
OBJECTIVES_FILE = os.path.join(DATA_DIR, "objectives.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
APPROVALS_QUEUE_FILE = os.path.join(DATA_DIR, "approvals_queue.json")
# Alias rétro-compatibilité (anciens patches)
APPROVAL_QUEUE_FILE = APPROVALS_QUEUE_FILE
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")

PAYROLL_FILE = os.path.join(DATA_DIR, "payroll.json")
PAY_RATE_CFA = 500


def _pay_rate_cfa() -> int:
    """Read pay rate from settings (fallback to default constant)."""
    s = _get_settings()
    try:
        v = int(s.get("pay_rate", PAY_RATE_CFA))
        return v if v >= 0 else PAY_RATE_CFA
    except Exception:
        return PAY_RATE_CFA


def _pay_period_days() -> int:
    """Read pay period (in days) from settings (fallback to default constant)."""
    s = _get_settings()
    try:
        v = int(s.get("pay_period_days", PAY_PERIOD_DAYS))
        return v if v > 0 else PAY_PERIOD_DAYS
    except Exception:
        return PAY_PERIOD_DAYS
PAY_PERIOD_DAYS = 14

SMS_CONFIG_FILE = os.path.join(DATA_DIR, "sms_config.json")
SMS_CAMPAIGNS_FILE = os.path.join(DATA_DIR, "sms_campaigns.json")
SMS_OUTBOX_FILE = os.path.join(DATA_DIR, "sms_outbox.json")
SMS_LOGS_FILE = os.path.join(DATA_DIR, "sms_logs.json")

DEFAULT_SECRET = "CHANGE-ME-SECRET-KEY-2028"
SECRET_KEY = os.environ.get("SECRET_KEY", DEFAULT_SECRET)

ALLOWED_UPLOAD_EXT = {".jpg", ".jpeg", ".png", ".pdf"}
MAX_UPLOAD_MB = 5

MAX_SMS_SEND_PER_REQUEST = 200  # sécurité: évite de bloquer le serveur

# Statuts dossiers
STATUS_DRAFT = "DRAFT"
STATUS_PENDING = "PENDING"
STATUS_NEEDS_CORRECTION = "NEEDS_CORRECTION"
STATUS_VERIFIED = "VERIFIED"  # validé par superviseur
STATUS_APPROVED = "APPROVED"  # approuvé par admin (si double validation)
STATUS_REJECTED = "REJECTED"


STATUS_PAID = "PAID"  # utilisé par le module de paie / historique
STATUS_PENDING_REVIEW = "PENDING_REVIEW"  # alias legacy
app = Flask(__name__)
app.secret_key = SECRET_KEY


# ----------------------------
# Jinja filters
# ----------------------------

@app.template_filter("format_cfa")
def _jinja_format_cfa(value):
    """Format int as '150 000 F CFA'."""
    try:
        x = int(round(float(value)))
    except Exception:
        x = 0
    return f"{x:,}".replace(",", " " ) + " F CFA"


@app.template_filter("prettyjson")
def _jinja_prettyjson(value):
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)



# ----------------------------
# Small JSON storage helpers (no database)
# ----------------------------

def _load_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def _atomic_write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def _save_json(path: str, data: Any) -> None:
    _atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_bool(value: Any, default: bool = False) -> bool:
    """Normalize a value (from form/json) into a strict boolean."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on", "oui", "vrai"):
        return True
    if s in ("0", "false", "no", "n", "off", "non", "faux"):
        return False
    return default


def _ensure_data_files() -> None:
    """Create missing files ONLY. Never overwrite existing data."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(BACKUPS_DIR, exist_ok=True)

    if not os.path.exists(ZONES_FILE):
        zones = [
            {"id": str(uuid.uuid4()), "name": "Adiaho", "active": True},
            {"id": str(uuid.uuid4()), "name": "Kodjoboue", "active": True},
            {"id": str(uuid.uuid4()), "name": "Résidentiel", "active": True},
            {"id": str(uuid.uuid4()), "name": "Samo est", "active": True},
            {"id": str(uuid.uuid4()), "name": "Samo ouest", "active": True},
            {"id": str(uuid.uuid4()), "name": "Begneri", "active": True},
            {"id": str(uuid.uuid4()), "name": "Koumassi", "active": True},
            {"id": str(uuid.uuid4()), "name": "Bronoukro", "active": True},
            {"id": str(uuid.uuid4()), "name": "Yaou ancien quartier", "active": True},
            {"id": str(uuid.uuid4()), "name": "Yaou nouveau quarier", "active": True},
            {"id": str(uuid.uuid4()), "name": "Yaou Ekressinville", "active": True},
        ]
        _save_json(ZONES_FILE, zones)

    if not os.path.exists(USERS_FILE):
        zones = _load_json(ZONES_FILE, [])
        zone_id = zones[0]["id"] if zones else None
        users = [
            {
                "id": str(uuid.uuid4()),
                "username": "admin",
                "full_name": "Administrateur",
                "role": "admin",
                "zone_id": None,
                "supervisor_id": None,
                "password_hash": generate_password_hash("Admin2028@"),
                "created_at": _now_iso(),
                "is_active": True,
            },
            {
                "id": str(uuid.uuid4()),
                "username": "sup_adiaho",
                "full_name": "Superviseur Adiaho",
                "role": "supervisor",
                "zone_id": zone_id,
                "supervisor_id": None,
                "password_hash": generate_password_hash("Sup2028@"),
                "created_at": _now_iso(),
                "is_active": True,
            },
        ]
        sup_id = users[1]["id"]
        users.append(
            {
                "id": str(uuid.uuid4()),
                "username": "agent_01",
                "full_name": "Agent Recenseur 01",
                "role": "agent",
                "zone_id": zone_id,
                "supervisor_id": sup_id,
                "password_hash": generate_password_hash("Agent2028@"),
                "created_at": _now_iso(),
                "is_active": True,
            }
        )
        _save_json(USERS_FILE, users)

    if not os.path.exists(REG_FILE):
        _save_json(REG_FILE, [])

    if not os.path.exists(CENTERS_FILE):
        # { zone_id: [ {"id":..., "name":..., "bureaux": ["BV01", ...]} ] }
        _save_json(CENTERS_FILE, {})

    if not os.path.exists(OBJECTIVES_FILE):
        # { zone_id: {"target": 0} }
        _save_json(OBJECTIVES_FILE, {})

    if not os.path.exists(SETTINGS_FILE):
        _save_json(SETTINGS_FILE, {"double_approval": True})

    if not os.path.exists(AUDIT_FILE):
        _save_json(AUDIT_FILE, [])

    if not os.path.exists(PAYROLL_FILE):
        _save_json(PAYROLL_FILE, [])

    if not os.path.exists(SMS_CONFIG_FILE):
        _save_json(
            SMS_CONFIG_FILE,
            {
                "mode": "dry_run",
                "sender_id": "Elections2028",
                "http_json": {
                    "url": "",
                    "token": "",
                    "to_field": "to",
                    "message_field": "message",
                    "sender_field": "sender",
                },
            },
        )

    if not os.path.exists(SMS_CAMPAIGNS_FILE):
        _save_json(SMS_CAMPAIGNS_FILE, [])

    if not os.path.exists(SMS_OUTBOX_FILE):
        _save_json(SMS_OUTBOX_FILE, [])

    if not os.path.exists(SMS_LOGS_FILE):
        _save_json(SMS_LOGS_FILE, [])


    # Approvals queue file (ids waiting for admin final approval)
    if not os.path.exists(APPROVALS_QUEUE_FILE):
        _save_json(APPROVALS_QUEUE_FILE, [])

# ----------------------------
# Domain helpers
# ----------------------------

def _get_settings() -> Dict[str, Any]:
    s = _load_json(SETTINGS_FILE, {})
    if not isinstance(s, dict):
        s = {}

    changed = False

    # Backward-compat: some older builds used "double_validation".
    if "double_approval" not in s and "double_validation" in s:
        s["double_approval"] = _norm_bool(s.get("double_validation"))
        changed = True

    # Defaults (never overwrite existing values)
    if "double_approval" not in s:
        s["double_approval"] = True
        changed = True
    s.setdefault("pay_rate", PAY_RATE_CFA)
    s.setdefault("pay_period_days", PAY_PERIOD_DAYS)

    # Normalize double_approval to a real boolean (handles strings like "false")
    s["double_approval"] = _norm_bool(s.get("double_approval"))

    # Normalize types
    try:
        s["pay_rate"] = int(s.get("pay_rate", PAY_RATE_CFA) or PAY_RATE_CFA)
    except Exception:
        s["pay_rate"] = PAY_RATE_CFA
    try:
        s["pay_period_days"] = int(s.get("pay_period_days", PAY_PERIOD_DAYS) or PAY_PERIOD_DAYS)
    except Exception:
        s["pay_period_days"] = PAY_PERIOD_DAYS

    if changed:
        _save_settings(s)

    return s


def _get_approval_queue() -> List[str]:
    q = _load_json(APPROVALS_QUEUE_FILE, [])
    if not isinstance(q, list):
        return []
    out: List[str] = []
    seen = set()
    for x in q:
        if x is None:
            continue
        sid = str(x).strip()
        if not sid or sid in seen:
            continue
        seen.add(sid)
        out.append(sid)
    return out


def _save_approval_queue(q: List[str]) -> None:
    # Keep it simple and atomic
    _save_json(APPROVALS_QUEUE_FILE, q)


def _queue_for_admin(reg_id: str) -> None:
    reg_id = str(reg_id).strip()
    if not reg_id:
        return
    q = _get_approval_queue()
    if reg_id not in q:
        q.append(reg_id)
        _save_approval_queue(q)


def _dequeue_for_admin(reg_id: str) -> None:
    reg_id = str(reg_id).strip()
    if not reg_id:
        return
    q = _get_approval_queue()
    if reg_id in q:
        q = [x for x in q if x != reg_id]
        _save_approval_queue(q)


def _save_settings(s: Dict[str, Any]) -> None:
    _save_json(SETTINGS_FILE, s)


def _get_centers_map() -> Dict[str, Any]:
    m = _load_json(CENTERS_FILE, {})
    return m if isinstance(m, dict) else {}


def _save_centers_map(m: Dict[str, Any]) -> None:
    _save_json(CENTERS_FILE, m)


def _get_objectives_map() -> Dict[str, Any]:
    m = _load_json(OBJECTIVES_FILE, {})
    return m if isinstance(m, dict) else {}


def _save_objectives_map(m: Dict[str, Any]) -> None:
    _save_json(OBJECTIVES_FILE, m)


def _audit(action: str, actor_id: str, target_type: str, target_id: str, details: Optional[Dict[str, Any]] = None) -> None:
    try:
        log = _load_json(AUDIT_FILE, [])
        if not isinstance(log, list):
            log = []
        log.append(
            {
                "id": str(uuid.uuid4()),
                "at": _now_iso(),
                "action": action,
                "actor_id": actor_id,
                "target_type": target_type,
                "target_id": target_id,
                "details": details or {},
            }
        )
        # keep audit file reasonable
        if len(log) > 20000:
            log = log[-20000:]
        _save_json(AUDIT_FILE, log)
    except Exception:
        # audit must never crash the app
        pass


# ----------------------------
# Auth + users
# ----------------------------

def _get_users() -> List[Dict[str, Any]]:
    data = _load_json(USERS_FILE, [])
    return data if isinstance(data, list) else []


def _save_users(users: List[Dict[str, Any]]) -> None:
    _save_json(USERS_FILE, users)


def _find_user(user_id: str) -> Optional[Dict[str, Any]]:
    for u in _get_users():
        if u.get("id") == user_id:
            return u
    return None


def _get_zones() -> List[Dict[str, Any]]:
    data = _load_json(ZONES_FILE, [])
    return data if isinstance(data, list) else []


def _save_zones(zones: List[Dict[str, Any]]) -> None:
    _save_json(ZONES_FILE, zones)


def _zone_name(zone_id: Optional[str]) -> str:
    if not zone_id:
        return "-"
    for z in _get_zones():
        if z.get("id") == zone_id:
            return z.get("name") or "-"
    return "Zone inconnue"


# ----------------------------
# Registrations
# ----------------------------

def _canon_status(value: Any) -> str:
    """Normalize historical / user-provided status values to canonical internal constants.

    This makes the app resilient to older French labels (e.g., "Vérifié") or
    accidental casing/spaces.
    """

    if value is None:
        return STATUS_PENDING

    s = str(value).strip()
    if not s:
        return STATUS_PENDING

    # Upper + remove accents for robust matching (Vérifié -> VERIFIE)
    s_norm = unicodedata.normalize("NFKD", s)
    s_norm = "".join(ch for ch in s_norm if not unicodedata.combining(ch))
    u = s_norm.strip().upper()

    # Common synonyms / legacy values
    if u in {"DRAFT", "BROUILLON"}:
        return STATUS_DRAFT
    if u in {"PENDING", "EN ATTENTE", "EN_ATTENTE", "A TRAITER", "A_TRAITER"}:
        return STATUS_PENDING
    if u in {"NEEDS_CORRECTION", "A CORRIGER", "A_CORRIGER", "CORRECTION"}:
        return STATUS_NEEDS_CORRECTION
    if u in {"REJECTED", "REJETE", "REJETE", "REFUSE", "REFUSE"}:
        return STATUS_REJECTED
    # "VALIDATED/VALIDE" are legacy labels often used for supervisor verification.
    if u in {"VERIFIED", "VERIFIE", "VALIDATED", "VALIDE"}:
        return STATUS_VERIFIED
    if u in {"APPROVED", "APPROUVE"}:
        return STATUS_APPROVED
    if u in {"PAID", "PAYE", "PAYE"}:
        return STATUS_PAID

    # Unknown: keep normalized version (without leading/trailing spaces)
    return u


def _needs_admin_approval_flag(r: Dict[str, Any]) -> bool:
    """Retourne True si un dossier est marqué comme nécessitant l'approbation admin.

    On supporte plusieurs clés (historique/patched versions) pour éviter que
    l'écran "Approbations" reste vide après une validation superviseur.
    """
    if not isinstance(r, dict):
        return False

    keys = [
        "needs_admin_approval",
        "need_admin_approval",
        "needs_admin_approvals",
        "awaiting_admin_approval",
        "awaiting_admin",
        "admin_pending_approval",
        "pending_admin_approval",
        "requires_admin_approval",
        "approval_pending",
    ]
    return any(_norm_bool(r.get(k)) for k in keys)

def _normalize_reg(r: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    changed = False
    def _setdefault(k: str, v: Any) -> None:
        nonlocal changed
        if k not in r:
            r[k] = v
            changed = True

    _setdefault("telephone", "")
    _setdefault("polling_center", "")
    _setdefault("polling_station", "")
    _setdefault("status", STATUS_PENDING)
    # Canonicalize status to avoid missing items in lists (approvals, etc.)
    canon = _canon_status(r.get("status"))
    if r.get("status") != canon:
        r["status"] = canon
        changed = True
    _setdefault("notes", "")
    _setdefault("qc_notes", "")
    _setdefault("correction_reason", "")
    # Double-validation fields (safe defaults for older data)
    _setdefault("verified_by", "")
    _setdefault("verified_at", "")
    _setdefault("supervisor_verified", False)
    _setdefault("supervisor_verified_by", "")
    _setdefault("supervisor_verified_at", "")
    _setdefault("supervisor_status", "")
    _setdefault("supervisor_review", "")
    # Drapeau canonique (et compat) "en attente d'approbation admin"
    _setdefault("needs_admin_approval", False)
    # Récupère le drapeau si une ancienne clé existe
    na = _needs_admin_approval_flag(r)
    if r.get("needs_admin_approval") != na:
        r["needs_admin_approval"] = na
        changed = True
    _setdefault("admin_approved_by", "")
    _setdefault("admin_approved_at", "")
    # Normalise admin_approved en bool
    aa = _norm_bool(r.get("admin_approved"))
    if r.get("admin_approved") != aa:
        r["admin_approved"] = aa
        changed = True
    _setdefault("approved_by", "")
    _setdefault("approved_at", "")
    _setdefault("updated_by", "")
    _setdefault("updated_at", "")
    _setdefault("photos", [])
    _setdefault("sms_last_at", "")
    return r, changed


def _get_regs() -> List[Dict[str, Any]]:
    regs = _load_json(REG_FILE, [])
    if not isinstance(regs, list):
        return []
    changed = False
    out: List[Dict[str, Any]] = []
    for r in regs:
        if not isinstance(r, dict):
            continue
        rr, ch = _normalize_reg(r)
        out.append(rr)
        changed = changed or ch
    if changed:
        _save_json(REG_FILE, out)
    return out


def _save_regs(regs: List[Dict[str, Any]]) -> None:
    _save_json(REG_FILE, regs)


def _norm_text(s: str) -> str:
    return (s or "").strip().lower()


def _find_duplicates(nom: str, prenoms: str, dob: str, telephone: str, regs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nn = _norm_text(nom)
    pp = _norm_text(prenoms)
    dd = (dob or "").strip()
    tt = _norm_text(telephone)

    matches: List[Dict[str, Any]] = []
    for r in regs:
        if r.get("status") == STATUS_DRAFT:
            continue
        same_dob = (r.get("dob") or "").strip() == dd and bool(dd)
        same_phone = _norm_text(r.get("telephone") or "") == tt and bool(tt)
        same_name = _norm_text(r.get("nom") or "") == nn and _norm_text(r.get("prenoms") or "") == pp and bool(nn) and bool(pp)

        # strong duplicate if (same_name and same_dob) OR (same_phone and same_dob) OR (same_phone and same_name)
        if (same_name and same_dob) or (same_phone and same_dob) or (same_phone and same_name):
            matches.append(r)

    return matches[:10]


# ----------------------------
# Uploads (photos)
# ----------------------------

def _allowed_upload(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_UPLOAD_EXT


def _save_upload(file_storage) -> str:
    """Save upload and return stored filename (relative)."""
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise ValueError("Nom de fichier invalide")
    if not _allowed_upload(filename):
        raise ValueError("Format non autorisé (jpg, png, pdf)")

    # size check
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"Fichier trop volumineux (max {MAX_UPLOAD_MB} MB)")

    ext = os.path.splitext(filename)[1].lower()
    stored = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(UPLOADS_DIR, stored)
    file_storage.save(path)
    return stored


def _can_view_reg(u: Dict[str, Any], reg: Dict[str, Any]) -> bool:
    role = u.get("role")
    if role == "admin":
        return True
    if role == "supervisor":
        return reg.get("zone_id") == u.get("zone_id")
    if role == "agent":
        return reg.get("created_by") == u.get("id")
    return False


# ----------------------------
# Payroll (paiement agents, stockage JSON)
# ----------------------------

def _get_payroll() -> List[Dict[str, Any]]:
    items = _load_json(PAYROLL_FILE, [])
    if not isinstance(items, list):
        return []

    changed = False
    for it in items:
        if not isinstance(it, dict):
            continue

        # Backward-compatible inference for older data where `type` was missing.
        # We try to distinguish PAYSLIP vs ADVANCE using available fields.
        # - Payslips typically have: count/gross_amount/balance_amount OR generated_by/generated_at
        # - Advances typically have: notes == "Avance" OR created_by/created_at without generated_by
        if "type" not in it or not str(it.get("type") or "").strip():
            inferred = "PAYSLIP"
            notes = (it.get("notes") or "").strip().lower()
            if notes == "avance":
                inferred = "ADVANCE"
            elif ("generated_by" not in it) and ("count" not in it) and ("gross_amount" not in it) and ("balance_amount" not in it):
                # Most likely an advance-like record
                inferred = "ADVANCE" if ("created_by" in it or "created_at" in it) else "PAYSLIP"
            it["type"] = inferred
            changed = True

        # Normalize type casing
        it["type"] = (it.get("type") or "PAYSLIP").strip().upper()
        if it["type"] not in {"PAYSLIP", "ADVANCE"}:
            it["type"] = "PAYSLIP"
            changed = True

        if "payment_number" not in it:
            it["payment_number"] = it.get("id", "")
            changed = True

        # Normalize status casing
        st = (it.get("status") or "GENERATED").strip().upper()
        if not st:
            st = "GENERATED"
            changed = True

        # Safety: a record cannot be considered paid without paid_at + paid_by.
        # (This prevents accidental/malformed 'PAID' states from being treated as paid.)
        if st == "PAID" and (not (it.get("paid_at") or "").strip() or not (it.get("paid_by") or "").strip()):
            st = "GENERATED"
            changed = True
        it["status"] = st

        it.setdefault("paid_at", "")
        it.setdefault("paid_by", "")
        it.setdefault("notes", "")
        it.setdefault("is_locked", False)
        it.setdefault("locked_at", "")
        it.setdefault("advance_amount", 0)
        it.setdefault("gross_amount", int(it.get("amount", 0) or 0))
        it.setdefault("balance_amount", int(it.get("amount", 0) or 0))
        it.setdefault("created_at", it.get("generated_at", "") or _now_iso())

    if changed:
        _save_json(PAYROLL_FILE, items)
    return items


def _is_paid_payslip(rec: Optional[Dict[str, Any]]) -> bool:
    """Return True only when a payslip has been *explicitly* marked paid by an admin."""
    if not rec or not isinstance(rec, dict):
        return False
    if (rec.get("type") or "").strip().upper() != "PAYSLIP":
        return False
    st = (rec.get("status") or "").strip().upper()
    return st == "PAID" and bool((rec.get("paid_at") or "").strip()) and bool((rec.get("paid_by") or "").strip())


def _save_payroll(items: List[Dict[str, Any]]) -> None:
    _save_json(PAYROLL_FILE, items)


def _next_payment_number(items: List[Dict[str, Any]]) -> str:
    max_n = 0
    for it in items:
        pn = (it.get("payment_number") or "").strip().upper()
        if pn.startswith("PAY-"):
            try:
                n = int(pn.split("-")[-1])
                max_n = max(max_n, n)
            except Exception:
                continue
    return f"PAY-{max_n + 1:06d}"


def _dt_from_iso(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _periods_for_user(user_id: str, regs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_dts = [_dt_from_iso(r["created_at"]) for r in regs if r.get("created_at")]
    if not all_dts:
        return []

    mine = [r for r in regs if r.get("created_by") == user_id and r.get("created_at")]
    if not mine:
        return []

    anchor = min(all_dts).date()
    max_dt = max(_dt_from_iso(r["created_at"]) for r in mine)

    start = datetime(anchor.year, anchor.month, anchor.day, tzinfo=timezone.utc)
    periods: List[Dict[str, Any]] = []
    while start <= max_dt + timedelta(days=1):
        end = start + timedelta(days=_pay_period_days())
        periods.append({
            "start": start,
            "end": end,
            "start_iso": start.date().isoformat(),
            "end_iso": end.date().isoformat(),
        })
        start = end
    return periods


def _count_regs_in_period(user_id: str, regs: List[Dict[str, Any]], start: datetime, end: datetime) -> int:
    n = 0
    for r in regs:
        if r.get("created_by") != user_id:
            continue
        if r.get("status") == STATUS_DRAFT:
            continue
        ca = r.get("created_at") or ""
        if not ca:
            continue
        dt = _dt_from_iso(ca)
        if start <= dt < end:
            n += 1
    return n


def _sum_advances(user_id: str, items: List[Dict[str, Any]], start_iso: str, end_iso: str) -> int:
    """Sum advances for a given pay period.

    Important: in the UI, periods are displayed as inclusive end dates
    (end_exclusive - 1 day). Some previously saved advances therefore
    contain an inclusive period_end (YYYY-MM-DD) instead of the internal
    end_exclusive date used by pay periods.

    To avoid mismatches (and missing deductions), we accept BOTH forms.
    """
    total = 0
    try:
        end_inclusive = (date.fromisoformat(end_iso) - timedelta(days=1)).isoformat()
    except Exception:
        end_inclusive = ""

    for it in items:
        if it.get("type") != "ADVANCE":
            continue
        if it.get("user_id") != user_id:
            continue
        if it.get("period_start") != start_iso:
            continue

        pe = (it.get("period_end") or "").strip()
        # accept end_exclusive OR end_inclusive
        if pe == end_iso or (end_inclusive and pe == end_inclusive):
            total += int(it.get("amount", 0) or 0)

    return total


def _find_payslip(user_id: str, start_iso: str, end_iso: str, items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Find a payslip for a user and period.

    We accept both internal end_exclusive (YYYY-MM-DD) and legacy end_inclusive
    values in stored data (YYYY-MM-DD = end_exclusive - 1 day).
    """
    try:
        end_inclusive = (date.fromisoformat(end_iso) - timedelta(days=1)).isoformat()
    except Exception:
        end_inclusive = ""

    for it in items:
        if (it.get("user_id") != user_id):
            continue
        if (it.get("period_start") or "") != start_iso:
            continue
        pe = (it.get("period_end") or "")
        if not (pe == end_iso or (end_inclusive and pe == end_inclusive)):
            continue
        if (it.get("type") or "").strip().upper() != "PAYSLIP":
            continue
        return it
    return None


def _calc_amount(count: int) -> int:
    return int(count) * int(_pay_rate_cfa())


def _format_money_cfa(x: int) -> str:
    s = f"{int(x):,}".replace(",", " ")
    return f"{s} F CFA"


def _period_label(start_iso: str, end_iso: str) -> str:
    try:
        s = date.fromisoformat(start_iso)
        e = date.fromisoformat(end_iso) - timedelta(days=1)
        return f"{s.strftime('%d/%m/%Y')} → {e.strftime('%d/%m/%Y')}"
    except Exception:
        return f"{start_iso} → {end_iso}"


# ----------------------------
# SMS
# ----------------------------

def _get_sms_config() -> Dict[str, Any]:
    return _load_json(
        SMS_CONFIG_FILE,
        {
            "mode": "dry_run",
            "sender_id": "Elections2028",
            "http_json": {"url": "", "token": "", "to_field": "to", "message_field": "message", "sender_field": "sender"},
        },
    )


def _save_sms_config(cfg: Dict[str, Any]) -> None:
    _save_json(SMS_CONFIG_FILE, cfg)


def _get_sms_campaigns() -> List[Dict[str, Any]]:
    data = _load_json(SMS_CAMPAIGNS_FILE, [])
    return data if isinstance(data, list) else []


def _save_sms_campaigns(camps: List[Dict[str, Any]]) -> None:
    _save_json(SMS_CAMPAIGNS_FILE, camps)


def _get_sms_outbox() -> List[Dict[str, Any]]:
    data = _load_json(SMS_OUTBOX_FILE, [])
    return data if isinstance(data, list) else []


def _save_sms_outbox(outbox: List[Dict[str, Any]]) -> None:
    _save_json(SMS_OUTBOX_FILE, outbox)


def _get_sms_logs() -> List[Dict[str, Any]]:
    data = _load_json(SMS_LOGS_FILE, [])
    return data if isinstance(data, list) else []


def _save_sms_logs(logs: List[Dict[str, Any]]) -> None:
    _save_json(SMS_LOGS_FILE, logs)


def _http_json_send(url: str, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    import urllib.request
    import urllib.error

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return {"ok": True, "status": resp.status, "body": body[:500]}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = str(e)
        return {"ok": False, "status": getattr(e, "code", 0), "body": body[:500]}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)[:500]}


def _send_sms(to_phone: str, message: str) -> Dict[str, Any]:
    cfg = _get_sms_config()
    mode = (cfg.get("mode") or "dry_run").lower()

    if mode == "http_json":
        http_cfg = cfg.get("http_json") or {}
        url = (http_cfg.get("url") or "").strip()
        if not url:
            return {"ok": False, "status": 0, "body": "sms_config.json: http_json.url vide"}
        token = (http_cfg.get("token") or "").strip()
        to_field = http_cfg.get("to_field") or "to"
        msg_field = http_cfg.get("message_field") or "message"
        sender_field = http_cfg.get("sender_field") or "sender"
        payload = {
            to_field: to_phone,
            msg_field: message,
            sender_field: cfg.get("sender_id") or "",
        }
        return _http_json_send(url, token, payload)

    return {"ok": True, "status": 0, "body": "DRY_RUN (aucun SMS envoyé)"}


def _process_due_campaigns(actor_id: str) -> None:
    """Process scheduled campaigns (best-effort). Called on admin/supervisor SMS pages."""
    now = datetime.now(timezone.utc)
    camps = _get_sms_campaigns()
    if not camps:
        return

    regs = _get_regs()
    logs = _get_sms_logs()

    changed = False
    sent_this_request = 0

    for c in camps:
        if sent_this_request >= MAX_SMS_SEND_PER_REQUEST:
            break
        if c.get("status") in ("DONE", "CANCELLED"):
            continue
        sched = (c.get("scheduled_at") or "").strip()
        if not sched:
            continue
        try:
            sched_dt = _dt_from_iso(sched)
        except Exception:
            continue
        if sched_dt > now:
            continue

        # Ready to send (or resume)
        c.setdefault("sent_count", 0)
        c.setdefault("total_count", 0)
        c.setdefault("status", "SCHEDULED")

        # Build targets from campaign filters
        zone_id = (c.get("zone_id") or "").strip()
        center = (c.get("polling_center") or "").strip()
        status_filter = (c.get("status_filter") or "").strip()  # APPROVED/VERIFIED/PENDING etc
        only_missing_voter = bool(c.get("only_missing_voter"))

        targets = []
        for r in regs:
            if zone_id and r.get("zone_id") != zone_id:
                continue
            if center and (r.get("polling_center") or "") != center:
                continue
            if status_filter and r.get("status") != status_filter:
                continue
            if only_missing_voter and (r.get("voter_number") or "").strip():
                continue
            phone = (r.get("telephone") or "").strip()
            if not phone:
                continue
            targets.append(r)

        c["total_count"] = len(targets)
        msg = (c.get("message") or "").strip()
        if not msg:
            c["status"] = "FAILED"
            c["error"] = "Message vide"
            changed = True
            continue

        # resume at offset
        offset = int(c.get("sent_count", 0) or 0)
        remaining = targets[offset:]

        if not remaining:
            c["status"] = "DONE"
            c["finished_at"] = _now_iso()
            changed = True
            continue

        c["status"] = "SENDING"
        changed = True

        for r in remaining:
            if sent_this_request >= MAX_SMS_SEND_PER_REQUEST:
                break

            res = _send_sms((r.get("telephone") or "").strip(), msg)
            logs.append({
                "id": str(uuid.uuid4()),
                "at": _now_iso(),
                "campaign_id": c.get("id"),
                "reg_id": r.get("id"),
                "to": (r.get("telephone") or "").strip(),
                "message": msg,
                "ok": bool(res.get("ok")),
                "provider_status": res.get("status"),
                "provider_body": res.get("body"),
            })
            r["sms_last_at"] = _now_iso()
            c["sent_count"] = int(c.get("sent_count", 0) or 0) + 1
            sent_this_request += 1

        if c.get("sent_count", 0) >= c.get("total_count", 0):
            c["status"] = "DONE"
            c["finished_at"] = _now_iso()

    if changed:
        _save_sms_campaigns(camps)
        _save_sms_logs(logs)
        _save_regs(regs)
        _audit("sms.process_due", actor_id, "sms", "campaigns", {"sent": sent_this_request})


# ----------------------------
# Session helpers
# ----------------------------

def current_user() -> Optional[Dict[str, Any]]:
    uid = session.get("user_id")
    if not uid:
        return None
    for u in _get_users():
        if u.get("id") == uid and u.get("is_active", True):
            return u
    return None


def _is_admin() -> bool:
    """Compat helper: certaines routes utilisent _is_admin()."""
    u = current_user()
    return bool(u) and u.get("role") == "admin"



def _supervisor_mark(reg: dict, st: str | None = None) -> bool:
    # True si le superviseur a 'Vérifié' ce dossier
    if st is None:
        st = _canon_status(reg.get('status'))
    return bool(
        reg.get('supervisor_verified')
        or reg.get('supervisor_verified_at')
        or reg.get('verified_by')
        or reg.get('verified_at')
        or (reg.get('supervisor_status') == STATUS_VERIFIED)
        or (st == STATUS_VERIFIED)
    )

def _admin_done(reg: dict) -> bool:
    # True si l'admin a déjà pris une décision finale sur ce dossier
    st = _canon_status(reg.get('status'))
    if st in (STATUS_APPROVED, STATUS_REJECTED, STATUS_PAID):
        return True

    if _norm_bool(reg.get('admin_approved')):
        return True

    if reg.get('admin_approved_by') or reg.get('admin_approved_at'):
        return True
    if reg.get('admin_rejected_by') or reg.get('admin_rejected_at'):
        return True

    # legacy fields
    if reg.get('approved_by') or reg.get('approved_at'):
        return True
    if reg.get('rejected_by') or reg.get('rejected_at'):
        return True

    return False


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u.get("role") not in roles:
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ----------------------------
# CSRF (minimal)
# ----------------------------

def _csrf_get_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_validate() -> bool:
    form_token = request.form.get("csrf_token", "")
    return bool(form_token) and form_token == session.get("csrf_token")


@app.context_processor
def inject_globals():
    settings = _get_settings()
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "csrf_token": _csrf_get_token,
        "me": current_user(),
        "zones_map": {z["id"]: z for z in _get_zones()},
        "format_money_cfa": _format_money_cfa,
        "pay_rate_cfa": _pay_rate_cfa(),
        "period_label": _period_label,
        "double_approval": bool(settings.get("double_approval")),
        "STATUS": {
            "DRAFT": STATUS_DRAFT,
            "PENDING": STATUS_PENDING,
            "NEEDS_CORRECTION": STATUS_NEEDS_CORRECTION,
            "VERIFIED": STATUS_VERIFIED,
            "APPROVED": STATUS_APPROVED,
            "REJECTED": STATUS_REJECTED,
        },
    }


# ----------------------------
# Utility
# ----------------------------

def _format_date(d: str) -> str:
    if not d:
        return "—"
    try:
        return date.fromisoformat(d).strftime("%d/%m/%Y")
    except Exception:
        return d


def _safe_filename(name: str) -> str:
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "".join([c if c in keep else "_" for c in (name or "file")])


# ----------------------------
# Auth routes
# ----------------------------

@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if u.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if u.get("role") == "supervisor":
        return redirect(url_for("supervisor_dashboard"))
    if u.get("role") == "agent":
        return redirect(url_for("agent_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = (request.args.get("next") or request.form.get("next") or "").strip()

        for u in _get_users():
            if u.get("username") == username and u.get("is_active", True):
                if check_password_hash(u.get("password_hash", ""), password):
                    session["user_id"] = u["id"]
                    _csrf_get_token()
                    _audit("auth.login", u["id"], "user", u["id"], {})
                    flash("Connexion réussie.", "success")
                    if next_url:
                        return redirect(next_url)
                    return redirect(url_for("index"))

        flash("Identifiants invalides.", "danger")
        return render_template("login.html", next=next_url)

    return render_template("login.html", next=(request.args.get("next") or ""))


@app.route("/logout")
def logout():
    u = current_user()
    if u:
        _audit("auth.logout", u["id"], "user", u["id"], {})
    session.clear()
    flash("Déconnexion.", "success")
    return redirect(url_for("login"))


# ----------------------------
# Admin routes
# ----------------------------

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    users = _get_users()
    regs = _get_regs()
    zones = _get_zones()
    objectives = _get_objectives_map()

    counts = {
        "agents": sum(1 for u in users if u.get("role") == "agent"),
        "supervisors": sum(1 for u in users if u.get("role") == "supervisor"),
        "registrations": len(regs),
        "draft": sum(1 for r in regs if r.get("status") == STATUS_DRAFT),
        "pending": sum(1 for r in regs if r.get("status") == STATUS_PENDING),
        "needs_correction": sum(1 for r in regs if r.get("status") == STATUS_NEEDS_CORRECTION),
        "verified": sum(1 for r in regs if r.get("status") == STATUS_VERIFIED),
        "approved": sum(1 for r in regs if r.get("status") == STATUS_APPROVED),
        "rejected": sum(1 for r in regs if r.get("status") == STATUS_REJECTED),
    }

    # performance table by agent
    agents = [u for u in users if u.get("role") == "agent" and u.get("is_active", True)]
    perf = []
    for a in agents:
        mine = [r for r in regs if r.get("created_by") == a.get("id")]
        perf.append({
            "agent": a,
            "zone": _zone_name(a.get("zone_id")),
            "total": len(mine),
            "pending": sum(1 for r in mine if r.get("status") == STATUS_PENDING),
            "needs_correction": sum(1 for r in mine if r.get("status") == STATUS_NEEDS_CORRECTION),
            "verified": sum(1 for r in mine if r.get("status") == STATUS_VERIFIED),
            "approved": sum(1 for r in mine if r.get("status") == STATUS_APPROVED),
            "rejected": sum(1 for r in mine if r.get("status") == STATUS_REJECTED),
        })
    perf = sorted(perf, key=lambda x: x["total"], reverse=True)

    # zone progress vs objective
    zone_rows = []
    for z in zones:
        zid = z.get("id")
        total_zone = sum(1 for r in regs if r.get("zone_id") == zid and r.get("status") != STATUS_DRAFT)
        target = int((objectives.get(zid) or {}).get("target", 0) or 0)
        pct = 0
        if target > 0:
            pct = int((total_zone / target) * 100)
        zone_rows.append({"zone": z, "total": total_zone, "target": target, "pct": pct})

    zone_rows = sorted(zone_rows, key=lambda x: x["total"], reverse=True)

    return render_template(
        "admin/dashboard.html",
        counts=counts,
        perf=perf,
        zone_rows=zone_rows,
    )


@app.route("/admin/zones", methods=["GET", "POST"])
@role_required("admin")
def admin_zones():
    zones = _get_zones()
    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Nom de zone requis.", "warning")
            return redirect(url_for("admin_zones"))
        zones.append({"id": str(uuid.uuid4()), "name": name, "active": True})
        _save_zones(zones)
        _audit("zone.create", current_user()["id"], "zone", zones[-1]["id"], {"name": name})
        flash("Zone ajoutée.", "success")
        return redirect(url_for("admin_zones"))

    return render_template("admin/zones.html", zones=zones)


@app.route("/admin/users", methods=["GET", "POST"])
@role_required("admin")
def admin_users():
    users = _get_users()
    zones = _get_zones()

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        username = (request.form.get("username") or "").strip()
        full_name = (request.form.get("full_name") or "").strip()
        role = (request.form.get("role") or "").strip()
        zone_id = (request.form.get("zone_id") or "").strip() or None
        supervisor_id = (request.form.get("supervisor_id") or "").strip() or None
        password = (request.form.get("password") or "").strip()

        if not (username and full_name and role and password):
            flash("Champs requis manquants.", "warning")
            return redirect(url_for("admin_users"))

        if any(u.get("username") == username for u in users):
            flash("Ce nom d'utilisateur existe déjà.", "danger")
            return redirect(url_for("admin_users"))

        if role == "agent" and not supervisor_id:
            flash("Un agent doit être rattaché à un superviseur.", "warning")
            return redirect(url_for("admin_users"))

        rec = {
            "id": str(uuid.uuid4()),
            "username": username,
            "full_name": full_name,
            "role": role,
            "zone_id": zone_id,
            "supervisor_id": supervisor_id,
            "password_hash": generate_password_hash(password),
            "created_at": _now_iso(),
            "is_active": True,
        }
        users.append(rec)
        _save_users(users)
        _audit("user.create", current_user()["id"], "user", rec["id"], {"role": role, "username": username})
        flash("Utilisateur ajouté.", "success")
        return redirect(url_for("admin_users"))

    supervisors = [u for u in users if u.get("role") == "supervisor"]
    return render_template("admin/users.html", users=users, zones=zones, supervisors=supervisors, zone_name=_zone_name)


@app.route("/admin/settings", methods=["GET", "POST"])
@role_required("admin")
def admin_settings():
    settings = _get_settings()
    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        # pay rate
        pay_rate_raw = (request.form.get("pay_rate") or "").strip()
        try:
            settings["pay_rate"] = max(0, int(pay_rate_raw)) if pay_rate_raw != "" else settings.get("pay_rate", PAY_RATE_CFA)
        except Exception:
            settings["pay_rate"] = settings.get("pay_rate", PAY_RATE_CFA)

        settings["double_approval"] = bool(request.form.get("double_approval"))
        _save_settings(settings)
        _audit("settings.update", current_user()["id"], "settings", "settings", {"pay_rate": settings.get("pay_rate"), "double_approval": settings.get("double_approval")})
        flash("Paramètres enregistrés.", "success")
        return redirect(url_for("admin_settings"))
    return render_template("admin/settings.html", settings=settings)


@app.route("/admin/reset-data", methods=["POST"])
@role_required("admin")
def admin_reset_data():
    """Réinitialisation contrôlée des données (avec sauvegarde automatique).

    Permet de remettre à zéro :
    - Liste des recensés (registrations.json)
    - Paiements (payroll.json)
    - Comptes agents recenseurs
    - Comptes superviseurs

    Les admins sont conservés.
    """
    if not _csrf_validate():
        abort(400)

    confirm = (request.form.get("confirm_text") or "").strip().upper()
    if confirm != "RESET":
        flash("Pour confirmer la réinitialisation, tapez RESET.", "danger")
        return redirect(url_for("admin_settings"))

    reset_registrations = request.form.get("reset_registrations") == "1"
    reset_payroll = request.form.get("reset_payroll") == "1"
    reset_agents = request.form.get("reset_agents") == "1"
    reset_supervisors = request.form.get("reset_supervisors") == "1"

    if not any([reset_registrations, reset_payroll, reset_agents, reset_supervisors]):
        flash("Sélectionnez au moins un élément à réinitialiser.", "warning")
        return redirect(url_for("admin_settings"))

    # Sauvegarde automatique avant toute réinitialisation
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_zip = os.path.join(BACKUPS_DIR, f"backup_reset_{ts}.zip")
    with zipfile.ZipFile(backup_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for p in [USERS_FILE, REG_FILE, SETTINGS_FILE, PAYROLL_FILE, APPROVALS_QUEUE_FILE, CENTERS_FILE, ZONES_FILE]:
            if os.path.exists(p):
                z.write(p, arcname=os.path.basename(p))

    # Reset recensés (+ file d'approbations)
    if reset_registrations:
        _save_json(REG_FILE, [])
        _save_json(APPROVALS_QUEUE_FILE, [])

    # Reset paiements
    if reset_payroll:
        _save_json(PAYROLL_FILE, [])

    # Reset comptes utilisateurs (agents / superviseurs)
    if reset_agents or reset_supervisors:
        users = _load_json(USERS_FILE, [])
        new_users = []
        for u in users:
            role = (u.get("role") or "").strip().lower()
            if role == "admin":
                new_users.append(u)
                continue
            if role == "agent" and reset_agents:
                continue
            if role == "supervisor" and reset_supervisors:
                continue
            new_users.append(u)

        # Sécurité : au moins 1 admin doit rester.
        if not any((u.get("role") or "").strip().lower() == "admin" for u in new_users):
            flash("Réinitialisation annulée : aucun compte admin ne resterait.", "danger")
            return redirect(url_for("admin_settings"))

        _save_json(USERS_FILE, new_users)

    flash(f"Réinitialisation effectuée. Sauvegarde créée : {os.path.basename(backup_zip)}", "success")
    return redirect(url_for("admin_settings"))


# --- Centers & bureaux ---
@app.route("/admin/centers", methods=["GET", "POST"])
@role_required("admin")
def admin_centers():
    zones = _get_zones()
    centers_map = _get_centers_map()

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        action = (request.form.get("action") or "").strip()
        zone_id = (request.form.get("zone_id") or "").strip()
        if not zone_id:
            flash("Zone requise.", "warning")
            return redirect(url_for("admin_centers"))

        centers_map.setdefault(zone_id, [])

        if action == "add_center":
            name = (request.form.get("center_name") or "").strip()
            if not name:
                flash("Nom du centre requis.", "warning")
                return redirect(url_for("admin_centers"))
            centers_map[zone_id].append({"id": str(uuid.uuid4()), "name": name, "bureaux": []})
            _save_centers_map(centers_map)
            _audit("center.create", current_user()["id"], "center", zone_id, {"name": name})
            flash("Centre ajouté.", "success")
            return redirect(url_for("admin_centers", zone_id=zone_id))

        if action == "add_station":
            center_id = (request.form.get("center_id") or "").strip()
            station = (request.form.get("station") or "").strip()
            if not (center_id and station):
                flash("Centre et bureau requis.", "warning")
                return redirect(url_for("admin_centers", zone_id=zone_id))
            for c in centers_map.get(zone_id, []):
                if c.get("id") == center_id:
                    if station not in c.get("bureaux", []):
                        c.setdefault("bureaux", []).append(station)
                        c["bureaux"] = sorted(list({x for x in c["bureaux"] if x}))
                        _save_centers_map(centers_map)
                        _audit("station.create", current_user()["id"], "center", center_id, {"station": station})
                        flash("Bureau ajouté.", "success")
                    return redirect(url_for("admin_centers", zone_id=zone_id))
            flash("Centre introuvable.", "danger")
            return redirect(url_for("admin_centers", zone_id=zone_id))

        if action == "delete_center":
            center_id = (request.form.get("center_id") or "").strip()
            centers_map[zone_id] = [c for c in centers_map.get(zone_id, []) if c.get("id") != center_id]
            _save_centers_map(centers_map)
            _audit("center.delete", current_user()["id"], "center", center_id, {})
            flash("Centre supprimé.", "success")
            return redirect(url_for("admin_centers", zone_id=zone_id))

        if action == "delete_station":
            center_id = (request.form.get("center_id") or "").strip()
            station = (request.form.get("station") or "").strip()
            for c in centers_map.get(zone_id, []):
                if c.get("id") == center_id:
                    c["bureaux"] = [x for x in c.get("bureaux", []) if x != station]
                    _save_centers_map(centers_map)
                    _audit("station.delete", current_user()["id"], "center", center_id, {"station": station})
                    flash("Bureau supprimé.", "success")
                    return redirect(url_for("admin_centers", zone_id=zone_id))
            flash("Centre introuvable.", "danger")
            return redirect(url_for("admin_centers", zone_id=zone_id))

    selected_zone_id = (request.args.get("zone_id") or "").strip() or (zones[0]["id"] if zones else "")
    selected_centers = centers_map.get(selected_zone_id, [])

    # Liste des recensés de la zone sélectionnée.
    # Exigence : quand on choisit une zone, on doit voir *tous* les dossiers de la zone.
    # On ne filtre donc pas par statut ici (y compris les brouillons si présents).
    regs_all = _get_regs()
    regs_zone = [r for r in regs_all if r.get("zone_id") == selected_zone_id]
    regs_zone = sorted(regs_zone, key=lambda r: (r.get("created_at") or ""), reverse=True)
    regs_preview = regs_zone

    return render_template(
        "admin/centers.html",
        zones=zones,
        selected_zone_id=selected_zone_id,
        centers=selected_centers,
        zone_name=_zone_name,
        regs_preview=regs_preview,
        regs_total=len(regs_zone),
        find_user=_find_user,
        format_date=_format_date,
    )


# --- Objectives ---
@app.route("/admin/objectives", methods=["GET", "POST"])
@role_required("admin")
def admin_objectives():
    zones = _get_zones()
    objectives = _get_objectives_map()
    regs = _get_regs()

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        for z in zones:
            zid = z.get("id")
            val = (request.form.get(f"target_{zid}") or "").strip()
            try:
                t = int(val) if val else 0
            except Exception:
                t = 0
            objectives[zid] = {"target": max(0, t)}
        _save_objectives_map(objectives)
        _audit("objectives.update", current_user()["id"], "objectives", "objectives", {})
        flash("Objectifs enregistrés.", "success")
        return redirect(url_for("admin_objectives"))

    rows = []
    for z in zones:
        zid = z.get("id")
        target = int((objectives.get(zid) or {}).get("target", 0) or 0)
        total = sum(1 for r in regs if r.get("zone_id") == zid and r.get("status") != STATUS_DRAFT)
        pct = int((total / target) * 100) if target else 0
        rows.append({"zone": z, "target": target, "total": total, "pct": pct})

    return render_template("admin/objectives.html", rows=rows)


# --- Audit log ---
@app.route("/admin/audit")
@role_required("admin")
def admin_audit():
    q = (request.args.get("q") or "").strip().lower()
    action = (request.args.get("action") or "").strip().lower()
    actor = (request.args.get("actor") or "").strip()

    log = _load_json(AUDIT_FILE, [])
    if not isinstance(log, list):
        log = []

    def _match(e: Dict[str, Any]) -> bool:
        if action and (e.get("action") or "").lower() != action:
            return False
        if actor and (e.get("actor_id") or "") != actor:
            return False
        if q:
            hay = " ".join([
                (e.get("action") or ""),
                (e.get("target_type") or ""),
                (e.get("target_id") or ""),
                json.dumps(e.get("details") or {}, ensure_ascii=False),
            ]).lower()
            return q in hay
        return True

    filtered = [e for e in log if isinstance(e, dict) and _match(e)]
    filtered = sorted(filtered, key=lambda x: x.get("at") or "", reverse=True)

    page = request.args.get("page", "1")
    pag = _paginate(filtered, int(page) if str(page).isdigit() else 1, 50)

    return render_template("admin/audit.html", events=pag["items"], pagination=pag, find_user=_find_user)


# --- Backup / restore ---
@app.route("/admin/backup")
@role_required("admin")
def admin_backup():
    """Create a ZIP backup of data/ + uploads/."""
    u = current_user()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"backup_{ts}.zip"
    out_path = os.path.join(BACKUPS_DIR, name)

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # data
        for fn in os.listdir(DATA_DIR):
            if fn.lower().endswith(".json"):
                z.write(os.path.join(DATA_DIR, fn), arcname=f"data/{fn}")
        # uploads
        for fn in os.listdir(UPLOADS_DIR):
            z.write(os.path.join(UPLOADS_DIR, fn), arcname=f"uploads/{fn}")

    _audit("backup.create", u["id"], "backup", name, {})
    return send_file(out_path, as_attachment=True, download_name=name)


@app.route("/admin/restore", methods=["GET", "POST"])
@role_required("admin")
def admin_restore():
    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        confirm = (request.form.get("confirm") or "").strip().upper()
        if confirm != "RESTORE":
            flash("Tape RESTORE pour confirmer.", "warning")
            return redirect(url_for("admin_restore"))

        f = request.files.get("backup_zip")
        if not f or not f.filename:
            flash("Fichier ZIP requis.", "warning")
            return redirect(url_for("admin_restore"))

        # Save uploaded zip temporarily
        tmp = os.path.join(BACKUPS_DIR, f"uploaded_{uuid.uuid4().hex}.zip")
        f.save(tmp)

        # Create safety backup first
        _ = admin_backup()

        try:
            with zipfile.ZipFile(tmp, "r") as z:
                members = z.namelist()
                if not any(m.startswith("data/") and m.lower().endswith(".json") for m in members):
                    flash("ZIP invalide (dossier data/ manquant).", "danger")
                    return redirect(url_for("admin_restore"))

                # Extract to temp dir
                extract_dir = os.path.join(BACKUPS_DIR, f"restore_{uuid.uuid4().hex}")
                os.makedirs(extract_dir, exist_ok=True)
                z.extractall(extract_dir)

                # Replace data json files
                data_src = os.path.join(extract_dir, "data")
                uploads_src = os.path.join(extract_dir, "uploads")

                if os.path.isdir(data_src):
                    for fn in os.listdir(data_src):
                        if fn.lower().endswith(".json"):
                            shutil.copy2(os.path.join(data_src, fn), os.path.join(DATA_DIR, fn))

                if os.path.isdir(uploads_src):
                    for fn in os.listdir(uploads_src):
                        shutil.copy2(os.path.join(uploads_src, fn), os.path.join(UPLOADS_DIR, fn))

            _audit("backup.restore", current_user()["id"], "backup", os.path.basename(tmp), {})
            flash("Restauration effectuée. Recharge la page.", "success")
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

        return redirect(url_for("admin_dashboard"))

    return render_template("admin/restore.html")


# --- Approvals (double validation) ---
@app.route("/admin/approvals", methods=["GET", "POST"])
@role_required("admin")
def admin_approvals():
    settings = _get_settings()
    # Force: any supervisor-verified dossier must pass through admin approvals
    double_approval = True

    # Actions (approve / reject)
    # NOTE: l'UI envoie une liste de cases cochées: name="reg_ids".
    # On supporte aussi l'ancien mode (un seul id) via name="id".
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        reg_ids = [str(x).strip() for x in request.form.getlist("reg_ids") if str(x).strip()]
        if not reg_ids:
            single_id = (request.form.get("id") or "").strip()
            if single_id:
                reg_ids = [single_id]

        if not reg_ids:
            flash("Aucun dossier sélectionné.", "warning")
            return redirect(url_for("admin_approvals"))

        if action not in {"approve", "reject"}:
            flash("Action inconnue.", "danger")
            return redirect(url_for("admin_approvals"))

        regs = _get_regs()
        by_id = {str(x.get("id")): x for x in regs if isinstance(x, dict) and x.get("id")}

        now = _now_iso()
        admin_user = session.get("username") or "admin"

        approved = 0
        rejected = 0
        skipped = 0

        for reg_id in reg_ids:
            r = by_id.get(reg_id)
            if not r:
                skipped += 1
                continue

            # Sécurité : si double validation est activée, on n'autorise l'admin
            # à traiter que les dossiers effectivement vérifiés par le superviseur.
            if double_approval and not _supervisor_mark(r):
                skipped += 1
                continue

            if action == "approve":
                r["status"] = STATUS_APPROVED
                r["admin_approved_by"] = admin_user
                r["admin_approved_at"] = now
                r["admin_approved"] = True
                r["needs_admin_approval"] = False
                r["approved_by"] = admin_user
                r["approved_at"] = now
                r.pop("admin_rejected_by", None)
                r.pop("admin_rejected_at", None)
                _dequeue_for_admin(reg_id)
                approved += 1
            else:  # reject
                r["status"] = STATUS_REJECTED
                r["admin_rejected_by"] = admin_user
                r["admin_rejected_at"] = now
                r["admin_approved"] = False
                r["needs_admin_approval"] = False
                r["rejected_by"] = admin_user
                r["rejected_at"] = now
                _dequeue_for_admin(reg_id)
                rejected += 1

        _save_regs(regs)

        if action == "approve":
            if approved:
                msg = f"{approved} dossier(s) approuvé(s)."
                if skipped:
                    msg += f" {skipped} ignoré(s)."
                flash(msg, "success")
            else:
                flash("Aucun dossier approuvé (vérifiez la sélection).", "warning")
        else:
            if rejected:
                msg = f"{rejected} dossier(s) rejeté(s)."
                if skipped:
                    msg += f" {skipped} ignoré(s)."
                flash(msg, "warning")
            else:
                flash("Aucun dossier rejeté (vérifiez la sélection).", "warning")

        return redirect(url_for("admin_approvals"))

    # GET: Build a robust pending list.
    regs = _get_regs()
    by_id = {r.get("id"): r for r in regs if r.get("id")}

    existing_queue = _get_approval_queue()
    queue_out: list[str] = []
    seen: set[str] = set()
    regs_changed = False

    def _ensure_needs_admin(rr: dict) -> None:
        nonlocal regs_changed
        if not _norm_bool(rr.get("needs_admin_approval")):
            rr["needs_admin_approval"] = True
            regs_changed = True

    # 1) keep relevant items already in queue
    for rid in existing_queue:
        if rid in seen:
            continue
        rr = by_id.get(rid)
        if not rr:
            continue
        st = _canon_status(rr.get("status"))
        if st == STATUS_PAID:
            continue
        if _admin_done(rr):
            continue
        if not _supervisor_mark(rr, st=st):
            continue
        if double_approval:
            _ensure_needs_admin(rr)
        if _norm_bool(rr.get("needs_admin_approval")):
            queue_out.append(rid)
            seen.add(rid)

    # 2) self-healing: add any verified dossier that must be in approvals
    if double_approval:
        for rr in regs:
            rid = rr.get("id")
            if not rid or rid in seen:
                continue
            st = _canon_status(rr.get("status"))
            if st == STATUS_PAID:
                continue
            if _admin_done(rr):
                continue
            if not _supervisor_mark(rr, st=st):
                continue
            _ensure_needs_admin(rr)
            queue_out.append(rid)
            seen.add(rid)

    # Persist queue + optional reg flag update
    if queue_out != existing_queue:
        # NOTE: Le fichier de file d'attente s'appelle APPROVALS_QUEUE_FILE.
        # Un ancien nom (APPROVAL_QUEUE_FILE) provoquait un NameError.
        _save_json(APPROVALS_QUEUE_FILE, queue_out)
    if regs_changed:
        _save_regs(regs)

    # Build view models (ordered by queue)
    pending_view = []
    for rid in queue_out:
        rr = by_id.get(rid)
        if not rr:
            continue
        pending_view.append(
            {
                "id": rr.get("id"),
                "nom": rr.get("nom"),
                "prenoms": rr.get("prenoms"),
                "zone": rr.get("zone"),
                "agent_username": rr.get("agent_username"),
                "created_at": rr.get("created_at"),
                "verified_by": rr.get("supervisor_verified_by"),
                "verified_at": rr.get("supervisor_verified_at"),
            }
        )

    return render_template(
        "admin/approvals.html",
        pending=pending_view,
        settings=settings,
    )


@app.route("/admin/registrations")
@role_required("admin")
def admin_registrations():
    zones = _get_zones()
    regs = _get_regs()

    zone_id = (request.args.get("zone_id") or "").strip()
    polling_center = (request.args.get("polling_center") or "").strip()
    status_filter = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    def _match(r: Dict[str, Any]) -> bool:
        if zone_id and r.get("zone_id") != zone_id:
            return False
        if polling_center and (r.get("polling_center") or "") != polling_center:
            return False
        if status_filter and (r.get("status") or "") != status_filter:
            return False
        if q:
            hay = " ".join(
                [
                    (r.get("nom") or ""),
                    (r.get("prenoms") or ""),
                    (r.get("telephone") or ""),
                    (r.get("quartier") or ""),
                    (r.get("voter_number") or ""),
                    (r.get("polling_center") or ""),
                    (r.get("polling_station") or ""),
                ]
            ).lower()
            return q in hay
        return True

    filtered = [r for r in regs if _match(r)]
    filtered_sorted = sorted(filtered, key=lambda r: r.get("created_at") or "", reverse=True)

    per_page = 20
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    total = len(filtered_sorted)
    pages = max(1, (total + per_page - 1) // per_page)
    if page > pages:
        page = pages

    start = (page - 1) * per_page
    regs_page = filtered_sorted[start : start + per_page]

    centers = sorted({(r.get("polling_center") or "").strip() for r in regs if (r.get("polling_center") or "").strip()})
    statuses = [STATUS_DRAFT, STATUS_PENDING, STATUS_NEEDS_CORRECTION, STATUS_VERIFIED, STATUS_APPROVED, STATUS_REJECTED]

    return render_template(
        "admin/registrations.html",
        regs=regs_page,
        zones=zones,
        centers=centers,
        statuses=statuses,
        selected_zone_id=zone_id,
        selected_center=polling_center,
        selected_status=status_filter,
        q=q,
        total=total,
        pagination={
            "page": page,
            "pages": pages,
            "total_pages": pages,
            "per_page": per_page,
            "total": total,
            "has_prev": page > 1,
            "has_next": page < pages,
        },
        zone_name=_zone_name,
        find_user=_find_user,
        format_date=_format_date,
    )


@app.route("/admin/registrations/pdf", methods=["GET"])
@role_required("admin")
def admin_registrations_pdf():
    regs = _get_regs()

    zone_id = (request.args.get("zone_id") or "").strip()
    polling_center = (request.args.get("polling_center") or "").strip()
    status_filter = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    def _match(r: Dict[str, Any]) -> bool:
        if zone_id and r.get("zone_id") != zone_id:
            return False
        if polling_center and (r.get("polling_center") or "") != polling_center:
            return False
        if status_filter and (r.get("status") or "") != status_filter:
            return False
        if q:
            hay = " ".join(
                [
                    (r.get("nom") or ""),
                    (r.get("prenoms") or ""),
                    (r.get("telephone") or ""),
                    (r.get("quartier") or ""),
                    (r.get("voter_number") or ""),
                    (r.get("polling_center") or ""),
                    (r.get("polling_station") or ""),
                ]
            ).lower()
            return q in hay
        return True

    filtered = [r for r in regs if _match(r)]
    filtered_sorted = sorted(filtered, key=lambda r: r.get("created_at") or "", reverse=True)

    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.pdfbase.pdfmetrics import stringWidth
    except ModuleNotFoundError:
        flash("Le module 'reportlab' n'est pas installé. Exécute: pip install -r requirements.txt", "danger")
        return redirect(
            url_for(
                "admin_registrations",
                zone_id=zone_id,
                polling_center=polling_center,
                status=status_filter,
                q=q,
            )
        )

    # --- helpers ---
    from datetime import datetime
    from xml.sax.saxutils import escape

    def _p(text: str, style: ParagraphStyle) -> Paragraph:
        return Paragraph(escape(text or ""), style)

    # --- document ---
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=12 * mm,
        bottomMargin=10 * mm,
        title="Personnes recensées",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "pdf_title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=18,
        spaceAfter=2 * mm,
        textColor=colors.HexColor("#0f172a"),
    )

    meta_style = ParagraphStyle(
        "pdf_meta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )

    cell_style = ParagraphStyle(
        "pdf_cell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.3,
        leading=10,
        textColor=colors.HexColor("#111827"),
    )

    cell_small = ParagraphStyle(
        "pdf_cell_small",
        parent=cell_style,
        fontSize=8,
        leading=9.5,
    )

    header_style = ParagraphStyle(
        "pdf_header",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=10.5,
        textColor=colors.white,
    )

    # Title
    title = "Personnes recensées"
    if zone_id:
        title += f" — {_zone_name(zone_id)}"
    if polling_center:
        title += f" — {polling_center}"
    if status_filter:
        title += f" — {status_filter}"

    elems = []
    elems.append(Paragraph(title, title_style))

    # Meta line (count + filters)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    meta_parts = [f"Total: <b>{len(filtered_sorted)}</b>", f"Généré le: {generated_at}"]
    if q:
        meta_parts.append(f"Recherche: <b>{escape(q)}</b>")
    meta = " &nbsp;&nbsp;|&nbsp;&nbsp; ".join(meta_parts)
    elems.append(Paragraph(meta, meta_style))
    elems.append(Spacer(1, 5 * mm))

    # --- table ---
    headers = [
        "Nom",
        "Prénoms",
        "Naissance",
        "Quartier",
        "Téléphone",
        "Statut",
        "N° Électeur",
        "Centre de vote",
        "Bureau",
        "Zone",
    ]

    data = [[_p(h, header_style) for h in headers]]

    for r in filtered_sorted:
        data.append(
            [
                _p(r.get("nom") or "", cell_style),
                _p(r.get("prenoms") or "", cell_style),
                _p(_format_date(r.get("dob") or ""), cell_small),
                _p(r.get("quartier") or "", cell_style),
                _p(r.get("telephone") or "", cell_small),
                _p((r.get("status") or "").replace("_", " "), cell_small),
                _p(r.get("voter_number") or "", cell_small),
                _p(r.get("polling_center") or "", cell_style),
                _p(r.get("polling_station") or "", cell_small),
                _p(_zone_name(r.get("zone_id")), cell_style),
            ]
        )

    # Force full-width table (prevents the "tiny table" effect when data is short)
    # Base column widths in mm, then scaled to doc.width.
    base_mm = [26, 32, 20, 28, 24, 20, 34, 52, 18, 26]
    base_pts = [w * mm for w in base_mm]
    scale = (doc.width / sum(base_pts)) if sum(base_pts) else 1
    col_widths = [w * scale for w in base_pts]

    table = Table(data, colWidths=col_widths, repeatRows=1)

    # Styling
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING", (0, 1), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 3.5),
                # align some columns
                ("ALIGN", (2, 1), (2, -1), "CENTER"),
                ("ALIGN", (4, 1), (4, -1), "CENTER"),
                ("ALIGN", (5, 1), (6, -1), "CENTER"),
                ("ALIGN", (8, 1), (8, -1), "CENTER"),
            ]
        )
    )

    elems.append(table)

    # Footer with page number
    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(doc_.leftMargin, 7 * mm, "Eureka — Liste des personnes recensées")
        canvas.drawRightString(doc_.pagesize[0] - doc_.rightMargin, 7 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(elems, onFirstPage=_on_page, onLaterPages=_on_page)
    buf.seek(0)

    fname = "personnes_recensees.pdf"
    return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/pdf")



# --- Admin SMS ---
@app.route("/admin/sms", methods=["GET", "POST"])
@role_required("admin")
def admin_sms():
    u = current_user()
    _process_due_campaigns(u["id"])  # auto-run scheduled

    regs = _get_regs()
    zones = _get_zones()
    cfg = _get_sms_config()

    # Centers list for filters
    centers = sorted({(r.get("polling_center") or "").strip() for r in regs if (r.get("polling_center") or "").strip()})

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "").strip()

        if action == "save_config":
            cfg["mode"] = (request.form.get("mode") or "dry_run").strip()
            cfg["sender_id"] = (request.form.get("sender_id") or "").strip()
            http_cfg = cfg.get("http_json") or {}
            http_cfg["url"] = (request.form.get("http_url") or "").strip()
            http_cfg["token"] = (request.form.get("http_token") or "").strip()
            http_cfg["to_field"] = (request.form.get("to_field") or "to").strip()
            http_cfg["message_field"] = (request.form.get("message_field") or "message").strip()
            http_cfg["sender_field"] = (request.form.get("sender_field") or "sender").strip()
            cfg["http_json"] = http_cfg
            _save_sms_config(cfg)
            _audit("sms.config", u["id"], "sms", "config", {"mode": cfg.get("mode")})
            flash("Configuration SMS enregistrée.", "success")
            return redirect(url_for("admin_sms"))

        if action in ("send_now", "schedule"):
            zone_id = (request.form.get("zone_id") or "").strip()
            polling_center = (request.form.get("polling_center") or "").strip()
            status_filter = (request.form.get("status_filter") or "").strip()
            only_missing_voter = bool(request.form.get("only_missing_voter") == "on")
            message = (request.form.get("message") or "").strip()
            scheduled_at = (request.form.get("scheduled_at") or "").strip()

            if not message:
                flash("Message requis.", "warning")
                return redirect(url_for("admin_sms"))

            if action == "send_now":
                # immediate campaign
                camps = _get_sms_campaigns()
                camp = {
                    "id": str(uuid.uuid4()),
                    "created_at": _now_iso(),
                    "created_by": u["id"],
                    "zone_id": zone_id,
                    "polling_center": polling_center,
                    "status_filter": status_filter,
                    "only_missing_voter": only_missing_voter,
                    "message": message,
                    "scheduled_at": _now_iso(),
                    "status": "SCHEDULED",
                    "sent_count": 0,
                    "total_count": 0,
                }
                camps.append(camp)
                _save_sms_campaigns(camps)
                _audit("sms.schedule", u["id"], "sms", camp["id"], {"now": True})
                flash("Campagne créée. Elle va être envoyée (par lots).", "success")
                _process_due_campaigns(u["id"])
                return redirect(url_for("admin_sms"))

            # schedule
            try:
                _ = _dt_from_iso(scheduled_at)
            except Exception:
                flash("Date/heure programmée invalide (format ISO). Exemple: 2028-04-01T18:00:00+00:00", "warning")
                return redirect(url_for("admin_sms"))

            camps = _get_sms_campaigns()
            camp = {
                "id": str(uuid.uuid4()),
                "created_at": _now_iso(),
                "created_by": u["id"],
                "zone_id": zone_id,
                "polling_center": polling_center,
                "status_filter": status_filter,
                "only_missing_voter": only_missing_voter,
                "message": message,
                "scheduled_at": scheduled_at,
                "status": "SCHEDULED",
                "sent_count": 0,
                "total_count": 0,
            }
            camps.append(camp)
            _save_sms_campaigns(camps)
            _audit("sms.schedule", u["id"], "sms", camp["id"], {"now": False})
            flash("Campagne programmée.", "success")
            return redirect(url_for("admin_sms"))

        if action == "run_due":
            _process_due_campaigns(u["id"])
            flash("Traitement des campagnes en attente terminé (ou limité par sécurité).", "success")
            return redirect(url_for("admin_sms"))

    camps = _get_sms_campaigns()
    camps_sorted = sorted(camps, key=lambda c: c.get("created_at") or "", reverse=True)

    return render_template(
        "admin/sms.html",
        cfg=cfg,
        zones=zones,
        centers=centers,
        camps=camps_sorted[:50],
        statuses=[STATUS_PENDING, STATUS_VERIFIED, STATUS_APPROVED, STATUS_REJECTED, STATUS_NEEDS_CORRECTION],
    )


# ----------------------------
# Payroll admin
# ----------------------------

@app.route("/admin/payroll", methods=["GET"])
@role_required("admin")
def admin_payroll():
    users = _get_users()
    agents = [u for u in users if u.get("role") == "agent" and u.get("is_active", True)]
    agents = sorted(agents, key=lambda x: x.get("full_name") or "")

    # Search by payment number
    payment_number = (request.args.get("payment_number") or "").strip()
    found = None
    if payment_number:
        items = _get_payroll()
        for it in items:
            if (it.get("payment_number") or "").strip().upper() == payment_number.strip().upper() or (it.get("id") or "") == payment_number:
                found = it
                break

    return render_template("admin/payroll_search.html", agents=agents, found=found, find_user=_find_user)


@app.route("/admin/payroll/user/<user_id>", methods=["GET", "POST"])
@role_required("admin")
def admin_payroll_user(user_id: str):
    u = current_user()
    target = _find_user(user_id)
    if not target or target.get("role") != "agent":
        abort(404)

    regs = _get_regs()
    payroll_items = _get_payroll()

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "").strip()

        if action == "generate":
            start_iso = (request.form.get("period_start") or "").strip()
            end_iso = (request.form.get("period_end") or "").strip()
            rec = _find_payslip(user_id, start_iso, end_iso, payroll_items)
            if rec and rec.get("is_locked"):
                flash("Cette période est verrouillée (fiche déjà générée).", "warning")
                return redirect(url_for("admin_payroll_user", user_id=user_id))

            periods = _periods_for_user(user_id, regs)
            p = next((x for x in periods if x["start_iso"] == start_iso and x["end_iso"] == end_iso), None)
            if not p:
                flash("Période invalide.", "danger")
                return redirect(url_for("admin_payroll_user", user_id=user_id))

            count = _count_regs_in_period(user_id, regs, p["start"], p["end"])
            gross = _calc_amount(count)
            advance = _sum_advances(user_id, payroll_items, start_iso, end_iso)
            balance = max(0, gross - advance)

            if rec:
                # update only if not locked
                rec["count"] = count
                rec["gross_amount"] = gross
                rec["advance_amount"] = advance
                rec["balance_amount"] = balance
                rec["amount"] = balance
                rec["generated_at"] = _now_iso()
                rec["status"] = "GENERATED"
                rec["is_locked"] = True
                rec["locked_at"] = _now_iso()
                _audit("payroll.regenerate", u["id"], "payslip", rec["id"], {"period": [start_iso, end_iso]})
                flash("Fiche mise à jour et verrouillée.", "success")
            else:
                pay_id = str(uuid.uuid4())
                rec = {
                    "id": pay_id,
                    "type": "PAYSLIP",
                    "payment_number": _next_payment_number(payroll_items),
                    "user_id": user_id,
                    "period_start": start_iso,
                    "period_end": end_iso,
                    "count": count,
                    "gross_amount": gross,
                    "advance_amount": advance,
                    "balance_amount": balance,
                    "amount": balance,
                    "generated_at": _now_iso(),
                    "generated_by": u["id"],
                    "status": "GENERATED",
                    "paid_at": "",
                    "paid_by": "",
                    "notes": "",
                    "is_locked": True,
                    "locked_at": _now_iso(),
                }
                payroll_items.append(rec)
                _audit("payroll.generate", u["id"], "payslip", pay_id, {"period": [start_iso, end_iso]})
                flash("Fiche générée et verrouillée.", "success")

            _save_payroll(payroll_items)
            return redirect(url_for("admin_payslip", pay_id=rec["id"]))

        if action == "add_advance":
            start_iso = (request.form.get("period_start") or "").strip()
            end_iso = (request.form.get("period_end") or "").strip()
            amount_raw = (request.form.get("advance_amount") or "").strip()

            # The table displays inclusive end dates (end_exclusive - 1 day).
            # Many users will copy that visible date into the form.
            # Here we normalize to the internal end_exclusive value when possible.
            if start_iso and end_iso:
                try:
                    periods_all = _periods_for_user(user_id, regs)
                    p = next((x for x in periods_all if x.get("start_iso") == start_iso), None)
                    if p:
                        try:
                            inclusive = (date.fromisoformat(p["end_iso"]) - timedelta(days=1)).isoformat()
                        except Exception:
                            inclusive = ""
                        if inclusive and end_iso == inclusive:
                            end_iso = p["end_iso"]
                except Exception:
                    # keep as is
                    pass
            try:
                amt = int(amount_raw)
            except Exception:
                amt = 0
            if amt <= 0:
                flash("Montant d'avance invalide.", "warning")
                return redirect(url_for("admin_payroll_user", user_id=user_id))

            adv = {
                "id": str(uuid.uuid4()),
                "type": "ADVANCE",
                "payment_number": _next_payment_number(payroll_items),
                "user_id": user_id,
                "period_start": start_iso,
                "period_end": end_iso,
                "amount": int(amt),
                "created_at": _now_iso(),
                "created_by": u["id"],
                "status": "PAID",
                "paid_at": _now_iso(),
                "paid_by": u["id"],
                "notes": "Avance",
                "is_locked": True,
                "locked_at": _now_iso(),
            }
            payroll_items.append(adv)

            # If a payslip for this period already exists (even locked),
            # refresh its advance/balance amounts so advances are effectively deducted.
            ps = _find_payslip(user_id, start_iso, end_iso, payroll_items)
            if ps and (ps.get("status") or "").upper() != "PAID":
                try:
                    gross_amount = int(ps.get("gross_amount", 0) or 0)
                except Exception:
                    gross_amount = 0
                total_adv = _sum_advances(user_id, payroll_items, start_iso, end_iso)
                balance_amount = max(0, gross_amount - total_adv)
                ps["advance_amount"] = total_adv
                ps["balance_amount"] = balance_amount
                ps["amount"] = balance_amount
                ps["updated_at"] = _now_iso()

            _save_payroll(payroll_items)
            _audit("payroll.advance", u["id"], "advance", adv["id"], {"amount": amt, "period": [start_iso, end_iso]})
            flash("Avance enregistrée.", "success")
            return redirect(url_for("admin_payroll_user", user_id=user_id))

    # compute periods
    periods = _periods_for_user(user_id, regs)
    periods = periods[-24:]  # show last

    payroll_changed = False
    rows: List[Dict[str, Any]] = []
    for p in periods:
        start_iso, end_iso = p["start_iso"], p["end_iso"]
        count = _count_regs_in_period(user_id, regs, p["start"], p["end"])
        if count <= 0:
            continue
        gross = _calc_amount(count)
        advance = _sum_advances(user_id, payroll_items, start_iso, end_iso)
        balance = max(0, gross - advance)
        rec = _find_payslip(user_id, start_iso, end_iso, payroll_items)
        status = rec.get("status") if rec else "NOT_GENERATED"

        # Backward-compatible fix: older advances may have been saved with
        # inclusive period_end values, which previously prevented deductions.
        # Refresh existing payslips (not PAID) to reflect the correct advance/balance.
        if rec and (status or "").upper() != "PAID":
            try:
                locked_gross = int(rec.get("gross_amount", gross) or 0)
            except Exception:
                locked_gross = gross
            total_adv = _sum_advances(user_id, payroll_items, start_iso, end_iso)
            new_balance = max(0, locked_gross - total_adv)
            if int(rec.get("advance_amount", 0) or 0) != int(total_adv) or int(rec.get("balance_amount", 0) or 0) != int(new_balance):
                rec["advance_amount"] = int(total_adv)
                rec["balance_amount"] = int(new_balance)
                rec["amount"] = int(new_balance)
                rec["updated_at"] = _now_iso()
                payroll_changed = True

        # Prefer locked amounts for display when a payslip exists,
        # so the table matches the generated PDF.
        display_count = int(rec.get("count", count) or count) if rec else count
        try:
            display_gross = int(rec.get("gross_amount", gross) or gross) if rec else gross
        except Exception:
            display_gross = gross
        display_advance = int(rec.get("advance_amount", advance) or advance) if rec else advance
        display_balance = int(rec.get("balance_amount", balance) or balance) if rec else balance

        rows.append({
            "start_iso": start_iso,
            "end_iso": end_iso,
            "label": _period_label(start_iso, end_iso),
            "count": display_count,
            "gross": display_gross,
            "advance": display_advance,
            "balance": display_balance,
            "status": status,
            "payslip": rec,
        })

    if payroll_changed:
        _save_payroll(payroll_items)

    # show recent advances
    advances = [x for x in payroll_items if x.get("type") == "ADVANCE" and x.get("user_id") == user_id]
    advances = sorted(advances, key=lambda x: x.get("created_at") or "", reverse=True)[:30]

    return render_template(
        "admin/payroll_user.html",
        target=target,
        zone_name=_zone_name(target.get("zone_id")),
        rows=rows,
        advances=advances,
    )


@app.route("/admin/payroll/export.csv")
@role_required("admin")
def admin_payroll_export_csv():
    items = _get_payroll()
    # export payslips only
    rows = [x for x in items if x.get("type") == "PAYSLIP"]
    rows = sorted(rows, key=lambda x: x.get("generated_at") or "", reverse=True)

    import csv

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["payment_number", "user", "period_start", "period_end", "count", "gross", "advance", "balance", "status", "paid_at"])
    for r in rows:
        user = _find_user(r.get("user_id"))
        w.writerow([
            r.get("payment_number"),
            (user.get("full_name") if user else r.get("user_id")),
            r.get("period_start"),
            r.get("period_end"),
            r.get("count"),
            r.get("gross_amount"),
            r.get("advance_amount"),
            r.get("balance_amount"),
            r.get("status"),
            r.get("paid_at"),
        ])

    data = buf.getvalue().encode("utf-8")
    return send_file(io.BytesIO(data), as_attachment=True, download_name="payroll_export.csv", mimetype="text/csv")


@app.route("/admin/payroll/payslip/<pay_id>", methods=["GET", "POST"])
@role_required("admin")
def admin_payslip(pay_id: str):
    payroll_items = _get_payroll()
    rec = next((x for x in payroll_items if x.get("id") == pay_id), None)
    if not rec:
        abort(404)

    target = _find_user(rec.get("user_id"))
    if not target:
        abort(404)

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)
        action = (request.form.get("action") or "").strip()
        if action == "mark_paid":
            rec["status"] = "PAID"
            rec["paid_at"] = _now_iso()
            rec["paid_by"] = current_user()["id"]
            rec["is_locked"] = True
            rec["locked_at"] = rec.get("locked_at") or _now_iso()
            _save_payroll(payroll_items)
            _audit("payroll.mark_paid", current_user()["id"], "payslip", pay_id, {})
            flash("Paiement marqué comme effectué.", "success")
        elif action == "mark_unpaid":
            # do not unlock period, but revert status
            rec["status"] = "GENERATED"
            rec["paid_at"] = ""
            rec["paid_by"] = ""
            _save_payroll(payroll_items)
            _audit("payroll.mark_unpaid", current_user()["id"], "payslip", pay_id, {})
            flash("Paiement remis en non-payé.", "warning")

        return redirect(url_for("admin_payslip", pay_id=pay_id))

    return render_template(
        "admin/payslip.html",
        target=target,
        zone_name=_zone_name(target.get("zone_id")),
        rec=rec,
        period_label=_period_label(rec.get("period_start", ""), rec.get("period_end", "")) if rec.get("type") == "PAYSLIP" else "Avance",
        amount_fmt=_format_money_cfa(int(rec.get("amount", 0) or 0)),
        gross_fmt=_format_money_cfa(int(rec.get("gross_amount", rec.get("amount", 0)) or 0)),
        advance_fmt=_format_money_cfa(int(rec.get("advance_amount", 0) or 0)),
        balance_fmt=_format_money_cfa(int(rec.get("balance_amount", rec.get("amount", 0)) or 0)),
    )


@app.route("/admin/payroll/payslip/<pay_id>/pdf", methods=["GET"])
@role_required("admin")
def admin_payslip_pdf(pay_id: str):
    payroll_items = _get_payroll()
    rec = next((x for x in payroll_items if x.get("id") == pay_id), None)
    if not rec:
        abort(404)

    target = _find_user(rec.get("user_id"))
    if not target:
        abort(404)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.pdfgen import canvas
    except ModuleNotFoundError:
        flash("Le module 'reportlab' n'est pas installé dans ton environnement. Exécute: pip install -r requirements.txt", "danger")
        return redirect(url_for("admin_payslip", pay_id=pay_id))

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    accent = colors.HexColor("#f97316")
    dark = colors.HexColor("#111827")
    gray = colors.HexColor("#4b5563")

    left = 18 * mm
    right = w - 18 * mm
    top = h - 18 * mm

    c.setFillColor(accent)
    c.rect(0, h - 6, w, 6, stroke=0, fill=1)

    c.setFillColor(dark)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(left, top + 2 * mm, "Recensement")
    c.setFont("Helvetica", 10)
    c.setFillColor(gray)
    c.drawString(left, top - 6 * mm, "support@recensement2028.local")
    c.drawString(left, top - 11 * mm, "+225 00 00 00 00 00")

    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 22)
    c.drawRightString(right, top + 2 * mm, "REÇU DE PAIEMENT")
    c.setFillColor(dark)
    c.setFont("Helvetica", 12)
    pay_no = rec.get("payment_number") or rec.get("id", "")
    c.drawRightString(right, top - 7 * mm, f"N°: {pay_no}")

    c.setFillColor(accent)
    c.rect(0, top - 18 * mm, w, 6, stroke=0, fill=1)

    y = top - 30 * mm
    c.setFillColor(dark)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(left, y, "INFORMATIONS MARCHAND")
    c.drawRightString(right, y, "INFORMATIONS AGENT")

    c.setFont("Helvetica", 10)
    c.setFillColor(dark)

    y2 = y - 10 * mm
    c.drawString(left, y2, "Entreprise : Recensement Électoral 2028")
    c.drawString(left, y2 - 6 * mm, "Adresse : Bonoua")
    c.drawString(left, y2 - 12 * mm, "Téléphone : +225 00 00 00 00 00")

    c.drawRightString(right, y2, f"Nom : {target.get('full_name')}")
    c.drawRightString(right, y2 - 6 * mm, f"Zone : {_zone_name(target.get('zone_id'))}")

    if rec.get("type") == "PAYSLIP":
        c.drawRightString(right, y2 - 12 * mm, f"Période : {_period_label(rec.get('period_start',''), rec.get('period_end',''))}")

    c.setStrokeColor(colors.HexColor("#e5e7eb"))
    c.setLineWidth(1)
    c.line(left, y2 - 20 * mm, right, y2 - 20 * mm)

    y3 = y2 - 32 * mm
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(dark)
    c.drawString(left, y3, "DÉTAILS")

    c.setFont("Helvetica", 10)
    c.setFillColor(dark)

    gross = int(rec.get("gross_amount", rec.get("amount", 0)) or 0)
    advance = int(rec.get("advance_amount", 0) or 0)
    balance = int(rec.get("balance_amount", rec.get("amount", 0)) or 0)

    lines = []
    if rec.get("type") == "PAYSLIP":
        lines.append(("Personnes recensées", str(int(rec.get("count", 0) or 0))))
        lines.append(("Montant brut", _format_money_cfa(gross)))
        if advance:
            lines.append(("Avance(s)", f"- {_format_money_cfa(advance)}"))
        lines.append(("Net à payer", _format_money_cfa(balance)))
    else:
        lines.append(("Avance", _format_money_cfa(int(rec.get("amount", 0) or 0))))

    yy = y3 - 10 * mm
    for k, v in lines:
        c.setFont("Helvetica", 10)
        c.drawString(left, yy, k)
        c.setFont("Helvetica-Bold", 10)
        c.drawRightString(right, yy, v)
        yy -= 7 * mm

    c.setFillColor(accent)
    c.setFont("Helvetica-Bold", 16)
    c.drawRightString(right, yy - 6 * mm, f"TOTAL: {_format_money_cfa(int(rec.get('amount',0) or 0))}")

    c.setFillColor(gray)
    c.setFont("Helvetica", 9)
    c.drawString(left, 18 * mm, f"Généré le {_now_iso()[:19].replace('T',' ')}")

    c.showPage()
    c.save()

    buf.seek(0)
    filename = f"recu_{_safe_filename(pay_no)}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


# ----------------------------
# Supervisor routes
# ----------------------------

@app.route("/supervisor")
@role_required("supervisor")
def supervisor_dashboard():
    u = current_user()
    if not u.get("zone_id"):
        flash("Ton compte n'a pas de zone assignée. Demande à l'admin.", "danger")
        return redirect(url_for("index"))

    regs = _get_regs()
    in_zone = [r for r in regs if r.get("zone_id") == u.get("zone_id")]

    pending = [r for r in in_zone if r.get("status") == STATUS_PENDING]
    needs = [r for r in in_zone if r.get("status") == STATUS_NEEDS_CORRECTION]
    verified = [r for r in in_zone if r.get("status") == STATUS_VERIFIED]
    approved = [r for r in in_zone if r.get("status") == STATUS_APPROVED]
    rejected = [r for r in in_zone if r.get("status") == STATUS_REJECTED]

    counts = {
        "pending": len(pending),
        "needs": len(needs),
        "verified": len(verified),
        "approved": len(approved),
        "rejected": len(rejected),
        "total": len(in_zone),
    }

    pending_sorted = sorted(pending, key=lambda r: r.get("created_at") or "", reverse=True)[:200]
    return render_template(
        "supervisor/dashboard.html",
        counts=counts,
        pending=pending_sorted,
        zone_name=_zone_name(u.get("zone_id")),
        find_user=_find_user,
        format_date=_format_date,
    )


@app.route("/supervisor/registration/<reg_id>", methods=["GET", "POST"])
@role_required("supervisor")
def supervisor_review(reg_id: str):
    u = current_user()
    regs = _get_regs()
    reg = next((r for r in regs if r.get("id") == reg_id), None)
    if not reg:
        abort(404)

    if reg.get("zone_id") != u.get("zone_id"):
        abort(403)

    centers_map = _get_centers_map()
    # If no centers are configured for this specific zone, fall back to a global
    # reference list stored under the special key "_default".
    centers = centers_map.get(u.get("zone_id"), []) or centers_map.get("_default", [])

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "").strip()
        voter_number = (request.form.get("voter_number") or "").strip()
        polling_center = (request.form.get("polling_center") or "").strip()
        polling_station = (request.form.get("polling_station") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        correction_reason = (request.form.get("correction_reason") or "").strip()

        if action == "verify":
            if not (voter_number and polling_center and polling_station):
                flash("Pour valider : numéro d’électeur, centre et bureau sont requis.", "warning")
                return render_template(
                    "supervisor/review.html",
                    reg=reg,
                    creator=_find_user(reg.get("created_by")),
                    zone_name=_zone_name(reg.get("zone_id")),
                    format_date=_format_date,
                    centers=centers,
                )

            reg["voter_number"] = voter_number
            reg["polling_center"] = polling_center
            reg["polling_station"] = polling_station
            reg["notes"] = notes

            # Horodatage unique pour tous les champs de validation
            now_iso = _now_iso()

            # Validation (superviseur)
            reg["verified_by"] = u["id"]
            reg["verified_at"] = now_iso
            reg["supervisor_status"] = STATUS_VERIFIED
            reg["supervisor_verified"] = True
            reg["supervisor_verified_by"] = u["id"]
            reg["supervisor_verified_at"] = now_iso

            # En mode double validation, le dossier DOIT passer par l'admin.
            # Force: any supervisor-verified dossier must pass through admin approvals
            double_approval = True
            reg["status"] = STATUS_VERIFIED
            reg["needs_admin_approval"] = True if double_approval else False
            if double_approval:
                _queue_for_admin(reg_id)

            # Compatibilité avec d'anciennes clés
            reg["need_admin_approval"] = reg["needs_admin_approval"]
            reg["awaiting_admin_approval"] = reg["needs_admin_approval"]
            reg["approval_stage"] = "PENDING_ADMIN" if reg["needs_admin_approval"] else ""

            # Réinitialise toujours les marqueurs admin tant que le dossier n'a pas été approuvé.
            reg["admin_approved"] = False
            reg["admin_approved_by"] = None
            reg["admin_approved_at"] = None

            _save_regs(regs)
            _audit("reg.verify", u["id"], "registration", reg.get("id"), {"status": reg.get("status")})
            flash("Enregistrement validé.", "success")
            return redirect(url_for("supervisor_dashboard"))

        if action == "reject":
            reg["status"] = STATUS_REJECTED
            _dequeue_for_admin(reg_id)
            reg["voter_number"] = ""
            reg["polling_center"] = ""
            reg["polling_station"] = ""
            reg["notes"] = notes
            reg["verified_by"] = u["id"]
            reg["verified_at"] = _now_iso()
            _save_regs(regs)
            _audit("reg.reject", u["id"], "registration", reg.get("id"), {"reason": notes})
            flash("Enregistrement rejeté.", "success")
            return redirect(url_for("supervisor_dashboard"))

        if action == "needs_correction":
            if not correction_reason:
                flash("Motif requis pour demander une correction.", "warning")
                return redirect(url_for("supervisor_review", reg_id=reg_id))
            reg["status"] = STATUS_NEEDS_CORRECTION
            _dequeue_for_admin(reg_id)
            reg["correction_reason"] = correction_reason
            reg["qc_notes"] = notes
            reg["verified_by"] = u["id"]
            reg["verified_at"] = _now_iso()
            _save_regs(regs)
            _audit("reg.needs_correction", u["id"], "registration", reg.get("id"), {"reason": correction_reason})
            flash("Correction demandée à l’agent.", "success")
            return redirect(url_for("supervisor_dashboard"))

        if action == "back_to_pending":
            reg["status"] = STATUS_PENDING
            reg["verified_by"] = ""
            reg["verified_at"] = ""
            reg["supervisor_verified"] = False
            reg["supervisor_verified_by"] = ""
            reg["supervisor_verified_at"] = ""
            reg["supervisor_status"] = ""
            reg["needs_admin_approval"] = False
            reg["need_admin_approval"] = False
            reg["awaiting_admin_approval"] = False
            reg["approval_stage"] = ""
            reg["admin_approved"] = False
            reg["admin_approved_by"] = None
            reg["admin_approved_at"] = None
            reg["approved_by"] = ""
            reg["approved_at"] = ""
            reg["voter_number"] = ""
            reg["polling_center"] = ""
            reg["polling_station"] = ""
            reg["notes"] = notes
            reg["qc_notes"] = ""
            reg["correction_reason"] = ""
            _save_regs(regs)
            _audit("reg.reset_pending", u["id"], "registration", reg.get("id"), {})
            flash("Enregistrement remis en attente.", "success")
            return redirect(url_for("supervisor_dashboard"))

    return render_template(
        "supervisor/review.html",
        reg=reg,
        creator=_find_user(reg.get("created_by")),
        zone_name=_zone_name(reg.get("zone_id")),
        format_date=_format_date,
        centers=centers,
    )


# Supervisor SMS for zone
@app.route("/supervisor/sms", methods=["GET", "POST"])
@role_required("supervisor")
def supervisor_sms():
    u = current_user()
    _process_due_campaigns(u["id"])  # scheduled for this user too

    regs = _get_regs()
    zone_id = u.get("zone_id")
    in_zone = [r for r in regs if r.get("zone_id") == zone_id]
    centers = sorted({(r.get("polling_center") or "").strip() for r in in_zone if (r.get("polling_center") or "").strip()})

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "").strip()
        if action in ("send_now", "schedule"):
            polling_center = (request.form.get("polling_center") or "").strip()
            status_filter = (request.form.get("status_filter") or "").strip()
            only_missing_voter = bool(request.form.get("only_missing_voter") == "on")
            message = (request.form.get("message") or "").strip()
            scheduled_at = (request.form.get("scheduled_at") or "").strip()

            if not message:
                flash("Message requis.", "warning")
                return redirect(url_for("supervisor_sms"))

            camps = _get_sms_campaigns()
            camp = {
                "id": str(uuid.uuid4()),
                "created_at": _now_iso(),
                "created_by": u["id"],
                "zone_id": zone_id,
                "polling_center": polling_center,
                "status_filter": status_filter,
                "only_missing_voter": only_missing_voter,
                "message": message,
                "scheduled_at": _now_iso() if action == "send_now" else scheduled_at,
                "status": "SCHEDULED",
                "sent_count": 0,
                "total_count": 0,
            }
            if action == "schedule":
                try:
                    _ = _dt_from_iso(scheduled_at)
                except Exception:
                    flash("Date/heure programmée invalide (format ISO).", "warning")
                    return redirect(url_for("supervisor_sms"))

            camps.append(camp)
            _save_sms_campaigns(camps)
            _audit("sms.schedule", u["id"], "sms", camp["id"], {"role": "supervisor"})
            flash("Campagne créée.", "success")
            _process_due_campaigns(u["id"])
            return redirect(url_for("supervisor_sms"))

        if action == "run_due":
            _process_due_campaigns(u["id"])
            flash("Traitement terminé (ou limité par sécurité).", "success")
            return redirect(url_for("supervisor_sms"))

    camps = _get_sms_campaigns()
    camps_zone = [c for c in camps if (c.get("zone_id") or "") == zone_id]
    camps_zone = sorted(camps_zone, key=lambda c: c.get("created_at") or "", reverse=True)[:50]

    return render_template(
        "supervisor/sms.html",
        centers=centers,
        camps=camps_zone,
        statuses=[STATUS_PENDING, STATUS_VERIFIED, STATUS_APPROVED, STATUS_REJECTED, STATUS_NEEDS_CORRECTION],
    )


# ----------------------------
# Agent routes
# ----------------------------

@app.route("/agent")
@role_required("agent")
def agent_dashboard():
    u = current_user()
    regs = _get_regs()
    mine = [r for r in regs if r.get("created_by") == u.get("id")]

    # counts
    counts = {
        "total": len(mine),
        "draft": sum(1 for r in mine if r.get("status") == STATUS_DRAFT),
        "pending": sum(1 for r in mine if r.get("status") == STATUS_PENDING),
        "needs": sum(1 for r in mine if r.get("status") == STATUS_NEEDS_CORRECTION),
        "verified": sum(1 for r in mine if r.get("status") == STATUS_VERIFIED),
        "approved": sum(1 for r in mine if r.get("status") == STATUS_APPROVED),
        "rejected": sum(1 for r in mine if r.get("status") == STATUS_REJECTED),
    }

    mine_sorted = sorted(mine, key=lambda r: r.get("created_at", ""), reverse=True)
    page = request.args.get("page", "1")
    pag = _paginate(mine_sorted, int(page) if str(page).isdigit() else 1, 10)

    # payroll preview
    payroll_items = _get_payroll()
    periods = _periods_for_user(u["id"], regs)

    pay_rows: List[Dict[str, Any]] = []
    for p in periods[-12:]:
        start_iso = p["start_iso"]
        end_iso = p["end_iso"]
        # Count dossiers in the period (used when no payslip exists yet).
        count_calc = _count_regs_in_period(u["id"], regs, p["start"], p["end"])
        if count_calc <= 0:
            continue

        gross_calc = _calc_amount(count_calc)
        advance_calc = _sum_advances(u["id"], payroll_items, start_iso, end_iso)
        balance_calc = max(0, gross_calc - advance_calc)

        rec = _find_payslip(u["id"], start_iso, end_iso, payroll_items)

        # IMPORTANT:
        # - A period is considered "paid" only if the admin explicitly marked it paid
        #   (status=PAID + paid_at + paid_by).
        # - When a payslip exists (generated/locked/paid), we display the *locked* values
        #   stored on the payslip instead of recalculating from current dossiers.
        if rec:
            is_paid = _is_paid_payslip(rec)
            status = "PAID" if is_paid else (rec.get("status") or "GENERATED")

            count = int(rec.get("count") or count_calc)
            gross = int(rec.get("gross_amount") or gross_calc)
            advance = int(rec.get("advance_amount") or advance_calc)
            amount = int(rec.get("balance_amount") or rec.get("amount") or max(0, gross - advance))
            paid_at = rec.get("paid_at") or ""
        else:
            status = "NOT_GENERATED"
            count = count_calc
            gross = gross_calc
            advance = advance_calc
            amount = balance_calc
            paid_at = ""
        pay_rows.append(
            {
                "label": _period_label(start_iso, end_iso),
                "count": count,
                "gross": gross,
                "advance": advance,
                "amount": amount,
                "amount_fmt": _format_money_cfa(amount),
                "status": (str(status).strip().upper() if status else "NOT_GENERATED"),
                "paid_at": paid_at,
            }
        )

    upcoming = [r for r in pay_rows if r["status"] != "PAID"]
    paid = [r for r in pay_rows if r["status"] == "PAID"]
    upcoming_total = sum(r["amount"] for r in upcoming)
    paid_total = sum(r["amount"] for r in paid)

    pay_tab = (request.args.get("pay_tab") or "upcoming").strip()
    if pay_tab not in ("upcoming", "paid"):
        pay_tab = "upcoming"

    return render_template(
        "agent/dashboard.html",
        regs=pag["items"],
        pagination=pag,
        counts=counts,
        zone_name=_zone_name(u.get("zone_id")),
        upcoming=upcoming,
        upcoming_total_fmt=_format_money_cfa(upcoming_total),
        paid=paid,
        paid_total_fmt=_format_money_cfa(paid_total),
        pay_tab=pay_tab,
    )


@app.route("/agent/duplicates/check", methods=["POST"])
@role_required("agent")
def agent_check_duplicates():
    u = current_user()
    if not _csrf_validate():
        abort(400)

    nom = (request.form.get("nom") or "").strip()
    prenoms = (request.form.get("prenoms") or "").strip()
    dob = (request.form.get("dob") or "").strip()
    telephone = (request.form.get("telephone") or "").strip()

    regs = _get_regs()
    matches = _find_duplicates(nom, prenoms, dob, telephone, regs)

    # Reduce payload
    out = []
    for r in matches:
        out.append({
            "id": r.get("id"),
            "nom": r.get("nom"),
            "prenoms": r.get("prenoms"),
            "dob": r.get("dob"),
            "telephone": r.get("telephone"),
            "quartier": r.get("quartier"),
            "zone": _zone_name(r.get("zone_id")),
            "status": r.get("status"),
        })

    return jsonify({"matches": out})


@app.route("/agent/registration/new", methods=["GET", "POST"])
@role_required("agent")
def agent_new_registration():
    u = current_user()
    if not u.get("zone_id"):
        flash("Ton compte n'a pas de zone assignée. Demande à l'admin.", "danger")
        return redirect(url_for("agent_dashboard"))

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "save").strip()  # save or draft

        nom = (request.form.get("nom") or "").strip()
        prenoms = (request.form.get("prenoms") or "").strip()
        dob = (request.form.get("dob") or "").strip()
        quartier = (request.form.get("quartier") or "").strip()
        telephone = (request.form.get("telephone") or "").strip()

        if not (nom and prenoms and dob and quartier and telephone):
            flash("Tous les champs sont obligatoires.", "warning")
            return render_template("agent/registration_new.html")

        regs = _get_regs()
        dups = _find_duplicates(nom, prenoms, dob, telephone, regs)
        confirm_dup = (request.form.get("confirm_duplicate") or "").strip() == "yes"
        if dups and not confirm_dup and action != "draft":
            flash("Doublon probable détecté. Coche la confirmation si tu veux enregistrer quand même.", "warning")
            return render_template("agent/registration_new.html", form=request.form, duplicates=dups, format_date=_format_date)

        photos = []
        if request.files.get("photo") and request.files["photo"].filename:
            try:
                stored = _save_upload(request.files["photo"])
                photos.append(stored)
            except Exception as e:
                flash(str(e), "danger")
                return render_template("agent/registration_new.html", form=request.form, duplicates=dups, format_date=_format_date)

        status = STATUS_DRAFT if action == "draft" else STATUS_PENDING

        reg = {
            "id": str(uuid.uuid4()),
            "nom": nom,
            "prenoms": prenoms,
            "dob": dob,
            "quartier": quartier,
            "telephone": telephone,
            "zone_id": u["zone_id"],
            "created_by": u["id"],
            "created_at": _now_iso(),
            "updated_by": u["id"],
            "updated_at": _now_iso(),
            "voter_number": "",
            "polling_center": "",
            "polling_station": "",
            "status": status,
            "verified_by": "",
            "verified_at": "",
            "approved_by": "",
            "approved_at": "",
            "notes": "",
            "qc_notes": "",
            "correction_reason": "",
            "photos": photos,
            "sms_last_at": "",
        }
        regs.append(reg)
        _save_regs(regs)
        _audit("reg.create", u["id"], "registration", reg["id"], {"status": status})

        if status == STATUS_DRAFT:
            flash("Brouillon enregistré. Tu peux le compléter puis l'envoyer.", "success")
        else:
            flash("Enregistrement ajouté. Il sera vérifié par ton superviseur.", "success")

        return redirect(url_for("agent_dashboard"))

    return render_template("agent/registration_new.html", form=None, duplicates=None, format_date=_format_date)


@app.route("/agent/registration/<reg_id>/edit", methods=["GET", "POST"])
@role_required("agent")
def agent_edit_registration(reg_id: str):
    u = current_user()
    regs = _get_regs()
    reg = next((r for r in regs if r.get("id") == reg_id), None)
    if not reg:
        abort(404)
    if reg.get("created_by") != u.get("id"):
        abort(403)

    if reg.get("status") not in (STATUS_DRAFT, STATUS_NEEDS_CORRECTION):
        flash("Ce dossier n'est pas modifiable (déjà en traitement).", "warning")
        return redirect(url_for("agent_dashboard"))

    if request.method == "POST":
        if not _csrf_validate():
            abort(400)

        action = (request.form.get("action") or "save").strip()  # save_draft or submit

        reg["nom"] = (request.form.get("nom") or "").strip()
        reg["prenoms"] = (request.form.get("prenoms") or "").strip()
        reg["dob"] = (request.form.get("dob") or "").strip()
        reg["quartier"] = (request.form.get("quartier") or "").strip()
        reg["telephone"] = (request.form.get("telephone") or "").strip()

        if not (reg["nom"] and reg["prenoms"] and reg["dob"] and reg["quartier"] and reg["telephone"]):
            flash("Tous les champs sont obligatoires.", "warning")
            return render_template("agent/registration_edit.html", reg=reg, format_date=_format_date)

        if request.files.get("photo") and request.files["photo"].filename:
            try:
                stored = _save_upload(request.files["photo"])
                reg.setdefault("photos", []).append(stored)
            except Exception as e:
                flash(str(e), "danger")
                return render_template("agent/registration_edit.html", reg=reg, format_date=_format_date)

        reg["updated_by"] = u["id"]
        reg["updated_at"] = _now_iso()

        if action == "submit":
            reg["status"] = STATUS_PENDING
            reg["qc_notes"] = ""
            reg["correction_reason"] = ""
            flash("Dossier envoyé au superviseur.", "success")
            _audit("reg.submit", u["id"], "registration", reg.get("id"), {})
        else:
            reg["status"] = STATUS_DRAFT
            flash("Brouillon mis à jour.", "success")
            _audit("reg.update_draft", u["id"], "registration", reg.get("id"), {})

        _save_regs(regs)
        return redirect(url_for("agent_dashboard"))

    return render_template("agent/registration_edit.html", reg=reg, format_date=_format_date)


@app.route("/uploads/<filename>")
@login_required
def view_upload(filename: str):
    u = current_user()
    safe = secure_filename(filename)
    path = os.path.join(UPLOADS_DIR, safe)
    if not os.path.exists(path):
        abort(404)

    # Find any reg that references this file, and check permission
    regs = _get_regs()
    reg = next((r for r in regs if safe in (r.get("photos") or [])), None)
    if not reg:
        # Admin can still view
        if u.get("role") != "admin":
            abort(403)
    else:
        if not _can_view_reg(u, reg):
            abort(403)

    return send_file(path, as_attachment=False)


# ----------------------------
@app.route("/admin/backup/download/<name>")
@role_required("admin")
def admin_backup_download(name: str):
    safe = os.path.basename(name)
    path = os.path.join(BACKUPS_DIR, safe)
    if not os.path.isfile(path):
        abort(404)
    _audit("backup.download", current_user()["id"], "backup", safe, {})
    return send_file(path, as_attachment=True, download_name=safe)


# Errors
# ----------------------------

@app.errorhandler(403)
def forbidden(_):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("errors/404.html"), 404


@app.errorhandler(400)
def bad_request(_):
    return render_template("errors/400.html"), 400


# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    _ensure_data_files()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=True)
