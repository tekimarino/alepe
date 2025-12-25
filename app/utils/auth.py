from functools import wraps
from flask import session, redirect, url_for, flash, request
from werkzeug.security import check_password_hash
from .storage import load_json


def _get_active_election_id() -> int:
    settings = load_json("settings.json", default={"active_election_id": 1})
    try:
        return int(settings.get("active_election_id") or 1)
    except Exception:
        return 1


def _get_election_status(election_id: int) -> str:
    elections = load_json("elections.json", default=[])
    for e in elections if isinstance(elections, list) else []:
        try:
            if int(e.get("id") or 0) == int(election_id):
                return str(e.get("status") or "ACTIVE").upper()
        except Exception:
            continue
    return "ACTIVE"


def _enforce_active_election_for_user(u: dict) -> bool:
    """Return True if user can stay logged in for the active election."""
    role = (u.get("role") or "").strip()
    if role not in ("rep", "supervisor"):
        return True

    active_id = _get_active_election_id()
    try:
        user_eid = int(u.get("election_id") or 0)
    except Exception:
        user_eid = 0

    # If election is not active anymore, force re-login.
    if user_eid != active_id:
        return False
    status = _get_election_status(active_id)
    return status == "ACTIVE"

def get_user(username: str):
    users = load_json("users.json", default=[])
    for u in users:
        if u.get("username") == username:
            return u
    return None

def current_user():
    username = session.get("username")
    if not username:
        return None
    u = get_user(username)
    if not u:
        return None
    # If the admin switched the active election, reps/supervisors are forced out.
    if not _enforce_active_election_for_user(u):
        session.clear()
        flash("Votre élection n’est plus active. Veuillez vous reconnecter.", "warning")
        return None
    return u

def authenticate(username: str, password: str):
    u = get_user(username)
    if not u or not u.get("is_active", True):
        return None
    if check_password_hash(u.get("password_hash", ""), password):
        return u
    return None

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u.get("role") not in roles:
                flash("Accès refusé.", "danger")
                return redirect(url_for("index"))
            return view(*args, **kwargs)
        return wrapped
    return decorator
