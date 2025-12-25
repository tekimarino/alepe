import csv
import io
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response

from werkzeug.security import generate_password_hash

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from .utils.storage import load_json, save_json, touch_last_update, DATA_DIR
from .utils.auth import authenticate, current_user, login_required, role_required
from .utils.calc import compute_summary

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    _ensure_seed_data()

    # -------------------------
    # Admin – Simulation (verrouillage “impossible à rattraper”)
    # Hypothèse: taux de participation (par défaut 70%) sur les bureaux restants.
    # -------------------------
    def _get_sim_turnout_rate() -> float:
        settings = load_json("settings.json", default={})
        raw = settings.get("simulation_turnout_rate", 0.70)
        try:
            rate = float(str(raw).replace(",", "."))
        except Exception:
            rate = 0.70
        # Allow user to store "70" instead of "0.7"
        if rate > 1.0:
            rate = rate / 100.0
        # Clamp
        if rate <= 0.0 or rate > 1.0:
            rate = 0.70
        return rate

    def _set_sim_turnout_rate(rate: float):
        settings = load_json("settings.json", default={})
        settings["simulation_turnout_rate"] = float(rate)
        save_json("settings.json", settings)

    def _compute_lock_state(election: dict) -> dict:
        turnout_rate = _get_sim_turnout_rate()

        polling_stations_all = load_json("polling_stations.json", default=[])
        polling_stations = _filter_stations_for_election(polling_stations_all, election)

        candidates = load_active_candidates()
        results = load_active_results()

        # Comptage officiel = PV validés superviseur
        allowed_statuses = {"SUPERVISOR_VALIDATED", "VALIDATED"}  # VALIDATED au cas où (legacy)
        validated_codes = {code for code, r in results.items() if (r.get("status") in allowed_statuses)}

        remaining_stations = [s for s in polling_stations if (s.get("code") not in validated_codes)]
        remaining_registered = 0
        for s in remaining_stations:
            try:
                remaining_registered += int(s.get("registered") or 0)
            except Exception:
                pass

        remaining_possible_votes = int(math.ceil(remaining_registered * turnout_rate))

        summary = compute_summary(
            polling_stations,
            candidates,
            results,
            include_statuses=("SUPERVISOR_VALIDATED", "VALIDATED"),
        )

        ranking = summary.get("candidate_totals") or []
        leader = ranking[0] if ranking else None
        leader_votes = int(leader["votes"]) if leader else 0

        # concurrent le plus fort (max des autres)
        others_max = 0
        if len(ranking) > 1:
            others_max = max(int(c.get("votes") or 0) for c in ranking[1:])

        # Verrouillage (projection taux de participation)
        locked = bool(leader) and (leader_votes > (others_max + remaining_possible_votes))
        votes_needed = 0 if locked else max(0, (others_max + remaining_possible_votes + 1) - leader_votes)

        margin = leader_votes - others_max
        margin_required = remaining_possible_votes + 1  # strictement >
        progress = 1.0 if locked else (margin / margin_required if margin_required > 0 else 0.0)
        if progress < 0:
            progress = 0.0
        if progress > 1:
            progress = 1.0

        meta = load_json("meta.json", default={})
        last_update = meta.get("last_update_utc")

        return {
            "election_label": _election_label(election),
            "last_update_utc": last_update,
            "bureaux_total": summary.get("bureaux_total", 0),
            "bureaux_valides": summary.get("bureaux_submitted", 0),  # ici = validés
            "bureaux_restants": summary.get("bureaux_remaining", 0),
            "turnout_rate": turnout_rate,
            "inscrits_restants": remaining_registered,
            "votes_restants_max": remaining_possible_votes,
            "ranking": ranking,
            "leader": leader,
            "leader_votes": leader_votes,
            "others_max": others_max,
            "margin": margin,
            "margin_required": margin_required,
            "progress": round(progress * 100, 2),
            "locked": locked,
            "votes_needed_to_lock": votes_needed,
            "rule": "V1 > V2 + ceil(taux_participation × inscrits_restants)",
        }

    @app.route("/admin/simulation", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_simulation():
        # Permet de régler le taux de participation depuis l'interface (ex: 70 ou 0.7)
        if request.method == "POST":
            raw = (request.form.get("turnout_rate") or "").strip()
            try:
                rate = float(raw.replace(",", "."))
                if rate > 1.0:
                    rate = rate / 100.0
                if 0.05 <= rate <= 1.0:
                    _set_sim_turnout_rate(rate)
                    flash(f"Taux de participation défini à {int(rate*100)}%.", "success")
                else:
                    flash("Taux invalide. Entrez une valeur entre 5 et 100.", "danger")
            except Exception:
                flash("Taux invalide. Exemple: 70 ou 0,7.", "danger")
            return redirect(url_for("admin_simulation"))

        election = get_active_election()
        data = _compute_lock_state(election)
        return render_template("admin_simulation.html", election=election, data=data)

    @app.get("/admin/simulation/data")
    @login_required
    @role_required("admin")
    def admin_simulation_data():
        election = get_active_election()
        data = _compute_lock_state(election)
        return jsonify(data)

    # -------------------------
    # Export helpers (CSV / PDF)
    # -------------------------
    def _csv_response(rows: list[dict], fieldnames: list[str], filename: str) -> Response:
        sio = io.StringIO()
        writer = csv.DictWriter(sio, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
        data = sio.getvalue().encode("utf-8-sig")  # Excel-friendly
        resp = Response(data, mimetype="text/csv; charset=utf-8")
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp

    def _pdf_lines_response(title: str, lines: list[str], filename: str) -> Response:
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=landscape(A4))
        width, height = landscape(A4)

        margin_x = 36
        y = height - 36
        c.setFont("Helvetica-Bold", 14)
        c.drawString(margin_x, y, title)
        y -= 18
        c.setFont("Helvetica", 9)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        c.drawString(margin_x, y, f"Export généré le {stamp}")
        y -= 18

        c.setFont("Helvetica", 9)
        line_height = 12
        for line in lines:
            if y < 36:
                c.showPage()
                y = height - 36
                c.setFont("Helvetica", 9)
            c.drawString(margin_x, y, line[:220])
            y -= line_height

        c.showPage()
        c.save()
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    
    def _pdf_table_response(title: str, headers: list[str], rows: list[list[str]], filename: str, subtitle: str = "", election_label: str = "", col_widths=None) -> Response:
        """PDF export avec mise en page (table), plus lisible que la version 'lignes'."""
        buf = io.BytesIO()

        page_size = landscape(A4)
        width, height = page_size
        # Marges : on garde une place pour un en-tête dessiné via canvas
        doc = SimpleDocTemplate(
            buf,
            pagesize=page_size,
            leftMargin=14 * mm,
            rightMargin=14 * mm,
            topMargin=28 * mm,
            bottomMargin=14 * mm,
        )

        logo_path = Path(app.root_path) / "static" / "img" / "logo.png"
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        def _on_page(c, d):
            # Bandeau haut
            c.saveState()
            c.setFillColor(colors.HexColor("#0b3d2e"))
            c.rect(0, height - 18 * mm, width, 18 * mm, stroke=0, fill=1)
            # Logo
            if logo_path.exists():
                try:
                    c.drawImage(str(logo_path), 10 * mm, height - 16.5 * mm, width=14 * mm, height=14 * mm, mask="auto")
                except Exception:
                    pass
            # Titre
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 13)
            c.drawString(28 * mm, height - 11.8 * mm, title[:120])

            # Sous-infos (élection / date)
            c.setFont("Helvetica", 9)
            info = []
            if election_label:
                info.append(election_label)
            info.append(f"Export : {stamp}")
            if subtitle:
                info.append(subtitle)
            c.drawRightString(width - 10 * mm, height - 11.2 * mm, " | ".join(info)[:180])

            # Pied de page
            c.setFillColor(colors.HexColor("#444444"))
            c.setFont("Helvetica", 8)
            c.drawString(10 * mm, 8 * mm, "Élections Bonoua — Export")
            c.drawRightString(width - 10 * mm, 8 * mm, f"Page {d.page}")
            c.restoreState()

        # Table
        data = [headers] + rows
        tbl = Table(data, repeatRows=1, colWidths=col_widths)

        style = TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("ALIGN", (0, 0), (-1, 0), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fbfbfb")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
        tbl.setStyle(style)

        doc.build([tbl], onFirstPage=_on_page, onLaterPages=_on_page)
        buf.seek(0)
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

# -------------------------
    # Active election helpers (multi-years / multi-types)
    # -------------------------
    def _load_elections():
        data = load_json("elections.json", default=[])
        return data if isinstance(data, list) else []

    def _save_elections(elections_list):
        save_json("elections.json", elections_list)

    def get_active_election_id() -> int | None:
        """Return the id of the ACTIVE election in settings, or None if none."""
        settings = load_json("settings.json", default={"active_election_id": 0})
        try:
            eid = int(settings.get("active_election_id") or 0)
        except Exception:
            eid = 0
        return eid if eid > 0 else None

    def set_active_election_id(election_id: int | None):
        settings = load_json("settings.json", default={"active_election_id": 0})
        settings["active_election_id"] = int(election_id) if election_id else 0
        save_json("settings.json", settings)

    def get_election_by_id(election_id: int) -> Dict[str, Any] | None:
        for e in _load_elections():
            try:
                if int(e.get("id") or 0) == int(election_id):
                    return e
            except Exception:
                continue
        return None

    def _election_label(e: Dict[str, Any]) -> str:
        t = (e.get("type") or "").strip().title() or "Élection"
        y = e.get("year")
        r = e.get("round")
        c = (e.get("commune") or "").strip() or ""
        bits = [t]
        if c:
            bits.append(c)
        if y:
            bits.append(str(y))
        if r:
            bits.append(f"Tour {r}")
        return " – ".join(bits)

    def get_active_election() -> Dict[str, Any]:
        eid = get_active_election_id()
        if not eid:
            e = {
                "id": 0,
                "type": "",
                "year": None,
                "round": None,
                "commune": "Bonoua",
                "name": "Aucune élection active",
                "status": "NONE",
            }
            e = dict(e)
            e["label"] = "Aucune élection active"
            return e

        e = get_election_by_id(eid) or {
            "id": eid,
            "type": "MUNICIPALE",
            "year": 2028,
            "round": 1,
            "commune": "Bonoua",
            "name": "Municipales – Bonoua",
            "status": "ACTIVE",
        }
        # keep a computed label for UI
        e = dict(e)
        e["label"] = _election_label(e)
        return e


    def _allowed_segments_for_election(election: dict) -> set:
        # If no election is active, show all segments (admin can still manage the reference).
        status = ((election or {}).get("status") or "").upper().strip()
        if status in {"NONE", ""}:
            return {"COMMUNE", "SOUS_PREFECTURE"}

        t = ((election or {}).get("type") or "MUNICIPALE").upper().strip()
        # Support a few variants (e.g. "LEGISLATIVES", accents removed upstream, etc.)
        if t.startswith("LEG"):
            return {"COMMUNE", "SOUS_PREFECTURE"}
        # MUNICIPALE (par défaut) : on limite aux centres/bureaux de la commune
        return {"COMMUNE"}

    def _filter_centers_for_election(centers: list, election: dict) -> list:
        allowed = _allowed_segments_for_election(election)
        etype = (election or {}).get("type") or ""
        is_municipal = str(etype).upper().startswith("MUNIC")
        out = []
        for c in centers or []:
            seg = (c.get("segment") or "COMMUNE").upper().strip()
            if seg not in allowed:
                continue
            # Le flag "municipal" sert uniquement à filtrer les élections municipales.
            # Pour les législatives, on conserve tous les centres autorisés par segment.
            if is_municipal and not bool(c.get("municipal", False)):
                continue
            out.append(c)
        return out

    def _filter_stations_for_election(stations: list, election: dict) -> list:
        allowed = _allowed_segments_for_election(election)
        etype = (election or {}).get("type") or ""
        is_municipal = str(etype).upper().startswith("MUNIC")
        out = []
        for s in stations or []:
            seg = (s.get("segment") or "COMMUNE").upper().strip()
            if seg not in allowed:
                continue
            if is_municipal and not bool(s.get("municipal", False)):
                continue
            out.append(s)
        return out


    def _filter_polling_stations_for_election(stations: list, election: dict) -> list:
        # Compat alias (ancienne fonction appelée par les exports)
        return _filter_stations_for_election(stations, election)

    def _load_candidates_all():
        data = load_json("candidates.json", default={})
        if isinstance(data, list):
            # legacy; treat as active
            return {str(get_active_election_id() or 1): data}
        return data if isinstance(data, dict) else {}

    def load_active_candidates():
        eid = get_active_election_id()
        if not eid:
            return []
        all_c = _load_candidates_all()
        return all_c.get(str(eid), [])

    def save_active_candidates(candidates_list):
        eid = get_active_election_id()
        if not eid:
            raise ValueError("No active election: cannot save candidates")
        all_c = _load_candidates_all()
        all_c[str(eid)] = candidates_list
        save_json("candidates.json", all_c)

    def _load_results_all() -> Dict[str, Any]:
        data = load_json("results.json", default={})
        if isinstance(data, dict):
            # legacy format: station_code -> pv
            keys = list(data.keys())
            looks_like_station_map = any(isinstance(k, str) and (k.startswith("BONOUA-") or k.startswith("ALEPE-") or "-BV" in k) for k in keys[:10])
            looks_like_election_map = any(str(k).isdigit() for k in keys[:10])
            if looks_like_station_map and not looks_like_election_map:
                return {str(get_active_election_id() or 1): data}
            return data
        return {}

    def _save_results_all(results_map: Dict[str, Any]):
        save_json("results.json", results_map)

    def load_active_results() -> Dict[str, Any]:
        eid = get_active_election_id()
        if not eid:
            return {}
        all_r = _load_results_all()
        return all_r.get(str(eid), {})

    def save_active_results(results_dict: Dict[str, Any]):
        eid = get_active_election_id()
        if not eid:
            raise ValueError("No active election: cannot save results")
        all_r = _load_results_all()
        all_r[str(eid)] = results_dict
        _save_results_all(all_r)

    def _is_active_election_open() -> bool:
        return str(get_active_election().get("status") or "").upper() == "ACTIVE"

    @app.context_processor
    def inject_user():
        return {
            "current_user": current_user(),
            "active_election": get_active_election(),
        }

    @app.get("/")
    def index():
        u = current_user()
        if not u:
            return redirect(url_for("login"))
        if u["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        if u["role"] == "rep":
            return redirect(url_for("rep_dashboard"))
        if u["role"] == "supervisor":
            return redirect(url_for("supervisor_dashboard"))
        return redirect(url_for("public_results"))

    # -------------------------
    # Auth
    # -------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            u = authenticate(username, password)
            if u:
                # Reps/supervisors are always scoped to the ACTIVE election.
                if (u.get("role") or "").strip() in ("rep", "supervisor"):
                    if not _is_active_election_open():
                        flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
                        return render_template("login.html")
                    try:
                        active_id = get_active_election_id()
                        if (not active_id) or (int(u.get("election_id") or 0) != active_id):
                            flash("Compte lié à une élection archivée. Contactez l’administrateur.", "danger")
                            return render_template("login.html")
                    except Exception:
                        flash("Compte mal configuré (élection). Contactez l’administrateur.", "danger")
                        return render_template("login.html")
                session["username"] = u["username"]
                flash("Connexion réussie.", "success")
                nxt = request.args.get("next") or url_for("index")
                return redirect(nxt)
            flash("Identifiants invalides.", "danger")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Déconnecté.", "info")
        return redirect(url_for("login"))

    # -------------------------
    # Public results (live)
    # -------------------------
    @app.get("/results")
    def public_results():
        return render_template("public_results.html", election=get_active_election())

    @app.get("/api/results/summary")
    def api_results_summary():
        election = get_active_election()
        polling_stations = load_json("polling_stations.json", default=[])
        polling_stations = _filter_stations_for_election(polling_stations, election)
        candidates = load_active_candidates()
        results = load_active_results()
        meta = load_json("meta.json", default={})
        summary = compute_summary(polling_stations, candidates, results, include_statuses=("SUPERVISOR_VALIDATED",))
        summary["last_update_utc"] = meta.get("last_update_utc")
        return jsonify(summary)

    # -------------------------
    # Representative
    # -------------------------
    @app.get("/rep")
    @login_required
    @role_required("rep")
    def rep_dashboard():
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        election = get_active_election()
        candidates = load_active_candidates()
        polling_stations = load_json("polling_stations.json", default=[])
        results = load_active_results()
        assigned_code = u.get("polling_station_code")

        station = next((s for s in polling_stations if s.get("code") == assigned_code), None)
        existing = results.get(assigned_code) if assigned_code else None

        return render_template(
            "rep_dashboard.html",
            election=election,
            candidates=candidates,
            station=station,
            existing=existing,
        )

    @app.post("/rep/submit")
    @login_required
    @role_required("rep")
    def rep_submit():
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        assigned_code = u.get("polling_station_code")
        if not assigned_code:
            flash("Aucun bureau n’est affecté à votre compte.", "danger")
            return redirect(url_for("rep_dashboard"))

        polling_stations = load_json("polling_stations.json", default=[])
        station = next((s for s in polling_stations if s.get("code") == assigned_code), None)

        candidates = load_active_candidates()
        votes: Dict[str, int] = {}

        # validate votes are integers >= 0
        for c in candidates:
            cid = c["id"]
            raw = request.form.get(f"votes_{cid}", "0").strip()
            if raw == "":
                raw = "0"
            try:
                iv = int(raw)
            except Exception:
                flash("Les voix doivent être des entiers.", "danger")
                return redirect(url_for("rep_dashboard"))
            if iv < 0:
                flash("Les voix ne peuvent pas être négatives.", "danger")
                return redirect(url_for("rep_dashboard"))
            votes[cid] = iv

        total = sum(votes.values())
        if total == 0:
            flash("Impossible d’enregistrer un PV avec 0 voix partout.", "warning")
            return redirect(url_for("rep_dashboard"))

        # Control: total votes cannot exceed registered voters for this polling station
        # (user requirement: total voix d'un PV <= inscrits du bureau)
        if station:
            registered = _safe_int(station.get("registered"), default=0)
            if registered > 0 and total > registered:
                flash(
                    f"PV invalide : total des voix ({total}) supérieur au nombre d’inscrits du bureau ({registered}).",
                    "danger",
                )
                return redirect(url_for("rep_dashboard"))

        results = load_active_results()
        existing = results.get(assigned_code, {}) or {}

        # Lock: once supervisor validated, representatives cannot overwrite the PV
        if existing.get("status") == "SUPERVISOR_VALIDATED":
            flash("PV déjà validé par le superviseur. Contactez l’admin en cas d’erreur.", "danger")
            return redirect(url_for("rep_dashboard"))

        now = datetime.now(timezone.utc).isoformat()

        # center info (useful for supervisor filtering / reporting)
        center_code = station.get("centre_code") if station else None
        center_name = station.get("centre_name") if station else None

        results[assigned_code] = {
            "polling_station_code": assigned_code,
            "polling_station_name": station.get("name") if station else assigned_code,
            "centre_code": center_code,
            "centre_name": center_name,
            "votes": votes,
            "total_votes": total,
            "status": "SUBMITTED",
            "submitted_by": u["username"],
            "submitted_at_utc": now,
            # supervisor decision fields (reset on each new submission)
            "supervisor_decided_by": None,
            "supervisor_decided_at_utc": None,
            "supervisor_comment": None,
        }

        save_active_results(results)
        touch_last_update()
        flash("PV soumis au superviseur. Merci !", "success")
        return redirect(url_for("rep_dashboard"))


    # -------------------------
    # Superviseur (Centre de vote)
    # -------------------------
    def _assert_station_in_center(code: str, center_code: str, stations: list[dict]) -> dict | None:
        station = next((s for s in stations if s.get("code") == code), None)
        if not station:
            return None
        if station.get("centre_code") != center_code:
            return None
        return station

    @app.get("/supervisor")
    @login_required
    @role_required("supervisor")
    def supervisor_dashboard():
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        centers = load_json("voting_centers.json", default=[])
        stations = load_json("polling_stations.json", default=[])
        results = load_active_results()

        center_code = (u.get("center_code") or "").strip()
        center = next((c for c in centers if c.get("code") == center_code), None)
        if not center_code or not center:
            flash("Aucun centre n’est affecté à votre compte superviseur. Contactez l’administrateur.", "danger")
            return redirect(url_for("index"))

        stations_center = [s for s in stations if s.get("centre_code") == center_code]

        items = []
        for s in stations_center:
            code = s.get("code")
            r = results.get(code) or {}
            items.append({
                "code": code,
                "station": s,
                "has_pv": True if results.get(code) else False,
                "status": r.get("status"),
                "submitted_by": r.get("submitted_by"),
                "submitted_at_utc": r.get("submitted_at_utc"),
                "supervisor_decided_by": r.get("supervisor_decided_by"),
                "supervisor_decided_at_utc": r.get("supervisor_decided_at_utc"),
                "supervisor_comment": r.get("supervisor_comment"),
                "total_votes": r.get("total_votes", 0),
            })
        items.sort(key=lambda x: x["code"])

        stats = {
            "bureaux_total": len(stations_center),
            "pv_soumis": sum(1 for it in items if it.get("status") == "SUBMITTED"),
            "pv_valides": sum(1 for it in items if it.get("status") == "SUPERVISOR_VALIDATED"),
            "pv_rejetes": sum(1 for it in items if it.get("status") == "SUPERVISOR_REJECTED"),
        }

        return render_template("supervisor_dashboard.html", center=center, items=items, stats=stats)

    @app.get("/supervisor/pv/<code>")
    @login_required
    @role_required("supervisor")
    def supervisor_pv(code: str):
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        center_code = (u.get("center_code") or "").strip()
        stations = load_json("polling_stations.json", default=[])
        station = _assert_station_in_center(code, center_code, stations)
        if not station:
            flash("Accès refusé à ce bureau.", "danger")
            return redirect(url_for("supervisor_dashboard"))

        results = load_active_results()
        pv = results.get(code)
        if not pv:
            flash("Aucun PV soumis pour ce bureau.", "warning")
            return redirect(url_for("supervisor_dashboard"))

        candidates = load_active_candidates()
        cand_map = {c["id"]: c for c in candidates}
        votes = pv.get("votes") or {}
        votes_human = []
        for cid in votes.keys():
            c = cand_map.get(cid, {"name": cid, "party": ""})
            votes_human.append({
                "id": cid,
                "name": c.get("name", cid),
                "party": c.get("party", ""),
                "votes": votes.get(cid, 0),
            })
        votes_human.sort(key=lambda x: x["name"])

        return render_template("supervisor_pv.html", station=station, pv=pv, votes=votes_human)

    @app.post("/supervisor/pv/<code>/validate")
    @login_required
    @role_required("supervisor")
    def supervisor_validate_pv(code: str):
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        center_code = (u.get("center_code") or "").strip()
        stations = load_json("polling_stations.json", default=[])
        station = _assert_station_in_center(code, center_code, stations)
        if not station:
            flash("Accès refusé à ce bureau.", "danger")
            return redirect(url_for("supervisor_dashboard"))

        results = load_active_results()
        if code not in results:
            flash("PV introuvable.", "danger")
            return redirect(url_for("supervisor_dashboard"))

        registered = _safe_int(station.get("registered"), default=0)
        total = int(results[code].get("total_votes") or 0)
        if registered > 0 and total > registered:
            flash(
                f"Validation refusée : total des voix ({total}) supérieur au nombre d’inscrits ({registered}).",
                "danger",
            )
            return redirect(url_for("supervisor_pv", code=code))

        comment = (request.form.get("comment") or "").strip()

        results[code]["status"] = "SUPERVISOR_VALIDATED"
        results[code]["supervisor_decided_by"] = u["username"]
        results[code]["supervisor_decided_at_utc"] = datetime.now(timezone.utc).isoformat()
        results[code]["supervisor_comment"] = comment or None

        save_active_results(results)
        touch_last_update()
        flash("PV validé. Il est maintenant comptabilisé dans les résultats publics.", "success")
        return redirect(url_for("supervisor_dashboard"))

    @app.post("/supervisor/pv/<code>/reject")
    @login_required
    @role_required("supervisor")
    def supervisor_reject_pv(code: str):
        u = current_user()
        if not _is_active_election_open():
            flash("Aucune élection active en ce moment. Contactez l’administrateur.", "danger")
            return redirect(url_for("logout"))
        center_code = (u.get("center_code") or "").strip()
        stations = load_json("polling_stations.json", default=[])
        station = _assert_station_in_center(code, center_code, stations)
        if not station:
            flash("Accès refusé à ce bureau.", "danger")
            return redirect(url_for("supervisor_dashboard"))

        results = load_active_results()
        if code not in results:
            flash("PV introuvable.", "danger")
            return redirect(url_for("supervisor_dashboard"))

        comment = (request.form.get("comment") or "").strip()
        if not comment:
            flash("Motif obligatoire pour rejeter un PV.", "danger")
            return redirect(url_for("supervisor_pv", code=code))

        results[code]["status"] = "SUPERVISOR_REJECTED"
        results[code]["supervisor_decided_by"] = u["username"]
        results[code]["supervisor_decided_at_utc"] = datetime.now(timezone.utc).isoformat()
        results[code]["supervisor_comment"] = comment

        save_active_results(results)
        touch_last_update()
        flash("PV rejeté. Le représentant devra corriger puis soumettre à nouveau.", "warning")
        return redirect(url_for("supervisor_dashboard"))


    # -------------------------
    # Admin
    # -------------------------
    @app.get("/admin")
    @login_required
    @role_required("admin")
    def admin_dashboard():
        election = get_active_election()
        polling_stations = load_json("polling_stations.json", default=[])
        polling_stations = _filter_stations_for_election(polling_stations, election)
        candidates = load_active_candidates()
        results = load_active_results()
        # Public results are computed ONLY from PV validated by the supervisor
        summary = compute_summary(polling_stations, candidates, results, include_statuses=("SUPERVISOR_VALIDATED",))

        total_bureaux = len(polling_stations)
        pv_received = len(results)
        pv_pending = sum(1 for r in results.values() if r.get("status") == "SUBMITTED")
        pv_validated = sum(1 for r in results.values() if r.get("status") == "SUPERVISOR_VALIDATED")
        pv_rejected = sum(1 for r in results.values() if r.get("status") == "SUPERVISOR_REJECTED")
        percent_validated = round((pv_validated * 100 / total_bureaux), 2) if total_bureaux else 0

        # Taux de participation "live" (calculé en temps réel à partir des PV validés par superviseur)
        station_by_code = { (s.get("code") or "").strip(): s for s in polling_stations if (s.get("code") or "").strip() }
        turnout_registered = 0
        turnout_voters = 0
        turnout_bureaux = 0
        for code, r in results.items():
            if (r.get("status") or "") != "SUPERVISOR_VALIDATED":
                continue
            station = station_by_code.get((code or "").strip())
            if not station:
                continue

            # Inscrits (priorité aux valeurs du PV si présentes)
            reg_val = r.get("registered", None)
            if reg_val is None:
                reg_val = station.get("registered", 0)

            # Votants (priorité au champ voters; sinon on reconstruit si possible)
            voters_val = r.get("voters", None)
            if voters_val is None:
                votes_dict = r.get("votes") or {}
                try:
                    votes_sum = sum(int(v) for v in votes_dict.values())
                except Exception:
                    votes_sum = 0
                try:
                    blank = int(r.get("blank_ballots") or 0)
                except Exception:
                    blank = 0
                try:
                    nulls = int(r.get("null_ballots") or 0)
                except Exception:
                    nulls = 0
                voters_val = votes_sum + blank + nulls

            try:
                turnout_registered += int(reg_val or 0)
            except Exception:
                pass
            try:
                turnout_voters += int(voters_val or 0)
            except Exception:
                pass
            turnout_bureaux += 1

        turnout_percent = round((turnout_voters * 100 / turnout_registered), 2) if turnout_registered else 0

        stats = {
            "bureaux_total": total_bureaux,
            "pv_received": pv_received,
            "pv_pending": pv_pending,
            "pv_validated": pv_validated,
            "pv_rejected": pv_rejected,
            "percent_validated": percent_validated,
        }

        return render_template("admin_dashboard.html", election=election, summary=summary, stats=stats, turnout={
            "percent": turnout_percent,
            "voters": turnout_voters,
            "registered": turnout_registered,
            "bureaux": turnout_bureaux,
        })

    @app.route("/admin/elections", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_elections():
        """Créer/activer des élections (type + année). Une seule élection est ACTIVE."""
        elections = _load_elections()
        active_id = get_active_election_id()

        if request.method == "POST":
            # Create a new election (inactive by default). It will not impact the system until activated.
            e_type = (request.form.get("type") or "MUNICIPALE").strip().upper()
            try:
                year = int((request.form.get("year") or "").strip() or "0")
            except Exception:
                year = 0
            try:
                rnd = int((request.form.get("round") or "1").strip() or "1")
            except Exception:
                rnd = 1
            commune = (request.form.get("commune") or "Bonoua").strip() or "Bonoua"
            name = (request.form.get("name") or "").strip() or f"{e_type.title()} – {commune} {year}"

            if e_type not in ("MUNICIPALE", "LEGISLATIVE"):
                flash("Type d’élection invalide.", "danger")
                return redirect(url_for("admin_elections"))
            if year < 1900 or year > 3000:
                flash("Année invalide.", "danger")
                return redirect(url_for("admin_elections"))
            if rnd < 1 or rnd > 2:
                flash("Tour invalide (1 ou 2).", "danger")
                return redirect(url_for("admin_elections"))

            new_id = (max([int(e.get("id") or 0) for e in elections], default=0) + 1) if elections else 1
            elections.append({
                "id": new_id,
                "type": e_type,
                "year": year,
                "round": rnd,
                "commune": commune,
                "name": name,
                "status": "ARCHIVED",  # inactive until activated
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            })
            _save_elections(elections)

            # Ensure per-election containers exist
            cand_all = _load_candidates_all()
            if str(new_id) not in cand_all:
                cand_all[str(new_id)] = []
                save_json("candidates.json", cand_all)

            res_all = _load_results_all()
            if str(new_id) not in res_all:
                res_all[str(new_id)] = {}
                _save_results_all(res_all)

            touch_last_update()
            flash("Élection créée. Activez-la quand elle devient l’élection en cours.", "success")
            return redirect(url_for("admin_elections"))

        elections_sorted = sorted(
            elections,
            key=lambda e: (str(e.get("status") or ""), int(e.get("year") or 0), str(e.get("type") or ""), int(e.get("round") or 0)),
            reverse=True,
        )
        return render_template("admin_elections.html", elections=elections_sorted, active_election_id=(active_id or 0))


    @app.post("/admin/elections/<int:eid>/activate")
    @login_required
    @role_required("admin")
    def admin_election_activate(eid: int):
        elections = _load_elections()
        if not any(int(e.get("id") or 0) == eid for e in elections):
            flash("Élection introuvable.", "danger")
            return redirect(url_for("admin_elections"))

        prev_active_id = get_active_election_id()
        cand_all_before = _load_candidates_all()
        prev_candidates = cand_all_before.get(str(prev_active_id), []) if prev_active_id else []

        # Archive current ACTIVE election, activate the target
        for e in elections:
            if int(e.get("id") or 0) == eid:
                e["status"] = "ACTIVE"
            else:
                if str(e.get("status") or "").upper() == "ACTIVE":
                    e["status"] = "ARCHIVED"
        _save_elections(elections)
        set_active_election_id(eid)

        # Ensure per-election containers exist
        cand_all = _load_candidates_all()
        if str(eid) not in cand_all:
            cand_all[str(eid)] = []
            save_json("candidates.json", cand_all)

        # Si l'élection activée n'a pas de candidats, on copie depuis l'élection active précédente (pratique au démarrage).
        # Cela évite "Aucun candidat" après un simple changement d'élection.
        try:
            if (not cand_all.get(str(eid))) and prev_candidates:
                cand_all[str(eid)] = prev_candidates
                save_json("candidates.json", cand_all)
                flash("Aucun candidat trouvé pour cette élection : la liste a été copiée depuis l’élection précédente. Vérifiez/ajustez si nécessaire.", "warning")
        except Exception:
            pass

        res_all = _load_results_all()
        if str(eid) not in res_all:
            res_all[str(eid)] = {}
            _save_results_all(res_all)

        touch_last_update()
        flash("Élection activée. Le système ne prend désormais en compte que cette élection.", "success")
        return redirect(url_for("admin_elections"))


    @app.post("/admin/elections/<int:eid>/deactivate")
    @login_required
    @role_required("admin")
    def admin_election_deactivate(eid: int):
        elections = _load_elections()
        target = next((e for e in elections if int(e.get("id") or 0) == eid), None)
        if not target:
            flash("Élection introuvable.", "danger")
            return redirect(url_for("admin_elections"))

        if str(target.get("status") or "").upper() != "ACTIVE":
            flash("Seule une élection ACTIVE peut être désactivée.", "warning")
            return redirect(url_for("admin_elections"))

        # Deactivate == archive and remove active election pointer
        target["status"] = "ARCHIVED"
        _save_elections(elections)
        set_active_election_id(None)

        touch_last_update()
        flash("Élection désactivée (archivée). Aucune élection n’est active pour l’instant.", "success")
        return redirect(url_for("admin_elections"))


    @app.route("/admin/candidates", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_candidates():
        elections = _load_elections()
        active_id = get_active_election_id()
        raw_eid = (request.args.get("election_id") or "").strip()
        if raw_eid:
            try:
                view_election_id = int(raw_eid)
            except Exception:
                view_election_id = 0
        else:
            view_election_id = int(active_id or 0)

        if view_election_id == 0:
            flash("Aucune élection active. Activez une élection pour accéder aux modules.", "warning")
            return redirect(url_for("admin_elections"))

        can_edit = (view_election_id == active_id and _is_active_election_open())

        cand_all = _load_candidates_all()
        candidates = cand_all.get(str(view_election_id), [])

        if request.method == "POST":
            if not can_edit:
                flash("Cette élection n'est pas active (ou est fermée). Modifications interdites.", "danger")
                return redirect(url_for("admin_candidates", election_id=view_election_id))

            name = request.form.get("name", "").strip()
            party = request.form.get("party", "").strip()

            if not name:
                flash("Nom du candidat requis.", "danger")
                return redirect(url_for("admin_candidates"))

            # Photo upload (optional)
            photo_url = ""
            file = request.files.get("photo")
            if file and file.filename:
                ext = os.path.splitext(file.filename)[1].lower()
                if ext not in (".png", ".jpg", ".jpeg", ".webp"):
                    flash("Format d’image non supporté.", "danger")
                    return redirect(url_for("admin_candidates"))
                safe_name = f"cand_{datetime.now(timezone.utc).timestamp():.0f}{ext}".replace(".", "_", 1)
                # NOTE: directory is defined as UPLOAD_DIR (not UPLOADS_DIR)
                out = UPLOAD_DIR / safe_name
                file.save(out)
                photo_url = url_for("static", filename=f"uploads/{safe_name}")

            # Generate id
            used = {c.get("id") for c in candidates}
            i = 1
            while True:
                cid = f"C{i:03d}"
                if cid not in used:
                    break
                i += 1

            candidates.append({"id": cid, "name": name, "party": party, "photo": photo_url})
            # Only the ACTIVE election can be edited
            cand_all[str(active_id)] = candidates
            save_json("candidates.json", cand_all)

            # Ensure results vote maps contain this candidate with 0
            res = load_active_results()
            for code in res.keys():
                if "votes" not in res[code]:
                    res[code]["votes"] = {}
                res[code]["votes"].setdefault(cid, 0)
            save_active_results(res)

            touch_last_update()
            flash("Candidat ajouté.", "success")
            return redirect(url_for("admin_candidates"))

        return render_template(
            "admin_candidates.html",
            candidates=candidates,
            elections=elections,
            active_election_id=active_id,
            view_election_id=view_election_id,
            can_edit=can_edit,
        )
    @app.route("/admin/candidates/<cid>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_candidate_edit(cid: str):
        if not _is_active_election_open():
            flash("Élection archivée : modification des candidats interdite.", "warning")
            return redirect(url_for("admin_candidates"))

        candidates = load_active_candidates()
        cand = next((c for c in candidates if c.get("id") == cid), None)
        if not cand:
            flash("Candidat introuvable.", "danger")
            return redirect(url_for("admin_candidates"))

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            party = request.form.get("party", "").strip()
            if not name:
                flash("Nom du candidat requis.", "danger")
                return redirect(url_for("admin_candidate_edit", cid=cid))

            # optional new photo
            photo = request.files.get("photo")
            if photo and photo.filename:
                ext = os.path.splitext(photo.filename)[1].lower()
                if ext not in [".png", ".jpg", ".jpeg", ".webp"]:
                    flash("Format image non supporté (png/jpg/webp).", "danger")
                    return redirect(url_for("admin_candidate_edit", cid=cid))
                fname = f"cand_{cid}_{int(datetime.utcnow().timestamp())}{ext}"
                dest = UPLOAD_DIR / fname
                photo.save(dest)
                cand["photo"] = f"/static/uploads/{fname}"

            cand["name"] = name
            cand["party"] = party
            save_active_candidates(candidates)
            touch_last_update()
            flash("Candidat modifié.", "success")
            return redirect(url_for("admin_candidates"))

        return render_template("admin_candidate_edit.html", cand=cand)

    @app.post("/admin/candidates/<cid>/delete")
    @login_required
    @role_required("admin")
    def admin_candidate_delete(cid: str):
        if not _is_active_election_open():
            flash("Élection archivée : suppression des candidats interdite.", "warning")
            return redirect(url_for("admin_candidates"))

        candidates = load_active_candidates()
        if not any(c.get("id") == cid for c in candidates):
            flash("Candidat introuvable.", "danger")
            return redirect(url_for("admin_candidates"))
        candidates = [c for c in candidates if c.get("id") != cid]
        save_active_candidates(candidates)

        # Clean votes in PVs
        results = load_active_results()
        changed = False
        to_delete = []
        for code, r in results.items():
            votes = r.get("votes") or {}
            if cid in votes:
                votes.pop(cid, None)
                r["votes"] = votes
                r["total_votes"] = int(sum(int(v) for v in votes.values()))
                changed = True
                if r["total_votes"] <= 0:
                    to_delete.append(code)
        for code in to_delete:
            results.pop(code, None)
        if changed or to_delete:
            save_active_results(results)

        touch_last_update()
        flash("Candidat supprimé.", "success")
        return redirect(url_for("admin_candidates"))

    

    @app.route("/admin/voting-centers", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_voting_centers():
        centers = load_json("voting_centers.json", default=[])
        # IMPORTANT: centres/bureaux are a global reference, but UI should show
        # only what's relevant to the ACTIVE election type (municipale vs legislative).
        view_election = get_active_election()
        centers = _filter_centers_for_election(centers, view_election)

        if request.method == "POST":
            mode = request.form.get("mode", "").strip()

            if mode == "import":
                f = request.files.get("csv_file")
                if not f or not f.filename:
                    flash("Veuillez choisir un fichier CSV.", "danger")
                    return redirect(url_for("admin_voting_centers"))

                decoded = f.stream.read().decode("utf-8", errors="ignore").splitlines()
                reader = csv.DictReader(decoded)

                # Support both FR (centre_*) and EN (center_*) headers
                fns = set(reader.fieldnames or [])
                required_any = [
                    {"commune", "centre_code", "centre_name", "nb_bureaux", "registered_total"},
                    {"commune", "center_code", "center_name", "nb_bureaux", "registered_total"},
                ]
                if not any(req.issubset(fns) for req in required_any):
                    flash(
                        "CSV invalide. Colonnes requises: commune + (centre_code/center_code) + (centre_name/center_name) + nb_bureaux + registered_total ",
                        "danger",
                    )
                    return redirect(url_for("admin_voting_centers"))

                new_centers = []
                for row in reader:
                    code = (row.get("centre_code") or row.get("center_code") or "").strip()
                    name = (row.get("centre_name") or row.get("center_name") or "").strip()
                    commune = (row.get("commune") or "ALEPE").strip() or "ALEPE"
                    segment = (row.get("segment") or "COMMUNE").strip().upper() or "COMMUNE"
                    nb_bureaux = int((row.get("nb_bureaux") or "0").replace(" ", "") or 0)
                    reg_total = int((row.get("registered_total") or "0").replace(" ", "") or 0)

                    if not code or not name:
                        continue

                    new_centers.append({
                        "code": code.zfill(3),
                        "name": name,
                        "nb_bureaux": nb_bureaux,
                        "registered_total": reg_total,
                        "commune": commune,
                        "segment": segment,
                    })

                save_json("voting_centers.json", new_centers)
                touch_last_update()
                flash(f"Import centres OK: {len(new_centers)} centre(s).", "success")
                return redirect(url_for("admin_voting_centers"))

        # Enrich with PV counts (badges) for quick visibility
        stations = load_json("polling_stations.json", default=[])
        stations = _filter_stations_for_election(stations, view_election)
        # Badges reflect the ACTIVE election only
        results = load_active_results()
        station_by_center = {}
        for s in stations:
            cc = (s.get("centre_code") or "").zfill(3)
            station_by_center.setdefault(cc, []).append(s.get("code"))

        for c in centers:
            cc = (c.get("code") or "").zfill(3)
            codes = station_by_center.get(cc, [])
            pv_total = 0
            pv_pending = 0
            pv_validated = 0
            pv_rejected = 0
            pv_other = 0
            for code in codes:
                r = results.get(code)
                if not r:
                    continue
                pv_total += 1
                st = (r.get("status") or "").upper()
                if st == "SUPERVISOR_VALIDATED":
                    pv_validated += 1
                elif st == "SUPERVISOR_REJECTED":
                    pv_rejected += 1
                elif st == "SUBMITTED":
                    pv_pending += 1
                else:
                    pv_other += 1

            c["pv_total"] = pv_total
            c["pv_pending"] = pv_pending
            c["pv_validated"] = pv_validated
            c["pv_rejected"] = pv_rejected
            c["pv_other"] = pv_other
            c["pv_missing"] = max(0, len(codes) - pv_total)

        centers_sorted = sorted(centers, key=lambda x: (x.get("code") or ""))
        return render_template(
            "admin_voting_centers.html",
            centers=centers_sorted,
            view_election=view_election,
        )


    @app.route("/admin/voting-centers/export.csv")
    @login_required
    @role_required("admin")
    def admin_voting_centers_export_csv():
        centers_all = load_json("voting_centers.json", default=[])
        view_election = get_active_election()
        centers_scope = _filter_centers_for_election(centers_all, view_election)
        rows = []
        for c in sorted(centers_scope, key=lambda x: (x.get("code") or "")):
            rows.append({
                "commune": c.get("commune") or "",
                "centre_code": c.get("code") or "",
                "centre_name": c.get("name") or "",
                "nb_bureaux": int(c.get("nb_bureaux") or 0),
                "registered_total": int(c.get("registered_total") or 0),
                "segment": c.get("segment") or "",
            })
        label = (view_election.get("type") or "election").lower() or "election"
        year = view_election.get("year") or ""
        filename = f"centres_vote_{label}_{year}.csv" if year else f"centres_vote_{label}.csv"
        return _csv_response(rows, ["commune", "centre_code", "centre_name", "nb_bureaux", "registered_total", "segment"], filename)


    @app.route("/admin/voting-centers/export.pdf")
    @login_required
    @role_required("admin")
    def admin_voting_centers_export_pdf():
        centers_all = load_json("voting_centers.json", default=[])
        try:
            view_election_id = int(request.args.get("election_id") or 0)
        except Exception:
            view_election_id = 0
        election = (get_election_by_id(view_election_id) if view_election_id > 0 else None) or get_active_election() or {}
        centers_scope = _filter_centers_for_election(centers_all, election)
        label = _election_label(election) if election else "Aucune élection active"
        headers = ["Code", "Nom du centre", "Bureaux", "Inscrits", "Segment"]
        rows = []
        for c in sorted(centers_scope, key=lambda x: (x.get("code") or "")):
            code = (c.get("code") or "").strip()
            name = (c.get("name") or "").strip()
            nb = int(c.get("nb_bureaux") or 0)
            reg = int(c.get("registered_total") or 0)
            seg = (c.get("segment") or "").strip()
            rows.append([code, name, str(nb), f"{reg:,}".replace(",", " "), seg])
        filename = f"centres_vote_{(election.get('type') or 'election').lower()}_{election.get('year') or ''}.pdf".replace("__", "_")
        return _pdf_table_response("Centres de vote", headers, rows, filename, election_label=label, col_widths=[20*mm, 160*mm, 25*mm, 30*mm, 34*mm])




    @app.route("/admin/voting-centers/<centre_code>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_voting_center_edit(centre_code: str):
        centers = load_json("voting_centers.json", default=[])
        stations = load_json("polling_stations.json", default=[])
        centre_code = (centre_code or "").strip().zfill(3)
        center = next((c for c in centers if (c.get("code") or "").zfill(3) == centre_code), None)
        if not center:
            flash("Centre introuvable.", "danger")
            return redirect(url_for("admin_voting_centers"))

        if request.method == "POST":
            new_code = (request.form.get("code") or centre_code).strip().zfill(3)
            new_name = (request.form.get("name") or "").strip()
            commune = (request.form.get("commune") or (center.get("commune") or "ALEPE")).strip() or "ALEPE"
            if not new_name:
                flash("Nom du centre requis.", "danger")
                return redirect(url_for("admin_voting_center_edit", centre_code=centre_code))

            # If code changed, cascade to polling stations + users + PV
            if new_code != centre_code:
                if any((c.get("code") or "").zfill(3) == new_code for c in centers):
                    flash("Ce code de centre existe déjà.", "danger")
                    return redirect(url_for("admin_voting_center_edit", centre_code=centre_code))

                # compute future station codes to avoid duplicates
                existing_codes = {s.get("code") for s in stations if s.get("centre_code") != centre_code}
                to_update = [s for s in stations if s.get("centre_code") == centre_code]
                future_codes = []
                for s in to_update:
                    bureau_code = (s.get("bureau_code") or "").strip() or "BV??"
                    prefix = ((s.get("code") or "").split("-")[0] or "").strip().upper() or str(commune).upper()
                    future_codes.append(f"{prefix}-{new_code}-{bureau_code}")
                if len(future_codes) != len(set(future_codes)) or any(fc in existing_codes for fc in future_codes):
                    flash("Changement de code impossible: conflit de codes bureaux.", "danger")
                    return redirect(url_for("admin_voting_center_edit", centre_code=centre_code))

                # Apply cascade
                users = load_json("users.json", default=[])
                results_all = _load_results_all()
                for s in to_update:
                    old_ps_code = s.get("code")
                    bureau_code = (s.get("bureau_code") or "").strip() or "BV??"
                    prefix = ((old_ps_code or "").split("-")[0] or "").strip().upper() or str(commune).upper()
                    new_ps_code = f"{prefix}-{new_code}-{bureau_code}"
                    s["centre_code"] = new_code
                    s["centre_name"] = new_name
                    s["code"] = new_ps_code
                    s["commune"] = prefix
                    s["name"] = f"{new_code} - {new_name} / {bureau_code}"

                    # user assignments
                    for u in users:
                        if u.get("polling_station_code") == old_ps_code:
                            u["polling_station_code"] = new_ps_code

                    # PV keys
                    if old_ps_code:
                        for eid, rmap in results_all.items():
                            if old_ps_code in (rmap or {}):
                                rmap[new_ps_code] = rmap.pop(old_ps_code)
                                rmap[new_ps_code]["polling_station_code"] = new_ps_code

                # Update center itself
                center["code"] = new_code
                centre_code = new_code
                save_json("users.json", users)
                _save_results_all(results_all)
                save_json("polling_stations.json", stations)

            # Update name/commune and refresh stats
            center["name"] = new_name
            center["commune"] = commune
            centers = _recompute_center_stats(centers, stations)
            save_json("voting_centers.json", centers)
            touch_last_update()
            flash("Centre modifié.", "success")
            return redirect(url_for("admin_voting_centers"))

        # compute current totals for display
        centers = _recompute_center_stats(centers, stations)
        center = next((c for c in centers if (c.get("code") or "").zfill(3) == centre_code), center)
        return render_template("admin_voting_center_edit.html", center=center)

    @app.post("/admin/voting-centers/<centre_code>/delete")
    @login_required
    @role_required("admin")
    def admin_voting_center_delete(centre_code: str):
        centre_code = (centre_code or "").strip().zfill(3)
        centers = load_json("voting_centers.json", default=[])
        if not any((c.get("code") or "").zfill(3) == centre_code for c in centers):
            flash("Centre introuvable.", "danger")
            return redirect(url_for("admin_voting_centers"))

        stations = load_json("polling_stations.json", default=[])
        station_count = sum(1 for s in stations if (s.get("centre_code") or "").zfill(3) == centre_code)
        if station_count > 0:
            flash(
                f"Suppression interdite : ce centre contient {station_count} bureau(x). "
                "Supprimez d’abord les bureaux (ou changez leur centre) avant de supprimer le centre.",
                "danger",
            )
            return redirect(url_for("admin_voting_centers"))

        # Centre vide : suppression autorisée
        centers = [c for c in centers if (c.get("code") or "").zfill(3) != centre_code]
        if centers:
            centers = _recompute_center_stats(centers, stations)
        save_json("voting_centers.json", centers)

        touch_last_update()
        flash("Centre supprimé.", "success")
        return redirect(url_for("admin_voting_centers"))



    @app.route("/admin/polling-stations", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_polling_stations():
        stations = load_json("polling_stations.json", default=[])
        view_election = get_active_election()
        stations = _filter_stations_for_election(stations, view_election)

        if request.method == "POST":
            mode = request.form.get("mode", "").strip()

            if mode == "import":
                f = request.files.get("csv_file")
                if not f or not f.filename:
                    flash("Veuillez choisir un fichier CSV.", "danger")
                    return redirect(url_for("admin_polling_stations"))

                decoded = f.stream.read().decode("utf-8", errors="ignore").splitlines()
                reader = csv.DictReader(decoded)

                fns = set(reader.fieldnames or [])
                required_any = [
                    {"polling_station_code", "centre_code", "centre_name", "bureau_code", "registered"},
                    {"polling_station_code", "center_code", "center_name", "bureau_code", "registered"},
                    # legacy path (bureau_num optional)
                    {"polling_station_code", "centre_code", "centre_name", "bureau_num", "registered"},
                    {"polling_station_code", "center_code", "center_name", "bureau_num", "registered"},
                ]
                if not any(req.issubset(fns) for req in required_any):
                    flash(
                        "CSV invalide. Colonnes requises: polling_station_code + (centre_code/center_code) + (centre_name/center_name) + (bureau_code ou bureau_num) + registered (segment optionnel)",
                        "danger",
                    )
                    return redirect(url_for("admin_polling_stations"))

                new_stations = []
                for row in reader:
                    code = (row.get("polling_station_code") or "").strip()
                    centre_code = (row.get("centre_code") or row.get("center_code") or "").strip().zfill(3)
                    centre_name = (row.get("centre_name") or row.get("center_name") or "").strip()
                    bureau_code = (row.get("bureau_code") or "").strip() or None
                    segment = (row.get("segment") or "COMMUNE").strip().upper() or "COMMUNE"
                    registered = int((row.get("registered") or "0").replace(" ", "") or 0)

                    if not code or not centre_code:
                        continue

                    if not centre_name:
                        centre_name = centre_code

                    if not bureau_code:
                        # fallback from bureau_num
                        try:
                            bn = int((row.get("bureau_num") or "0").strip() or 0)
                            bureau_code = f"BV{bn:02d}" if bn else "BV??"
                        except Exception:
                            bureau_code = "BV??"

                    new_stations.append({
                        "code": code,
                        "name": f"{centre_code} - {centre_name} / {bureau_code}",
                        "centre_code": centre_code,
                        "centre_name": centre_name,
                        "bureau_code": bureau_code,
                        "registered": registered,
                        "segment": segment,
                    })

                save_json("polling_stations.json", new_stations)
                # refresh center stats if centers exist
                centers = load_json("voting_centers.json", default=[])
                if centers:
                    centers = _recompute_center_stats(centers, new_stations)
                    save_json("voting_centers.json", centers)
                touch_last_update()
                flash(f"Import bureaux OK: {len(new_stations)} bureau(x).", "success")
                return redirect(url_for("admin_polling_stations"))

        return render_template(
            "admin_polling_stations.html",
            stations=stations,
            view_election=view_election,
        )


    @app.route("/admin/polling-stations/export.csv")
    @login_required
    @role_required("admin")
    def admin_polling_stations_export_csv():
        stations_all = load_json("polling_stations.json", default=[])
        view_election = get_active_election()
        stations_scope = _filter_polling_stations_for_election(stations_all, view_election)
        rows = []
        for s in sorted(stations_scope, key=lambda x: (x.get("code") or "")):
            rows.append({
                "polling_station_code": s.get("code") or "",
                "centre_code": s.get("centre_code") or "",
                "centre_name": s.get("centre_name") or "",
                "bureau_code": s.get("bureau_code") or "",
                "registered": int(s.get("registered") or 0),
                "segment": s.get("segment") or "",
            })
        label = (view_election.get("type") or "election").lower() or "election"
        year = view_election.get("year") or ""
        filename = f"bureaux_vote_{label}_{year}.csv" if year else f"bureaux_vote_{label}.csv"
        return _csv_response(rows, ["polling_station_code", "centre_code", "centre_name", "bureau_code", "registered", "segment"], filename)


    @app.route("/admin/polling-stations/export.pdf")
    @login_required
    @role_required("admin")
    def admin_polling_stations_export_pdf():
        stations_all = load_json("polling_stations.json", default=[])
        try:
            view_election_id = int(request.args.get("election_id") or 0)
        except Exception:
            view_election_id = 0
        election = (get_election_by_id(view_election_id) if view_election_id > 0 else None) or get_active_election() or {}
        stations_scope = _filter_polling_stations_for_election(stations_all, election)
        label = _election_label(election) if election else "Aucune élection active"
        headers = ["Code", "Centre", "Nom du centre", "Bureau", "Inscrits", "Segment"]
        rows = []
        for s in sorted(stations_scope, key=lambda x: (x.get("code") or "")):
            code = (s.get("code") or "").strip()
            ccode = (s.get("centre_code") or "").strip()
            cname = (s.get("centre_name") or "").strip()
            bcode = (s.get("bureau_code") or "").strip()
            reg = int(s.get("registered") or 0)
            seg = (s.get("segment") or "").strip()
            rows.append([code, ccode, cname, bcode, f"{reg:,}".replace(",", " "), seg])
        filename = f"bureaux_vote_{(election.get('type') or 'election').lower()}_{election.get('year') or ''}.pdf".replace("__", "_")
        return _pdf_table_response("Bureaux de vote", headers, rows, filename, election_label=label, col_widths=[65*mm, 18*mm, 120*mm, 20*mm, 22*mm, 24*mm])

    @app.route("/admin/polling-stations/<ps_code>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_polling_station_edit(ps_code: str):
        stations = load_json("polling_stations.json", default=[])
        centers = load_json("voting_centers.json", default=[])
        station = next((s for s in stations if s.get("code") == ps_code), None)
        if not station:
            flash("Bureau introuvable.", "danger")
            return redirect(url_for("admin_polling_stations"))

        if request.method == "POST":
            centre_code = (request.form.get("centre_code") or station.get("centre_code") or "").strip().zfill(3)
            bureau_code = (request.form.get("bureau_code") or station.get("bureau_code") or "").strip() or "BV??"
            registered = _safe_int(request.form.get("registered"), default=int(station.get("registered") or 0))

            centre_name = next((c.get("name") for c in centers if (c.get("code") or "").zfill(3) == centre_code), station.get("centre_name") or centre_code)

            old_code = station.get("code")
            prefix = ((old_code or "").split("-")[0] if old_code else "").strip().upper() or "ALEPE"
            new_code = f"{prefix}-{centre_code}-{bureau_code}"

            if new_code != old_code and any(s.get("code") == new_code for s in stations):
                flash("Impossible: ce code de bureau existe déjà.", "danger")
                return redirect(url_for("admin_polling_station_edit", ps_code=ps_code))

            # Update station
            station["centre_code"] = centre_code
            station["centre_name"] = centre_name
            station["bureau_code"] = bureau_code
            station["registered"] = registered
            station["name"] = f"{centre_code} - {centre_name} / {bureau_code}"
            station["code"] = new_code
            station["commune"] = prefix

            # Cascade updates if code changed
            if new_code != old_code:
                users = load_json("users.json", default=[])
                results_all = _load_results_all()
                for u in users:
                    if u.get("polling_station_code") == old_code:
                        u["polling_station_code"] = new_code
                if old_code:
                    for eid, rmap in results_all.items():
                        if old_code in (rmap or {}):
                            rmap[new_code] = rmap.pop(old_code)
                            rmap[new_code]["polling_station_code"] = new_code
                save_json("users.json", users)
                _save_results_all(results_all)
                ps_code = new_code

            save_json("polling_stations.json", stations)
            # refresh center stats
            if centers:
                centers = _recompute_center_stats(centers, stations)
                save_json("voting_centers.json", centers)
            touch_last_update()
            flash("Bureau modifié.", "success")
            return redirect(url_for("admin_polling_stations"))

        return render_template("admin_polling_station_edit.html", station=station, centers=centers)

    @app.post("/admin/polling-stations/<ps_code>/delete")
    @login_required
    @role_required("admin")
    def admin_polling_station_delete(ps_code: str):
        stations = load_json("polling_stations.json", default=[])
        if not any(s.get("code") == ps_code for s in stations):
            flash("Bureau introuvable.", "danger")
            return redirect(url_for("admin_polling_stations"))

        results_all = _load_results_all()
        has_pv_any = any(ps_code in (rmap or {}) for rmap in results_all.values())
        if has_pv_any:
            flash("Suppression interdite : ce bureau a déjà un PV. Supprimez d’abord le PV.", "danger")
            return redirect(url_for("admin_polling_stations"))

        # suppression autorisée (aucun PV)
        stations = [s for s in stations if s.get("code") != ps_code]
        save_json("polling_stations.json", stations)

        # Clear assignment (un-assign automatiquement)
        users = load_json("users.json", default=[])
        for u in users:
            if u.get("polling_station_code") == ps_code:
                u["polling_station_code"] = None
        save_json("users.json", users)

        # refresh center stats
        centers = load_json("voting_centers.json", default=[])
        if centers:
            centers = _recompute_center_stats(centers, stations)
            save_json("voting_centers.json", centers)

        touch_last_update()
        flash("Bureau supprimé.", "success")
        return redirect(url_for("admin_polling_stations"))


    # -------------------------
    # Helpers (Users / Assignments)
    # -------------------------
    def _assigned_polling_station_codes(
        users_list: list[dict],
        election_id: int | None,
        exclude_username: str | None = None,
    ) -> set[str]:
        """Return polling station codes already assigned to a representative *for a given election*.

        If election_id is None/0, returns an empty set (no active election context).
        """
        try:
            election_id_int = int(election_id or 0)
        except Exception:
            election_id_int = 0
        if election_id_int == 0:
            return set()

        assigned: set[str] = set()
        for uu in users_list:
            if (uu.get("role") or "").lower() != "rep":
                continue
            if int(uu.get("election_id") or 0) != election_id_int:
                continue
            if exclude_username and uu.get("username") == exclude_username:
                continue
            code = (uu.get("polling_station_code") or "").strip()
            if code:
                assigned.add(code)
        return assigned

    def _assigned_center_codes(
        users_list: list[dict],
        election_id: int | None,
        exclude_username: str | None = None,
    ) -> set[str]:
        """Return center codes already assigned to a supervisor *for a given election*.

        If election_id is None/0, returns an empty set (no active election context).
        """
        try:
            election_id_int = int(election_id or 0)
        except Exception:
            election_id_int = 0
        if election_id_int == 0:
            return set()

        assigned: set[str] = set()
        for uu in users_list:
            if (uu.get("role") or "").lower() != "supervisor":
                continue
            if int(uu.get("election_id") or 0) != election_id_int:
                continue
            if exclude_username and uu.get("username") == exclude_username:
                continue
            code = (uu.get("center_code") or "").strip().zfill(3)
            if code:
                assigned.add(code)
        return assigned


    @app.route("/admin/users", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_users():
        users = load_json("users.json", default=[])
        elections = _load_elections()
        active_id = get_active_election_id()
        raw_eid = (request.args.get("election_id") or "").strip()
        if raw_eid:
            try:
                view_election_id = int(raw_eid)
            except Exception:
                view_election_id = 0
        else:
            view_election_id = int(active_id or 0)

        if view_election_id == 0:
            flash("Aucune élection active. Activez une élection pour accéder aux modules.", "warning")
            return redirect(url_for("admin_elections"))
        can_edit = (view_election_id == active_id and _is_active_election_open())
        stations_all = load_json("polling_stations.json", default=[])
        centers = load_json("voting_centers.json", default=[])
        view_election = get_election_by_id(view_election_id) or {}
        stations_scope = _filter_stations_for_election(stations_all, view_election)
        centers_scope = _filter_centers_for_election(centers, view_election)
        station_codes_all = {(s.get("code") or "").strip() for s in stations_all if (s.get("code") or "").strip()}
        # Codes des bureaux valides dans le périmètre de l'élection consultée
        # (sert à valider la sélection lors de l'ajout d'un représentant)
        station_codes_scope = {(s.get("code") or "").strip() for s in stations_scope if (s.get("code") or "").strip()}

        station_map = {((s.get("code") or "").strip()): s for s in stations_all if (s.get("code") or "").strip()}
        center_map = {((c.get("code") or "").strip()): c for c in centers if (c.get("code") or "").strip()}

        # For the "add representative" form: only show polling stations not already assigned
        # (Active election only)
        assigned_codes_view = _assigned_polling_station_codes(users, election_id=view_election_id)
        stations_available = []
        if can_edit:
            stations_available = [s for s in stations_scope if (s.get("code") or "").strip() not in assigned_codes_view]

        if request.method == "POST":
            if not can_edit:
                flash("Cette élection n'est pas active (ou est fermée). Modifications interdites.", "danger")
                return redirect(url_for("admin_users", election_id=view_election_id))

            role = (request.form.get("role", "rep") or "rep").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            full_name = request.form.get("full_name", "").strip()
            contacts = request.form.get("contacts", "").strip()
            polling_station_code = request.form.get("polling_station_code", "").strip() or None
            center_code = request.form.get("center_code", "").strip() or None

            if role not in ("admin", "rep", "supervisor"):
                flash("Rôle invalide.", "danger")
                return redirect(url_for("admin_users"))

            if not username or not password:
                flash("Username et mot de passe requis.", "danger")
                return redirect(url_for("admin_users"))

            if any(x.get("username") == username for x in users):
                flash("Username déjà utilisé.", "danger")
                return redirect(url_for("admin_users"))

            if role == "supervisor":
                if not center_code:
                    flash("Centre requis pour un superviseur.", "danger")
                    return redirect(url_for("admin_users"))
                if center_code not in {c.get("code") for c in centers_scope}:
                    flash("Centre invalide.", "danger")
                    return redirect(url_for("admin_users"))
                if any(
                    (x.get("role") or "") == "supervisor"
                    and (x.get("center_code") or "") == center_code
                    and int(x.get("election_id") or 0) == int(active_id or 0)
                    and x.get("is_active", True)
                    for x in users
                ):
                    flash("Ce centre a déjà un superviseur actif.", "danger")
                    return redirect(url_for("admin_users"))
                polling_station_code = None
            else:
                center_code = None  # not used
                if role == "rep" and not polling_station_code:
                    flash("Bureau requis pour un représentant.", "danger")
                    return redirect(url_for("admin_users"))

                if role == "rep" and polling_station_code:
                    if polling_station_code not in station_codes_scope:
                        flash("Bureau invalide.", "danger")
                        return redirect(url_for("admin_users"))
                    # Enforce uniqueness: a polling station can only be assigned to one representative
                    if polling_station_code in _assigned_polling_station_codes(users, election_id=(active_id or 0)):
                        flash("Ce bureau est déjà affecté à un autre représentant. Choisissez un autre bureau.", "danger")
                        return redirect(url_for("admin_users"))

            # Election scoping
            election_id = None
            if role in ("rep", "supervisor"):
                election_id = active_id

            users.append({
                "username": username,
                "password_hash": generate_password_hash(password),
                "role": role,
                "full_name": full_name,
                "contacts": contacts,
                "polling_station_code": polling_station_code,
                "center_code": center_code,
                "is_active": True,
                "election_id": election_id,
            })
            save_json("users.json", users)
            flash("Utilisateur ajouté.", "success")
            return redirect(url_for("admin_users"))

        # --- Search + pagination for the (potentially large) users list ---
        q = (request.args.get("q") or "").strip()
        q_l = q.lower()
        try:
            page = int(request.args.get("page", "1") or "1")
        except Exception:
            page = 1
        per_page = 20

        def _assignment_text(u: dict) -> str:
            role = (u.get("role") or "").strip()
            if role == "rep":
                code = (u.get("polling_station_code") or "").strip()
                st = station_map.get(code) or {}
                bureau_name = (st.get("name") or "").strip()
                center_code = (st.get("center_code") or "").strip()
                c = center_map.get(center_code) or {}
                center_name = (c.get("name") or "").strip()
                return f"{code} {bureau_name} {center_code} {center_name}".strip()
            if role == "supervisor":
                center_code = (u.get("center_code") or "").strip()
                c = center_map.get(center_code) or {}
                center_name = (c.get("name") or "").strip()
                return f"{center_code} {center_name}".strip()
            return ""

        # List: admins (global) + reps/supervisors for the selected election
        users_for_list = []
        for uu in users:
            r = (uu.get("role") or "").lower()
            if r == "admin":
                users_for_list.append(uu)
            elif r in ("rep", "supervisor") and int(uu.get("election_id") or 0) == view_election_id:
                users_for_list.append(uu)

        users_filtered = users_for_list
        if q_l:
            tmp = []
            for u in users_for_list:
                hay = " ".join([
                    (u.get("username") or ""),
                    (u.get("role") or ""),
                    (u.get("full_name") or ""),
                    (u.get("contacts") or ""),
                    _assignment_text(u),
                ]).lower()
                if q_l in hay:
                    tmp.append(u)
            users_filtered = tmp

        total = len(users_filtered)
        pages = max(1, (total + per_page - 1) // per_page)
        page = max(1, min(page, pages))
        start = (page - 1) * per_page
        end = start + per_page
        users_page = users_filtered[start:end]

        # Build compact pagination links (ints + None for ellipsis)
        def build_page_links(cur: int, last: int):
            if last <= 7:
                return list(range(1, last + 1))
            links = [1]
            left = max(2, cur - 2)
            right = min(last - 1, cur + 2)
            if left > 2:
                links.append(None)
            links.extend(range(left, right + 1))
            if right < last - 1:
                links.append(None)
            links.append(last)
            # Deduplicate while preserving order
            out = []
            for x in links:
                if out and out[-1] == x:
                    continue
                out.append(x)
            return out

        page_links = build_page_links(page, pages)

        return render_template(
            "admin_users.html",
            users=users_page,
            stations=stations_available,
            centers=centers_scope,
            station_map=station_map,
            center_map=center_map,
            elections=elections,
            active_election_id=active_id,
            view_election_id=view_election_id,
            can_edit=can_edit,
            q=q,
            page=page,
            pages=pages,
            total=total,
            per_page=per_page,
            page_links=page_links,
        )


    @app.route("/admin/users/export.csv")
    @login_required
    @role_required("admin")
    def admin_users_export_csv():
        # Export all reps/supervisors for the selected election (or active election), with optional search.
        q = (request.args.get("q") or "").strip().lower()
        try:
            view_election_id = int(request.args.get("election_id") or 0)
        except Exception:
            view_election_id = 0
        if view_election_id <= 0:
            view_election_id = get_active_election_id() or 0

        users = load_json("users.json", default=[])
        stations = load_json("polling_stations.json", default=[])
        centers = load_json("voting_centers.json", default=[])

        # Keep only election-scoped users (rep/supervisor) for the selected election.
        filtered = []
        for u in users:
            role = (u.get("role") or "").strip()
            if role not in ("rep", "supervisor"):
                continue
            try:
                if int(u.get("election_id") or 0) != int(view_election_id):
                    continue
            except Exception:
                continue

            if q:
                hay = " ".join([
                    u.get("username") or "",
                    u.get("full_name") or "",
                    u.get("polling_station_code") or "",
                    u.get("center_code") or "",
                ]).lower()
                # enrich with station/center names
                st = next((s for s in stations if s.get("code") == u.get("polling_station_code")), None)
                if st:
                    hay += " " + (st.get("name") or "").lower()
                    hay += " " + (st.get("centre_name") or "").lower()
                c = next((c for c in centers if (c.get("code") or "").zfill(3) == (u.get("center_code") or "").zfill(3)), None)
                if c:
                    hay += " " + (c.get("name") or "").lower()
                if q not in hay:
                    continue

            filtered.append(u)

        election = get_election_by_id(view_election_id) or {}
        station_map = {s.get("code"): s for s in stations}
        center_map = {(c.get("code") or "").zfill(3): c for c in centers}

        rows = []
        for u in sorted(filtered, key=lambda x: (x.get("role") or "", x.get("username") or "")):
            role = u.get("role") or ""
            ps_code = u.get("polling_station_code") or ""
            st = station_map.get(ps_code) or {}
            ccode = (u.get("center_code") or "")
            if not ccode and st:
                ccode = st.get("centre_code") or ""
            cobj = center_map.get((ccode or "").zfill(3)) or {}
            rows.append({
                "election_id": int(view_election_id or 0),
                "election_type": election.get("type") or "",
                "election_year": election.get("year") or "",
                "role": role,
                "username": u.get("username") or "",
                "full_name": u.get("full_name") or "",
                "contacts": u.get("contacts") or "",
                "polling_station_code": ps_code,
                "polling_station_name": st.get("name") or "",
                "center_code": ccode or "",
                "center_name": cobj.get("name") or (st.get("centre_name") or ""),
                "is_active": "Oui" if u.get("is_active") else "Non",
            })

        label = (election.get("type") or "election").lower() or "election"
        year = election.get("year") or ""
        filename = f"representants_superviseurs_{label}_{year}.csv" if year else f"representants_superviseurs_{label}.csv"
        return _csv_response(
            rows,
            [
                "election_id",
                "election_type",
                "election_year",
                "role",
                "username",
                "full_name",
                "contacts",
                "polling_station_code",
                "polling_station_name",
                "center_code",
                "center_name",
                "is_active",
            ],
            filename,
        )


    @app.route("/admin/users/export.pdf")
    @login_required
    @role_required("admin")
    def admin_users_export_pdf():
        q = (request.args.get("q") or "").strip().lower()
        try:
            view_election_id = int(request.args.get("election_id") or 0)
        except Exception:
            view_election_id = 0
        if view_election_id <= 0:
            view_election_id = get_active_election_id() or 0

        users = load_json("users.json", default=[])
        stations = load_json("polling_stations.json", default=[])
        centers = load_json("voting_centers.json", default=[])
        station_map = {s.get("code"): s for s in stations}
        center_map = {(c.get("code") or "").zfill(3): c for c in centers}

        filtered = []
        for u in users:
            role = (u.get("role") or "").strip()
            if role not in ("rep", "supervisor"):
                continue
            try:
                if int(u.get("election_id") or 0) != int(view_election_id):
                    continue
            except Exception:
                continue

            if q:
                hay = " ".join([
                    u.get("username") or "",
                    u.get("full_name") or "",
                    u.get("polling_station_code") or "",
                    u.get("center_code") or "",
                ]).lower()
                st = station_map.get(u.get("polling_station_code"))
                if st:
                    hay += " " + (st.get("name") or "").lower()
                    hay += " " + (st.get("centre_name") or "").lower()
                c = center_map.get((u.get("center_code") or "").zfill(3))
                if c:
                    hay += " " + (c.get("name") or "").lower()
                if q not in hay:
                    continue

            filtered.append(u)

        election = get_election_by_id(view_election_id) or {}
        label = _election_label(election) if election else f"Élection {view_election_id}"

        headers = ["Username", "Nom complet", "Rôle", "Affectation", "Actif"]
        rows = []
        for u in sorted(filtered, key=lambda x: (x.get("role") or "", x.get("username") or "")):
            role = (u.get("role") or "").strip()
            username = u.get("username") or ""
            fullname = (u.get("full_name") or "").strip()
            active_txt = "Oui" if u.get("is_active", True) else "Non"
            aff = ""
            if role == "rep":
                # PDF export request: show ONLY the polling station name in the "Affectation" column
                ps = (u.get("polling_station_code") or "").strip()
                st = station_map.get(ps) or {}
                aff = (st.get("name") or "").strip() or ps
            elif role == "supervisor":
                # Keep supervisor assignment readable (center name)
                ccode = (u.get("center_code") or "").strip()
                cobj = center_map.get((ccode or "").zfill(3)) or {}
                aff = (cobj.get("name") or "").strip() or ccode

            rows.append([username, fullname, role, aff, active_txt])

        filename = f"representants_superviseurs_{(election.get('type') or 'election').lower()}_{election.get('year') or ''}.pdf".replace("__", "_")
        subtitle = f"Recherche: {q}" if q else ""
        return _pdf_table_response("Représentants & superviseurs", headers, rows, filename, subtitle=subtitle, election_label=label, col_widths=[35*mm, 55*mm, 25*mm, 124*mm, 30*mm])


    @app.route("/admin/users/<username>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_user_edit(username: str):
        users = load_json("users.json", default=[])
        active_id = get_active_election_id()
        can_edit = _is_active_election_open()
        stations_all = load_json("polling_stations.json", default=[])
        centers = load_json("voting_centers.json", default=[])
        station_codes_all = {(s.get("code") or "").strip() for s in stations_all if (s.get("code") or "").strip()}
        # Scope = élection active (les représentants/superviseurs ne s'attachent qu'à l'élection active)
        active_election = get_election_by_id(active_id) or {}
        stations_scope = _filter_stations_for_election(stations_all, active_election)
        centers_scope = _filter_centers_for_election(centers, active_election)
        station_codes_scope = {(s.get("code") or "").strip() for s in stations_scope if (s.get("code") or "").strip()}
        u = next((x for x in users if x.get("username") == username), None)
        if not u:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_users"))

        u_role = (u.get("role") or "").lower()
        u_eid = int(u.get("election_id") or 0)
        # Reps/supervisors are editable only for the ACTIVE election.
        if u_role in ("rep", "supervisor") and u_eid != int(active_id or 0):
            flash("Ce compte appartient à une élection archivée. Lecture seule.", "warning")
            return redirect(url_for("admin_users", election_id=(u_eid or int(active_id or 0) or 0)))

        if request.method == "POST":
            if u_role in ("rep", "supervisor") and not can_edit:
                flash("Élection active fermée. Modifications interdites.", "danger")
                return redirect(url_for("admin_user_edit", username=username))
            if not can_edit:
                flash("Élection active fermée : modifications interdites.", "danger")
                return redirect(url_for("admin_user_edit", username=username))
            role = (request.form.get("role", u.get("role", "rep")) or "rep").strip()
            full_name = request.form.get("full_name", "").strip()
            contacts = request.form.get("contacts", "").strip()
            polling_station_code = request.form.get("polling_station_code", "").strip() or None
            center_code = request.form.get("center_code", "").strip() or None
            is_active = True if request.form.get("is_active") == "on" else False
            new_password = request.form.get("password", "").strip()

            if role not in ("admin", "rep", "supervisor"):
                flash("Rôle invalide.", "danger")
                return redirect(url_for("admin_user_edit", username=username))

            if role == "supervisor":
                if not center_code:
                    flash("Centre requis pour un superviseur.", "danger")
                    return redirect(url_for("admin_user_edit", username=username))
                if center_code not in {c.get("code") for c in centers_scope}:
                    flash("Centre invalide.", "danger")
                    return redirect(url_for("admin_user_edit", username=username))
                if any(
                    x.get("username") != username
                    and x.get("role") == "supervisor"
                    and x.get("center_code") == center_code
                    and int(x.get("election_id") or 0) == int(active_id or 0)
                    and x.get("is_active", True)
                    for x in users
                ):
                    flash("Ce centre a déjà un superviseur actif.", "danger")
                    return redirect(url_for("admin_user_edit", username=username))
                polling_station_code = None
            else:
                center_code = None
                if role == "rep" and not polling_station_code:
                    flash("Bureau requis pour un représentant.", "danger")
                    return redirect(url_for("admin_user_edit", username=username))

                if role == "rep" and polling_station_code:
                    if polling_station_code not in station_codes_scope:
                        flash("Bureau invalide.", "danger")
                        return redirect(url_for("admin_user_edit", username=username))
                    # Enforce uniqueness: a polling station can only be assigned to one representative
                    if polling_station_code in _assigned_polling_station_codes(users, election_id=(active_id or 0), exclude_username=username):
                        flash("Ce bureau est déjà affecté à un autre représentant. Choisissez un autre bureau.", "danger")
                        return redirect(url_for("admin_user_edit", username=username))

            # Election scoping
            if role in ("rep", "supervisor"):
                u["election_id"] = active_id
            else:
                u["election_id"] = None

            u["role"] = role
            u["full_name"] = full_name
            u["contacts"] = contacts
            u["polling_station_code"] = polling_station_code
            u["center_code"] = center_code
            u["is_active"] = is_active
            if new_password:
                u["password_hash"] = generate_password_hash(new_password)

            save_json("users.json", users)
            touch_last_update()
            flash("Utilisateur modifié.", "success")
            return redirect(url_for("admin_users"))

        # Only show unassigned polling stations + the current one (if any)
        assigned_other = _assigned_polling_station_codes(users, election_id=(active_id or 0), exclude_username=username)
        current_code = (u.get("polling_station_code") or "").strip()
        stations_available = [
            s for s in stations_all
            if (s.get("code") or "").strip() not in assigned_other or (s.get("code") or "").strip() == current_code
        ]
        # Only show unassigned centers + the current one (if any)
        assigned_centers_other = _assigned_center_codes(users, election_id=(active_id or 0), exclude_username=username)
        cur_center = (u.get("center_code") or "").strip()
        centers_available = [
            c for c in centers
            if (c.get("code") or "").strip() not in assigned_centers_other or (c.get("code") or "").strip() == cur_center
        ]

        return render_template("admin_user_edit.html", user=u, stations=stations_available, centers=centers_available)


    @app.post("/admin/users/<username>/delete")
    @login_required
    @role_required("admin")
    def admin_user_delete(username: str):
        users = load_json("users.json", default=[])
        active_id = get_active_election_id()
        u = next((x for x in users if x.get("username") == username), None)
        if not u:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_users"))
        if u.get("role") == "admin":
            flash("Suppression d’un admin interdite.", "danger")
            return redirect(url_for("admin_users"))

        # If the representative already submitted a PV for their election, do not allow deletion.
        if (u.get("role") == "rep"):
            eid = int(u.get("election_id") or active_id)
            res_e = _load_results_all().get(str(eid), {})
            if any((pv.get("submitted_by") == username) for pv in res_e.values()):
                flash("Impossible de supprimer ce représentant : il a déjà soumis un PV.", "danger")
                return redirect(url_for("admin_users", election_id=eid))

        users = [x for x in users if x.get("username") != username]
        save_json("users.json", users)
        touch_last_update()
        flash("Utilisateur supprimé.", "success")
        return redirect(url_for("admin_users"))

    

    @app.post("/admin/users/<username>/unassign")
    @login_required
    @role_required("admin")
    def admin_user_unassign(username: str):
        """Désaffecter un représentant (bureau) ou un superviseur (centre) sans supprimer le compte."""
        users = load_json("users.json", default=[])
        u = next((x for x in users if x.get("username") == username), None)
        if not u:
            flash("Utilisateur introuvable.", "danger")
            return redirect(url_for("admin_users"))
        if u.get("role") == "admin":
            flash("Impossible de désaffecter un admin.", "danger")
            return redirect(url_for("admin_users"))

        active_id = get_active_election_id()
        if not _is_active_election_open():
            flash("Élection active fermée : désaffectation interdite.", "danger")
            return redirect(url_for("admin_users", election_id=active_id))
        if (u.get("role") in ("rep", "supervisor")) and int(u.get("election_id") or 0) != active_id:
            flash("Désaffectation interdite : ce compte appartient à une élection archivée.", "danger")
            return redirect(url_for("admin_users", election_id=int(u.get("election_id") or 0)))

        role = (u.get("role") or "").strip()
        if role == "rep":
            if not (u.get("polling_station_code") or "").strip():
                flash("Ce représentant n’a déjà aucun bureau affecté.", "warning")
            else:
                eid = int(u.get("election_id") or active_id)
                res_e = _load_results_all().get(str(eid), {})
                if any((pv.get("submitted_by") == username) for pv in res_e.values()):
                    flash("Désaffectation impossible : ce représentant a déjà soumis un PV.", "danger")
                    return redirect(url_for("admin_users", election_id=eid))
                u["polling_station_code"] = None
                flash("Représentant désaffecté (bureau libéré).", "success")
        elif role == "supervisor":
            if not (u.get("center_code") or "").strip():
                flash("Ce superviseur n’a déjà aucun centre affecté.", "warning")
            else:
                u["center_code"] = None
                flash("Superviseur désaffecté (centre libéré).", "success")
        else:
            flash("Rôle non pris en charge.", "danger")
            return redirect(url_for("admin_users"))

        save_json("users.json", users)
        touch_last_update()

        nxt = (request.args.get("next") or "").strip()
        if nxt and nxt.startswith("/"):
            return redirect(nxt)
        return redirect(url_for("admin_users"))

    @app.route("/admin/assignments", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_assignments():
        """
        Import CSV: username,polling_station_code
        """
        if request.method == "POST":
            active_id = get_active_election_id()
            if not _is_active_election_open():
                flash("Élection active fermée : import d’affectations interdit.", "danger")
                return redirect(url_for("admin_assignments"))
            f = request.files.get("csv_file")
            if not f or not f.filename:
                flash("Veuillez sélectionner un fichier CSV.", "danger")
                return redirect(url_for("admin_assignments"))

            users = load_json("users.json", default=[])
            stations = load_json("polling_stations.json", default=[])
            # For the ACTIVE election, restrict assignments to the relevant segment(s)
            view_election = get_active_election()
            stations_scope = _filter_stations_for_election(stations, view_election)
            station_codes = {s["code"] for s in stations_scope}
            user_map = {u["username"]: u for u in users}

            decoded = f.read().decode("utf-8-sig").splitlines()
            reader = csv.DictReader(decoded)

            required = {"username", "polling_station_code"}
            if not required.issubset(set(reader.fieldnames or [])):
                flash("CSV invalide. Colonnes requises: username,polling_station_code", "danger")
                return redirect(url_for("admin_assignments"))

            # Two-pass import (allows swaps between reps within the CSV)
            desired: dict[str, str] = {}
            errors: list[str] = []

            for row in reader:
                username = (row.get("username") or "").strip()
                code = (row.get("polling_station_code") or "").strip()
                if not username or not code:
                    continue
                if username not in user_map:
                    errors.append(f"Utilisateur introuvable: {username}")
                    continue
                # Import is only for representatives of the ACTIVE election
                uu = user_map.get(username) or {}
                if (uu.get("role") or "").strip() != "rep" or int(uu.get("election_id") or 0) != active_id:
                    errors.append(f"Utilisateur non-éligible (doit être représentant de l’élection active): {username}")
                    continue
                if code not in station_codes:
                    errors.append(f"Bureau introuvable: {code}")
                    continue
                desired[username] = code

            if not desired:
                flash("Aucune affectation valide trouvée dans le CSV.", "warning")
                return redirect(url_for("admin_assignments"))

            # Check duplicates within the CSV
            seen_codes: set[str] = set()
            dup_codes: set[str] = set()
            for code in desired.values():
                if code in seen_codes:
                    dup_codes.add(code)
                seen_codes.add(code)
            if dup_codes:
                errors.append("Bureaux en double dans le CSV: " + ", ".join(sorted(dup_codes)[:10]))

            # Check conflicts with reps NOT in the CSV
            target_users = set(desired.keys())
            other_assigned = {
                (u.get("polling_station_code") or "").strip()
                for u in users
                if u.get("role") == "rep"
                and int(u.get("election_id") or 0) == active_id
                and u.get("username") not in target_users
                and (u.get("polling_station_code") or "").strip()
            }
            conflicts = sorted({code for code in desired.values() if code in other_assigned})
            if conflicts:
                errors.append("Bureaux déjà affectés à d’autres représentants: " + ", ".join(conflicts[:10]))

            if errors:
                flash("Import bloqué.", "danger")
                flash("Erreurs: " + " | ".join(errors[:10]), "warning")
                return redirect(url_for("admin_assignments"))

            # Apply assignments (clear then set)
            for uname in target_users:
                user_map[uname]["polling_station_code"] = None
                user_map[uname]["role"] = user_map[uname].get("role") or "rep"
                # We do not force role change, but most will be reps.

            updated = 0
            for uname, code in desired.items():
                user_map[uname]["polling_station_code"] = code
                updated += 1

            save_json("users.json", list(user_map.values()))
            touch_last_update()
            flash(f"Affectations importées: {updated}.", "success")
            return redirect(url_for("admin_assignments"))

        return render_template("admin_assignments.html")

    @app.route("/admin/results", methods=["GET"])
    @login_required
    @role_required("admin")
    def admin_results():
        elections = _load_elections()
        active_id = get_active_election_id()
        raw_eid = (request.args.get("election_id") or "").strip()
        if raw_eid:
            try:
                view_election_id = int(raw_eid)
            except Exception:
                view_election_id = 0
        else:
            view_election_id = int(active_id or 0)

        if view_election_id == 0:
            flash("Aucune élection active. Activez une élection pour accéder aux modules.", "warning")
            return redirect(url_for("admin_elections"))

        can_edit = (view_election_id == active_id and _is_active_election_open())

        cand_all = _load_candidates_all()
        res_all = _load_results_all()

        candidates = cand_all.get(str(view_election_id), [])
        results = res_all.get(str(view_election_id), {})

        # Reference data (global) then filtered by the VIEW election type
        stations_all = load_json("polling_stations.json", default=[])
        centers_all = load_json("voting_centers.json", default=[])

        view_election = get_election_by_id(view_election_id) or {"id": view_election_id, "type": "MUNICIPALE", "status": "ACTIVE"}
        centers = _filter_centers_for_election(centers_all, view_election)
        stations = _filter_stations_for_election(stations_all, view_election)

        # Filters
        centre_filter = (request.args.get("centre") or "").strip()
        if centre_filter:
            centre_filter = centre_filter.zfill(3)

        status_filter = (request.args.get("status") or "").strip().upper()

        # Maps
        station_map = {s["code"]: s for s in stations}
        cand_map = {c["id"]: c for c in candidates}

        # Badge counts (by centre, regardless of status filter)
        counts = {"total": 0, "pending": 0, "validated": 0, "rejected": 0, "other": 0}
        for code, r in results.items():
            st = station_map.get(code)
            # Ignore PV that are outside the perimeter of the selected election
            # (e.g. SOUS-PREFECTURE stations during a MUNICIPALE election)
            if not st:
                continue
            if centre_filter and (not st or (st.get("centre_code") or "").zfill(3) != centre_filter):
                continue
            counts["total"] += 1
            s = (r.get("status") or "").upper()
            if s == "SUPERVISOR_VALIDATED":
                counts["validated"] += 1
            elif s == "SUPERVISOR_REJECTED":
                counts["rejected"] += 1
            elif s == "SUBMITTED":
                counts["pending"] += 1
            else:
                counts["other"] += 1

        stations_total_in_scope = (
            sum(1 for s in stations if (s.get("centre_code") or "").zfill(3) == centre_filter)
            if centre_filter
            else len(stations)
        )

        # Enrich for display
        items = []
        for code, r in results.items():
            station = station_map.get(code)

            # Skip PV that are outside the perimeter of the selected election
            if not station:
                continue

            # Outside the perimeter of the selected election
            if not station:
                continue

            # Apply filters
            if centre_filter and (not station or (station.get("centre_code") or "").zfill(3) != centre_filter):
                continue

            status = (r.get("status") or "").upper()
            if status_filter and status != status_filter:
                continue

            votes = r.get("votes") or {}
            items.append({
                "code": code,
                "station": station,
                "centre_code": (station.get("centre_code") if station else None),
                "centre_name": (station.get("centre_name") if station else None),
                "total_votes": r.get("total_votes", 0),
                "status": r.get("status"),
                "submitted_by": r.get("submitted_by"),
                "submitted_at_utc": r.get("submitted_at_utc"),
                "supervisor_decided_by": r.get("supervisor_decided_by"),
                "supervisor_decided_at_utc": r.get("supervisor_decided_at_utc"),
                "supervisor_comment": r.get("supervisor_comment"),
                "admin_reviewed_by": r.get("admin_reviewed_by"),
                "admin_reviewed_at_utc": r.get("admin_reviewed_at_utc"),
                "votes_human": [(cand_map.get(cid, {"name": cid})["name"], votes.get(cid, 0)) for cid in votes.keys()],
            })
        items.sort(key=lambda x: x["code"])

        centers_sorted = sorted(centers, key=lambda c: (c.get("code") or ""))
        return render_template(
            "admin_results.html",
            items=items,
            centers=centers_sorted,
            centre_filter=centre_filter,
            status_filter=status_filter,
            counts=counts,
            stations_total_in_scope=stations_total_in_scope,
            elections=elections,
            active_election_id=active_id,
            view_election_id=view_election_id,
            can_edit=can_edit,
        )
    @app.route("/admin/results/<code>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def admin_result_edit(code: str):
        candidates = load_active_candidates()
        stations = load_json("polling_stations.json", default=[])
        results = load_active_results()
        if code not in results:
            flash("PV introuvable.", "danger")
            return redirect(url_for("admin_results"))
        r = results[code]
        station = next((s for s in stations if s.get("code") == code), None)

        if request.method == "POST":
            votes: Dict[str, int] = {}
            for c in candidates:
                cid = c["id"]
                raw = request.form.get(f"votes_{cid}", "0").strip() or "0"
                try:
                    iv = int(raw)
                except Exception:
                    flash("Les voix doivent être des entiers.", "danger")
                    return redirect(url_for("admin_result_edit", code=code))
                if iv < 0:
                    flash("Les voix ne peuvent pas être négatives.", "danger")
                    return redirect(url_for("admin_result_edit", code=code))
                votes[cid] = iv

            total = sum(votes.values())

            # Control: total votes cannot exceed registered voters for this polling station
            if station:
                registered = _safe_int(station.get("registered"), default=0)
                if registered > 0 and total > registered:
                    flash(
                        f"PV invalide : total des voix ({total}) supérieur au nombre d’inscrits du bureau ({registered}).",
                        "danger",
                    )
                    return redirect(url_for("admin_result_edit", code=code))

            r["votes"] = votes
            r["total_votes"] = total

            # Any edit resets the supervisor workflow: PV must be revalidated
            r["status"] = "SUBMITTED"
            r["supervisor_decided_by"] = None
            r["supervisor_decided_at_utc"] = None
            r["supervisor_comment"] = None

            results[code] = r
            save_active_results(results)
            touch_last_update()
            flash("PV modifié.", "success")
            return redirect(url_for("admin_results"))

        return render_template("admin_result_edit.html", code=code, station=station, cand=candidates, pv=r)

    @app.post("/admin/results/<code>/delete")
    @login_required
    @role_required("admin")
    def admin_result_delete(code: str):
        results = load_active_results()
        if code not in results:
            flash("PV introuvable.", "danger")
            return redirect(url_for("admin_results"))
        results.pop(code, None)
        save_active_results(results)
        touch_last_update()
        flash("PV supprimé.", "success")
        return redirect(url_for("admin_results"))

    @app.post("/admin/results/<code>/validate")
    @login_required
    @role_required("admin")
    def admin_validate_result(code: str):
        results = load_active_results()
        if code not in results:
            flash("Résultat introuvable.", "danger")
            return redirect(url_for("admin_results"))

        # Safety control: do not validate if total votes exceed registered voters
        stations = load_json("polling_stations.json", default=[])
        station = next((s for s in stations if s.get("code") == code), None)
        if station:
            registered = _safe_int(station.get("registered"), default=0)
            total = int(results[code].get("total_votes") or 0)
            if registered > 0 and total > registered:
                flash(
                    f"Validation refusée : total des voix ({total}) supérieur au nombre d’inscrits ({registered}).",
                    "danger",
                )
                return redirect(url_for("admin_results"))

        u = current_user()
        results[code]["status"] = "ADMIN_REVIEWED"
        results[code]["admin_reviewed_by"] = u["username"]
        results[code]["admin_reviewed_at_utc"] = datetime.now(timezone.utc).isoformat()
        save_active_results(results)
        touch_last_update()
        flash(f"Résultat validé: {code}", "success")
        return redirect(url_for("admin_results"))

    return app

# -------------------------
# Helpers / seed data
# -------------------------
def _next_id(existing_ids, prefix="C"):
    nums = []
    for x in existing_ids:
        if isinstance(x, str) and x.startswith(prefix):
            try:
                nums.append(int(x[len(prefix):]))
            except Exception:
                pass
    n = max(nums) + 1 if nums else 1
    return f"{prefix}{n:03d}"


def _safe_int(val, default: int = 0) -> int:
    """Parse an int coming from forms/CSV. Accepts spaces and commas."""
    if val is None:
        return default
    try:
        s = str(val).strip().replace(" ", "").replace(",", "")
        if s == "":
            return default
        return int(s)
    except Exception:
        return default


def _recompute_center_stats(centers, stations):
    """Recompute nb_bureaux and registered_total for each center based on stations."""
    if not isinstance(centers, list):
        return centers
    if not isinstance(stations, list):
        stations = []

    counts = {}
    totals = {}
    for s in stations:
        cc = (s.get("centre_code") or "").strip().zfill(3)
        if not cc:
            continue
        counts[cc] = counts.get(cc, 0) + 1
        totals[cc] = totals.get(cc, 0) + int(s.get("registered") or 0)

    out = []
    for c in centers:
        code = (c.get("code") or "").strip().zfill(3)
        if not code:
            continue
        c["code"] = code
        c["nb_bureaux"] = int(counts.get(code, 0))
        c["registered_total"] = int(totals.get(code, 0))
        if not c.get("commune"):
            c["commune"] = "ALEPE"
        out.append(c)
    out.sort(key=lambda x: x.get("code"))
    return out

def _ensure_seed_data():
    """Ensure data files exist, and migrate legacy single-election format to multi-election."""

    # -------------------------
    # Elections meta (multi-years / multi-types)
    # -------------------------
    elections_path = DATA_DIR / "elections.json"
    settings_path = DATA_DIR / "settings.json"

    # Legacy election.json (from older versions)
    legacy_election = None
    legacy_path = DATA_DIR / "election.json"
    if legacy_path.exists():
        legacy_election = load_json("election.json", default={})

    if not elections_path.exists():
        # Build a default election from legacy data if present.
        year = int((legacy_election or {}).get("year") or 2028)
        rnd = int((legacy_election or {}).get("round") or 1)
        commune = (legacy_election or {}).get("commune") or "Bonoua"
        name = (legacy_election or {}).get("name") or "Municipales – Bonoua"

        default = {
            "id": 1,
            "type": "MUNICIPALE",
            "year": year,
            "round": rnd,
            "commune": commune,
            "name": name,
            "status": "ACTIVE",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        save_json("elections.json", [default])

    if not settings_path.exists():
        save_json("settings.json", {"active_election_id": 1})

    # Ensure there is exactly one ACTIVE election (defensive)
    elections = load_json("elections.json", default=[])
    if isinstance(elections, list):
        active = [e for e in elections if str(e.get("status") or "").upper() == "ACTIVE"]
        if not active:
            # Activate the first election
            if elections:
                elections[0]["status"] = "ACTIVE"
                save_json("elections.json", elections)
        elif len(active) > 1:
            # Keep the one pointed by settings, archive the rest
            settings = load_json("settings.json", default={"active_election_id": 1})
            try:
                active_id = int(settings.get("active_election_id") or 1)
            except Exception:
                active_id = int(active[0].get("id") or 1)
                settings["active_election_id"] = active_id
                save_json("settings.json", settings)

            for e in elections:
                if int(e.get("id") or 0) != active_id and str(e.get("status") or "").upper() == "ACTIVE":
                    e["status"] = "ARCHIVED"
            save_json("elections.json", elections)

    # Determine active election id for migrations
    settings = load_json("settings.json", default={"active_election_id": 1})
    try:
        active_id = int(settings.get("active_election_id") or 1)
    except Exception:
        active_id = 1

    # Candidates seed (now per election)
    cand_path = DATA_DIR / "candidates.json"
    if not cand_path.exists():
        save_json(
            "candidates.json",
            {
                str(active_id): [
                    {"id": "C001", "name": "Candidat 1", "party": "Parti A", "photo": ""},
                    {"id": "C002", "name": "Candidat 2", "party": "Parti B", "photo": ""},
                    {"id": "C003", "name": "Candidat 3", "party": "Parti C", "photo": ""},
                    {"id": "C004", "name": "Candidat 4", "party": "Indépendant", "photo": ""},
                ]
            },
        )
    else:
        # Migration: list -> {active_id: list}
        data = load_json("candidates.json", default={})
        if isinstance(data, list):
            save_json("candidates.json", {str(active_id): data})

    # Polling stations seed (Bonoua sample)
    ps_path = DATA_DIR / "polling_stations.json"
    if not ps_path.exists():
        save_json("polling_stations.json", [
            {
                "code": "BONOUA-001-BV01",
                "name": "001 - ECOLE METHODISTE / BV01",
                "centre_code": "001",
                "centre_name": "ECOLE METHODISTE",
                "bureau_code": "BV01",
                "registered": 441,
            },
            {
                "code": "BONOUA-001-BV02",
                "name": "001 - ECOLE METHODISTE / BV02",
                "centre_code": "001",
                "centre_name": "ECOLE METHODISTE",
                "bureau_code": "BV02",
                "registered": 439,
            },
        ])

    # Voting centers seed (optional, in case the file is missing)
    vc_path = DATA_DIR / "voting_centers.json"
    if not vc_path.exists():
        save_json("voting_centers.json", [
            {"code": "001", "name": "ECOLE METHODISTE", "nb_bureaux": 2, "registered_total": 880, "commune": "BONOUA"}
        ])

    # Users seed + migration (ensure supervisor role exists + election_id)
    users_path = DATA_DIR / "users.json"
    if not users_path.exists():
        save_json("users.json", [
            {
                "username": "admin",
                "password_hash": generate_password_hash("Admin123!"),
                "role": "admin",
                "full_name": "Administrateur",
                "contacts": "",
                "polling_station_code": None,
                "center_code": None,
                "election_id": None,
                "is_active": True,
            },
            {
                "username": "rep1",
                "password_hash": generate_password_hash("Rep123!"),
                "role": "rep",
                "full_name": "Représentant 1",
                "contacts": "",
                "polling_station_code": "BONOUA-001-BV01",
                "center_code": None,
                "election_id": active_id,
                "is_active": True,
            },
            {
                "username": "rep2",
                "password_hash": generate_password_hash("Rep123!"),
                "role": "rep",
                "full_name": "Représentant 2",
                "contacts": "",
                "polling_station_code": "BONOUA-001-BV02",
                "center_code": None,
                "election_id": active_id,
                "is_active": True,
            },
            {
                "username": "sup001",
                "password_hash": generate_password_hash("Sup123!"),
                "role": "supervisor",
                "full_name": "Superviseur Centre 001",
                "contacts": "",
                "polling_station_code": None,
                "center_code": "001",
                "election_id": active_id,
                "is_active": True,
            },
        ])
    else:
        # migrate: add missing keys + ensure at least 1 supervisor exists
        users = load_json("users.json", default=[])
        changed = False
        for u in users:
            if "polling_station_code" not in u:
                u["polling_station_code"] = None
                changed = True
            if "center_code" not in u:
                u["center_code"] = None
                changed = True
            if "election_id" not in u:
                # admin is global; other roles are scoped to the active election
                if (u.get("role") or "").strip() == "admin":
                    u["election_id"] = None
                else:
                    u["election_id"] = active_id
                changed = True

        has_supervisor = any(u.get("role") == "supervisor" and u.get("is_active", True) for u in users)
        if not has_supervisor:
            centers = load_json("voting_centers.json", default=[])
            default_center = (centers[0].get("code") if centers else None) or "001"
            users.append({
                "username": "sup001",
                "password_hash": generate_password_hash("Sup123!"),
                "role": "supervisor",
                "full_name": f"Superviseur Centre {default_center}",
                "contacts": "",
                "polling_station_code": None,
                "center_code": default_center,
                "election_id": active_id,
                "is_active": True,
            })
            changed = True

        if changed:
            save_json("users.json", users)

    # Results seed (now per election)
    res_path = DATA_DIR / "results.json"
    if not res_path.exists():
        save_json("results.json", {str(active_id): {}})
    else:
        # Migration: if results is a dict of station_code -> pv, wrap under active election id
        data = load_json("results.json", default={})
        if isinstance(data, dict):
            keys = list(data.keys())
            looks_like_station_map = any(isinstance(k, str) and (k.startswith("BONOUA-") or k.startswith("ALEPE-") or "-BV" in k) for k in keys[:10])
            looks_like_election_map = any(str(k).isdigit() for k in keys[:10])
            if looks_like_station_map and not looks_like_election_map:
                save_json("results.json", {str(active_id): data})
            elif looks_like_election_map:
                # ensure active id exists
                if str(active_id) not in data:
                    data[str(active_id)] = {}
                    save_json("results.json", data)

    meta_path = DATA_DIR / "meta.json"
    if not meta_path.exists():
        save_json("meta.json", {"last_update_utc": None})
