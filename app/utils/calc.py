from __future__ import annotations
from typing import Dict, List, Any, Tuple

def compute_summary(
    polling_stations: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    results: Dict[str, Any],
    include_statuses: Tuple[str, ...] | None = None,
) -> Dict[str, Any]:
    """
    Returns a summary:
    - bureaux_total / bureaux_submitted / bureaux_remaining / percent_depouilles
    - candidate_totals: list sorted by votes desc with percent
    - total_votes

    include_statuses: statuses to include in the summary (counts + totals).
      - Public results should typically include only ("SUPERVISOR_VALIDATED",)
      - Admin monitoring may include ("SUBMITTED", "SUPERVISOR_VALIDATED")
    """
    if include_statuses is None:
        include_statuses = ("SUBMITTED", "SUPERVISOR_VALIDATED", "VALIDATED")  # legacy
    allowed = set(include_statuses)

    bureaux_total = len(polling_stations)
    submitted_codes = [code for code, r in results.items() if r.get("status") in allowed]
    bureaux_submitted = len(set(submitted_codes))
    bureaux_remaining = max(bureaux_total - bureaux_submitted, 0)
    percent_depouilles = round((bureaux_submitted / bureaux_total) * 100, 2) if bureaux_total else 0.0

    # totals (only for allowed statuses)
    totals = {c["id"]: 0 for c in candidates}
    for code, r in results.items():
        if r.get("status") not in allowed:
            continue
        votes = r.get("votes") or {}
        for cid, v in votes.items():
            if cid in totals:
                try:
                    totals[cid] += int(v)
                except Exception:
                    pass

    total_votes = sum(totals.values())
    out = []
    for c in candidates:
        v = totals.get(c["id"], 0)
        pct = (v / total_votes * 100) if total_votes else 0.0
        out.append({
            "id": c["id"],
            "name": c["name"],
            "party": c.get("party", ""),
            "votes": v,
            "percent": round(pct, 2),
            "photo": c.get("photo", ""),
        })

    out.sort(key=lambda x: (-x["votes"], x["name"]))

    return {
        "bureaux_total": bureaux_total,
        "bureaux_submitted": bureaux_submitted,
        "bureaux_remaining": bureaux_remaining,
        "percent_depouilles": percent_depouilles,
        "total_votes": total_votes,
        "candidate_totals": out,
    }


def validate_pv_numbers(registered: int, voters: int, null_ballots: int, blank_ballots: int, votes_by_candidate: Dict[str, int]) -> Tuple[bool, str, int]:
    """
    Enforces:
      voters <= registered
      null + blank + expressed == voters
      sum(votes_by_candidate) == expressed
    Returns (ok, message, expressed)
    """
    try:
        registered = int(registered)
        voters = int(voters)
        null_ballots = int(null_ballots)
        blank_ballots = int(blank_ballots)
    except Exception:
        return (False, "Les champs inscrits/votants/nuls/blancs doivent être des entiers.", 0)

    if any(x < 0 for x in [registered, voters, null_ballots, blank_ballots]):
        return (False, "Aucune valeur ne peut être négative.", 0)

    if voters > registered:
        return (False, "Les votants ne peuvent pas dépasser les inscrits.", 0)

    expressed = voters - null_ballots - blank_ballots
    if expressed < 0:
        return (False, "Nuls + blancs ne peuvent pas dépasser les votants.", 0)

    s = 0
    for k, v in votes_by_candidate.items():
        try:
            iv = int(v)
        except Exception:
            return (False, "Les voix par candidat doivent être des entiers.", 0)
        if iv < 0:
            return (False, "Les voix par candidat ne peuvent pas être négatives.", 0)
        s += iv

    if s != expressed:
        return (False, f"Incohérence: somme des voix candidats ({s}) ≠ exprimés ({expressed}).", expressed)

    # final identity is implied: null + blank + expressed == voters
    return (True, "OK", expressed)
