"""
tools.py - graph tools for the security triage agent.

Each function runs one graph query and returns JSON text, including the PATH
it used, so the agent can explain how it got to every answer.

These are plain Python functions so you can test them without an LLM:
    python tools.py
In agent.py we wrap them with Strands' `tool` decorator.
"""
import json
import os

from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

_db = FalkorDB(
    host=os.getenv("FALKORDB_HOST", "localhost"),
    port=int(os.getenv("FALKORDB_PORT", "6379")),
    username=os.getenv("FALKORDB_USER") or None,
    password=os.getenv("FALKORDB_PASSWORD") or None,
)
g = _db.select_graph("security")


def _rows(query: str, params: dict | None = None) -> list:
    return g.query(query, params or {}).result_set


# --------------------------------------------------------------------------
# Tool 1: blast radius of a CVE (multi-hop)
# --------------------------------------------------------------------------
def blast_radius(cve_id: str) -> str:
    """Find every service affected by a CVE through its dependency chain.

    Returns each affected service with its owning team, criticality,
    whether it is public-facing, and the exact dependency path
    (service -> package -> ... -> CVE).
    """
    rows = _rows(
        """
        MATCH p=(s:Service)-[:DEPENDS_ON*1..4]->(:Package)-[:HAS_VULN]->(c:CVE {id:$id})
        MATCH (t:Team)-[:OWNS]->(s)
        RETURN s.name, s.criticality, s.public, t.name, t.oncall, length(p) AS hops,
               [n IN nodes(p) | coalesce(n.name, n.id)] AS path
        ORDER BY hops
        """,
        {"id": cve_id},
    )
    shortest = {}  # keep the shortest path per service
    for name, crit, public, team, oncall, hops, path in rows:
        if name not in shortest:
            shortest[name] = {
                "service": name,
                "team": team,
                "oncall": oncall,
                "criticality": crit,
                "public_facing": public,
                "hops": hops,
                "path": " -> ".join(path),
            }
    return json.dumps(
        {"cve": cve_id, "affected_services": list(shortest.values())}, indent=2
    )


# --------------------------------------------------------------------------
# Tool 2: who owns a service
# --------------------------------------------------------------------------
def find_owner(service_name: str) -> str:
    """Find the team that owns a service and who is on call for it."""
    rows = _rows(
        "MATCH (t:Team)-[:OWNS]->(s:Service {name:$n}) RETURN t.name, t.oncall",
        {"n": service_name},
    )
    if not rows:
        return json.dumps({"service": service_name, "error": "service not found"})
    team, oncall = rows[0]
    return json.dumps({"service": service_name, "team": team, "oncall": oncall})


# --------------------------------------------------------------------------
# Tool 3: who is affected indirectly (services that call this one)
# --------------------------------------------------------------------------
def downstream_impact(service_name: str) -> str:
    """Find services that call this service (up to 3 hops), i.e. who would be
    indirectly affected if this service were compromised or taken down."""
    rows = _rows(
        """
        MATCH p=(caller:Service)-[:CALLS*1..3]->(s:Service {name:$n})
        RETURN caller.name, caller.criticality, caller.public, length(p) AS hops,
               [n IN nodes(p) | n.name] AS path
        ORDER BY hops
        """,
        {"n": service_name},
    )
    shortest = {}
    for name, crit, public, hops, path in rows:
        if name not in shortest:
            shortest[name] = {
                "service": name,
                "criticality": crit,
                "public_facing": public,
                "hops": hops,
                "path": " -> ".join(path),
            }
    return json.dumps(
        {"target": service_name, "callers": list(shortest.values())}, indent=2
    )


# --------------------------------------------------------------------------
# Tool 4: explain how one service is exposed to one CVE
# --------------------------------------------------------------------------
def explain_path(service_name: str, cve_id: str) -> str:
    """Show the shortest dependency path that exposes a service to a CVE."""
    rows = _rows(
        """
        MATCH p=(s:Service {name:$s})-[:DEPENDS_ON*1..4]->(:Package)-[:HAS_VULN]->(c:CVE {id:$c})
        RETURN [n IN nodes(p) | coalesce(n.name, n.id)] AS path, length(p) AS hops
        ORDER BY hops
        LIMIT 1
        """,
        {"s": service_name, "c": cve_id},
    )
    if not rows:
        return json.dumps(
            {"service": service_name, "cve": cve_id, "exposed": False}
        )
    path, hops = rows[0]
    return json.dumps(
        {
            "service": service_name,
            "cve": cve_id,
            "exposed": True,
            "hops": hops,
            "path": " -> ".join(path),
        }
    )


# --------------------------------------------------------------------------
# Tool 5: rank CVEs by real risk, not just CVSS score
# --------------------------------------------------------------------------
def prioritize_cves(top_n: int = 5) -> str:
    """Rank CVEs by real risk: CVSS score x how many important services are
    affected (public-facing services count double). Use this to decide which
    vulnerability to fix first."""
    rows = _rows(
        """
        MATCH (s:Service)-[:DEPENDS_ON*1..4]->(:Package)-[:HAS_VULN]->(c:CVE)
        RETURN DISTINCT c.id, c.severity, c.cvss, s.name, s.criticality, s.public
        """
    )
    cves = {}
    for cve_id, sev, cvss, svc, crit, public in rows:
        entry = cves.setdefault(
            cve_id,
            {"cve": cve_id, "severity": sev, "cvss": cvss, "services": [], "weight": 0},
        )
        entry["services"].append(svc)
        entry["weight"] += crit * (2 if public else 1)

    ranked = []
    for e in cves.values():
        ranked.append(
            {
                "cve": e["cve"],
                "severity": e["severity"],
                "cvss": e["cvss"],
                "affected_service_count": len(e["services"]),
                "risk_score": round(e["cvss"] * e["weight"], 1),
                "affected_services": sorted(e["services"]),
            }
        )
    ranked.sort(key=lambda x: x["risk_score"], reverse=True)
    return json.dumps(ranked[: int(top_n)], indent=2)


ALL_TOOLS = [blast_radius, find_owner, downstream_impact, explain_path, prioritize_cves]


# --------------------------------------------------------------------------
# Quick test, no LLM needed:  python tools.py
# --------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== prioritize_cves(3) ===")
    print(prioritize_cves(3))
    print("\n=== blast_radius('CVE-2026-1001') ===")
    print(blast_radius("CVE-2026-1001"))
    print("\n=== find_owner('payments-api') ===")
    print(find_owner("payments-api"))
    print("\n=== downstream_impact('auth-service') ===")
    print(downstream_impact("auth-service"))
    print("\n=== explain_path('payments-api', 'CVE-2026-1001') ===")
    print(explain_path("payments-api", "CVE-2026-1001"))