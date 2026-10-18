"""
memory_tools.py - MEMORY and ACTION tools for the security triage agent.

Memory: every investigation is saved in the graph as a (:Case) linked to the
CVEs it concerned, so the agent can recall what it already concluded.
Action:  create_ticket writes a (:Ticket) linked to the CVE, the service and
the owning team. The graph decides who gets the ticket.

WARNING: seed.py deletes and rebuilds the whole "security" graph, which also
erases saved cases and tickets. Don't re-run seed.py after your demo data
is ready (or re-run it on purpose to reset the demo).
"""
import json
import time
import uuid

from tools import g, _rows


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


# --------------------------------------------------------------------------
# MEMORY: save what the agent concluded
# --------------------------------------------------------------------------
def save_case(question: str, cve_ids: str, conclusion: str) -> str:
    """Save a finished investigation to long-term memory in the graph.

    question: the user's question.
    cve_ids: comma-separated CVE ids the investigation was about, e.g. "CVE-2026-1004,CVE-2026-1001".
    conclusion: one or two sentences with the final recommendation.
    """
    case_id = _new_id("CASE")
    g.query(
        "CREATE (:Case {id:$id, question:$q, conclusion:$c, created:$t})",
        {"id": case_id, "q": question, "c": conclusion, "t": int(time.time())},
    )
    linked = []
    for cve in [c.strip() for c in cve_ids.split(",") if c.strip()]:
        res = g.query(
            "MATCH (k:Case {id:$k}), (c:CVE {id:$c}) CREATE (k)-[:CONCERNS]->(c) RETURN c.id",
            {"k": case_id, "c": cve},
        )
        if res.result_set:
            linked.append(cve)
    return json.dumps({"saved_case": case_id, "linked_cves": linked})


# --------------------------------------------------------------------------
# MEMORY: recall past investigations
# --------------------------------------------------------------------------
def recall_cases(cve_id: str) -> str:
    """Recall past investigations and open tickets about a CVE.
    Call this BEFORE investigating a CVE to see what was already concluded."""
    cases = _rows(
        """
        MATCH (k:Case)-[:CONCERNS]->(c:CVE {id:$id})
        RETURN k.id, k.question, k.conclusion, k.created
        ORDER BY k.created DESC
        LIMIT 5
        """,
        {"id": cve_id},
    )
    tickets = _rows(
        """
        MATCH (k:Ticket)-[:ABOUT]->(c:CVE {id:$id})
        MATCH (k)-[:ABOUT_SERVICE]->(s:Service)
        MATCH (k)-[:ASSIGNED_TO]->(t:Team)
        RETURN k.id, k.status, s.name, t.name
        """,
        {"id": cve_id},
    )
    return json.dumps(
        {
            "cve": cve_id,
            "past_cases": [
                {"case": i, "question": q, "conclusion": c, "created": ts}
                for i, q, c, ts in cases
            ],
            "tickets": [
                {"ticket": i, "status": st, "service": s, "team": t}
                for i, st, s, t in tickets
            ],
        },
        indent=2,
    )


# --------------------------------------------------------------------------
# ACTION: open a ticket for the team that owns the service
# --------------------------------------------------------------------------
def create_ticket(cve_id: str, service_name: str, summary: str) -> str:
    """Open a remediation ticket for a service affected by a CVE. The ticket is
    assigned automatically to the team that owns the service (found through the graph).
    Does nothing if an open ticket for the same CVE and service already exists."""
    owner = _rows(
        """
        MATCH (t:Team)-[:OWNS]->(s:Service {name:$s}), (c:CVE {id:$c})
        RETURN t.name, t.oncall
        """,
        {"s": service_name, "c": cve_id},
    )
    if not owner:
        return json.dumps({"error": "unknown service or CVE", "service": service_name, "cve": cve_id})
    team, oncall = owner[0]

    existing = _rows(
        """
        MATCH (k:Ticket {status:'open'})-[:ABOUT]->(c:CVE {id:$c}),
              (k)-[:ABOUT_SERVICE]->(s:Service {name:$s})
        RETURN k.id
        """,
        {"s": service_name, "c": cve_id},
    )
    if existing:
        return json.dumps({"already_open": existing[0][0], "service": service_name, "cve": cve_id})

    ticket_id = _new_id("TICKET")
    g.query(
        """
        MATCH (t:Team)-[:OWNS]->(s:Service {name:$s}), (c:CVE {id:$c})
        CREATE (k:Ticket {id:$id, summary:$sum, status:'open', created:$ts})
        CREATE (k)-[:ABOUT]->(c)
        CREATE (k)-[:ABOUT_SERVICE]->(s)
        CREATE (k)-[:ASSIGNED_TO]->(t)
        """,
        {"s": service_name, "c": cve_id, "id": ticket_id, "sum": summary, "ts": int(time.time())},
    )
    return json.dumps(
        {"ticket": ticket_id, "cve": cve_id, "service": service_name,
         "assigned_team": team, "oncall": oncall, "status": "open"}
    )


# --------------------------------------------------------------------------
# ACTION: list tickets
# --------------------------------------------------------------------------
def list_open_tickets() -> str:
    """List all open remediation tickets with their CVE, service and team."""
    rows = _rows(
        """
        MATCH (k:Ticket {status:'open'})-[:ABOUT]->(c:CVE)
        MATCH (k)-[:ABOUT_SERVICE]->(s:Service)
        MATCH (k)-[:ASSIGNED_TO]->(t:Team)
        RETURN k.id, c.id, s.name, t.name
        """
    )
    return json.dumps(
        [{"ticket": i, "cve": c, "service": s, "team": t} for i, c, s, t in rows],
        indent=2,
    )


MEMORY_TOOLS = [save_case, recall_cases, create_ticket, list_open_tickets]


if __name__ == "__main__":
    # quick test, no LLM:  python memory_tools.py
    print(create_ticket("CVE-2026-1004", "auth-service", "Patch openssl"))
    print(create_ticket("CVE-2026-1004", "auth-service", "Patch openssl"))  # should say already_open
    print(save_case("test question", "CVE-2026-1004", "test conclusion"))
    print(recall_cases("CVE-2026-1004"))
    print(list_open_tickets())