"""
seed.py - builds the synthetic security-triage graph in FalkorDB.

Run:  python seed.py
Safe to re-run any time: it deletes and rebuilds the "security" graph.

NOTE: all CVE ids, services and teams are SYNTHETIC (made up for the demo).
"""
from falkordb import FalkorDB

import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

db = FalkorDB(
   host=os.getenv("FALKORDB_HOST", "localhost"),
   port=int(os.getenv("FALKORDB_PORT", "6379")),
   username=os.getenv("FALKORDB_USER") or None,
   password=os.getenv("FALKORDB_PASSWORD") or None,
)

# ---- start clean so the script is re-runnable --------------------------------
try:
    db.select_graph("security").delete()
except Exception:
    pass
g = db.select_graph("security")

# ---- data --------------------------------------------------------------------
TEAMS = {  # team -> on-call person
    "Payments": "Asha",
    "Identity": "Ravi",
    "Platform": "Meera",
    "Data": "Karthik",
    "Mobile": "Sana",
}

# name, team, criticality (1-5), public_facing
SERVICES = [
    ("payments-api",       "Payments", 5, True),
    ("checkout-web",       "Payments", 4, True),
    ("fraud-engine",       "Payments", 5, False),
    ("auth-service",       "Identity", 5, True),
    ("user-profile",       "Identity", 3, True),
    ("sso-gateway",        "Identity", 5, True),
    ("platform-gateway",   "Platform", 5, True),
    ("config-service",     "Platform", 3, False),
    ("metrics-collector",  "Platform", 2, False),
    ("etl-pipeline",       "Data",     3, False),
    ("analytics-api",      "Data",     3, True),
    ("data-lake-sync",     "Data",     2, False),
    ("mobile-bff",         "Mobile",   4, True),
    ("push-service",       "Mobile",   3, False),
    ("notification-svc",   "Mobile",   2, False),
]

# service -> packages it uses directly
SERVICE_DEPS = {
    "payments-api":      ["spring-boot", "grpc"],
    "checkout-web":      ["express", "axios"],
    "fraud-engine":      ["flask", "requests", "protobuf"],
    "auth-service":      ["spring-boot", "openssl"],
    "user-profile":      ["django", "requests"],
    "sso-gateway":       ["netty", "express"],
    "platform-gateway":  ["netty", "grpc"],
    "config-service":    ["spring-boot"],
    "metrics-collector": ["flask", "protobuf"],
    "etl-pipeline":      ["requests", "flask"],
    "analytics-api":     ["django", "requests"],
    "data-lake-sync":    ["grpc"],
    "mobile-bff":        ["express", "axios"],
    "push-service":      ["axios"],
    "notification-svc":  ["flask"],
}

# package -> packages it depends on (transitive chains = multi-hop paths)
PACKAGE_DEPS = {
    "spring-boot":  ["spring-core", "log4j-core", "jackson-databind"],
    "spring-core":  ["commons-text"],
    "commons-text": ["commons-lang"],
    "express":      ["body-parser", "qs"],
    "body-parser":  ["qs", "raw-body"],
    "axios":        ["follow-redirects"],
    "flask":        ["werkzeug", "jinja2"],
    "jinja2":       ["markupsafe"],
    "requests":     ["urllib3", "certifi"],
    "django":       ["sqlparse"],
    "grpc":         ["protobuf", "openssl"],
    "netty":        ["openssl"],
}

# id, severity, cvss, vulnerable package
CVES = [
    ("CVE-2026-1001", "critical", 9.8, "log4j-core"),
    ("CVE-2026-1002", "high",     8.1, "jackson-databind"),
    ("CVE-2026-1003", "high",     7.5, "qs"),
    ("CVE-2026-1004", "critical", 9.1, "openssl"),
    ("CVE-2026-1005", "medium",   5.3, "urllib3"),
    ("CVE-2026-1006", "high",     7.8, "commons-text"),
    ("CVE-2026-1007", "medium",   6.1, "follow-redirects"),
    ("CVE-2026-1008", "high",     8.8, "werkzeug"),
    ("CVE-2026-1009", "low",      3.7, "markupsafe"),
    ("CVE-2026-1010", "high",     7.4, "protobuf"),
]

# service -> service calls (lets risk spread between services)
CALLS = [
    ("checkout-web", "payments-api"),
    ("mobile-bff", "payments-api"),
    ("mobile-bff", "auth-service"),
    ("payments-api", "auth-service"),
    ("payments-api", "fraud-engine"),
    ("platform-gateway", "auth-service"),
    ("platform-gateway", "payments-api"),
    ("sso-gateway", "auth-service"),
    ("user-profile", "auth-service"),
    ("analytics-api", "etl-pipeline"),
    ("etl-pipeline", "data-lake-sync"),
    ("push-service", "notification-svc"),
    ("mobile-bff", "push-service"),
]

# ---- build the graph ---------------------------------------------------------
for team, oncall in TEAMS.items():
    g.query("CREATE (:Team {name:$n, oncall:$o})", {"n": team, "o": oncall})

for name, team, crit, public in SERVICES:
    g.query(
        """
        MATCH (t:Team {name:$team})
        CREATE (t)-[:OWNS]->(:Service {name:$name, criticality:$crit, public:$public})
        """,
        {"team": team, "name": name, "crit": crit, "public": public},
    )

# every package that appears anywhere
all_packages = set()
for pkgs in SERVICE_DEPS.values():
    all_packages.update(pkgs)
for parent, children in PACKAGE_DEPS.items():
    all_packages.add(parent)
    all_packages.update(children)
for _, _, _, pkg in CVES:
    all_packages.add(pkg)

for pkg in sorted(all_packages):
    g.query("CREATE (:Package {name:$n})", {"n": pkg})

for svc, pkgs in SERVICE_DEPS.items():
    for pkg in pkgs:
        g.query(
            "MATCH (s:Service {name:$s}), (p:Package {name:$p}) CREATE (s)-[:DEPENDS_ON]->(p)",
            {"s": svc, "p": pkg},
        )

for parent, children in PACKAGE_DEPS.items():
    for child in children:
        g.query(
            "MATCH (a:Package {name:$a}), (b:Package {name:$b}) CREATE (a)-[:DEPENDS_ON]->(b)",
            {"a": parent, "b": child},
        )

for cve_id, sev, cvss, pkg in CVES:
    g.query(
        """
        MATCH (p:Package {name:$p})
        CREATE (p)-[:HAS_VULN]->(:CVE {id:$id, severity:$sev, cvss:$cvss})
        """,
        {"p": pkg, "id": cve_id, "sev": sev, "cvss": cvss},
    )

for a, b in CALLS:
    g.query(
        "MATCH (a:Service {name:$a}), (b:Service {name:$b}) CREATE (a)-[:CALLS]->(b)",
        {"a": a, "b": b},
    )

# ---- sanity checks -----------------------------------------------------------
print("Graph 'security' built.\n")
for label in ["Team", "Service", "Package", "CVE"]:
    count = g.query(f"MATCH (n:{label}) RETURN count(n)").result_set[0][0]
    print(f"  {label:8s} {count}")
rels = g.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
print(f"  edges    {rels}\n")

print("Blast radius of CVE-2026-1001 (should show multi-hop paths):")
res = g.query(
    """
    MATCH p=(s:Service)-[:DEPENDS_ON*1..4]->(:Package)-[:HAS_VULN]->(c:CVE {id:$id})
    RETURN s.name, length(p) AS hops, [n IN nodes(p) | coalesce(n.name, n.id)] AS path
    ORDER BY hops
    """,
    {"id": "CVE-2026-1001"},
)
for row in res.result_set:
    print("  ", row)