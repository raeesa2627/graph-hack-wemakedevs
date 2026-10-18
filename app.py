"""
app.py - Streamlit UI for the security triage agent.

Run:  streamlit run app.py

Shows, for every answer:
  1. the agent's explanation,
  2. the tools it called (and what they returned),
  3. the knowledge graph with the exact path the agent used highlighted.
"""
import functools
import json
import re
import time

import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from strands import Agent, tool

from agent import SYSTEM_PROMPT, model
from memory_tools import MEMORY_TOOLS, list_open_tickets
from tools import ALL_TOOLS, _rows

st.set_page_config(page_title="Security Triage Agent", page_icon="🛡️", layout="wide")

EXAMPLES = [
    "Which vulnerability should we fix first and why?",
    "Who is affected by CVE-2026-1001 and who do I notify?",
    "How is payments-api exposed to CVE-2026-1004?",
    "Open tickets for the public-facing services affected by CVE-2026-1004.",
    "What do we already know about CVE-2026-1004?",
]

BRIGHT = {"Service": "#4c9aff", "Package": "#c9d1d9", "CVE": "#ff5c5c"}
DIM = {"Service": "#24384f", "Package": "#30363d", "CVE": "#522626"}


# --------------------------------------------------------------------------
# Agent with tool-call tracing (so the UI can show what the agent did)
# --------------------------------------------------------------------------
@st.cache_resource
def get_agent():
    trace = []

    def traced(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            trace.append({"tool": fn.__name__, "args": kwargs or list(args), "result": result})
            return result

        return wrapper

    tools = [tool(traced(fn)) for fn in ALL_TOOLS + MEMORY_TOOLS]
    agent = Agent(model=model, system_prompt=SYSTEM_PROMPT, tools=tools, callback_handler=None)
    return agent, trace


# --------------------------------------------------------------------------
# Graph data + drawing
# --------------------------------------------------------------------------
@st.cache_data(ttl=300)
def load_graph():
    nodes = {}
    for name, crit, public in _rows("MATCH (s:Service) RETURN s.name, s.criticality, s.public"):
        nodes[name] = ("Service", f"{name} | criticality {crit} | {'public' if public else 'internal'}", 14 + 3 * crit)
    for (name,) in _rows("MATCH (p:Package) RETURN p.name"):
        nodes[name] = ("Package", name, 12)
    for cid, sev, cvss in _rows("MATCH (c:CVE) RETURN c.id, c.severity, c.cvss"):
        nodes[cid] = ("CVE", f"{cid} | {sev} | CVSS {cvss}", 18)
    edges = []
    for rel in ["DEPENDS_ON", "HAS_VULN", "CALLS"]:
        for a, b in _rows(f"MATCH (a)-[:{rel}]->(b) RETURN coalesce(a.name, a.id), coalesce(b.name, b.id)"):
            edges.append((a, b, rel))
    return nodes, edges


def render_graph(paths, height=560):
    nodes, edges = load_graph()
    hl_nodes = {n for p in paths for n in p}
    hl_edges = {(p[i], p[i + 1]) for p in paths for i in range(len(p) - 1)}
    has_hl = bool(hl_nodes)

    net = Network(height=f"{height}px", width="100%", directed=True,
                  bgcolor="#0e1117", font_color="#e6edf3", cdn_resources="remote")
    # drawThreshold 0 = always draw node names, even when the graph is zoomed out
    net.set_options("""var options = {
      "nodes": {"scaling": {"label": {"enabled": false, "drawThreshold": 0}}},
      "physics": {"barnesHut": {"gravitationalConstant": -6000, "springLength": 90,
                                "centralGravity": 0.5, "avoidOverlap": 0.2},
                  "stabilization": {"iterations": 200}},
      "interaction": {"hover": true, "zoomView": true}
    }""")

    for name, (kind, title, size) in nodes.items():
        hl = name in hl_nodes
        if has_hl and not hl:
            net.add_node(name, label=name, title=title, size=size * 0.8,
                         color=DIM[kind],
                         font={"color": "#8b949e", "size": 14})
        else:
            net.add_node(name, label=name, title=title, size=size * (1.4 if hl else 1),
                         color=BRIGHT[kind], borderWidth=4 if hl else 1,
                         font={"color": "#ffffff", "size": 24 if hl else 16,
                               "strokeWidth": 4, "strokeColor": "#0e1117"})

    for a, b, rel in edges:
        if a not in nodes or b not in nodes:
            continue
        if (a, b) in hl_edges:
            net.add_edge(a, b, color="#ffb347", width=4, title=rel)
        else:
            net.add_edge(a, b, color="#30363d" if has_hl else "#6e7681", width=1, title=rel)

    html = net.generate_html().replace(
        "</head>",
        "<style>html,body{background:#0e1117!important;margin:0}"
        ".card{border:none!important;background:#0e1117!important}"
        "#mynetwork{border:none!important}</style></head>",
    )
    components.html(html, height=height + 20, scrolling=False)
    st.caption("🔵 service · ⚪ package · 🔴 CVE — orange edges and large nodes = the path the agent used")


def extract_paths(trace):
    """Pull every 'a -> b -> c' path string out of the tool results."""
    found = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "path" and isinstance(v, str):
                    found.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    for t in trace:
        try:
            walk(json.loads(t["result"]))
        except Exception:
            pass
    return [[n.strip() for n in p.split("->")] for p in found]


def extract_paths_from_text(text):
    """Fallback: find 'a -> b -> c' chains written in the agent's answer."""
    nodes, _ = load_graph()
    paths = []
    for chain in re.findall(r"[\w.\-]+(?:\s*(?:->|→)\s*[\w.\-]+)+", text):
        names = [n.strip() for n in re.split(r"->|→", chain)]
        if len(names) >= 2 and all(n in nodes for n in names):
            paths.append(names)
    return paths


def render_assistant(msg, expanded=False):
    st.markdown(msg["text"])
    paths = extract_paths(msg["trace"]) or extract_paths_from_text(msg["text"])
    if msg["trace"]:
        with st.expander("🔎 Tools the agent called"):
            for t in msg["trace"]:
                st.markdown(f"**{t['tool']}** `{json.dumps(t['args'])}`")
                st.code(t["result"], language="json")
    if msg["trace"] or paths:
        with st.expander("🕸️ Graph path behind this answer", expanded=expanded):
            render_graph(paths)


# --------------------------------------------------------------------------
# Page
# --------------------------------------------------------------------------
st.title("🛡️ Security Triage Agent")
st.caption("An agent that reasons over a FalkorDB knowledge graph, remembers past cases, "
           "acts by opening tickets, and shows the path behind every answer.")

agent, trace = get_agent()
if "messages" not in st.session_state:
    st.session_state.messages = []

clicked = None
with st.sidebar:
    st.subheader("Try asking")
    for q in EXAMPLES:
        if st.button(q, use_container_width=True):
            clicked = q

    st.subheader("🎫 Open tickets")
    try:
        tickets = json.loads(list_open_tickets())
    except Exception:
        tickets = []
    if tickets:
        for t in tickets:
            st.markdown(f"**{t['ticket']}** — {t['cve']} on `{t['service']}` → {t['team']}")
    else:
        st.caption("No tickets yet.")

    if st.button("Reset conversation"):
        st.session_state.messages = []
        agent.messages.clear()
        st.rerun()

if not st.session_state.messages:
    st.markdown("#### The knowledge graph the agent reasons over")
    render_graph([], height=400)
    st.caption("Ask a question. The agent will light up the exact path it follows.")

for i, m in enumerate(st.session_state.messages):
    with st.chat_message(m["role"]):
        if m["role"] == "user":
            st.markdown(m["text"])
        else:
            render_assistant(m, expanded=(i == len(st.session_state.messages) - 1))

prompt = st.chat_input("Ask about vulnerabilities, owners, or exposure...") or clicked
if prompt:
    st.session_state.messages.append({"role": "user", "text": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    with st.chat_message("assistant"):
        with st.spinner("Investigating the graph..."):
            reply = None
            for attempt in range(3):  # retry only temporary overloads (503)
                trace.clear()
                try:
                    reply = str(agent(prompt))
                    break
                except Exception as e:
                    msg_text = str(e)
                    print(f"[agent error, attempt {attempt + 1}] {msg_text[:300]}", flush=True)
                    if "503" in msg_text or "UNAVAILABLE" in msg_text:
                        time.sleep(3 * (attempt + 1))
                        continue
                    # quota (429), bad key, etc.: retrying will not help, show it now
                    reply = f"⚠️ Something went wrong: {e}"
                    break
            if reply is None:
                reply = "⚠️ The Gemini model is overloaded right now. Please try again in a minute."
            used = [dict(t) for t in trace]
    st.session_state.messages.append({"role": "assistant", "text": reply, "trace": used})
    st.rerun()