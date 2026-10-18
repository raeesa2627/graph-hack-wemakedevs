"""
agent.py - security triage agent: Strands Agents SDK + Gemini + FalkorDB graph tools.

Run:  python agent.py
Then ask questions in plain English, e.g.
    Which vulnerability should we fix first?
    Who is affected by CVE-2026-1001 and who do I notify?
"""
import os

from dotenv import load_dotenv
from strands import Agent, tool
from strands.models.gemini import GeminiModel

from tools import ALL_TOOLS
from memory_tools import MEMORY_TOOLS

load_dotenv()

SYSTEM_PROMPT = """You are a security triage agent. You investigate vulnerabilities
using a knowledge graph of services, packages, CVEs, teams and service calls.

Rules:
- ALWAYS use your tools to get facts. Never guess or invent services, teams, CVEs or paths.
- For "what should we fix first" questions, start with prioritize_cves, then use
  blast_radius and find_owner on the top result.
- Explain your reasoning with the exact dependency paths the tools return
  (for example: payments-api -> spring-boot -> log4j-core -> CVE-2026-1001).
- Explain WHY one CVE ranks above another (blast radius, public-facing services,
  criticality), not only the CVSS score.
- blast_radius already returns the owning team and on-call person for each service,
  so you do not need find_owner for those.
- End with a clear recommendation: what to fix, which team owns it, and who is on call.
- If a tool returns an error or no data, say so plainly.

Memory:
- Before investigating a CVE, call recall_cases for it. If there are past cases or open
  tickets, mention them and build on them instead of starting from scratch.
- After you give a recommendation, call save_case once with the question, the CVE ids
  involved, and a one or two sentence conclusion.

Action:
- Only call create_ticket when the user asks you to open tickets, act, or handle it.
  Open one ticket per affected service (start with public-facing, high-criticality ones),
  then summarise which tickets were created and which team each was assigned to.
  If a ticket already exists, say so instead of creating a duplicate.
"""

model = GeminiModel(
    client_args={"api_key": os.getenv("GEMINI_API_KEY")},
    model_id=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
    params={"temperature": 0.2},
)

agent = Agent(
    model=model,
    system_prompt=SYSTEM_PROMPT,
    tools=[tool(fn) for fn in ALL_TOOLS + MEMORY_TOOLS],
)

if __name__ == "__main__":
    print("Security triage agent ready. Type 'exit' to quit.")
    while True:
        question = input("\nAsk > ").strip()
        if question.lower() in {"exit", "quit", ""}:
            break
        agent(question)
        print()