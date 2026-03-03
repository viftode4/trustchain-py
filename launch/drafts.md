TrustChain Launch Drafts — March 4, 2026

================================================================
MESSAGING STRATEGY
================================================================

Core angle: "AI agents have no ID."

Plain English framing — no protocol names as headlines, no jargon (Sybil, Byzantine,
cryptographic primitive), no feature lists before the problem, no comparison matrices.

The TLS analogy: "TrustChain is for AI agents what TLS was for the early web."
Everyone understands this. It implies inevitability.

Key language rules:

  Instead of...                          Say...
  Bilateral half-blocks                  Both sides sign a receipt
  NetFlow Sybil resistance               Fake agents can't fake a history — no connections to real ones
  Ed25519 signatures                     Cryptographic proof
  Max-flow analysis                      Trust flows through real relationships
  IETF draft-viftode-trustchain-trust-00 IETF draft filed
  Transparent sidecar proxy              Works with any agent, zero code changes
  Protocol-agnostic                      Works with MCP, A2A, anything

The scary fact: Right now, when two AI agents talk, neither can verify who the other
is. No audit trail. No accountability. Nothing.

The analogy: We spent 40 years building internet trust (DNS, TLS, HTTPS). Then we gave
AI agents access to our most sensitive systems and forgot to build trust for them.

The proof it's already broken: 341 malicious OpenClaw skills. 82% impersonation
success rate. 8,000+ exposed MCP servers.

Our answer in plain English: Every interaction — both sides sign a receipt. You can't
fake a track record because trust flows through real relationships. Spin up 1000 fake
agents? They have no connections to real ones. Dead on arrival.

The one-liner: "TrustChain is the missing trust layer for AI agents — the same way
TLS was the missing security layer for the early web."

================================================================
CREDIBILITY STACK (use in all posts, but translate)
================================================================

- IETF draft filed
- NIST submission accepted
- Built on TU Delft research — original author is aware
- 12 framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, Google ADK,
  ElizaOS, Claude, Smolagents, PydanticAI, SemanticKernel, Agno, LlamaIndex)
- 930+ tests across Rust, Python, TypeScript
- OpenClaw plugin live on npm

OpenClaw GitHub issues to reference/comment on:
- #11014 — skill security scanning pipeline
- #23926 — skill:pre-install/post-install hooks
- #19640 — workspace file integrity + skill trust


================================================================
1. X/TWITTER THREAD (4 tweets)
================================================================

TWEET 1 — The alarm (no jargon)

Right now, when two AI agents talk to each other, neither one can prove who it is.

No ID. No audit trail. No way to verify.

We spent 40 years building trust for the internet (DNS, TLS, HTTPS). Then gave
autonomous agents the keys and forgot to build trust for them.


TWEET 2 — The proof it's already broken

This isn't theoretical:

- 341 malicious skills found on OpenClaw's marketplace
- 82% impersonation success rate in multi-agent systems
- 8,000+ MCP servers exposed with zero verification
- 91% of companies use AI agents, 10% have governance

The trust layer doesn't exist. So I built it.


TWEET 3 — What it does (plain English)

TrustChain: every agent-to-agent call — both sides sign a receipt. Like a contract,
not a diary.

Can't fake a history. New fake agents have no real connections — they're dead on arrival.

No blockchain. No tokens. No gas fees. Works offline. One decorator:

@with_trust(name="my-agent")


TWEET 4 — Builder credibility + CTA

Found a 2018 IETF draft from TU Delft that designed exactly this. Nobody built it.
So I did.

930+ tests. Rust + Python + TypeScript.
IETF draft filed. NIST submission accepted.
OpenClaw plugin live on npm.

pip install trustchain-py
github.com/viftode4/trustchain


================================================================
2. OPENCLAW DISCORD — #self-promotion
================================================================

AI agents have no ID. Here's the fix.

Right now, when two agents talk, neither can verify who the other is. VirusTotal
scans skill code for malware — great for static analysis. But nothing verifies
the agent running it.

A legitimate skill can start behaving maliciously after gaining trust. An agent can
impersonate another at runtime. VirusTotal can't catch that. Nobody can.

TrustChain fixes this. Every agent-to-agent call — both sides sign a receipt.
Trust builds through real interactions. Spin up 1000 fake agents? They have no
connections to real ones. Dead on arrival.

Already have an OpenClaw plugin with 5 tools:
- trustchain_check_trust — verify a peer before interacting
- trustchain_discover_peers — find capable agents ranked by trust
- trustchain_record_interaction — create proof of interaction
- trustchain_verify_chain — detect tampering in history
- trustchain_get_identity — resolve identity + delegation status

For Python agents:

pip install trustchain-py

from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # Done. Binary auto-downloads. All calls go through trust verification.
    ...

No blockchain. No tokens. Works offline. MIT licensed.

GitHub: https://github.com/viftode4/trustchain
Plugin: https://github.com/viftode4/trustchain-js/tree/master/packages/openclaw
PyPI: https://pypi.org/project/trustchain-py/


================================================================
3. SHOW HN
================================================================

Title: Show HN: TrustChain – The missing trust layer for AI agents

Body:

Hi HN,

I kept hitting the same problem: AI agents calling each other with zero way to verify
who's on the other end. No audit trail. No accountability. Nothing.

Then I found a 2018 IETF draft from TU Delft (Pouwelse et al.) that designed exactly
this — a bilateral trust protocol where every interaction creates cryptographic proof.
Nobody built it. So I did.

Why now:

The trust gap is already being exploited. 341 malicious skills were found on OpenClaw's
marketplace. Multi-agent impersonation attacks succeed 82% of the time. 8,000+ MCP
servers are running with zero caller verification. And 91% of organizations use AI
agents, but only 10% have any governance strategy.

We spent 40 years building internet trust (DNS, TLS, HTTPS). Then gave autonomous agents
the keys and forgot to build trust for them.

How it works (plain English):

Every call between two agents — both sides sign a receipt. Like a contract, not a diary.
Trust scores emerge from real interaction history — trust flows through real relationships.
Spin up 1000 fake agents? They have no connections to legitimate ones. Dead on arrival.

A transparent proxy means zero code changes for existing agents. Or use the decorator:

from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # Binary auto-downloads. All HTTP calls now go through trust verification.
    ...

What this is NOT: Not a blockchain (no global consensus, no mining, no tokens). Each
agent maintains its own local chain of interactions. Think Git for trust.

What I shipped:

- Rust core + Python SDK + TypeScript SDK (930+ tests, MIT licensed)
- 12 framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, Google ADK, etc.)
- OpenClaw plugin with 5 trust tools (live on npm)
- IETF draft filed (extending the original TU Delft protocol with trust computation)
- NIST CAISI submission accepted

This isn't a weekend project. It's infrastructure.

GitHub: https://github.com/viftode4/trustchain
PyPI: https://pypi.org/project/trustchain-py/
npm: https://www.npmjs.com/package/@trustchain/sdk
Paper: https://doi.org/10.1016/j.future.2017.08.048
IETF draft: https://datatracker.ietf.org/doc/draft-viftode-trustchain-trust/


================================================================
4. REDDIT POSTS
================================================================

--- r/OpenClaw ---

Title: VirusTotal scans skill code. Nothing verifies the agent running it. I built the missing piece.

Body:

VirusTotal integration is great for static analysis — scanning skill code for known
malware patterns. But it can't catch:

- A legitimate skill that starts behaving maliciously after gaining trust
- An agent impersonating another agent at runtime
- A man-in-the-middle modifying agent responses
- Fake agents manufacturing reputation through coordinated behavior

These are runtime problems. You need runtime trust.

I built TrustChain — every agent-to-agent call creates a receipt signed by both sides.
Trust builds through real interactions. Fake agents can't fake a history because they
have no connections to real ones. Dead on arrival.

Already have an OpenClaw plugin with 5 tools (check_trust, discover_peers,
record_interaction, verify_chain, get_identity). Works alongside VirusTotal, not
instead of it.

pip install trustchain-py

from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # Done. Binary auto-downloads. Trust verification is automatic.
    ...

No blockchain. No tokens. Works offline. MIT licensed.

Based on TU Delft research (IETF draft). 930+ tests across Rust, Python, TypeScript.

GitHub: https://github.com/viftode4/trustchain
Plugin: https://github.com/viftode4/trustchain-js/tree/master/packages/openclaw
Related issues: #11014, #23926, #19640


--- r/LocalLLaMA ---

Title: Built an open-source trust layer for AI agents — runs entirely local, no cloud, your data stays on your machine

Body:

When two AI agents talk, neither can verify who the other is. There's no audit trail,
no accountability. We built TrustChain to fix this.

Why you'd care (local-first angle):

- Runs entirely on your machine. No cloud. No vendor. No phone-home.
- The sidecar binary runs on localhost. Your trust data stays on disk.
- Works offline — trust history travels with your local chain.
- No blockchain, no tokens, no consensus network to sync with.

How it works:

Every agent-to-agent call — both sides sign a receipt. Trust builds through real
interactions. Fake agents can't fake a history — they have no connections to
legitimate ones.

One decorator:

from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # Binary auto-downloads. Runs on localhost. All data stays local.
    ...

Also available in TypeScript (@trustchain/sdk) and Rust.

930+ tests. MIT licensed. Based on TU Delft research.

GitHub: https://github.com/viftode4/trustchain
PyPI: https://pypi.org/project/trustchain-py/


--- r/MachineLearning ---

Title: [P] TrustChain: Bilateral trust protocol for AI agents with max-flow Sybil resistance (IETF draft filed)

Body:

We implemented and extended the TrustChain protocol from TU Delft (Otte, de Vos,
Pouwelse — Future Generation Computer Systems, 2020). The original protocol defined
bilateral half-block pairs for tamper-evident interaction recording but left trust
computation "out of scope." We filled that gap.

Protocol summary:

Every interaction between two agents creates a half-block pair. Each party independently
signs their own block referencing the shared transaction. Blocks form a personal hash
chain per agent (like a Git commit history). Chains are immutable and independently
verifiable.

Trust computation (our extension):

Trust scores are computed via max-flow network analysis (Ford-Fulkerson) from a set of
seed nodes. This provides Sybil resistance: an attacker can create arbitrarily many
fake identities, but they can only contribute as much trust capacity as their connections
to legitimate nodes allow. Below a threshold (netflow < 1e-10), trust is hard-zeroed
regardless of other signals.

Composite scoring: integrity (interaction completion rate with temporal decay) x 0.5 +
netflow x 0.5. The Sybil gate ensures netflow dominance in adversarial conditions.

Implementation:
- Rust core (Ed25519 signatures, BTreeMap canonical hashing, SQLite storage)
- Python SDK: pip install trustchain-py
- TypeScript SDK: @trustchain/sdk
- 12 framework adapters (LangGraph, CrewAI, AutoGen, OpenAI Agents, Google ADK, etc.)
- Delegation with TTL enforcement and scope restriction (max depth=2, 30-day TTL)

Filed: draft-viftode-trustchain-trust-00 (extending draft-pouwelse-trustchain-01).
Also submitted to NIST CAISI RFI on AI Agent Security.

930+ tests across Rust, Python, TypeScript. MIT licensed.

GitHub: https://github.com/viftode4/trustchain
Paper: https://doi.org/10.1016/j.future.2017.08.048
IETF draft: https://datatracker.ietf.org/doc/draft-viftode-trustchain-trust/


================================================================
5. DEV.TO ARTICLE
================================================================

Title: I Built the Missing Trust Layer for AI Agents


Last month, 341 malicious skills were discovered on OpenClaw's marketplace. Researchers
showed that multi-agent impersonation attacks succeed 82% of the time. Over 8,000 MCP
servers are running with zero caller verification.

We spent 40 years building trust for the internet. DNS tells you where to go. TLS tells
you the connection is secure. HTTPS tells you nobody's listening in.

Then we gave AI agents access to our most sensitive systems — our calendars, our code,
our databases — and forgot to build trust for them.

The problem is simple: when two AI agents talk to each other, neither one can prove
who it is. There's no ID. No audit trail. No way to verify.


What trust actually means for agents

Not ratings. Not reputation scores. Not "this agent has 4.5 stars."

Trust means: I can verify that you are who you say you are. I can see your actual
history of interactions. And you can't fake that history, because it's co-signed by
every agent you've ever interacted with.


How TrustChain works

Every call between two agents creates a receipt — signed by both sides. Like a contract,
not a diary. You can't write fake entries because the other party has to co-sign.

These receipts form a chain. Every agent builds their own chain over time. Trust scores
emerge from the actual network of interactions — trust flows through real relationships.

What about fake agents? Spin up 1000 of them. They can sign receipts with each other
all day long. But they have no connections to real agents. They're in a bubble. Dead on
arrival.

No blockchain. No tokens. No global consensus. No gas fees. Each agent just keeps their
own local chain of signed interactions.


One decorator

pip install trustchain-py

from trustchain import with_trust

@with_trust(name="my-agent")
def main():
    # That's it. Binary auto-downloads. All HTTP calls now go through
    # trust verification. No config needed.
    response = requests.get("https://some-agent-api.com/data")
    # Response headers now include trust score, verified identity,
    # and interaction count for the peer.

The @with_trust decorator:
1. Downloads the TrustChain binary (if not already present)
2. Starts a local sidecar proxy
3. Routes all HTTP traffic through it
4. Injects trust headers into every response
5. Cleans up when your function exits

Zero code changes to your existing agent logic.


Works with everything

TrustChain isn't tied to any specific agent protocol. It works with:

- MCP — trust-gated tool access
- A2A — verified agent-to-agent calls
- OpenClaw — plugin with 5 trust tools (live on npm)
- LangChain — callback handler
- FastAPI — ASGI middleware
- CrewAI — crew wrapper
- 12 framework adapters total


The backstory

I found a 2018 IETF draft from TU Delft (by Johan Pouwelse, who also created Tribler)
that designed exactly this protocol. The paper was published in Future Generation
Computer Systems in 2020. Nobody built it.

The original protocol defined how to create bilateral interaction records, but left
trust computation "out of scope." I built the full implementation and added the missing
piece — a trust scoring algorithm based on network flow analysis that makes it
mathematically expensive to fake trust.

I filed our own IETF draft extending the original. Submitted a response to NIST's AI
Agent Security initiative. Built SDKs in Rust, Python, and TypeScript. 930+ tests
across all three.


Getting started

Python:
pip install trustchain-py

TypeScript:
npm install @trustchain/sdk

CLI demo (see it working in 30 seconds):
pip install trustchain-py
trustchain demo


Links

GitHub: https://github.com/viftode4/trustchain
PyPI: https://pypi.org/project/trustchain-py/
npm: https://www.npmjs.com/package/@trustchain/sdk
Paper: https://doi.org/10.1016/j.future.2017.08.048
IETF draft: https://datatracker.ietf.org/doc/draft-viftode-trustchain-trust/

Every agent protocol handles communication. None handle trust. Until now.


================================================================
6. OPENCLAW GITHUB ISSUE — #33106 (already posted)
================================================================

Already live. No changes needed.


================================================================
7. COMMENT ON openclaw/openclaw#11014 (skill security scanning)
================================================================

Great start with VirusTotal for static analysis. One gap it can't cover: runtime trust.

A skill can pass code scanning and still be operated by a malicious agent — or a
legitimate operator can go rogue after building reputation. These are runtime problems.

We built TrustChain for this: every agent interaction creates a receipt signed by both
sides. Trust builds through real relationships. Fake agents have no connections to
legitimate ones — dead on arrival.

Already have an OpenClaw plugin ready. The skill:pre-install hook (#23926) could
check the publisher's trust score before allowing installation.

Plugin: https://github.com/viftode4/trustchain-js/tree/master/packages/openclaw
GitHub: https://github.com/viftode4/trustchain


================================================================
8. DM TO PETER STEINBERGER (@steipete)
================================================================

Hey Peter — congrats on the OpenAI move. I built TrustChain, an open-source trust
layer for AI agents. The problem is simple: when two agents talk, neither can prove
who the other is. No ID, no audit trail.

TrustChain fixes this — every agent-to-agent call, both sides sign a receipt. Trust
builds through real interactions. Fake agents can't manufacture history because they
have no connections to real ones.

Already have an OpenClaw plugin with 5 trust tools. Given the ClawHub supply chain
situation (341 malicious skills), this could help agents verify who they're talking
to before executing anything.

Integration is one line: pip install trustchain-py then @with_trust(name="my-agent").
IETF draft filed. NIST submission accepted.

Repo: https://github.com/viftode4/trustchain
Plugin: https://github.com/viftode4/trustchain-js/tree/master/packages/openclaw

Would love your thoughts — happy to hop on a call.


================================================================
9. NIST CAISI EMAIL
================================================================

Subject: Working implementation of agent trust verification — re: NIST-2025-0035

We submitted a response to your RFI on AI Agent Security. Since then, we've shipped
a working implementation:

- pip install trustchain-py — one-line integration for Python agents
- Every agent interaction — both sides sign a receipt (cryptographic proof)
- Fake agents can't manufacture trust — trust flows through real relationships
- 930+ tests, MIT licensed

The OWASP Top 10 for Agentic Applications 2026 lists several risks our implementation
addresses directly: identity spoofing, unauthorized tool access, and trust boundary
violations.

We'd welcome the opportunity to demonstrate to the CAISI team.

Implementation: https://github.com/viftode4/trustchain
IETF draft: https://datatracker.ietf.org/doc/draft-viftode-trustchain-trust/


================================================================
10. LINKEDIN POST (enterprise angle)
================================================================

91% of organizations use AI agents. 10% have a governance strategy.

We spent 40 years building trust for the internet — DNS, TLS, HTTPS. Then gave
autonomous agents access to our most sensitive systems and forgot to build trust
for them.

The result? 341 malicious skills on OpenClaw's marketplace. 82% impersonation
success rate in multi-agent systems. 8,000+ exposed MCP servers.

I built TrustChain — the missing trust layer for AI agents. The same way TLS was
the missing security layer for the early web.

How it works: every agent-to-agent interaction, both sides sign a receipt. Trust
builds through real relationships. Fake agents can't fake a history — they have no
connections to real ones.

IETF draft filed. NIST CAISI submission accepted. 930+ tests. MIT licensed.
Works with MCP, A2A, and 12 major agent frameworks.

GitHub: https://github.com/viftode4/trustchain
PyPI: https://pypi.org/project/trustchain-py/


================================================================
11. VIDEO SCRIPT (90 seconds)
================================================================

[0-5s] "Right now, when two AI agents talk, neither can prove who the other is."

[5-15s] Terminal: pip install trustchain-py

[15-25s] Editor: Write the 6-line @with_trust script

[25-40s] Terminal: Run it. Binary downloads, sidecar starts.

[40-50s] Browser: Open localhost dashboard — see agent identity

[50-70s] Terminal: Start second agent, run interactions. Dashboard shows trust
scores building in real-time.

[70-80s] "Every interaction, both sides sign a receipt. Fake agents have no real
connections — dead on arrival."

[80-90s] End card: "TrustChain — the missing trust layer for AI agents."
github.com/viftode4/trustchain


================================================================
POSTING SEQUENCE
================================================================

1. Today: X thread (4 tweets) + OpenClaw Discord
2. Tomorrow 9am ET: Show HN
3. Tomorrow midday: r/OpenClaw + r/LocalLLaMA
4. Tomorrow PM: r/MachineLearning + Dev.to article
5. This week: LinkedIn, NIST email, comment on openclaw#11014


================================================================
WHAT'S ALREADY DONE
================================================================

[x] GitHub issue on openclaw/openclaw: #33106
[x] Comment on openclaw/openclaw#11014
[x] npm: @trustchain/sdk + @trustchain/openclaw live
[ ] ClawHub: blocked by rate limit (retry later)
