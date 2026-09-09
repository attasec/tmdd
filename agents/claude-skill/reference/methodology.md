# Threat Modeling Methodology

The method answers the four classic questions in order, with an artifact for each:

| Question | Artifact | Where it lands |
|----------|----------|----------------|
| What are we working on? | Scope + attack-surface inventory + assets | `components.yaml`, `data_flows.yaml`, `actors.yaml`, analysis file |
| What can go wrong? | Threat actors, authorization matrix, abuse cases, sequence/state checklist, STRIDE-per-element matrix, traces, reachability | `threat_actors.yaml`, `threats.yaml`, analysis file |
| What are we going to do about it? | Bypass analysis of existing controls, mitigations with status and code references | `mitigations.yaml`, `features.yaml` |
| Did we do a good job? | Lint, coverage, human review fields, `tmdd review` on future diffs | lint output, summary, `reviewed_*` fields |

## 1. Scoping interview

Ask these before writing YAML, in one message, only the ones the repository cannot
answer. Offer your best guess from the code for each so the user can just confirm.
Do not block on them if the user is unavailable: proceed with the guess and record it
under *Assumptions* in `.tmdd/analysis/stride_matrix.md` and in the summary.

1. **Deployment and exposure.** Internet-facing, internal network, single-tenant on-prem,
   multi-tenant SaaS, developer tool run locally, CI? Which parts are reachable
   unauthenticated?
2. **Crown jewels.** Which data or capability would hurt most if stolen, altered, or made
   unavailable? (Names the assets and calibrates `sensitivity` and impact.)
3. **Threat actors in and out of scope.** For example: is a malicious insider with repo
   write access in scope? Is a compromised CI runner? Is physical access?
4. **Risk appetite.** What does `critical` mean here (regulatory breach, money movement,
   safety)? Are there threats the team has consciously accepted?
5. **Compliance or contractual drivers** (PCI, HIPAA, SOC 2, GDPR, customer security
   questionnaires) that force specific controls.
6. **Scope boundary.** Whole repo or specific services/directories? Any generated or
   vendored code to skip?

## 2. Attack-surface inventory

Enumerate every way data or control enters the system. This list is the backbone for
components, flows, and later for STRIDE. Record each with a file reference.

| Entry point class | Examples to look for |
|-------------------|----------------------|
| Network listeners | HTTP routes, gRPC services, WebSocket handlers, GraphQL resolvers |
| Async inputs | queue consumers, webhooks, scheduled jobs, file watchers, email ingestion |
| Local inputs | CLI arguments, stdin, environment variables, config files, files read from user-specified paths |
| Data stores read | databases, caches, object storage, secrets stores, YAML/JSON model files |
| Third-party responses | payment providers, OAuth/IdP, LLM APIs, package registries, CDNs |
| Outputs that execute elsewhere | generated HTML/JS, generated prompts, generated code, shell commands, emails with links |

For each entry point note: who can reach it (actor), authentication in front of it,
what data crosses, and where it lands (component). That maps 1:1 onto data flows.

## 3. Trust boundaries

Draw boundaries where the level of trust changes: internet -> edge; edge -> app; app ->
data store; app -> third party; developer workstation -> CI; model files -> generated
artifacts viewed in a browser. Every flow crossing a boundary is a mandatory row in the
STRIDE matrix. Set `trust_boundary` on components consistently (`public`, `dmz`,
`internal`, `external`, or the user's own vocabulary).

## 4. Assets

List what an attacker wants, in the user's terms: customer PII, credentials and tokens,
money-moving operations, integrity of security decisions (for a threat modeling tool, the
model itself), availability of a service, secrets in CI. Assets calibrate impact in the
severity rubric and sensitivity on flows.

## 5. Threat actors

Profile each adversary with access, capability, and motivation; keep it specific to
this system. Typical set, prune to what is in scope:

| ID pattern | Access | Notes |
|------------|--------|-------|
| `unauthenticated_internet_attacker` | public entry points only | automated scanning, credential stuffing, injection |
| `authenticated_user_malicious` | a legitimate account | IDOR, privilege escalation, abuse of business logic, cross-tenant access |
| `malicious_insider_repo_write` | repo write, can edit model/config files | poisons inputs to tooling, plants backdoors, prompt injection into generated prompts |
| `compromised_ci_runner` / `ci_pipeline_untrusted` | runs commands with untrusted PR input | argument injection, secret exfiltration |
| `supply_chain_attacker` | controls a dependency, CDN, model weights, container base image | code execution in build or in viewers' browsers |
| `network_adversary` | on-path between components | only relevant where TLS/mTLS is absent |

Map each threat actor to the entry points they can reach; a feature's `threat_actors`
list is derived from its flows' sources.

## 6. Authorization matrix

Build this for any system with more than one role, tenant, or ownership relation, before
the abuse cases. It is the most reliable way to find IDOR, missing function-level checks,
and tenant leaks, because it turns "authz exists" into a cell-by-cell claim that can be
checked in code. For a single-role, single-user system write one line in the analysis
file saying so and skip the rest.

Rows: every actor from `actors.yaml` plus `unauthenticated`. Columns: every resource the
code exposes (orders, users, reports, settings, files, jobs, API keys) crossed with the
operations on it (create, read one, list, update, delete, execute or approve). Fill each
cell in two passes:

1. **Intended policy**: `allow` or `deny`, from docs, the interview, or the obvious
   reading of the product. Mark guesses.
2. **Enforcement**: for every `deny` cell reachable through an entry point, the file:line
   of the check that enforces it, or `MISSING`. For every `allow` cell on an object owned
   by another user or tenant, the file:line of the ownership or tenant predicate, or
   `MISSING`.

Look specifically for:
- Lookups by id without an owner or tenant predicate (`get(id)` where `get(id, owner=me)`
  is needed); list, search, export, and report paths that skip the filter the
  single-object path applies.
- Checks that live in the client, in a decorator some routes do not use, or in one
  controller while a second path (bulk, admin, webhook, CLI, GraphQL field, older API
  version) reaches the same data.
- Role changes, invitations, approvals, and impersonation: who can grant what, and
  whether the grantor's own role is verified server-side.
- Horizontal moves inside a tenant (user A reads user B) as well as vertical ones
  (user to admin).

Every `MISSING` cell is a threat, cited at the handler that lacks the check: `E` for a
missing authz check, `I` for a read of another principal's data, `T` for a write. Record
the matrix in the analysis file under `## Authorization matrix`.

## 7. Abuse cases per feature

Before enumerating threats for a feature, write at least three attacker stories, and at
least one for every threat actor that can reach the feature:
"As `<threat actor>`, I want to `<goal against an asset>` by `<abusing this entry point>`."
They anchor severity (what is actually gained) and stop the matrix from becoming an
abstract exercise. Draw them from three sources: the `MISSING` cells of the authorization
matrix (section 6), the sequence and state questions (section 8), and the traces that
reach a sink without a control (`discovery.md` section 5). Keep them in the analysis
file under the feature's heading.

## 8. Sequence, state, and race threats

STRIDE is element-centric and misses threats that only exist across several steps. For
every feature that is a multi-step workflow (checkout, signup with verification,
password reset, approval, upload then process, import or export, OAuth or token
exchange, any job queue) and for every operation with money, quota, inventory, or
one-time semantics, walk this list and add a row to the analysis file under
`## Sequence and state` for each applicable item:

| Question | Typical finding | CWE |
|----------|-----------------|-----|
| Can a step be skipped, repeated, or run out of order? (call step 3 without step 2, replay the callback, resubmit the form) | state-machine bypass, double redemption | 841, 294 |
| Is the operation idempotent under retries, duplicate webhooks, double-click? | duplicate charge or credit | 799 |
| Two concurrent requests on the same resource: are the check and the use one atomic step? (balance check then debit, coupon check then apply, exists check then write, uniqueness check then insert) | TOCTOU, race to double-spend, limit bypass | 367, 362 |
| Is a security decision cached or precomputed and reused after the underlying fact changes? (role in session, token valid after password change or logout, invite valid after revocation) | stale authorization | 613, 672 |
| Do one-time artifacts (reset tokens, invite links, OTPs, nonces, upload URLs) expire, bind to one principal, and get invalidated on use? | token reuse, cross-account reset | 640, 294 |
| Can the client influence a server-computed value at any step? (price, quantity, fee, recipient, role, redirect) | parameter tampering | 602, 915 |
| What happens on partial failure between two writes (DB plus external call, two stores, file plus index)? | inconsistent state exploitable for free goods or privilege | 691 |
| Can a long-running or scheduled job be triggered more often, or with another user's parameters? | quota bypass, cross-user job | 285, 770 |

Write each candidate abuse case as a numbered sequence ("1. attacker starts checkout;
2. ...; 3. ...") so a reviewer can reproduce it, then apply the reachability check in
section 10. A concurrency finding must name the shared resource, the check, and the use
with file:line; "there could be a race" without those is not a finding.

## 9. STRIDE-per-element matrix

Rows: every component and every data flow (flows crossing a trust boundary first).
Columns: S, T, R, I, D, E. Fill every cell with one of:

- a threat ID (new or existing),
- `n/a: <reason>` (e.g. "n/a: internal function call, same process, no untrusted input"),
- `covered: <mitigation_id>` when an existing control removes the threat and you verified it
  by trace (`discovery.md` section 5) and the bypass questions (section 12); still
  consider recording it as a threat with `status: implemented` so future diffs re-verify it.

A cell's threat candidates come from the traces for that element's inputs, the
authorization matrix, and the sequence and state checklist, checked against the
per-element prompts below; the prompts are there to catch what the traces missed, not to
replace them.

Per-element prompts:

| Element type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| External actor -> component flow | can the caller be impersonated (weak auth, replayable tokens, missing signature)? | can the payload be altered or malformed to change behavior (validation, CSRF, injection)? | can the caller deny the action (no audit log, no request id)? | does the response over-share (verbose errors, excessive fields)? | can it be flooded or made expensive (no rate limit, unbounded work, regex/zip bombs)? | can the caller do more than allowed (missing authz, mass assignment, IDOR)? |
| Component -> data store flow | can a rogue writer pose as the app (shared creds)? | injection into the query; unvalidated writes | no change history | reads return other tenants' rows; secrets in plain text | unbounded queries, lock contention | app account over-privileged |
| Component -> third party flow | is the third party verified (TLS, pinning, webhook signature)? | can responses be tampered (no integrity check)? | disputes on callbacks | secrets or PII sent unnecessarily | dependency outage, retries storm | callback used to escalate |
| Generated artifact -> viewer/agent | can the artifact impersonate a trusted source? | stored XSS, prompt injection, script breakout | none of note | model or secret data embedded | huge artifacts | agent gains tools/permissions via injected instructions |
| Local process with CLI/file input | env/config spoofing | path traversal, argument injection, unsafe deserialization | none of note | error messages as oracles, world-readable outputs | ReDoS, decompression bombs | subprocess with shell, setuid, privilege of the running user |

Write the matrix to `.tmdd/analysis/stride_matrix.md` with this header:

```markdown
# STRIDE coverage matrix — <system> — <date>

## Assumptions
- ...

## Abuse cases
### <Feature>
- As <actor>, I want ... by ...

## Authorization matrix
| Actor | <resource>.read | <resource>.list | <resource>.update | ... |
|-------|-----------------|-----------------|-------------------|-----|
| end_user | allow, own only: `src/api/orders.py:52` | allow, filtered: `orders.py:31` | MISSING (`orders.py:70` has no owner check) | ... |

## Traces
- `POST /api/search -> q -> search.ts:38 build_where() -> prisma.$queryRaw search.ts:47 [controls: none]`

## Sequence and state
- Checkout: coupon check `cart.ts:88` and apply `cart.ts:104` are separate transactions -> `race_coupon_double_apply`

## Dependencies
- pip-audit 2026-09-07: <package> <version> <advisory> -> `<threat_id>` / not reachable because ...

## Reachability
- `sqli_search_where_clause`: unauthenticated_internet_attacker -> GET /api/search; reproduced 2026-09-07 with q=`' OR 1=1--` against local instance

## Matrix
| Element | Type | S | T | R | I | D | E |
|---------|------|---|---|---|---|---|---|
| df_user_to_api | flow (public->internal) | `spoof_session_fixation` | `sqli_search_where_clause` | n/a: audit log in place (`request_audit_log`) | `verbose_search_errors` | `search_enum_rate_limit` | `idor_order_lookup` |

## Not modeled
- <directory or subsystem>: <why>
```

Update the file incrementally in later runs; do not rewrite history.

## 10. Reachability check (before severity)

A threat is only as real as the path to it. Before assigning severity, establish for
each candidate threat, and record under `## Reachability` in the analysis file:

1. **Entry point**: the route, command, job, or file the attacker uses, and which threat
   actor (section 5) can reach it.
2. **Path**: the trace from `discovery.md` section 5 showing the input reaching the
   sink, with every control on the way and why it does or does not stop the payload
   (section 12).
3. **Preconditions**: what the attacker must already have (an account, a role, a victim
   action, repo write, a compromised dependency, network position).
4. **Demonstration**, when it is cheap and safe: call the function with a crafted
   argument in a scratch script or unit test, time a regex, send a request to a local
   instance, run the CLI with the payload against a throwaway directory. Never test
   against production or shared environments and never run a payload that can destroy
   data or leave persistent changes. Record the result in the threat description's last
   sentence as "reproduced <date>: <how>" or "not reproduced: <why>".

Outcomes:
- **Reachable and demonstrated**: severity by the rubric; likelihood is not lower than
  Medium.
- **Reachable by trace, not demonstrated**: severity by the rubric; say it was not
  demonstrated.
- **Not reachable today** (dead code, control verified on every path after section 12):
  not an open threat. Either write `n/a` in the matrix cell citing the blocking control
  at file:line, or record it with `status: implemented` bound to that control so future
  diffs re-verify it.
- **Unknown** (dynamic dispatch, generated code, path could not be followed): record the
  threat with the uncertainty stated and list it under *Open questions* in the summary.

## 11. Severity rubric

Severity describes the risk *as the code is today*, so existing controls lower likelihood,
but only controls that survived the bypass analysis (section 12). Assign likelihood after
the reachability check (section 10): a demonstrated path is never Low. When a control is
later removed, `tmdd review` surfaces the threat for re-verification.

Likelihood (pick the highest that applies):

| Level | Criteria |
|-------|----------|
| High | reachable by an unauthenticated or low-privilege actor over the network, no meaningful control in the path, well-known technique or trivial payload |
| Medium | requires a valid account, a specific precondition, or the attacker already inside a boundary (insider, CI); partial controls exist |
| Low | requires local access, a compromised trusted party, or chaining with another weakness; strong controls exist and the residual is edge cases |

Impact (pick the highest that applies, in the user's asset terms):

| Level | Criteria |
|-------|----------|
| High | full compromise of a crown-jewel asset: cross-tenant data access, code execution, money movement, credentials/secrets, integrity of a security decision |
| Medium | bounded data exposure or tampering, single-user impact, service degradation, oracle/enumeration that enables the above |
| Low | cosmetic, requires victim cooperation, affects only the attacker's own data, or availability of a non-critical local tool |

Mapping:

| | Impact High | Impact Medium | Impact Low |
|---|---|---|---|
| **Likelihood High** | critical | high | medium |
| **Likelihood Medium** | high | medium | low |
| **Likelihood Low** | medium | low | low |

Record the two inputs in the threat description's last sentence when they are not obvious
("Residual risk is low given the suffix concatenation" style), so a reader can challenge the
call. If the user gave a risk appetite in the interview, apply it here and say so.

## 12. Control-bypass analysis

An existing control lowers likelihood only if it cannot be bypassed. Before writing
`covered:` in a matrix cell, setting `status: implemented`, or lowering likelihood because
a control exists, answer these for that control and put the answer next to its
`references` in the mitigation description:

| Bypass class | Ask | Where to look |
|--------------|-----|---------------|
| Alternate route | Does every path to the sink pass through the control? Other routes, bulk or batch endpoints, admin and internal APIs, GraphQL fields, CLI flags, background jobs, webhooks, older API versions, direct calls from other modules | every caller of the sink (`rg` its name); route tables; middleware registration |
| Ordering | Is the control registered before the handler and before body parsing or any early return? Does an exception path skip it? | middleware and decorator order; try/except; early `return`; error handlers |
| Encoding and normalisation | Is the check applied to the same representation the sink consumes? Unicode normalisation, case folding, URL and double encoding, path normalisation (`..`, `\\`, trailing dot or space), null bytes, JSON versus form parsing, content-type sniffing | any decode or normalise step between validator and sink |
| Type and shape | Arrays where a scalar is expected, objects where a string is expected, duplicate keys or parameters, huge or negative numbers, empty strings, `null` | parser configuration; validator strictness |
| Scope of the check | Denylist instead of allowlist; unanchored regex; prefix match; only the first element checked; a copy checked while the sink reads the original | the validator's code |
| Time of check | Value re-read from a mutable source after the check (section 8) | shared state between check and use |
| Fail-open | What happens when the control errors, times out, or its dependency is down (IdP, rate limiter, WAF, cache)? | exception handling around the control |
| Configuration | Can the control be disabled by config, env var, debug or feature flag, or a header? Is the secure setting the default? | settings, env parsing, flags |
| Client-side only | Is any part of the decision made in the browser or app, or trusted from a client-supplied field (`role`, `price`, `is_admin`, redirect target)? | request parsing; mass assignment |

A bypass found becomes a threat at the bypass location, and the mitigation describes the
missing enforcement point, not a second copy of the same check. If the control holds on
every path, cite the enforcement point and the callers you checked in the mitigation
description; that is what makes `status: implemented` trustworthy.

## 13. Mitigation discipline

For every threat, decide one of:

- **Verified in code** -> only after the bypass analysis (section 12) found no alternate
  path; rich mitigation with `references`; feature mapping `status: implemented`.
- **Missing** -> mitigation described concretely (mechanism, where it goes, what it rejects);
  `status: required`; no `references` unless the target file exists and is the right home.
- **Accepted** -> only on the user's explicit decision; `mitigations: accepted` or
  `status: accepted`; YAML comment with who/why/date; tell the user the feature needs
  `reviewed_by`.

Prefer one mitigation per mechanism, reused across threats, over one mitigation per
threat. Good IDs name the mechanism: `parameterized_queries`, `webhook_hmac_verify`,
`sri_hashes_cdn`, `bound_glob_complexity`.

## 14. Prioritized output

The summary's *Top findings* section lists threats by severity, each with: where (file),
who can exploit it (actor), what they gain (asset), what to do (mitigation ID and the
concrete change), and the status. Three to seven items; the rest live in the report.
