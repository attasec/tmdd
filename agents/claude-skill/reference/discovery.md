# Codebase Discovery Checklists

How to find the architecture and the security-relevant code fast, and which threat
patterns to test each element against. Use `grep`/`rg` and `git ls-files`; read the
handful of files that matter (entry points, auth, data access, anything that shells out
or renders), not the whole tree, then trace inputs to sinks (section 5) before
concluding anything about them.

## 1. Orientation (5 minutes)

```bash
git ls-files | sed 's|/[^/]*$||' | sort | uniq -c | sort -rn | head -40   # directory shape
ls package.json pyproject.toml setup.py requirements*.txt go.mod Cargo.toml pom.xml build.gradle Gemfile composer.json 2>/dev/null
ls Dockerfile* docker-compose* *.tf k8s helm .github/workflows 2>/dev/null
```

Identify: languages and frameworks; process boundaries (services, workers, CLIs, front
ends); how it is deployed (containers, serverless, desktop, library); test layout (to add
to `source_paths`).

## 2. Dependency audit

Third-party code is part of the attack surface. Run the audit for every manifest found
in section 1 and record the result in the analysis file under `## Dependencies`.

| Ecosystem | Command | Notes |
|-----------|---------|-------|
| Python | `pip-audit -r requirements.txt` (or `pip-audit` inside the venv) | `pip install pip-audit` if missing; also read `pyproject.toml` pins |
| Node | `npm audit --omit=dev` (`pnpm audit`, `yarn npm audit`) | needs a lockfile; note if there is none |
| Go | `govulncheck ./...` | reports only reachable vulnerabilities |
| Rust | `cargo audit` | `cargo install cargo-audit` |
| Java / Kotlin | `mvn org.owasp:dependency-check-maven:check` or `gradle dependencyCheckAnalyze` | slow on first run |
| Ruby | `bundle audit` | |
| .NET | `dotnet list package --vulnerable --include-transitive` | |
| PHP | `composer audit` | |
| Containers / CI | `trivy fs .` or `grype .` when available; otherwise read `Dockerfile` base-image tags and `.github/workflows` action pins by hand | |

If the tool is not installed and cannot be installed, say so and fall back to reading the
manifest: flag unpinned versions and floating ranges (`^`, `>=`, `latest`), git or URL
dependencies, packages that are end-of-life, and CI actions pinned to a branch or tag
instead of a commit SHA.

How results enter the model:
- A vulnerable dependency that a modeled component imports becomes a threat on that
  component: name the package, version, and advisory ID; `stride` by the vulnerability's
  effect; `cwe: CWE-1395`; mitigation is the fixed version. Bind it to the flows that
  exercise the package. If the vulnerable function is provably not called, record it as
  `n/a` in the analysis file with the evidence instead.
- Unpinned or unverifiable dependencies and unpinned CI actions become one supply-chain
  threat per delivery path (`CWE-1104` / `CWE-829`), not one per package.
- Dev-only findings are noted in the analysis file, not modeled, unless the dev tooling
  runs in CI with access to secrets.

## 3. Entry points by stack

| Stack | Where routes/handlers live | Grep |
|-------|----------------------------|------|
| Express/Koa/Fastify | `routes/`, `app.get(`, `router.` | `rg -n "\.(get|post|put|patch|delete)\(" --type js --type ts` |
| Next.js/Remix | `app/api/**/route.ts`, `pages/api/**`, server actions (`"use server"`) | `rg -n "use server|export async function (GET|POST)"` |
| Django/Flask/FastAPI | `urls.py`, `@app.route`, `@router.` | `rg -n "@(app|router|api)\.(get|post|route)|path\(" --type py` |
| Spring | `@RestController`, `@RequestMapping` | `rg -n "@(Get|Post|Put|Delete|Request)Mapping"` |
| Go net/http, gin, chi | `HandleFunc(`, `r.GET(` | `rg -n "HandleFunc\(|\.(GET|POST)\(" --type go` |
| Rails | `config/routes.rb` | read the file |
| gRPC | `.proto` services, generated servers | `rg -n "service .* \{" --type proto` |
| GraphQL | schema files, resolvers | `rg -n "type (Query|Mutation)"` |
| CLI | argparse/click/cobra/clap definitions | `rg -n "add_argument\(|@click\.|cobra\.Command|#\[derive\(Parser"` |
| Workers/queues | consumers, cron | `rg -n "consume|subscribe|@shared_task|cron|schedule\("` |
| Webhooks | routes named webhook/callback | `rg -n -i "webhook|callback"` |

## 4. Security-relevant patterns (grep first, then read)

| Concern | What to grep for | What to record |
|---------|------------------|----------------|
| Authentication | `passport|jwt|jsonwebtoken|session|OAuth|oidc|login|bcrypt|argon2|verify_password` | mechanism, where enforced (middleware vs per-route), token lifetime, storage |
| Authorization | `role|permission|can\(|policy|authorize|is_admin|owner_id|tenant_id` | central vs scattered checks; object-level checks on lookups by id |
| Input validation | `zod|joi|yup|pydantic|marshmallow|validator|schema\.parse` | present on which inputs; absent where |
| SQL / ORM | `\.raw\(|\$queryRaw|execute\(f"|execute\(.*%|text\(|cursor\.execute|sequelize\.query|knex\.raw` | raw query sites with user input |
| NoSQL | `\$where|find\(req\.|find\(\{.*req` | query object injection |
| Command execution | `subprocess|os\.system|exec\(|spawn\(|execSync|child_process|Runtime\.getRuntime|os/exec` | shell=True, string-built commands, user-controlled args |
| File system | `open\(|readFile|writeFile|sendFile|path\.join\(.*req|os\.path\.join|Path\(` with user input | path traversal on read and write; temp files |
| Deserialization | `pickle|yaml\.load\(|yaml\.unsafe|unserialize|ObjectInputStream|Marshal\.load|eval\(` | unsafe loaders on untrusted input |
| HTML rendering | `innerHTML|dangerouslySetInnerHTML|\|safe|mark_safe|render_template_string|v-html|document\.write` | XSS sinks; template autoescape settings |
| Redirects / URLs | `redirect\(|fetch\(|axios|requests\.get\(|http\.Get\(|urllib` with user input | open redirect, SSRF |
| Secrets | `process\.env|os\.environ|getenv|API_KEY|SECRET|PRIVATE_KEY|-----BEGIN` | hardcoded secrets, secret handling |
| Crypto | `md5|sha1|Random\(|Math\.random|crypto\.|AES|ECB` | weak hashes for passwords, weak randomness for tokens |
| Logging | `logger\.|console\.log|print\(` near auth or payment code | secrets or PII in logs; absence of audit logs on sensitive actions |
| Rate limiting | `rate|throttle|limiter|slowDown` | present where |
| CORS / headers / CSP | `cors\(|Access-Control|helmet|Content-Security-Policy|SameSite` | policy values |
| File upload | `multer|multipart|UploadFile|FormFile` | type/size checks, storage location, filename handling |
| Regex on input | `re\.compile|new RegExp|regex` fed by user input | ReDoS |
| Compression / archives | `zipfile|tarfile|unzip|extractall` | zip slip, bombs |
| Third-party calls | SDK imports, `https://` literals | which providers, how authenticated, response trust |
| Generated artifacts | code that writes `.html`, `.js`, prompts, scripts | injection into what runs elsewhere |

## 5. Input-to-sink traces

Greps find candidate sinks; traces decide whether untrusted input reaches them. Do this
for every entry point from section 3 and for every sink hit in section 4 whose caller is
not obvious. Read the code along the path; never infer from names.

For each entry point:

1. **List its untrusted inputs**: path and query parameters, headers (including `Host`,
   `X-Forwarded-*`, `Origin`, `Referer`), body fields, cookies, uploaded file names and
   contents, CLI arguments, environment variables, files read from user-supplied paths,
   queue and webhook payloads, and the responses of third-party calls made on the way.
2. **Follow each input forward** through assignments, helper functions, ORM and model
   layers, serializers, and background hand-offs until it is consumed or dropped. Use
   `rg` on the variable and function names and open every callee that takes the value.
3. **Record each sink it reaches** as one line:
   `<entry> -> <param> -> <fn>:<line> -> ... -> <sink fn>:<line> [controls: <fn>:<line> (what it rejects) | none]`
4. **Classify the sink** and pair it with the control that should protect it:

| Sink class | Examples | Protecting control |
|------------|----------|--------------------|
| Query | SQL/NoSQL builders, raw query APIs, ORM `raw`/`extra`, LDAP, search DSLs | parameterisation; builder without string concatenation |
| Command / process | `subprocess`, `exec`, `spawn`, shell strings, argument lists to external tools | argv lists, `--` end-of-options, allowlisted arguments |
| Filesystem | open/read/write/delete, path joins, archive extraction, temp files, `sendFile` | normalisation plus root confinement; name allowlist |
| Network | outbound HTTP, redirects, webhooks, DNS, sockets | destination allowlist; scheme and host validation |
| Markup / code | HTML templates, `innerHTML`, Markdown renderers, generated JS/CSS, `eval`, template engines, generated prompts, generated shell or CI files | context-aware encoding; autoescape on; sandboxed templates |
| Deserialisation | pickle, YAML loaders, XML parsers, Java/PHP object streams, JWT parsing | safe loader; schema validation; external entities off; alias/size limits |
| Security decision | role, tenant, and owner comparisons; redirect targets; price and quantity; signature-verification inputs | server-side source of truth; constant-time compare; signed values |
| Logs and errors | log calls; exception text returned to the caller | redaction; generic error responses |
| Stored, rendered later | DB columns shown in another UI, stored filenames, stored URLs, stored model text | output encoding at every consumer (stored XSS / stored injection) |

5. **Decide.** A trace that reaches a sink with no adequate control on the path is a
   threat; quote the trace in the threat description. A trace stopped by a control is the
   evidence for `covered:` or `status: implemented`, but only after the bypass questions
   in `methodology.md` section 12. Store every trace in the analysis file under
   `## Traces` so the next audit can re-walk them.

**Trace backwards too** for the highest-value sinks: from each sink, list every caller
(`rg` the function name) and confirm the origin of each caller's argument. This finds the
second route that skips the validator.

## 6. Per-stack threat prompts

Use with the STRIDE matrix. Each item is a candidate threat to test, with the CWE to cite.

**Web application / HTTP API**
- Missing/weak authn on a route (CWE-306/287); session fixation, no rotation on login (CWE-384)
- Object-level authz missing, IDOR (CWE-639); function-level authz missing (CWE-285)
- Mass assignment / over-posting (CWE-915)
- Injection: SQL (89), NoSQL (943), command (78), LDAP (90), template (1336), header (113)
- XSS stored/reflected/DOM (79); CSRF (352); clickjacking (1021)
- SSRF (918); open redirect (601)
- Path traversal on read/write (22); unrestricted upload (434)
- Insecure deserialization (502)
- Verbose errors, stack traces (209); excessive data in responses (200/213)
- Missing rate limiting, resource exhaustion (770/400); ReDoS (1333)
- Weak password storage (916); weak token randomness (330); JWT `alg:none`/weak secret (347)
- Secrets in repo/config (798); sensitive data in logs (532)
- Missing audit trail for sensitive actions (778)
- Missing TLS/HSTS, mixed content (319); permissive CORS (942); missing CSP (1021)

**CLI tools / developer tooling / build steps**
- Argument injection into subprocesses (88); shell=True with input (78)
- Path traversal via output/name/path args (22); symlink following (59); insecure temp files (377)
- Unsafe YAML/pickle loading of project files (502)
- ReDoS from user-supplied patterns/globs (1333); decompression bombs (409)
- Injection into generated artifacts: HTML reports (79), prompts for AI agents (77/1427), shell scripts (78)
- Trusting repo-controlled config when run in CI on untrusted PRs (829/1104)
- World-readable outputs containing secrets (732); secrets in CLI history/logs (532)

**Data stores / caches / queues**
- Over-privileged service accounts (250); shared credentials across services (287)
- Missing tenant scoping in queries (285); unencrypted sensitive columns (311)
- Poison messages crash consumers (20); no idempotency on retries (leads to duplicate money movement)
- Cache poisoning / unkeyed inputs (349); stale authz decisions cached
- Backups and dumps exposure (530)

**Third-party integrations / webhooks / OAuth**
- Unverified webhook signatures (345/347); replay (294)
- OAuth: missing `state`/PKCE (352), redirect URI validation (601), token leakage in logs/URLs (598)
- API keys in client bundles (798); overly broad scopes (250)
- Trusting third-party response content (unvalidated data, SSRF via callback URLs)

**Infrastructure as code / containers / CI**
- Public buckets, open security groups (284); IAM wildcards (269)
- Containers as root, writable filesystem (250); secrets in images/env (798)
- CI: `pull_request_target` with checkout of PR head, script injection via `${{ github.event... }}` (78/94); unpinned actions/dependencies (829/1104); cache poisoning
- Missing dependency pinning and lockfiles; typosquat exposure (1357)

**Front end / SPA / mobile client**
- Tokens in localStorage exposed to XSS (922); auth decisions in client only (602)
- Secrets embedded in bundles (798); deep-link/intent injection
- Insecure WebView/`postMessage` origin checks (346)

## 7. AI / LLM-specific checklist

Activate when the code calls a model API (Anthropic, OpenAI, Bedrock, Vertex, local
models), builds agents or tools (function calling, MCP servers/clients, LangChain-style
chains), does RAG/embeddings, or generates prompts for other agents.

| Threat pattern | Where to look | STRIDE / CWE |
|----------------|---------------|--------------|
| Direct prompt injection: user text alters system instructions | prompt assembly, string concatenation of user content into system/developer messages | T / CWE-1427 |
| Indirect prompt injection: retrieved docs, tool results, web pages, repo files carry instructions | RAG loaders, tool result handling, generated prompt files built from repo-controlled data | T / CWE-1427 |
| Excessive agency: tools that write files, run commands, send money/email without confirmation | tool definitions, MCP server capabilities, permission gating | E / CWE-250 |
| Unsafe output handling: model output rendered as HTML, executed as code/SQL/shell | sinks fed by model responses | T / CWE-79, 78, 89, 94 |
| Sensitive data disclosure: secrets/PII in prompts, logs, traces, or model responses | prompt logging, observability, context assembly | I / CWE-532, 200 |
| System prompt leakage exposing business logic or credentials | system prompts containing secrets or authz rules | I / CWE-200 |
| Model denial of wallet/service: unbounded tokens, loops, recursive agents | max_tokens, iteration caps, timeouts, per-user quotas | D / CWE-770, 400 |
| Insecure tool/MCP supply chain: untrusted servers, unpinned versions, tool description injection | MCP config, dependency manifests | T / CWE-829, 1104 |
| RAG/embedding poisoning and cross-tenant retrieval | ingestion pipeline, vector store tenancy filters | T,I / CWE-285 |
| Missing human-in-the-loop for irreversible actions | agent loops, approval gates | E / CWE-862 |
| Weak isolation between model-generated code and host | sandboxing of executed code | E / CWE-94 |

Mitigation vocabulary: `prompt_delimiters_and_roles`, `tool_result_untrusted_marking`,
`tool_allowlist_least_privilege`, `human_confirmation_irreversible_actions`,
`model_output_encoding_before_sink`, `prompt_log_redaction`, `token_and_iteration_caps`,
`mcp_server_pinning`, `tenant_scoped_retrieval`, `code_execution_sandbox`.

## 8. Component and flow extraction rules

- One component per process or clearly separate module with its own responsibility and
  files. Split a directory into several components when its files serve different features
  (avoids hubs).
- External services and third-party CDNs/registries are components with
  `trust_boundary: external` and no `source_paths`.
- Data stores are components (`database`, `cache`, `queue`) even when managed; the flow to
  them carries the query/data description.
- Generated artifact stores (output directories) are components only when something
  consumes them (a viewer, an agent). Give them no `source_paths`.
- A flow per direction of real data movement, with the actual protocol (`HTTPS`, `gRPC`,
  `AMQP`, `filesystem`, `subprocess`, `function_call`) and the actual auth (`none`,
  `session cookie`, `JWT`, `mTLS`, `HMAC signature`).
- Actors: legitimate roles and external systems that initiate flows. Adversaries go in
  `threat_actors.yaml`.
