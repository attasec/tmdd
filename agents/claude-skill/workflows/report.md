# Workflow: Reports, diagrams, compiled prompts

Use for "generate the report", "show me the threat model", "give me the diagram", or when a
stakeholder-facing artifact is needed. Always lint first so the artifacts reflect a valid
model.

```bash
tmdd lint                              # must exit 0
tmdd-report --format md                # .tmdd/out/tm.md   (Markdown, mermaid diagram, per-feature tables)
tmdd-report                            # .tmdd/out/tm.html (interactive; loads Cytoscape from a CDN)
tmdd-diagram [-f "<Feature>"]          # .tmdd/out/diagram.html, optional feature highlight
tmdd compile [--feature "<Feature>"]   # .tmdd/out/<system>.tm.yaml + secure-coding prompt
```

Then:

1. Read `.tmdd/out/tm.md` and check it against the model for anything that reads wrong to a
   stakeholder: features with no threats, threats with "risk accepted" but no reviewer,
   `needs re-review` markers. Fix the model, not the report.
2. Tell the user where each file is, that the HTML artifacts need internet access for the
   CDN libraries, and which features await human review.
3. If the user wants a narrative, write it from the report: system overview, trust
   boundaries, top risks by severity with status, accepted risks and by whom, open work
   grouped by mitigation. Keep numbers in tables.
4. `.tmdd/out/` is generated; recommend adding it to `.gitignore` if it is not, unless the
   team intentionally commits `tm.md` as documentation.
