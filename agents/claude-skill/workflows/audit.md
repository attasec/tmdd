# Workflow: Audit an existing model against the code

Use for "is the threat model current", periodic hygiene, after large refactors, or before
trusting the model for reviews. It finds drift in both directions: model claims the code no
longer supports, and code the model does not cover. Read `reference/schema.md` first.

## Steps

1. **Baseline.** `tmdd lint` and `tmdd lint --strict-refs`. Record errors, missing
   references, stale-review warnings, features without `reviewed_by`.
2. **Coverage of the repo by components.**
   ```bash
   git ls-files > /tmp/tmdd_files.txt
   ```
   For each component's `source_paths`, confirm the glob matches at least one file (translate
   `**`/`*` to a grep or use `git ls-files '<glob>'`). List source directories that match no
   component at all (exclude docs, assets, lockfiles, generated output). Each unmatched
   directory is either out of scope (say why in the analysis file) or a missing component.
3. **Hub check.** For each component, count the features reachable through its flows. A
   component reachable from every feature via one shared flow is a hub; propose splitting
   the component or the flow (see `schema.md` on `source_paths` and flows). Test with
   `tmdd review --files <one file per component>` and see how many features light up.
4. **Mitigation truth.** For each mitigation with `references`, open the file and line range
   and confirm the control is still there and still on the path: re-run the bypass
   questions in `methodology.md` section 12 (a newer route, a reordered middleware, a
   new decode step between validator and sink). Re-walk the stored traces in
   `.tmdd/analysis/stride_matrix.md` and update any that no longer match the code. For each feature threat with `status: implemented`, the referenced control must
   exist; otherwise downgrade to `required` and report it. For `status: required` threats,
   check whether the control has since been implemented; if so, add `references` and
   upgrade to `implemented` with evidence.
5. **Threat truth.** For each threat, confirm the described weakness still exists at the
   cited location and is still reachable (`methodology.md` section 10); re-run any
   recorded demonstration. Fixed weaknesses are not deleted: keep the threat, mark the feature
   mapping `implemented`, and point the mitigation at the fix, so future changes re-verify
   it. Threats whose component was removed: remove the mapping and note it.
6. **New surface.** Run the orientation and grep passes from `reference/discovery.md` on
   files changed since the model's newest `last_updated`:
   ```bash
   git log --since="<date>" --name-only --pretty=format: | sort -u
   ```
   Trace new inputs to sinks (`discovery.md` section 5), extend the authorization matrix
   for new resources or roles, run the sequence and state checklist on new workflows, and
   apply STRIDE to new entry points, sinks, subprocesses, external calls, and AI/LLM usage.
   Re-run the dependency audit (`discovery.md` section 2) and diff it against the
   `## Dependencies` section. Append rows to `.tmdd/analysis/stride_matrix.md` with the
   audit date.
7. **Model hygiene.** Threats mapped by no feature; features with no threats; mitigations
   used by nothing; template placeholders left over; generic descriptions with no file
   reference; severities that contradict the rubric given the controls now present.
8. **Apply fixes** in the YAML (append/edit, never rewrite), bump `last_updated` on changed
   features, keep `reviewed_by` untouched, then `tmdd lint` -> exit 0.
9. **Report** per `SKILL.md` Step 3, with an explicit drift table: claim, evidence, action
   taken or decision needed. List features whose `last_updated` now exceeds `reviewed_at`
   so a human can re-review and set `reviewed_by`/`reviewed_at`.
