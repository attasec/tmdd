# Workflow: Security review of a diff, branch, or PR

Use for "review this PR against the threat model", "what threats does this change touch",
or as the security pass in a code review. Requires an existing model with `source_paths`.
Read `reference/schema.md` section *Review traversal* first.

## Steps

1. **Establish the change set.** Prefer the PR-style range:
   ```bash
   git fetch -q origin 2>/dev/null; BASE=${BASE:-origin/main}
   git diff --name-only "$BASE"...HEAD
   git ls-files --others --exclude-standard      # untracked files; tmdd review cannot see these
   ```
   Use `--staged` or the working tree when the user asks about uncommitted work.
2. **Run the mapping.**
   ```bash
   tmdd review --base "$BASE" --format md
   # add untracked files explicitly when present:
   tmdd review --files $(git diff --name-only "$BASE"...HEAD) $(git ls-files --others --exclude-standard) --format md
   ```
   Keep the JSON form (`--format json`) if you need to iterate programmatically.
3. **Verify each surfaced threat against the actual diff.** For every threat in the
   output, read the changed hunks (`git diff "$BASE"...HEAD -- <file>`) and decide:
   - `[ ]` required control: is it now present in the change? Cite the hunk. If absent,
     this is a finding with the mitigation ID and the concrete fix.
   - `[x]` implemented, re-verify: does the change weaken or bypass the control (removed
     middleware, new raw query path, new sink)? Run the bypass questions in
     `methodology.md` section 12 against the changed code, in particular *alternate
     route* and *ordering*. Cite evidence either way.
   - accepted: confirm the change does not enlarge the accepted risk (new exposure, new
     actor); if it does, flag for re-acceptance.
4. **Look beyond the model.** The mapping only knows modeled threats. For each changed file
   also run the relevant grep patterns from `reference/discovery.md` section 4, trace every
   new or changed input to its sinks (section 5), and apply STRIDE to any new entry point,
   sink, subprocess, or external call the diff introduces. A new resource, operation, or
   role gets a row in the authorization matrix (`methodology.md` section 6); a new
   multi-step flow gets the sequence and state questions (section 8). Changed manifests
   or lockfiles get the dependency audit (`discovery.md` section 2). Run the reachability
   check (section 10) before calling anything a finding.
   New findings become new threats (add to `threats.yaml`, map in `features.yaml`, bind
   `flows`) rather than review-only remarks, so the next review sees them.
5. **Close coverage gaps.** For each changed file marked `?` (no component):
   - Real source of an existing unit -> extend that component's `source_paths` narrowly.
   - New unit -> add a component, its flows, and feature mapping (short version of
     `workflows/feature.md`).
   - Docs, generated output, lockfiles -> leave unmapped and say so.
   Components listed as having no `source_paths` that do own code in this repo should get
   globs now.
6. **Update the model for what the change did.** A change that implements a required
   control: add/adjust the mitigation `references` and set `status: implemented` on the
   feature threat, with the diff as evidence. A change that removes a control: set
   `status: required` and raise it as a finding. Bump `last_updated` on touched features;
   leave `reviewed_by`/`reviewed_at` alone.
7. `tmdd lint` -> exit 0.
8. **Deliver a PR-ready review.** Markdown with:
   - Verdict line (blocking findings count, non-blocking count).
   - Findings table: severity, threat ID, file:line in the diff, what is missing, the
     mitigation ID and concrete fix.
   - Re-verified controls (implemented threats touched, with the evidence that they hold).
   - Model updates made (new `source_paths`, threats, statuses) and what still needs a
     human (`reviewed_by` on changed features, acceptances).
   Include the `tmdd review --format md` table as an appendix or link to it.
