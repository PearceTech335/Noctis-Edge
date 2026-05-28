# Noctis Edge — Version History

---

## v0.11.7 — CVE Loop Efficiency + Repo Traffic Tracking

### CVE no-safe-path early stop
- CVE probe generation now exits early for a CVE when no safe target-specific validation path is available.
- Prevents repeated low-yield retries against the same CVE when evidence is insufficient for safe validation.

### Duplicate-strategy and CVE instance controls
- Tightened duplicate-attempt handling so equivalent strategies are suppressed earlier.
- Improved CVE instance traceability across attempts to reduce repeated equivalent generation paths.

### Phase 1b KB-fix efficiency improvements
- Phase 1b now deduplicates fix candidates by normalized script hash before consuming correction budget.
- Added one bounded syntax-only retry when a corrected script still fails sanitization.
- Non-syntax quality failures continue to fail fast without additional retries.

### Repository traffic tracking workflow
- Added `.github/workflows/clone-tracker.yml` schedule + `workflow_dispatch` path for manual and daily collection.
- Added `scripts/track_repo_traffic.py` using Python stdlib only to collect clone/view/release-download metrics.
- History is persisted via workflow artifacts, avoiding committed telemetry files in the repository.

---

## v0.11.6 — Lean Scaffolding and Evidence Controls

### Deterministic narrative gating
- Added deterministic evidence-confidence narrative tiers (`suppress`, `generic`, `specific`, `full`) to constrain when attacker-style prose is generated.
- Low-confidence CVE/finding paths now produce deterministic fallback language instead of speculative narratives.

### Prompt policy deduplication
- Repeated prohibited-word/evidence-only clauses were consolidated into shared helper functions used across prose generation paths.
- Reduced prompt duplication while preserving anti-speculation guardrails.

### Observed vs Inferred explainability
- Added explicit `observed_evidence` and `inferred_assessment` fields for findings and CVE records.
- HTML report cards now render Observed vs Inferred sections for clearer evidence provenance.

### Temporal stability metadata
- Tool KB slots now persist `first_run` in addition to `last_run` and counters.
- Findings now carry `temporal_stability` metadata (`seen_count`, `first_seen`, `last_seen`, `verification_success_count`) surfaced in diagnostics.

### CVE mismatch suppression hardening
- Match confidence now applies explicit negative-evidence penalties for known summary/product drift patterns (for example Dropbear-vs-OpenSSH style mismatches).
- Penalty factors are recorded in `_confidence_factors` for analyst traceability.

## v0.11.4 — Adaptive NSE Reliability + Community Merge Patch

### Adaptive NSE debug and retry controls
- NSE debug decisions now retain structured decision history and raw previews for better incident diagnosis.
- Retry behavior is bounded and safer: family-aware retry caps are applied and no-op adjustment loops are short-circuited.
- Default adjustment retry handling now supports deeper but controlled retries for difficult services.

### NSE script reliability learning
- Added per-script reliability scoring and ranking for `nmap_nse` script execution.
- Added failure taxonomy tracking (`tax_*` counters, including debug-request patterns) to improve future script selection and throttling.
- Added script-family retry policy controls to prevent runaway retries while still allowing targeted persistence.

### Tool KB community merge improvements
- `scripts/merge_tool_kb.py` now performs confidence-weighted merges for existing `nmap_nse` slots instead of skipping existing local slots.
- Core counters and taxonomy counters are blended proportionally to local confidence; derived rates are recomputed after merge.

### Reporting polish
- Removed duplicate attacker perspective presentation from testing evidence flow while preserving exploitation-details narrative.

---

## v0.11.2 — Patch Release

### Ollama concurrency cap
- `threading.Semaphore(3)` (`_LLM_CONCURRENCY_SEMAPHORE`) added at module level. Acquired inside `query_llm_for_service` and `query_llm_for_timeout_fallback` around their `requests.post` calls.
- Without the cap, a scan with 21 services dispatches 21 `run_in_executor` LLM calls simultaneously. Ollama processes them serially; the last call waits ≈ 20 × 90 s ≈ 30 min before inference begins — well past `OLLAMA_TIMEOUT=600`.
- Capped at 3 so the worst-case Ollama wait per call stays under ~5 min regardless of scan size.
- Overridable at runtime via `NOCTIS_LLM_CONCURRENCY` environment variable.

### Tool timeout retry-with-feedback
- When a tool times out with no findings, the LLM is now given the tool's original selection reason plus any partial output captured during the run, and asked to suggest an alternative approach for the same service.
- A concurrent recovery wave executes the suggested alternative immediately. One extra probe round is granted per recovery so the scan doesn't short-circuit after a timeout.
- Previously, a timeout simply banned the tool for the remainder of the service's probe rounds and moved on with no follow-up.

### Executive summary retry loop fixes (3 bugs)
- **`break` placement bug:** The hallucination guard `break` was executing even on rejection (placed outside the `else` block), so if the first LLM attempt triggered the guard the loop always terminated early. Rejections now `continue` to the next attempt.
- **Hallucination guard over-breadth:** `\bcritical\b` was firing on natural-language constructions such as "it is critical to patch", incorrectly rejecting valid summaries. Guard now only fires on explicit severity-label patterns: `critical severity`, `critical finding(s)`, `critical vulnerability/vulnerabilities`, `critical issue(s)`, `critical risk`, `critical-severity`.
- **`_build_conclusion_with_cve` single-shot:** The post-CVE executive summary rebuild had zero retry logic. It now loops up to `MAX_LLM_RETRIES` with 2-second backoff between attempts, applying the same hallucination guard.

### NSE script policy system
- NSE script selection is now driven by three JSON policy files: `safe_nse_scripts.json`, `aggressive_nse_scripts.json`, `unsafe_nse_scripts.json`.
- Scripts are validated against a denylist of unsafe script families (`brute`, `backdoor`, `vuln`, `exploit`, `dos`, `ftp-data`, `http-form-brute`, `http-brute`, `smtp-brute`, `ssh-brute`, `rdp-brute`, `smb-brute`). Only the `unsafe` tier may include exploit/auth families.
- Added `_load_nse_script_policy()`, `_filter_nse_scripts_by_tier()`, `_collect_policy_scripts()`, `_script_csv_from_list()` helpers. `get_nse_scripts_for_service()` now delegates entirely to the policy files.

### CVE matching improvements
- **`_cve_service_rejection_reason()`** — new function that explicitly rejects CVE candidates that clearly don't match the observed service (Dropbear CVEs on OpenSSH, Samba CVEs where Samba wasn't fingerprinted, SMB1 CVEs where SMB1 wasn't observed, Linksys firmware CVEs on generic SMB). Rejection reasons are logged for audit.
- **`_match_cves_for_service()`** returns a 3-tuple `(active, suppressed, rejected)` with structured reasons. `test_cve_matching.py` updated to align.
- **`CVE_LOW_CONFIDENCE_THRESHOLD`** raised `0.35 → 0.50` to reduce low-confidence noise.
- **CVE dict key robustness** — all `cve["id"]` accesses replaced with `cve.get("id", cve.get("cve_id", ""))` throughout to handle both key naming conventions without `KeyError`.

### Web UI (noctis_web.py)
- Title updated to `Noctis Edge - DangerMouse`.
- UNSAFE MODE banner rebuilt with inline `display:none` + JavaScript `style.display` control (replacing a CSS `.open` class that wasn't always toggling correctly).
- Unsafe modal overlay gets explicit inline styles for reliable cross-browser display.
- Terminal area gains `.unsafe-banner-visible` margin class when the UNSAFE banner is shown.

### `.gitignore` additions
- `*.bak`, `fix_funcs.py`, `_scan_*.log`, `build.log`, `build_full.log`, `COPILOT_INSTRUCTIONS.md.bak` added to prevent development artefacts reaching the repository.

### Constant additions
- `MAX_VERIFIER_LLM_RETRIES = 10` added as a separate constant (was previously sharing `MAX_LLM_RETRIES`).
- `_TOOL_PURPOSES` dict added — maps tool names to investigation purpose strings used as context in timeout recovery LLM calls.

---

## v0.11.0 — CVE Matching, Version Range, and Reporting

**CVE Matching and Version Range Enforcement**

- CVE matching now enforces strict product, vendor, and version correlation. Each CVE match is annotated with a `cve_match_status` (e.g., `matched`, `product_mismatch`, `vendor_mismatch`, `version_not_affected`) and a `version_range_check` field (`affected`, `not_affected`, `unknown_version`, `no_range`).
- Version range checks are transparent: the detected version, affected range, and match status are shown in the report for every CVE.
- Robust support for dash-separated version ranges in CVE matching and validation logic.
- Improved test coverage for version range parsing and normalization.
- Minor fixes to Docker build and test scripts.

**Narrative and Severity Logic**

- Attacker perspectives and remediation advice are concise, realistic, and avoid risk inflation or speculation. Prompts enforce strict sentence and length limits.
- Severity is never inflated; only evidence-based, context-aware severity is shown.

**UI and Report Output**

- The HTML report displays new badges and fields for CVE match status, version range, and severity.
- Suppressed and not-affected CVEs are clearly separated in the report UI, with reasons for exclusion visible for auditability.
- All LLM-generated sections (attacker perspective, remediation, executive summary) are proof-read and validated for accuracy and tone.

---

## What's New in v0.10.1

### Patch: Dash-Range Version Support

- Robust support for dash-separated version ranges in CVE matching and validation logic.
- Improved test coverage for version range parsing and normalization.
- Minor fixes to Docker build and test scripts.

---
## What's New in v0.10.0

- **Single-model runtime:** All default LLM roles now use `qwen2.5-coder:3b-instruct`. Docker launchers, `docker-compose.yml`, `setup.sh`, and `update.sh` no longer pull or configure a separate `REPORT_MODEL`; normal installs need only one ~2 GB model. `MODEL`, `SCRIPT_MODEL`, and `CVE_SCRIPT_MODEL` remain logical roles in code, but by default they resolve to the same physical model.
- **Large-report filtering:** HTML reports now include clickable severity summary boxes plus a vanilla-JavaScript filter/sort bar for finding text, severity, service type, and sort order. This keeps large scans navigable without external assets or a server-side UI.
- **Cleaner remediation layout:** Finding details keep remediation in the existing `IMMEDIATE REMEDIATION PATH` and `Long-term Fix` cards, avoiding duplicate action sections while preserving copy-ready operator steps.
- **Evidence callouts:** Finding evidence and execution output previews now highlight matching lines and substrings, making relevant proof easier to spot inside raw tool output.
- **Executive summary quality controls:** Executive summary generation now uses warmer but bounded prose settings and validates severity counts, unsupported CVE claims, unsupported generic web-security advice, markdown/list drift, and falsely reassuring posture language. Invalid prose is replaced with a polished evidence-grounded summary generated from recorded scan data.

---

## What's New in v0.9.5

- **FP hardening — banner conflict detection:** `_capture_http_banner()` compares the HTTP `Server:` header against the nmap banner and sets a `banner_conflict` flag when the two disagree. CVE matching in `enrich_cve` suppresses matches that rely solely on the conflicting banner, preventing false positives where a reverse proxy exposes a different product header than the backend actually runs.
- **FP hardening — OS plausibility check:** `_check_os_guess_plausibility()` validates the nmap OS guess against the full service-stack context discovered in Phase 4. If the guess is an RTOS or embedded OS but the port list contains clear full-OS signals (SSH, HTTP, databases, etc.) the guess is suppressed and replaced with an empty string. The plausibility accuracy floor constant `_OS_PLAUSIBILITY_ACCURACY_FLOOR = 90` means guesses below 90 % accuracy are also discarded.
- **FP hardening — match confidence scoring:** `_compute_match_confidence()` scores every CVE match 0.0–1.0 using source, version precision, KEV listing, and exploit maturity. NSE-sourced matches start at 0.80 (base 0.50 + `_MC_NSE_SOURCE_BONUS` 0.30); banner-conflict matches are penalised −0.30. Scores flow into `risk_score` via `tool_confidence`, replacing the previous uniform per-tool weight.
- **FP hardening — CVE verdict tiers:** `--cve-test` verdicts now have four tiers: `CONFIRMED_VULNERABLE` (multiple independent probes unanimously VULNERABLE), `VULNERABLE` (at least one VULNERABLE), `NOT_VULNERABLE`, `INCONCLUSIVE`. The tier is surfaced in both the JSON report and the HTML card.
- **Bug fix — OS guess leaking into report header:** `gather_target_info()` runs its own `nmap -O` pass and stored the OS guess directly on `target_info`. Phase 4's plausibility suppression only cleared the internal `nmap_meta` dict, leaving the original unreliable guess visible in the report header. Fixed: after `gather_target_info` returns, `main_async` now checks if Phase 4 suppressed the guess and unconditionally clears `target_info.os_guess` and `target_info.os_accuracy`.
- **Bug fix — LLM conclusion hallucinating vulnerabilities:** the executive summary prompt and `_build_conclusion_with_cve()` prompt both now include a strong grounding constraint preventing the report model from drawing on training knowledge about a product version instead of the actual scan results.
- **Code cleanup — `_run_script()`:** resource-limit constants and the `_build_rlimit_preexec()` helper extracted to module scope. Function body reduced from ~95 LOC to ~45 LOC.
- **Code cleanup — `_load_community_nuclei_template()`:** template layout probing extracted into a dedicated helper with compiled regex constants. Call site reduced from ~40 LOC to 3 LOC.

---

## What's New in v0.9.4

- **Bug fix — empty `attacker_perspective` on all CVE matches:** Two root causes were eliminated. (1) `_generate_attacker_perspective()` (qwen3:1.7b) had no `<think>` stripping, so when the model ignored `/no_think` and emitted internal reasoning the entire response was discarded as the raw output. The function now strips both closed and unclosed `<think>` blocks, retries up to `MAX_LLM_RETRIES`, applies a stronger directive (`"Output the answer directly. Do not include any reasoning or <think> tags."`), and `num_predict` set to 500 — sufficient for 2 × 4-sentence paragraphs while keeping calls within the 600s timeout at qwen3:1.7b CPU speeds (~1 t/s). (2) The Phase 2 perspective loop lived inside `_run_cve_test_phase()`, which is gated on `if CVE_TEST:` (off unless `--cve-test` is set), so on every normal scan the loop never ran. Phase 2 has been extracted into a standalone `generate_cve_attacker_perspectives()` function that is now invoked unconditionally in the main scan flow before report audit.
- **Bug fix — report audit returning empty `audit_notes` (`conclusion_audited: False`):** `_audit_report()` (qwen3:1.7b) was emitting `<think>` content that consumed its entire `num_predict: 350` budget, leaving an empty response after stripping. The audit prompt has been simplified to a notes-only contract (dropped full-rewrite path), the data digest trimmed to top-5 findings + top-5 CVEs (was 8 + 10), `num_predict` raised to 800, both closed and unclosed `<think>` blocks stripped, the same `"Output the answer directly..."` directive added, and a plain-text regex fallback added so a non-JSON response still produces usable notes.
- **Bug fix — executive summary truncated mid-sentence:** Reduced the prose target from 4 paragraphs × 3-5 sentences to 3 paragraphs × 2-4 sentences, raised `num_predict` from 600 to 1000, and added `<think>` stripping. Previously qwen3:1.7b would consistently cut off mid-clause (e.g. `"...missing headers like"`) when its budget was exhausted by reasoning tokens.
- **Bug fix — per-finding remediation exceeding 600s timeout:** `_enrich_finding_remediation()` `num_predict` reduced from 800 to 350. At qwen3:1.7b's ~1 t/s CPU speed, 800 tokens ≈ 13 minutes per finding — on an 18-finding scan this produced a ~3.9 hour report generation phase and caused individual calls to exceed the `OLLAMA_TIMEOUT` budget. 350 tokens is sufficient for 6 concise bullet steps in JSON format and keeps each call under 6 minutes.

---

## What's New in v0.9.3

- Internal release used during v0.9.4 LLM-quality investigation. Tag retained on `master` at commit `c5c9614`.

---

## What's New in v0.9.2

- **Bug fix — executive summary cold-load timeout eliminated:** The executive summary LLM call (`qwen3:4b`) is now deferred to run *after* `_enrich_finding_remediation()` rather than before it. By the time the summary is generated, `qwen3:4b` has already been actively used for per-finding remediation and is resident in Ollama's model cache — the cold-load penalty no longer applies. The background warmup thread (`_preload_report_model`) has been removed entirely as it is no longer needed. Previously, on short scans where `qwen3:4b` was never previously loaded, the combined cold-load + inference time routinely exceeded the 360 s `OLLAMA_TIMEOUT`, producing the error `Conclusion LLM error: Read timed out` and falling back to the deterministic anchor sentence only.
- **Bug fix — executive summary retry loop silently gave up after 1 attempt:** The `except` block in the executive summary retry loop contained an unconditional `break`, meaning transient errors were never retried despite `MAX_LLM_RETRIES = 3`. The break is removed; each attempt now logs `Conclusion LLM error (attempt N/3)` and sleeps 2 s before the next retry.
- **Bug fix — CVE verifier scripts blind to winning probe:** `_generate_verification_script()` previously received only a one-sentence strategy string from the triggering attempt. The verifier prompt now includes the full source code of the winning probe (up to 800 chars) and its terminal output (up to 400 chars). The LLM can now read exactly what request was made and what evidence was observed, enabling a genuinely orthogonal verification approach rather than defaulting to the generic TCP banner template. The CONTRAST RULE in the prompt has been updated with concrete examples (e.g. if reference used HTTP GET → use raw socket; if it matched a header → match a response body).

---

## What's New in v0.9.1

- **Expanded NSE script coverage (23 → 36 service entries):** `_NSE_SCRIPT_MAP` now covers a wider range of services and provides richer script selection for each.
  - **HTTP/alt-HTTP/http-proxy enriched:** `http-cookie-flags`, `http-cors`, `http-git`, `http-config-backup`, `http-server-header`, `http-php-version`, `http-generator`, `http-favicon`, `http-waf-detect`, `http-apache-server-status`, `http-devframework` added across all HTTP service entries. SSL/HTTPS entries additionally gain `ssl-heartbleed`, `ssl-dh-params`, `ssl-poodle`, `sslv2-drown`, `ssl-ccs-injection`, `tls-ticketbleed`.
  - **Other enriched entries:** SSH adds `sshv1` (obsolete protocol detection); FTP adds `ftp-vsftpd-backdoor`, `ftp-proftpd-backdoor`, `ftp-vuln-cve2010-4221`; SMTP adds `smtp-ntlm-info` and three vuln scripts; SMB/NetBIOS adds `smb-protocols`, `smb2-capabilities`, `smb-enum-users`, `smb-vuln-ms17-010` (EternalBlue), `smb-vuln-cve-2017-7494` (SambaCry), `smb-double-pulsar-backdoor`; DNS adds five additional query-behaviour scripts; RDP adds `rdp-ntlm-info`, `rdp-vuln-ms12-020`; SNMP adds `snmp-interfaces`, `snmp-processes`, `snmp-netstat`, `snmp-win32-services`, `snmp-win32-users`; VNC adds `realvnc-auth-bypass`; LDAP adds `ldap-search` (anonymous enumeration).
  - **13 new service entries:** Redis, MongoDB, CouchDB, Oracle, NFS, rpcbind, rsync, Memcached, AJP (Tomcat), JDWP (Java debugger), IPMI, Docker API (port 2375/2376), X11, IRC. All scripts are safe/discovery category — no DoS, active exploitation, brute-force, or external API key requirements.
- **Bug fix — CVE detection on non-standard HTTP ports:** Services labelled by nmap as `http-proxy` (e.g. port 8080) now receive NSE script execution and a post-Phase-3 product/version backfill that parses `http-server-header` output, enabling CVE matching on alt-HTTP ports. Previously these ports completed Phase 3 with an empty `product` field, causing the CVE search to return zero results.
- **Bug fix — LLM executive summary timeout on short scans:** `_preload_report_model()` now launches as a daemon thread at the start of `generate_report()` and warms `qwen3:4b` during the report-preparation phase, eliminating cold-load timeouts when the main scan completes before the model is resident.
- **Executive summary `num_ctx` reduced 4096 → 2048:** Reduces inference latency on CPU-only hardware with no quality loss on typical report sizes.

---

## What's New in v0.9.0

- **Report Audit Pass (`_audit_report()`):** After all LLM-generated sections are complete, a final proof-read pass feeds a compact digest of the finished report (executive summary, finding counts, top-8 findings with first remediation step, CVE verdicts) back to `REPORT_MODEL`. The model checks factual accuracy (do counts match what the summary says?), CVE verdict consistency (does the narrative correctly reflect CONFIRMED_VULNERABLE vs UNVERIFIED?), internal consistency, and professional tone. If corrections are needed it rewrites the full executive summary; if not, it confirms the report is clean. A second verification pass runs automatically — but only when the first pass made a revision — ensuring the rewrite itself is consistent. On clean reports only one LLM call is made. Results appear in a collapsed **Report Audit** section below the executive summary in the HTML report: green ✓ "no changes required" or amber ✏ "conclusion revised", with 1–3 sentence audit notes. Non-fatal — any timeout or parse failure leaves the report unchanged.
- **LLM completeness warning banners:** Three new orange warning banners appear in the HTML report when LLM calls fail or time out:
  - **Executive Summary Incomplete** — shown when the conclusion LLM timed out and only the auto-generated anchor sentence is present.
  - **Remediation Advice Incomplete** — shown above the Security Findings section when `N` finding(s) failed to receive LLM remediation advice (static fallback shown for those items).
  - **CVE Analysis Incomplete** — shown above the CVE Matches section when `N` CVE attacker-perspective or remediation calls failed.
- **CVE section split into three bands:** The CVE Matches section is now divided into three collapsible bands: **Active CVE Matches** (open by default, blue border — all CVEs not confirmed not-vulnerable, ranked by EPSS exploit probability); **Tested — NOT VULNERABLE** (collapsed, green border — CVEs where active probe testing returned `NOT_VULNERABLE`, with testing evidence accordion); **Suppressed** (collapsed, grey border — CVEs where detected version ≥ fixed version). Previously all CVEs appeared in a single flat list.
- **Detection Source badges on finding cards:** The raw `detection_method` slug is replaced with a styled confidence badge on each finding card. Five types: **Exploit Confirmed** (red), **Active Probe** (teal), **Template Match** (blue), **Banner Match** (amber), **Heuristic** (grey) — each labelled with a confidence tier description.
- **Composite risk score with EPSS weighting:** `calculate_risk_score()` now uses a composite formula: `score = (base × 0.70) + (epss_score × 0.30)`. The base component includes a detection-method modifier: `exploit_confirmed→1.00`, `service_probe→0.85`, `template_match→0.80`, `banner_analysis→0.65`. EPSS scores are looked up from the offline `CVE/epss-scores.csv` database during `generate_report()`.
- **Legend updated:** The Security Findings legend now has three columns — Severity, Verification Status, and Detection Source (new). A footnote explains the composite risk score formula.
- **Estimated Time to Fix removed:** The "Estimated Time to Fix" field has been removed from both finding cards and CVE match cards. The effort level indicator (Low/Medium/High) remains on CVE cards.
- **Per-finding LLM remediation for all active and hardening findings:** `_enrich_finding_remediation()` uses `REPORT_MODEL` to generate 3 concrete, technology-specific steps for both the immediate workaround and the permanent fix for every critical, high, medium, and low severity finding. Steps are rendered as numbered lists in the report. Static fallback maps (`_REMEDIATION_SHORT_TERM` / `_REMEDIATION_LONG_TERM`) are used when the LLM call fails or times out.

---

## What's New in v0.8.5

- **`REPORT_MODEL` switched to `qwen3:4b`:** Default `REPORT_MODEL` changed from `qwen3:8b` to `qwen3:4b` — reducing model size from ~5 GB to ~2.6 GB and peak concurrent RAM (during `--cve-test`) from ~7 GB to ~4.6 GB. Minimum recommended RAM drops from 16 GB to 8 GB. Override via `NOCTIS_OLLAMA_REPORT_MODEL=qwen3:8b` to restore the larger model. All deployment files (`setup.sh`, `update.sh`, `docker-run.sh`, `docker-run.ps1`, `docker-compose.yml`) updated to pull `qwen3:4b` on fresh install and `./update.sh` runs.
- **`/no_think` prefix on prose prompts:** The three prose-generation call sites (executive summary, attacker perspective, scan conclusion) now prepend `/no_think\n` to their prompts, disabling qwen3's chain-of-thought reasoning overhead. Eliminates `<think>...</think>` blocks in responses and reduces inference latency on CPU-only hardware.

---

## What's New in v0.8.4

- **CISA KEV integration:** `scripts/build_kev_db.py` downloads the CISA Known Exploited Vulnerabilities catalog to `CVE/kev-catalog.csv`. `_load_kev_db()` follows the same lazy-load pattern as EPSS. In `enrich_cve()`, any CVE present in the KEV catalog sets `kev_listed: true` and `kev_due_date` in the enriched CVE dict. `calculate_risk_score()` applies a +0.2 bonus (capped at 1.0) for KEV-listed CVEs. The HTML report displays an animated red **MUST-PATCH (KEV)** badge and a due-date alert banner on matching CVE cards. `kev_listed` and `kev_due_date` are included in the JSON export. `update.sh` gains step 5d to refresh the catalog alongside EPSS, NVD, and CWE.
- **CVE version suppression:** `_parse_semver()` and `_extract_fixed_version()` parse machine-comparable version tuples from CVE summary text. `_version_is_suppressed()` returns `True` when the detected service version is at or above the fixed version. `cves_for_service()` partitions results into `(active_cves, suppressed_cves)` — suppressed CVEs are retained in the service record with a `suppression_reason` field (e.g. `version 10.0 >= fixed 9.8p1`) and rendered as a collapsed section in the HTML report. Nothing is silently dropped.
- **Confidence label tiers:** `_confidence_label()` maps the existing `Finding.confidence` float to human-readable tiers: **Validated** (≥ 0.95), **Strong Fingerprint** (≥ 0.75), **Banner / Heuristic** (≥ 0.40), **Weak Inference** (< 0.40). Finding cards in the HTML report now display `87% — Strong Fingerprint` with a tooltip explaining each tier. The new `Finding.detection_method` field records how each finding was produced (`template_match`, `banner_analysis`, `service_probe`, `header_analysis`).
- **Finding category separation:** `generate_report()` partitions all findings into four buckets: **Confirmed** (`verification_status == "confirmed"`), **Probable** (`discovered` + confidence ≥ 0.60), **Review Needed** (`probe_inconclusive` or `manual_review`), and **Informational** (remaining). Executive summary severity counts are calculated from Confirmed + Probable only, eliminating the contradiction where the summary showed zero criticals while the flat finding list contained unvalidated criticals. All four lists are exported to the JSON report. The HTML report renders colour-coded collapsible sections with tier badge pills.
- **Scan coverage state:** `run_parallel_wave()` propagates the `timed_out` flag from each tool invocation into `scan_records`. `generate_report()` collects `timed_out_tools` and surfaces a **Scan Coverage** table in the HTML report before the executive summary — any timed-out tool is flagged `INCOMPLETE — results may be partial` with its target and duration. `timed_out_tools` is included in the JSON export.
- **Nuclei KB community submissions:** `scripts/submit_nuclei_kb.py` is now a public script (no longer subscriber-only) and distributed with every install. `update.sh` submits `nuclei_kb.json` alongside the CVE and Tool KBs on every `./update.sh` run. The Cloudflare Worker gains a `/submit-nuclei` route that writes submissions to the `nuclei/` subfolder of the community submissions repository. All users now contribute Nuclei template performance data automatically after running `./update.sh`.

---

## What's New in v0.8.3

- **Offline CWE dictionary (`CVE/cwe-data.csv`):** New `scripts/build_cwe_db.py` downloads the MITRE CWE XML bundle at build time and writes 969 weakness entries to `CVE/cwe-data.csv` (name, abstraction, description, likelihood, consequences, mitigation). Integrated into `Dockerfile` (step 18), `docker-entrypoint.sh` (monthly background refresh), `update.sh` (step 5c), and `setup.sh`.
- **Authoritative CWE IDs from NVD:** `scripts/build_nvd_cvss.py` now extracts CWE IDs directly from the NVD `weaknesses` array (prefers `type=="Primary"`, validates `CWE-{digits}` format) and writes them to the updated 7-column `nvd-cvss.csv`. Authoritative NVD IDs take precedence over inferred `_CWE_MAPPING` values.
- **CWE-enriched CVE report cards:** Every CVE match card now resolves the weakness against the offline CWE dictionary and displays an expandable accordion with the weakness name, description, likelihood, consequences, and recommended mitigations — fully offline, no NVD or MITRE network calls at scan time.
- **LLM probe prompts hardened:**
  - `shutil.which()` guard added — before calling any subprocess tool the generated script must verify the binary exists; if not, it prints `VERDICT: INCONCLUSIVE` and exits cleanly rather than crashing with `FileNotFoundError`.
  - Raw socket instruction for path-traversal probes — `requests` and `urllib` normalise encoded paths (e.g. `/.%2e/`) before sending, producing 400 responses; the prompt now explicitly directs the LLM to use the `socket` library to send the literal byte string for these probe types.
  - Default timeout raised 5 s → 8 s; maximum timeout raised 10 s → 15 s, reducing false `INCONCLUSIVE` verdicts on slower services.
  - CWE mechanism hint injected into fresh CVE probe prompts — the weakness class (e.g. `CWE-22 — Improper Limitation of a Pathname to a Restricted Directory`) is included as context to improve strategy selection for the initial script generation.

---

## What's New in v0.8.2

- **CVE verdict language precision:** Report conclusion no longer uses "confirmed exploitable" for version/banner-match CVEs. Language now distinguishes between "confirmed by active probe testing" (script ran and triggered the vulnerable behaviour) and "matched by version/banner analysis — manual verification recommended" (version string in range, but no live proof). Eliminates the risk of overclaiming to stakeholders.
- **Detection confidence badges on CVE test results:** Each CVE test result card now displays a colour-coded evidence type badge: `Active Probe` (teal — specific behaviour observed), `Version Match` (blue — version string confirmed in range), `KB Replay` (purple — replayed from prior knowledge base entry), `Banner Analysis` (grey — product/banner match only). Derived by `_derive_evidence_type()`.
- **Ease-of-Fix effort tags on CVE match cards:** Every CVE match now shows a `Low` / `Medium` / `High` effort pill (green/amber/red) between the business impact block and the compliance section, sourced from the new `_REMEDIATION_EFFORT` dict (18 vulnerability types). Helps operators prioritise patches they can ship quickly.
- **Compliance control reasoning:** Each compliance control chip (PCI-DSS, SOC2, ISO 27001, NIST CSF 2.0) in the CVE match section now expands with a one-sentence explanation of why the specific control applies to that vulnerability type. Sourced from the new `_COMPLIANCE_REASONING` dict (26 entries). No more bare control IDs without context.
- **Expanded executive summary:** Conclusion prompt now requests exactly 4 paragraphs of 3–5 sentences each in plain business language, with `top_findings` context (top 6 findings by risk score) injected into the LLM call. `num_ctx` raised from 2048 → 4096 for this call.
- **Remediation LLM speed improvement:** `_generate_immediate_remediation()` and `_generate_remediation()` switched from `REPORT_MODEL` to `SCRIPT_MODEL` (`qwen2.5-coder:3b-instruct`), which is significantly faster at structured output generation. Per-CVE remediation latency reduced.
- **Nuclei KB message accuracy:** Console output now correctly distinguishes `(N new template(s))` vs `unchanged (no HTTP/web CVEs tested this run)` instead of always printing a misleading "updated" message.
- **Nuclei HTTPS coverage expanded:** `_NUCLEI_HTTP_SERVICES` frozenset now includes `https-alt` and `ssl/https` in addition to the existing `https` and `ssl/http` entries, ensuring all common HTTPS service label variants trigger template generation.
- **ETA timing fix:** Phase checkpoint `frac_done` values are now strictly non-decreasing across the full scan pipeline. Previously "Base reports saved" used `frac_done=0.70` after MSF validation done at `0.85`, causing the estimated completion time to jump backwards mid-scan. All checkpoints now form a monotonically increasing sequence.
- **CVE verdict strictness hardened:** The CVE test LLM prompt now explicitly requires (a) a version string extracted and confirmed within the CVE range, OR (b) the specific vulnerable behaviour directly observed. Product/service name presence alone (e.g. `OpenSSH` in banner, `Apache` in Server header) is explicitly forbidden as a basis for `VULNERABLE`.
- **`docker-run.sh` macOS compatibility:** Replaced `df --output=avail /` (GNU coreutils only) with `df -k / | awk 'NR==2 {print $4}'` which works identically on macOS (BSD) and Linux.
- **Model alignment across all deployment files:** `setup.sh`, `update.sh`, `docker-run.sh`, and `docker-compose.yml` now all correctly reference `qwen2.5-coder:3b-instruct` for planning and scripting, and `qwen3:8b` for report prose — matching the runtime defaults in `noctis.py`. Fresh installs and `./update.sh` runs now pull the correct models.

---

## What's New in v0.8.1

- **Semantic false-positive checking — `probe_inconclusive` verification status:** Low-confidence tool findings (nikto: 0.40, ffuf: 0.60) that cannot be automatically confirmed are no longer marked `verified` by the naive evidence-length heuristic. `verify_finding()` now applies a three-stage check: (1) if `matched_url` is present, curl is run against it and the response body is scanned for vuln-type-specific confirmation keywords (`_VULN_BODY_KEYWORDS`); (2) if no keywords match — or no usable curl response comes back — and the reporting tool has `TOOL_CONFIDENCE < 0.65`, the finding is marked `verification_status = "probe_inconclusive"` with `manual_review = True`; (3) high-confidence tool findings (nmap, ssh-audit, curl) with substantial evidence still auto-verify as before. Findings already marked `"confirmed"` by the tool itself (e.g. ssh-audit) are trusted immediately without re-running curl.
- **Vuln-type keyword validation (`_VULN_BODY_KEYWORDS`):** New constant dict mapping 11 vulnerability type strings to lists of HTTP response-body keywords that are meaningful confirmation signals. Types covered: Information Disclosure, XSS, SQL Injection, Directory Traversal, RCE, Open Redirect, SSRF, File Inclusion, Authentication Bypass, Misconfiguration, Weak SSL/TLS. Findings with an unknown or unlisted `vuln_type` fall back to the legacy heuristic (any response > 20 chars = verified) so no regression occurs for unclassified findings.
- **`verifier_tool` field on `Finding`:** New `str` field (default `""`) records which tool was dispatched in the verification attempt. Set to `"curl"` when curl is run and returns inconclusive results. Left empty when no tool was dispatched (low-confidence finding with no `matched_url`). Persisted to `session.json` and rendered in the report.
- **LLM re-probe guidance (Rule 9 + `needs_verification` context):** `query_llm()` now includes a `needs_verification` key in `ctx_summary` — a list of `{title, service, tool, vuln_type, evidence[:120]}` dicts for every finding currently at `probe_inconclusive` status. Rule 9 in the planning prompt instructs the model: *"If NEEDS_VERIFICATION findings appear in CURRENT FINDINGS, prioritise re-probing each with a different higher-confidence tool matched to its vuln_type and service (e.g. curl for HTTP header issues, nuclei for web vulns, ssh-audit for SSH) before exploring new areas."* This gives the LLM the information and the directive it needs to automatically dispatch a second, better-suited verifier tool in the next iteration.
- **Report — `probe_inconclusive` visual treatment:** Findings at `probe_inconclusive` status are rendered distinctly in the report: the verification badge uses the new `.probe-inc` CSS class (amber, bold: `#ff9800`) and displays `⚠ probe inconclusive` instead of the generic `discovered` label. An amber left-bordered callout box is inserted inside the expanded finding detail, stating which tool was used in the verification attempt and that manual inspection is recommended before treating the finding as confirmed. The orange `⚠ MANUAL REVIEW` badge is also set automatically. Confirmed findings remain green; unverified high-confidence findings remain amber `discovered`. No findings are demoted or hidden.

---

## What's New in v0.8.0

- **Per-service tool timeout tracking (replaces global tool ban):** Previously, if a tool timed out with no findings on one service (e.g. `dns_enum` on port 53), it was permanently added to `broken_tools` and banned for the entire scan — meaning it could never be tried on SSH, HTTP, or any other service later. The new mechanic tracks timeouts in `timed_out_tools: dict[str, set]` — a mapping from tool name to the set of service-type keys where it timed out. A tool is only skipped for the specific service type it failed on; it remains available for every other service type in the scan. The LLM planning prompt now includes a "TIMED OUT PER SERVICE" block listing which service types to avoid per tool, so the model can make informed routing decisions. `_fast_path_actions()` and `_untested_service_fallback()` both respect the per-service ban. Structural failures (binary missing, permission denied) still trigger the full session-wide `broken_tools` ban as before.
- **Iteration budget overhaul — formula now scales with services found:** Previously the base budget was `min(max(10, n_services), 40)` — one iteration per service — so 6 services gave only 10 iterations (floor). The new formula is `min(max(10, n_services × 5), 40)`: **5 iteration slots per service**, floored at 10, hard-capped at 40. For a typical 6-service web target this yields 30 iterations instead of 10, giving each port an initial probe plus 4 follow-ups without consuming the entire budget on a single noisy scanner. The budget log line now prints the full calculation: `services × 5 = N, floor: 10, cap: 40`.
- **Proactive finding-based extension mechanic replaces single-shot extension:** The old code granted one automatic extension equal to the raw count of uninvestigated findings, which could push `effective_max` far above `MAX_ITERATIONS_CAP`. The new mechanic fires at every budget exhaustion point (not just once): it counts findings with no follow-up tool run, grants `+2 iterations per uninvestigated finding`, and consumes from a pool of `MAX_EXTENSION_BUDGET = 8` total auto-granted iterations across the entire scan. The pool is bounded by remaining headroom to `MAX_ITERATIONS_CAP`. For 10 uninvestigated findings: `min(20, 8, headroom)` = **+8** iterations maximum from auto-extension.
- **All-tools-disabled early exit:** At the start of every iteration (after `i += 1`) the engine now checks whether every tool is in `broken_tools`. If true it prints a warning and stops immediately rather than spinning out the remaining budget producing empty iterations.
- **Operator-approved ceiling overage is now exact and one-shot:** When the hard ceiling (`MAX_ITERATIONS_CAP = 40`) is reached, the interactive prompt offers exactly `MAX_EXTEND_ONCE = 20` additional iterations (`effective_max = 40 + 20 = 60`). Previously the prompt added an unbounded `+= 20` that could be triggered repeatedly. The extension is now capped at exactly one overage. In `--unattended` mode the ceiling stops the scan immediately without prompting.
- **Bug fix — `NameError: _svc_list` crash at first LLM iteration:** `query_llm()` referenced `_svc_list` in the tool-reference block comprehension but never defined it. This caused every scan to crash silently at the start of iteration 1 after Phase 1 tools finished — session directories were created but all files (including `session.json`) were never written. Fixed by assigning `_svc_list = context.get("services", [])` immediately before the check. Also hardened the loop to use `.get()` instead of direct key access so missing `status` or `recommended_tools` fields on a service dict no longer raise `KeyError`.
- **Nmap Phase 2 failure resilience:** When Phase 2 (`-sV -sC --version-intensity 7`) returns no service data (timeout on high-latency targets, or `-sC` default scripts hanging), the scanner now automatically retries with a lighter scan (`-sV --version-intensity 5`, no `-sC`, 120 s timeout) before continuing. Any port that Phase 2 still cannot enrich is flagged `version_unknown: True` in the service record. These ports are: (1) logged as a warning with a list of affected ports so the operator is aware; (2) annotated in the LLM planning prompt as `[VERSION UNKNOWN — probe with curl or nmap]` so the model actively probes them rather than silently skipping; (3) tagged in the CVE lookup path so missing version data is treated as expected rather than an error. Previously Phase 2 failure produced zero enrichment with no warning, no CVE matches, and the LLM receiving bare port numbers with empty service names.
- **LLM tool-selection guidance now conditional and lean:** The TOOL REFERENCE block (manifest capability guide) is only injected into the LLM planning prompt when there are services with `status == NOT_YET_TESTED` or no `recommended_tools` entry. For well-explored targets where every service already has KB history, the block is omitted entirely — keeping prompts shorter and faster to process. Rule 5 in the LLM prompt was updated to reflect this: *"Prefer tools from each service's `recommended_tools` list — use higher KB success rate tools first. For NOT_YET_TESTED services, consult the TOOL REFERENCE block."*
- **LLM prompt hardened against stale service dicts:** service fields `status` and `recommended_tools` are now accessed via `.get()` throughout `query_llm()`, so partial service records (e.g. services that completed nmap Phase 2 but did not reach Phase 3 enrichment) no longer raise `KeyError` and silently abort the iteration.
- **Bug fix — Dockerfile EPSS step incorrectly fails the build:** `build_epss_db.py` was returning a non-zero exit code when the FIRST.org CDN returns HTTP 403 (rate-limiting). Although the `||` fallback catches the failure at the shell level, Docker's BuildKit was still recording exit code 1 and marking the build as failed. Fixed by appending `; true` to the fallback branch to guarantee the layer always exits 0.

---

## What's New in v0.7.8

- **Tool manifest system (`tool_manifest.json`):** New subscriber artifact that gives the LLM per-tool capability guidance, service routing keywords, and flag examples for every scanning tool. `_tools_for_service()` is now manifest-driven — service keywords are matched against nmap service names, with `curl` as the automatic catch-all for unrecognised ports. Delivered via `update.sh` step 11 (license-key gated). Build or extend locally with `scripts/build_tool_manifest.py` and `scripts/add_tool_manifest.py`. The manifest is gitignored and never submitted to the community pipeline.
- **LLM stuck-on-duplicate fix (`_untested_service_fallback()`):** A new rule-based function intercepts the first consecutive duplicate action before burning 90-second LLM retries. It scans the service list for the first port with no prior `used_actions` entry and returns the best tool for that port (from `recommended_tools` or curl). This eliminates the pattern where a multi-service scan (e.g. SSH + VNC + HTTP) kept looping `ssh_enum` because VNC and unknown services returned `[]` from `_tools_for_service()` and were silently excluded from Phase 1.
- **`_tools_for_service()` catch-all fixed:** Previously returned `[]` for unknown services, causing the Phase-1 parallel scan filter to silently skip VNC, Kerberos, NetAssistant, and any other unrecognised port. Now returns `["curl"]` as a safe fallback with a logged advisory message.
- **`_FAST_PATH` extended:** Added `curl` fast-path entries for `vnc`, `rfb`, `kerberos`, `netassistant`, and `apple-remote` services so Phase 1 immediately probes these ports rather than waiting for LLM guidance.
- **Nikto severity triage:** `parse_nikto_output()` previously assigned `severity="info"` to every finding regardless of content. A new `_NIKTO_SEVERITY_UPGRADES` table (~40 pattern rules) now upgrades findings to `critical`/`high`/`medium`/`low` based on content keywords (CVEs → high, HTTP TRACE/XST → high, directory listing → medium, security header absence → low, etc.). The cap on returned findings increased from 15 → 30.
- **`manual_review` flag on findings:** `Finding` dataclass gains a `manual_review: bool` field. Nikto sets it to `True` on any finding upgraded above `info`. HTML report cards for these findings display an orange **⚠ MANUAL REVIEW** badge in the finding summary line.
- **LLM prompt enriched with service coverage status:** `query_llm()` now passes each service as a structured dict including `recommended_tools` and `status: NOT_YET_TESTED / tested` — previously the LLM saw only bare port/service strings and could not tell which ports had been exercised. A TOOL REFERENCE block (from the manifest) is injected into the prompt when untested or no-recommendation services are present.
- **`num_ctx` 1024 → 2048 for planning calls:** `_OLLAMA_PLAN_OPTIONS` `num_ctx` increased to accommodate the richer prompt with the TOOL REFERENCE block (~300 extra tokens). RAM impact is minimal (~100 MB).

---

## What's New in v0.7.7

- **Script model upgraded to `qwen2.5-coder:7b-instruct`:** `SCRIPT_MODEL` and `CVE_SCRIPT_MODEL` default changed from `qwen2.5-coder:3b-instruct` to `qwen2.5-coder:7b-instruct` for improved CVE probe and verification script quality. Peak concurrent RAM during `--cve-test` increases to ~7.7 GB; 16 GB recommended.
- **Nikto `libjson-perl` fix:** `libjson-perl` added to the Dockerfile `apt-get install` list. Previously missing, causing nikto to print `Required module not found: JSON` at startup, which matched `BROKEN_TOOL_SIGNALS` and disabled nikto for every session without explanation. A post-clone sanity check is now baked into the Dockerfile build so missing Perl modules fail the build immediately.
- **CVE database race condition fixed:** `docker-entrypoint.sh` now always builds `cve-summary.csv` synchronously if missing (previously built in background `&`, so the scan started before the CSV was ready, producing "no CVEs matched" on every port).
- **`_load_cve_db()` self-heal:** if `cve-summary.csv` is missing at runtime, `noctis.py` now attempts to rebuild it automatically via `build_cve_db.py`. If the build also fails, it hard-exits with a `[FATAL]` message and exact instructions instead of silently returning an empty DB.
- **Bug fix — CVE knowledge base never persisted in Docker:** `_save_cve_kb()` was only called once after all CVEs finished testing. Fixed with two layers: (1) called after every individual CVE completes; (2) `_run_cve_test_phase` wraps the test loop in `try/finally`, guaranteeing a final flush even on unexpected exits.

---

## What's New in v0.7.6

- **Two-model architecture:** `gemma3:4b` handles planning and report prose; `qwen2.5-coder:3b-instruct` handles CVE and tool scripts. Updated `setup.sh`, `update.sh`, `docker-run.sh`, `docker-compose.yml`.
- **`nikto_cgi` auto-selected for HTTP/HTTPS in fast-path:** placed before plain `nikto` so all web services receive the exhaustive CGI scan without any LLM request.
- **Bash permitted in CVE probe scripts:** all three CVE script generation prompts now offer Python 3 or bash.
- **Bug fix — `nxc_smb`/`nxc_ldap` silently blocked:** both tools were missing from `KNOWN_TOOLS` and `validate_action()`, so every SMB/LDAP action was dropped before execution.
- **Bug fix — `nxc_smb`/`nxc_ldap` missing dispatch handlers in `run_tool()`:** added correct `nxc smb`/`nxc ldap` command strings.
- **Bug fix — `nxc` first-time-use race condition:** two parallel Phase 1 `nxc_smb` actions crashed when both tried to create `~/.nxc/` simultaneously. Fixed by running `nxc --version` at startup pre-flight.
- **Bug fix — `OLLAMA_TIMEOUT` increased 180 → 360 s.**
- **Runtime & ETA status line** at every major scan phase in CLI and Web UI.
- **HTML report — CVE Matches sorted by EPSS:** CVEs now appear highest exploit probability first.
- **Community KB pipeline fixes:** `SVC_KEY_RE` broadened; `timed_out_count` field name corrected.
- **Bug fix — `update.sh` now rebuilds Docker image** after source pull when Docker is present.
- **Bug fix — Docker KB persistence:** `os.replace()` fails with `EXDEV` across bind-mount boundaries. Fixed with `shutil.copy2()` + `os.unlink()` fallback.

---

## What's New in v0.7.5

- **CVE test pipeline reverted to sequential execution:** `asyncio.gather` removed; scripts run in sequence so each generation sees the previous attempt's output and verdict.
- **Stronger strategy-pivot enforcement:** each CVE test prompt includes a `BANNED STRATEGIES` block; `temperature` raised 0 → 0.4; `num_ctx` raised 2048 → 4096.
- **Neutral example JSON in CVE script prompt:** replaced version-check anchor with a socket-based skeleton.
- **`CVE_SCRIPT_MODEL` constant added:** env var `NOCTIS_OLLAMA_CVE_SCRIPT_MODEL` for a dedicated probe-generation model.
- **Report conclusion rebuilt after `--cve-test`:** `CONFIRMED_VULNERABLE` promotes posture to `critical`; `VULNERABLE` promotes to at least `high`.
- **`IMMEDIATE REMEDIATION PATH` green bar:** renamed from `THE FIX`; shows LLM-generated 3-step guidance specific to the CVE, product, and port.
- **Attacker Gain & Lateral Movement Potential section:** new amber-bordered block inside every CVE match card with a confirmed or likely-vulnerable verdict.

---

## What's New in v0.7.4

- **CVE IDs hyperlinked to NVD.**
- **Real CVSS v3.1/v4.0 from offline NVD database:** authoritative scores sourced from local NVD data; both v3.1 and v4.0 shown where available.
- **EPSS exploitation probability badge:** amber `EPSS X.X%` badge with exact probability and percentile rank.
- **"The Fix" green one-liner:** prominent `THE FIX` block at the top of every expanded CVE card.
- **CWE IDs hyperlinked to MITRE.**
- **OT warning banner + Type column:** orange banner when OT/ICS services are detected.
- **EPSS offline database:** `build_epss_db.py` downloads daily FIRST.org EPSS scores to `CVE/epss-scores.csv`.
- **NVD CVSS offline database:** `build_nvd_cvss.py` incrementally downloads NVD JSON 2.0 feeds to `CVE/nvd-cvss.csv`.
- **NIST CSF 2.0 compliance mappings:** all 17 vulnerability types map to NIST CSF 2.0 functions and control identifiers.
- **`ot` assessment profile:** classifies services using 15 OT/ICS protocol ports and 20 vendor/product keywords.
- **Docker improvements:** EPSS scores pre-fetched at image build time; `CVE` bind mount added.

---

## What's New in v0.7.3

- **Three-role model split:** dedicated `REPORT_MODEL` (default `qwen2.5:3b`) for report conclusion, attacker perspective, and remediation prose.
- **Deterministic conclusion anchor:** the first sentence of the conclusion is built from real finding counts, not asked of the LLM.
- **Polar.sh → Lemon Squeezy migration:** license validation for the community KB subscription moved to Lemon Squeezy.

---

## What's New in v0.7.2

- **Collapsible report sections:** Findings and CVE Matches sections collapse to header-only by default.
- **Attacker perspective narrative in CVE test cards:** LLM-generated threat context added above remediation inside each CVE test result card.
- **CVE test scripts parallelised:** Phase 2 probe scripts run concurrently via `asyncio.gather`, cutting worst-case CVE test wall-clock time by ~60%.

---

## What's New in v0.7.1

- **Automatic Ollama startup + model pull:** `noctis.py` starts `ollama serve` automatically if not running and pulls the configured model if not present locally.
- **Line-buffered stdout when piped:** `sys.stdout.reconfigure(line_buffering=True)` at startup.
- **Single-model architecture:** `phi4-mini:3.8b` removed; `qwen2.5-coder:3b-instruct` handles all LLM tasks.
- **Deterministic fast-path tool selector:** `_FAST_PATH` table maps well-known service fingerprints to tools without any LLM call.
- **Model keep-alive:** `keep_alive="1h"` sent with every Ollama request — eliminates cold-load penalty between scan phases.
- **Inference options tightened:** `num_ctx` capped at 1024; `temperature: 0`; `format: json` grammar-constrained decoding.
- **Model warm-start:** `_warmup_models()` fires a tiny prompt at each model during the nmap discovery phase.
- **INCONCLUSIVE reason surfaced in reports:** HTML report shows an amber ⚠ callout per CVE row; JSON gains `inconclusive_reason` field.

---

## What's New in v0.7.0

- **Five-phase nmap discovery pipeline:** replaces the single fast-port-scan with: (1) full port list (`-p-`), (2) service/version enumeration (`-sV -sC`), (3) targeted NSE scripts per service, (4) OS detection (`-O`), (5) normalisation and merge.
- **NSE results injected into LLM context:** full NSE output summary included in every planning prompt.
- **Nmap NSE Script Results table in HTML report:** lists each port and the NSE scripts executed against it.
- **`nmap_discovery` key in JSON report:** captures `open_ports`, `os_detected`, and `nse_summary`.

---

## What's New in v0.6.8

- **Docker Ollama health check:** replaced `curl` with a pure-bash TCP probe (`</dev/tcp/localhost/11434`).
- **Ollama `start_period` increased 20 s → 45 s.**
- **Docker env vars corrected:** `docker-compose.yml` now uses `NOCTIS_OLLAMA_MODEL` and `NOCTIS_OLLAMA_SCRIPT_MODEL`.
- **Disk space pre-flight checks:** `docker-run.sh` requires 8 GB free; `docker-test.sh` requires 2 GB free.
- **`exec -T` flag added** to all `docker compose exec` calls in `docker-run.sh` and `docker-test.sh`.
- **Dockerfile Go cache cleanup:** removes ~1 GB of intermediate build cache from the final image.
- **`.dockerignore` expanded:** `CVE/cve/` (~200 MB raw NVD JSON) excluded from Docker build context.

---

## What's New in v0.6.7

- **`ffuf` scoped to HTTP/HTTPS only:** removed from the IPP/CUPS service branch.
- **Tiered KB script selection with per-script success ranking:** scripts track `runs`, `vulnerable_count`, `not_vulnerable_count`, `inconclusive_count`; `VULNERABLE` weighted 3×.
- **Community confirmation bonus:** `+0.5` score per confirmation beyond the minimum-2 required for community KB inclusion.
- **Tool Knowledge Base community pipeline:** `submit_tool_kb.py`, `merge_tool_kb.py`, and Cloudflare Worker routes added.

---

## What's New in v0.6.6

- **Split-model architecture:** `qwen2.5-coder:3b-instruct` added for CVE script generation; `phi4-mini:3.8b` retained for planning and prose.
- **`SCRIPT_MODEL` constant added:** overridable via `NOCTIS_OLLAMA_SCRIPT_MODEL`.
- **Three CVE script generation sites switched to `SCRIPT_MODEL`.**
- **Models run sequentially:** no concurrent model loading — no additional RAM overhead.
- **Fixes false-positive CVE verdicts:** broken Python syntax in LLM-generated probe scripts caused false positives; `qwen2.5-coder` produces significantly fewer broken scripts.

---

## What's New in v0.6.5

- **Single-model architecture:** `llama3.2:3b` removed; `phi4-mini:3.8b` handles all LLM tasks.
- **`REPORT_MODEL` / `NOCTIS_REPORT_MODEL` removed:** `MODEL` constant used for all tasks.
- **phi4-mini v1 prompt improvements:** `PYTHON RULES` block, `FORBIDDEN` import list, single-quote rule, concrete working script example, and `CONTRAST RULE — MANDATORY` in verification prompt.
- **`ALREADY RUN` moved to top of iteration prompt:** exploits primacy bias to prevent the model from repeating failed tool invocations.
- **Collapsible CVE test result cards in HTML report.**

---

## What's New in v0.6.4

- **Scan engine switched to `phi4-mini:3.8b`:** 2.5 GB model with 128K context window; ~60–90 s/call on CPU.
- **4-strategy LLM response parser added.**
- **`nikto_cgi` tool added:** runs `nikto -C all` for exhaustive CGI directory scanning.
- **Port-qualified service keys and best-tool-per-service rankings.**
- **Fixed `ffuf -retries` flag and Phase 1 URL construction.**
- **CVE test verdicts shown in console summary.**
- **Version displayed in CLI banner and Web UI.**
- **Dedicated short-term/long-term remediation and Steps to Reproduce sections added to HTML report.**
