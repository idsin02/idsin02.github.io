# DHRUxMAN Final Portfolio + Advanced Detection Engineering Labs

## Run locally

Open `index.html` directly, or serve the folder:

```bash
python3 -m http.server 8000
# browse to http://localhost:8000
```

No backend, build step, package manager, or external JavaScript dependency is required.

## What is preserved

- The supplied HTML is the exact opening of `index.html` through **02 — core focus**.
- The previous portfolio continues from **featured research** through the footer.
- The original 42 detections remain present: KQL 13, CQL 12, Sigma 10, and YARA 7.
- Existing query editing, syntax highlighting, deterministic execution, result filters, investigation rows, JSON export, analyst guidance, and clean-baseline behavior remain available.
- The public PHP2Shell package and its publication safeguards are unchanged.

## New labs

- **PHP2Shell lab** — preserved 42-rule implementation.
- **Active Directory lab** — 24 sanitized KQL hunts with deterministic synthetic telemetry.
- **Artex lab** — listed as **Under Construction** and intentionally contains no fake controls or content.

## Phase 2 workflow

`Detection → MITRE Mapping → Process Investigation → Attack Timeline → IOC Enrichment → Detection Tuning`

- ATT&CK Enterprise coverage metadata with direct, partial, indirect, and uncovered states.
- Fourteen-tactic dashboard, per-technique detection counts, telemetry, and explicit lab-scope gaps.
- Parent/child process trees generated from shared process identifiers and validated PID/PPID relationships.
- Correlated endpoint, network, file, authentication, and persistence timelines across multiple synthetic hosts.
- Simulated IOC enrichment for IPv4, IPv6, domains, URLs, SHA256, MD5, file names, paths, registry keys, and process names.
- Deterministic detection tuning with TP/FP/FN/TN, precision, recall, FPR, before/after counts, local save, and variant export.
- Clear warning when manual query text cannot be interpreted by the local tuning controls.

## Architecture

- `index.html` — exact supplied opening, preserved portfolio continuation, and integrated lab markup.
- `assets/css/portfolio-continuation.css` — compatibility styles for preserved sections.
- `assets/css/playground.css` — preserved lab styling.
- `assets/css/phase2.css` — Phase 2 module styling.
- `assets/js/library.js` — preserved 42-rule library and synthetic telemetry.
- `assets/js/ad-library.js` — 24 AD detection definitions, ATT&CK metadata, and synthetic events.
- `assets/js/investigations.js` — shared process, timeline, IOC, and tuning datasets.
- `assets/js/engine.js` — preserved deterministic detection simulator.
- `assets/js/phase2-engine.js` — coverage, correlation validation, and tuning metrics.
- `assets/js/playground.js` — integrated selector, existing UI features, investigation pivots, and Phase 2 components.
- `ad/kql/` — 24 standalone sanitized KQL files.
- `cve/` — preserved public-safe PHP2Shell package.

## Validation performed

- JavaScript syntax checks passed for every JavaScript file.
- All 66 detections execute without exceptions.
- All 24 AD detections return deterministic incident evidence and zero clean-baseline results.
- Existing four-language engine self-test passed.
- ATT&CK metadata exists for all 66 detections.
- All process-tree parent relationships and PID/PPID links passed validation.
- All timelines passed chronological and entity-link validation.
- IOC-to-event links passed validation.
- Tuning evaluates original and tuned variants against the same labelled corpus; confusion-matrix arithmetic passed.
- HTML has no duplicate IDs and all local script/stylesheet references resolve.
- The three URL/image placeholders remain unchanged.
- Public bundle scan found no private AD report name or production identifiers.

## Limitations

- All telemetry, reputation scores, and investigation evidence are synthetic and deterministic.
- The browser does not execute real SIEM queries or contact threat-intelligence providers.
- ATT&CK coverage is a scoped lab matrix, not a claim of complete Enterprise ATT&CK coverage.
- Tuning metrics are shown only for scenarios with labelled ground truth; other scenarios display an honest empty state.
- Browser automation was not run because no browser executable is installed in the delivery environment; DOM, syntax, engine, data-integrity, and local-reference tests were run instead.