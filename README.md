# Detection Rule Workbench

An offline workbench for writing, validating and testing detection rules against normalized event fixtures. Inspect field predicates, compare a candidate with a baseline, and export evidence.

**Python 3.12 standard library only. No pip dependencies, API keys, database or external service.** The browser talks only to your local loopback server. The CLI does not start a server or make network requests. Sample command lines are inert text and are never executed.

The native **DRW/1** JSON profile is inspired by Sigma selections and conditions. It is not a Sigma parser or converter, and it makes no full Sigma/SIEM compatibility claim. Sigma YAML, pySigma backends, query generation, correlations and rule deployment are not implemented.

## Start on Windows

1. Extract the ZIP fully.
2. Open `DetectionRuleWorkbench`.
3. Double-click `start_windows.cmd`.
4. Open http://127.0.0.1:8830 if the page does not open automatically.

Keep the console open. Stop with Ctrl+C.

From Windows CMD:

```cmd
py -3.12 server.py
```

If the default port is busy:

```cmd
set RULE_WORKBENCH_PORT=8831
py -3.12 server.py
```

Linux/macOS: `python3 server.py`. `RULE_WORKBENCH_NO_BROWSER=1` suppresses opening a browser. Binding is fixed to `127.0.0.1`; this standard-library training server is not intended for public deployment, reverse proxies or a hosted multi-user service.

## Practice workflow

1. **Broad rule** loads a rule looking for a PowerShell executable and an encoded-command flag. Select **Test rule**. Review which predicates matched and which fixture expectations were missed.
2. **Tuning comparison** adds the alternative `pwsh.exe` image and an explicit training-account exclusion. Compare against the broad baseline using the exact same events. Excluding a named user is an illustrative fixture change, not a safe production recommendation.
3. **Authentication** demonstrates two selections joined with AND.
4. **Parsing gaps** demonstrates invalid records, a missing filter field and an event from another log source.
5. **Unsupported rule** demonstrates explicit regex rejection. A rejected rule produces no partial report.
6. Export report JSON, evidence CSV, the validated candidate rule JSON, or Print / Save PDF.

Expected results:

| Example | Valid / invalid | Candidate matches | Fixture TP / FP / FN / TN | Changed matches |
| --- | --- | ---: | --- | ---: |
| Broad rule | 6 / 0 | 3 | 2 / 1 / 1 / 2 | Not compared |
| Tuning comparison | 6 / 0 | 3 | 3 / 0 / 0 / 3 | 2 |
| Authentication | 4 / 0 | 2 | 2 / 0 / 0 / 2 | Not compared |
| Parsing gaps | 3 / 2 | 2 | 2 / 0 / 1 / 0 | Not compared |
| Unsupported rule | Not evaluated | — | Validation rejection | — |

The broad and tuned rules both match three events, but two specific match decisions change. That distinction is why a match count alone is insufficient to evaluate tuning.

## Native rule profile

Rules must contain exactly these properties:

```json
{
  "format": "drw/1",
  "id": "17140487-c4cf-4bd8-8a02-133438ef9479",
  "title": "Failed authentication to a named admin account",
  "description": "Training fixture rule; review matches in context.",
  "level": "medium",
  "logsource": {"product": "training", "category": "authentication"},
  "selections": {
    "failure": {"Result": "failure"},
    "account": {"User|startswith": "admin"}
  },
  "condition": "failure and account"
}
```

`id` is a UUID string. It identifies the author's rule; it is not an authenticity guarantee. `level` accepts informational, low, medium, high and critical as author-supplied metadata; it is not inferred risk or a score. A log source must contain exactly product and category. Both must match an event's source exactly before the condition is evaluated.

### Operators

| Predicate | Meaning |
| --- | --- |
| `Field` or `Field|eq` | Exact equality; casefolded for strings, strict types otherwise |
| `Field|contains` | Literal casefolded substring |
| `Field|startswith` | Literal casefolded prefix |
| `Field|endswith` | Literal casefolded suffix |
| `Field|exists` | Boolean key-presence test, including a present null value |
| `Field|contains|all` (or another equality/text operator + all) | Every rule-list item must match that event field |

Fields in one selection are ANDed. A rule value list is ORed unless `all` is specified. An event field is a scalar, not a list. `all` requires a rule list. `exists` accepts only a single Boolean and cannot be combined with another modifier. At most one ordinary operator is allowed per predicate.

Strings use Python Unicode `casefold()` comparison. Field names are case-sensitive; dots are literal, not nested property access. Integers do not equal numeric strings, and Booleans do not equal integers. Null rule values are unsupported: use `exists` to check key presence. Ordinary comparisons to missing or null event fields return false.

Conditions support named selections and lowercase `and`, `or`, `not`, and parentheses. Precedence is NOT, then AND, then OR. Every selection must be referenced. Conditions are parsed by a small recursive-descent parser; no Python `eval` or arbitrary expression execution is used. Unsupported words/operators and unclosed parentheses fail validation.

Missing fields require care with NOT: when `User` is missing, `filter_automation` can be false, making `not filter_automation` true. The workbench reports missing predicate counts and per-event presence evidence. If a field must be present, explicitly add a selection with `User|exists: true` to the condition.

Wildcard characters `*` and `?` are rejected in rule strings, including literal uses. There is no escape syntax for them in v0.1. Regex, case-sensitive text modifiers, numeric ranges, IP/CIDR matching, time windows, aggregations, correlations, field mapping, nested events and external lookups are outside this profile. Native rules are not exported as Sigma because equivalent backend semantics have not been established.

## Event fixture format

Use UTF-8 JSON Lines: one JSON object on each nonblank physical line.

```json
{"event_id":"auth-001","source":{"product":"training","category":"authentication"},"fields":{"Result":"failure","User":"admin"},"expected_match":true}
```

Required: `event_id` (nonempty string), `source` (exact product/category), `fields` (flat named scalar values). Optional: Boolean `expected_match`. Other top-level keys are rejected. Event fields may be strings, signed 64-bit integers, Booleans or null. Floats, nested objects and arrays are unsupported. Missing fields are allowed structurally but ordinary predicates against them fail.

Raw Windows EVTX/XML, vendor-specific JSON, ECS nested objects, Sysmon exports, arbitrary CSV and native operating-system logs need a separate, independently verified normalization step before this tool can evaluate them. A familiar field name does not establish that the value or source is authentic.

Invalid nonblank lines are excluded with line-numbered diagnostics. Duplicate keys and non-finite JSON numbers are rejected. Duplicate event IDs and records are retained: physical line numbers identify occurrences. Blank lines are counted separately. An invalid record does not become a non-match. Zero valid records is reported as `no_valid_events` rather than a completed assessment.

## Fixture metrics

The label describes **whether this rule is expected to match**, not whether an event is an attack:

| Observed match | expected_match | Outcome |
| --- | --- | --- |
| true | true | true positive (TP) |
| true | false | false positive (FP) |
| false | true | false negative (FN) |
| false | false | true negative (TN) |
| either | absent | unlabeled; excluded from metric denominators |

Precision = TP / (TP + FP); recall = TP / (TP + FN). JSON also includes fixture agreement = (TP + TN) / all labeled valid events. Undefined denominators return JSON null and display N/A. Source-excluded valid records count as non-matches, including when labeled. These metrics do not measure real-world accuracy, alert quality or maliciousness.

When comparing rules, the same fixture labels are applied to both rules. Choose fixtures that reflect the intended detection behavior; do not treat good scores on a tiny edited sample as production validation.

## Evidence, exports and privacy

- JSON includes full rule definitions, input fingerprints, aggregates, up to 200 event evidence rows per rule, up to 200 changed-match rows and up to 50 diagnostics. Omitted counts are explicit.
- CSV includes the retained event evidence rows for each evaluated rule, not full uncapped input. Common spreadsheet formula prefixes in identifiers are guarded; review before opening untrusted exports.
- Rule JSON exports the validated native candidate, not Sigma, YAML or a deployed rule.
- Print / Save PDF includes the visible comparison, coverage and event preview. Expand the configuration/limits section or predicate evidence if you want those sections printed too. Large evidence expansions can produce many pages.
- Event field values are withheld from reports, CSV and per-event evidence. Full rule values, event IDs, field names, fixture labels and fingerprints remain; they can still be sensitive. A rule may itself contain sensitive search strings. Review before sharing.
- SHA-256 identifies the exact submitted UTF-8 text for rules/events. It is not a signature, provenance check or an assertion that the file was collected correctly. CLI file decoding removes a UTF-8 BOM; browser/editor normalization can also change text, so this is not guaranteed to be the original file-byte hash.
- No inputs/reports are persisted by the server. Editor content stays in browser memory; refreshing or Clear session discards it. Exports are saved only when requested. Changing input hides stale results until another evaluation. Clearing does not delete existing downloads.

## Limits

Rules: 32 KiB each, 8 selections, 8 predicates per selection, 16 values per predicate, 256 characters per rule value, 64 condition tokens and nesting depth 16. Rule field names are literal identifiers allowing dots; selection names use letters/digits/underscore, beginning with a letter/underscore, excluding reserved Boolean operators.

Events: 1 MiB submitted text, 1000 physical lines including blanks, 64 scalar fields per event, strings up to 4096 characters, IDs up to 80. HTTP request limit is 2 MiB including JSON escaping, so a heavily escaped input can hit the request limit before the inner event limit. Reduce input or use the CLI. The total evaluation work budget is 20 million approximate string units across both rules. Exceeding it returns an error and no partial report.

The HTTP server checks local Host/Origin, rejects cross-site fetch metadata, requires a custom API header and JSON for POSTs, serves a static allowlist, and sets a restrictive CSP. It has no production authentication or TLS. It is an educational local tool, not a hardened network service or an exhaustive security assessment.

## CLI and tests

From the project folder in Windows CMD:

```cmd
py -3.12 -m unittest discover -s tests -v
py -3.12 workbench.py --rule examples\tuned-rule.json --baseline examples\broad-rule.json --events examples\process-events.jsonl
```

The CLI writes `reports/rule-report.json` and `reports/rule-events.csv`. Add `--output DIRECTORY` to choose another local destination. There is no network target or command-execution option. CLI input reads are bounded before decoding.

Optional Node.js validation (not needed to run the app):

```cmd
node --check static/app.js
node tests/test_ui.js
```

The UI controller smoke harness requires the server on port 8830. It is not a browser rendering test. See `VALIDATION.md` for exact validation performed and remaining acceptance checks.

## Files

- `engine.py`: strict native-profile parsing, conditions, matching, fixture metrics, report and CSV generation.
- `samples.py`: synthetic rules/events and example loader.
- `server.py`: loopback UI and in-memory evaluation routes.
- `workbench.py`: offline CLI.
- `static/`: editors, comparison, safe text rendering, exports and print styles.
- `examples/`: native rules, normalized fixture files and generated example JSON/CSV.
- `tests/`: engine/HTTP regressions and optional controller harness.

## References

- [Sigma rules concepts](https://sigmahq.io/docs/basics/rules.html)
- [Sigma conditions](https://sigmahq.io/docs/basics/conditions.html)
- [Sigma modifiers](https://sigmahq.io/docs/basics/modifiers.html)

These references explain the broader ecosystem. DRW/1 intentionally implements its own smaller documented semantics and is not a substitute for Sigma tooling or operational SIEM testing.
