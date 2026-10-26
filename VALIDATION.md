# Validation — v0.1

Validated on 2026-10-26 in the development environment with Python 3.12.14 and Node.js 24.22.1.

## Automated validation performed

`python -m unittest discover -s tests -q`: **41 tests passed**.

Engine checks cover:

- Known broad/tuned/authentication fixture results and changed-match identity.
- Boolean precedence, parentheses, nesting, unknown names, unused selections and rejected code/unsupported syntax.
- Field AND, list OR/ALL, exact/contains/prefix/suffix matching and casefolding.
- Case-sensitive/literal field names, strict integer/Boolean types, missing/null/exists behavior.
- Missing negative-filter fields and exact source gating, including fixture metrics for excluded sources.
- Unlabeled and zero-denominator metrics without invented accuracy values.
- Unsupported modifiers, invalid values, duplicate JSON keys and non-finite JSON numbers.
- Invalid-record diagnostics, label validation, no-valid-event state and retained duplicate occurrences.
- Evidence/diagnostic/change caps with full aggregate counts and explicit omitted counts.
- Line, byte, nesting and work bounds; invalid Unicode input rejection.
- Withheld event values in reports, basic CSV formula guarding and input fingerprints.
- Engine execution with network socket creation and subprocess creation patched to fail, confirming those operations are not required.

HTTP checks use a real temporary loopback server. They cover sample routes, evaluated JSON/CSV responses, explicit invalid-rule rejection, formatting that retains duplicate-key validation, malformed outer payloads, large declared lengths rejected before body processing, Unicode errors, Host/Origin/fetch checks, required custom header/media type, static allowlist/security headers and refusal to bind to non-loopback.

`node --check static/app.js`: passed.

`node tests/test_ui.js`: passed against a real local HTTP server using a minimal DOM controller harness. It exercised broad/tuned/partial/invalid sample loading and evaluation, table row generation, two changed matches, metric values, server-validated formatting, report JSON/CSV/rule JSON payloads, the print-function call and clear behavior.

The DOM harness is **not a browser rendering engine**. It does not validate CSS, browser security enforcement, file-picker UX, actual download dialogs, accessibility comprehensively, print pagination or PDF output.

`python workbench.py --rule examples/tuned-rule.json --baseline examples/broad-rule.json --events examples/process-events.jsonl`: passed; generated local JSON and CSV reports. Bundled example reports are generated from the same synthetic fixtures.

## Expected acceptance results

| Example | Valid events | Invalid | Matches | Fixture TP / FP / FN / TN | Changes |
| --- | ---: | ---: | ---: | --- | ---: |
| Broad rule | 6 | 0 | 3 | 2 / 1 / 1 / 2 | N/A |
| Tuning comparison | 6 | 0 | 3 | 3 / 0 / 0 / 3 | 2 |
| Authentication | 4 | 0 | 2 | 2 / 0 / 0 / 2 | N/A |
| Parsing gaps | 3 | 2 | 2 | 2 / 0 / 1 / 0 | N/A |
| Unsupported rule | Not evaluated | — | — | Explicit unsupported modifier error | — |

Parsing gaps intentionally includes a source-excluded labeled event, which is a false negative relative to the supplied fixture expectation. It also includes a missing User field where NOT filter evaluates true; the missing-field report makes this visible. Neither behavior establishes anything about a real incident.

The tuned sample has 100% precision/recall **on six invented fixture events only**. This is not a real-world detection accuracy result, malware identification claim, or production recommendation for user exclusions.

## Not verified here

- Windows launcher execution on a Windows host.
- A real browser render, mobile layout and actual browser downloads/PDF appearance.
- Sigma/YAML import, pySigma conversion, equivalent SIEM behavior or a production telemetry corpus; these are unsupported, not pending implicit promises.
- Real-world accuracy, adversarial evasion resistance, exhaustive fuzzing, concurrent service load, production authentication or TLS.

## Windows/browser acceptance checklist

1. Extract the ZIP and run `start_windows.cmd`.
2. Test each sample and compare the table above.
3. Inspect `proc-003` and `proc-006` in Tuning comparison; their match decisions should change in opposite directions.
4. Inspect the missing User field in Parsing gaps and read the source-exclusion counts.
5. Change a rule field, rerun and verify that results reflect the new input. Editing should hide the previous report.
6. Load `examples/process-events.jsonl` with the file picker.
7. Export report JSON, evidence CSV and candidate rule JSON; open them. The tuning sample CSV has 12 data rows (six per rule).
8. Save a PDF and confirm readable metrics, event columns and coverage text. Expand optional evidence/configuration before printing if desired.
9. Clear the session and confirm editors/results clear. Stop with Ctrl+C.
