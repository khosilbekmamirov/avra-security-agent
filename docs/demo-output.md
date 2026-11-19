# Offline demo — example output

Captured 2026-11-19 on Windows 11 / Python 3.12 from this repository, using a copy of the
synthetic session fixtures (`AVRA_DATA_DIR=demo-data`). No network connection is made.

```text
$ avra check-scope scope/example.scope.yaml
Valid.
example-lab-session: 1 target(s), expires 2026-12-31T23:59:59+00:00

$ avra verify session --session 7e868faf-768d-49af-aea6-81dc9d435e20
Verification report (avra-verification-report/2, engine 1)
Session 7e868faf-768d-49af-aea6-81dc9d435e20  created under scope 'm8.3-http-probe-juice-shop'  audit valid (3 records), no scope snapshot
Run: 3 round(s), stop: evidence_exhausted, proposers: rules
Observations from verified evidence: 1; excluded evidence: 0
CONFIRMED FINDINGS (vulnerability rules): 0
Verified observations (facts, not vulnerabilities): 1
  [CONFIRMED] http.service_observed @ 10.66.7.103:3000 - HTTP/1.1 status 200 received (1 trusted probe(s)).
Rejected hypotheses: 1
  [REJECTED] http.missing_x_content_type_options @ 10.66.7.103:3000 - Every eligible response sends X-Content-Type-Options: nosniff.
Inconclusive (open questions): 0
Proposed next actions (all candidates, regardless of budget; NOT executed; owner approval needed): 0
Report: demo-data/verification/7e868faf-768d-49af-aea6-81dc9d435e20/report-32cb9bfc90505505.json
Report sha256: 32cb9bfc90505505775ec94c68791483f81d0eea468d8ea8fb7d5f343f9e3fb0  (audit: demo-data/verification/7e868faf-768d-49af-aea6-81dc9d435e20/verification-audit.jsonl)

$ avra verify check 7e868faf-768d-49af-aea6-81dc9d435e20
Verification check: VERIFIED (2 result(s) reproduced)
Report: demo-data/verification/7e868faf-768d-49af-aea6-81dc9d435e20/report-32cb9bfc90505505.json sha256 32cb9bfc90505505775ec94c68791483f81d0eea468d8ea8fb7d5f343f9e3fb0

$ avra validate fixture --file tests/fixtures/validation/idor-cross-account-read.json
idor.cross_account_object_access on 192.168.56.250:8080: CONFIRMED (cross_account_read) [SIMULATED - not a lab finding]
  The second synthetic account received the owner's object (marker present).
  - owner_baseline: met owner status 200
  - cross_account_read: met the owner's data marker is in the second account's response
  limitation: Only the recorded pair of requests is judged; other objects and methods may behave differently.
  limitation: A 2xx without the owner's data marker is not counted as a leak.
Result sha256: ff93653ef7688cc6bae8b9f5c7742d0a9bd36f1db7ad001ae563b0035cbab609  (audit: demo-data/validation/validation-audit.jsonl)
```
