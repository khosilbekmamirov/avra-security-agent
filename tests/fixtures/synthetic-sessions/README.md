# Synthetic sessions

Two AVRA sessions in the exact on-disk format (hash-chained audit log + evidence files),
used by the offline tests and the README demo. They are **synthetic**: the structure
follows real lab runs, but every captured value was replaced -

- addresses use the synthetic lab range `10.66.7.0/24`;
- model provider request ids are `req_SYNTHETIC_*`;
- the HTTP response is a short hand-written page (same security-relevant headers and
  referenced paths as the scenario needs), not a capture of any server;
- all body/response/request/evidence SHA-256 values and the audit hash chain were
  recomputed, so integrity checks pass.

Do not edit these files by hand: the tests verify their hashes byte for byte.
