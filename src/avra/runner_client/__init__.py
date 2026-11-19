"""Windows-side access to the Kali Tool Runner (ADR 0003, M6).

``tunnel``  — the restricted avra-tunnel SSH port forward (fixed options).
``client``  — typed HTTP client for the Runner API (stdlib urllib).
``scan``    — one end-to-end tool run: local policy → audit → tunnel →
              Runner → verify → evidence → parse → audit.

Nothing here decides *whether* something may run: the Windows-side policy
(``avra.policy.tools``) and the Runner's own policy both must allow it.
"""
