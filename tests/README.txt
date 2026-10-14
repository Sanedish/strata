Run everything:

  python tests/run_all.py              builds a throwaway instance in a temp folder, runs every suite, cleans up
  python tests/run_all.py --keep       leaves the instance and its server running afterwards
  python tests/run_all.py --offline    skips ssrf_test.py, which needs https://example.com

Needs 127.0.0.1:8190 to be free. Caddy is not needed: the harness uses a stub that accepts every config.

The suites, in the order run_all.py runs them:

  setup_test.py         first-run owner setup (/setup): loopback only, validation, works once; an owner with an
                        authenticator app and no e-mail signs in with it
  smtp_test.py          SMTP mail delivery against a recorder (no mail server needed)
  sec_regress.py        takeover paths, zones, SSRF, CSRF, headers
  caddy_test.py         the generated Caddy config through a real `caddy validate` (skipped without Caddy)
  anubis_test.py        bot protection: config off/on, policy and key files, settings checks, the download (fake archives),
                        then real requests through a real Caddy and a stub Anubis (skipped without Caddy); with STRATA_ANUBIS set (or anubis on the PATH)
                        the same requests run again against the real Anubis, puzzle solved
  granular_regress.py   fine-grained capabilities, per-zone actions, end dates, IP allowlists, session length,
                        share-link ownership, profile pictures, synced preferences
  office_regress.py     the Team view: directory privacy, presence, notes, the Moderator flag, delegation
  login_test.py         the /login password step and where it sends each account next
  ssrf_test.py          remote upload: public HTTPS works, LAN and loopback are refused
  media/tests/          unit tests for Strata Media (python -m unittest)

anubis_demo.py is not a suite: a small site behind a real Caddy and a real Anubis, to open in a browser (see its docstring).
seed_granular.py and devsession.py are helpers: the first seeds the example employee 'mara', the second mints a
session cookie for a dev database. The HTTP suites refuse any database outside a folder named *scratchpad*.
