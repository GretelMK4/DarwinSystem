# Security policy

The Darwin System is a research prototype. It has been tested only in simulations,
including live red-team attacks by Claude Opus 5.5 (medium effort) agents. It has not
been tested on production systems, and it is not hardened for exposure to the internet.

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue.

- **Preferred:** use GitHub's private vulnerability reporting for this repository
  (the **Security** tab, then **Report a vulnerability**).
- **Email:** spiritus5150@gmail.com

Please include what you found, how to reproduce it, and what an attacker could do with
it. You should get a reply within 7 days. This is a small volunteer project, so fixes
may take time; we will tell you what we plan to do and credit you if you would like.

## What counts

Reports we especially want:

- a way for a trap to harm a real visitor: sealing people, serving them fake pages,
  trapping a real search crawler, or leaking visitor data
- a way to forge, replay or tamper with intel messages between the plants
- a way to use a Darwin server to attack a third party, or to reach anything on the
  host beyond the fake content it is meant to serve
- an injection or memory-exhaustion problem in the servers

A new way for an attacker to recognise or avoid the traps is welcome too, but it is
research feedback and not a vulnerability: please open a normal issue or discussion.

## Known limits

These are documented in the README and are not new findings: the dashboard and stats
ports have no login and rely on being bound to localhost; per-visitor state is kept in
memory without a size limit; the entry challenge is a delay and not a proof of work;
all plants share one intel key.

## Out of scope

Anything that needs you to attack systems you do not own. See
[docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md).
