# The Darwin System

**Defensive deception against automated AI attack swarms.** Three traps modeled on
carnivorous plants, wired together so each one makes the others stronger. They lure
automated attackers in, keep them busy with convincing fakes, and warn people early.

> **Research prototype.** Tested only in simulations, including live red-team attacks
> by Claude Opus 5.5 (medium effort) agents. Not yet tested on production systems.

A project of **GretelMK4**. Apache License 2.0. Python standard library only.

## The idea

Hacking an attacker back is illegal for private defenders and risks hitting innocent
machines that attackers hijack. Darwin never touches the attacker's systems. Everything
happens on infrastructure you own: you make your own site expensive, confusing and
dangerous to attack.

The design rests on one observation. Some things on a network have no legitimate users
at all: a hidden link, a decoy server, a hidden decoy app. Anything that touches them is
almost certainly an attacker. That gives an alarm with very few false positives, and it
gives attackers something to waste their time on.

## The three plants

| Plant | Trap type | Where it lives | What it does |
|---|---|---|---|
| **Judith** | pitcher plant (pitfall) | inside a real website you protect | Bait leads into endless generated mazes and a fake API where planted keys "work". Past a set depth the trap seals one way: that visitor now sees a shadow copy of the site with believable fake data. Several pitchers per site, a lockdown when alarms combine. |
| **Hercules** | sundew (flypaper) | a farm of fake servers with no real purpose | No legitimate visitor ever arrives, so everything is sticky from the first request. Whatever it catches (visitor identities, the fake keys it handed out, sweep surges) is shared with Judith as signed intel. |
| **Venus** | flytrap (snap trap) | phones and workstations | Decoy files and hidden decoy apps act as trigger hairs. Touching one pauses the suspect app; repeated touches cut the device's network and alert the user. |

Connected, the plants cover each other's blind spots. In testing each plant alone was
beatable, and an unconnected Hercules once made Judith worse by drawing off the
attackers that would have tripped her alarm.

### Why these names

- **Darwin**: Charles Darwin, whose favourite plant was the sundew.
- **Judith**: the *Judith Hindle* pitcher plant (not the biblical Judith).
- **Hercules**: the Hercules sundew.
- **Venus**: the Venus flytrap.

The "ant pheromone" scout idea came from watching real pitcher plants feed on ants:
a few scouts are allowed to leave with fake "gold", so the swarm recruits itself.

## What is real code and what is a model

Be clear about this before you rely on anything here.

| Part | Status |
|---|---|
| Judith's pitcher (`darwin/judith/pitcher.py`) | Working local server: bait, maze, fake API, one-way seal, scouts, catch and release, dashboard |
| Judith's shop (`darwin/judith/shop.py`) | Working local server: five pitchers, lockdown, shadow site and shield, hidden links, crowd tripwires, signed intel intake, verified-crawler protection |
| Hercules (`darwin/hercules/honeyfarm.py`) | Working local library: a farm of fake sites on localhost ports |
| Signed intel (`darwin/intel.py`) | Working: HMAC-SHA256 envelopes with replay protection |
| Crawler verification (`darwin/crawlers.py`) | Working, but tested only with fake DNS, never against live search-engine traffic |
| **Venus** (`darwin/venus/`) | **Model only.** Two probability simulations of a phone. No app or on-device code exists |
| Long-tail coverage detector, visible decoy products, behavioural linking, tail cap | **Model only** (`simulations/attackers/patient_swarm.py`). Not implemented in the shop |
| Critical-infrastructure and corporate scenarios, real-attack replay | **Abstract models** with assumed probabilities |

## Quick start

Python 3.10 or newer. Nothing to install to run it.

```
git clone https://github.com/GretelMK4/DarwinSystem
cd DarwinSystem

# Judith's pitcher on http://127.0.0.1:8088, dashboard on http://127.0.0.1:8089
python -m darwin.judith.pitcher

# in a second terminal: send a simulated crawler into it
python -m simulations.attackers.crawler greedy 20
```

The full ecosystem against a 300-bot swarm (about one to two minutes):

```
python -m simulations.ecosystem.full ecosystem
SWARM=v4x python -m simulations.ecosystem.full eco_v3
```

Tests:

```
python -m pip install pytest
python -m pytest -q
```

Everything binds to `127.0.0.1`. Results and logs are written to `results/`, which git
ignores. The networked simulations use fixed ports (8088, 8089, 9000-9950): run one at
a time.

## Layout

```
darwin/
  judith/      pitcher.py, shop.py, dashboard.html
  hercules/    honeyfarm.py
  venus/       flytrap_model.py, decoy_apps_model.py   (models only)
  intel.py     signed messages between the plants
  crawlers.py  verified search-crawler protection
simulations/
  attackers/   crawler.py, swarm.py, ant_scouts.py, patient_swarm.py
  ecosystem/   fake_internet.py, full.py
  models/      infrastructure.py, corporate.py, real_attacks_replay.py, spider.py
  redteam/     target.py, score.py
tests/         unit and server tests
docs/          FINDINGS.md, RESPONSIBLE_USE.md, writeup.html
```

Every module's docstring explains its settings and how to run it.

## Results so far

RESULTS_PLACEHOLDER

## Honest limits

- **Both sides were written by the same team.** The simulated attackers could only be
  as clever as we thought to make them. Every new attacker tactic broke something, so a
  real adversary will find cracks these tests never imagined. The red-team run by AI
  agents that had not seen the defence is the only result here not graded by our own
  attacker model, and it was a single run against loud, fast attackers.
- **A patient attacker wins against the code as released.** In the model, a swarm that
  stays under every threshold takes the whole catalog in 24 hours. The countermeasures
  that slow it down exist only as a model, and the best of them still loses most of the
  catalog.
- **The fakes fail against any trusted outside copy:** an older scrape, a
  price-comparison site, or a person checking from an ordinary connection. The shadow
  site works only when the attacker has nothing real to compare against.
- **Attackers with real logins who ignore bait leave little for deception to catch.**
  Darwin belongs beside controls that do not depend on deception: patching, logins that
  cannot be phished, backups, monitoring.
- **Thresholds were tuned to simulated traffic.** A real flash sale could trip the
  traffic tripwire. A real site would set every number from its own baseline.
- **Time was compressed and repeats were few.** Web tests ran for about a minute, mostly
  one or two runs each; results move from run to run.
- **Not hardened.** The dashboard and stats ports have no login and rely on being bound
  to localhost. Per-visitor state is kept in memory without a size limit. The entry
  challenge is a one-second delay, not a proof of work. All plants share one intel key,
  and intel travels unencrypted.
- **Identity is IP address plus User-Agent.** Visitors behind one shared address with
  the same browser look like one visitor.
- **Venus does not exist as software yet**, and what a phone platform allows a decoy
  app and a network watcher to do is untested.
- **The building blocks are not new.** Honeytokens, tarpits, decoy networks and crawler
  mazes exist today. The combination here has not been checked against the literature.

## Roadmap

- **Phase 1: the three plants.** Design complete; this release. Judith and Hercules as
  local prototypes, Venus as a model.
- **Phase 2: the spider.** An internal watcher that lives inside the site, like an
  immune cell. It inspects the site and Darwin itself and alerts people when something
  is not approved. Aimed at slow attackers. It does not need to be an AI agent.
- **Phase 3: protected communication.** Hardening the messages between the plants so
  they cannot be tampered with or read: per-plant keys, rotation, encrypted transport.

Also needed before anyone should depend on this: independent red teams, a few weeks of
Judith and Hercules on an isolated server to see what real bots do, and a first Venus
prototype on a real phone.

## Responsible use

Defensive only. No hack-back. Fictional brands only. Owned infrastructure only. Real
people come first. Read the [responsible-use charter](docs/RESPONSIBLE_USE.md) before
running or changing this code; it also covers the privacy of visitor data.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md). Please do not open a public
issue.

## Contributing

The most useful thing you can do is break it. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits and license

Concept and design: OJ, GretelMK4. Simulations and prototype code built with Claude.

Copyright 2026 GretelMK4. Licensed under the [Apache License 2.0](LICENSE).
