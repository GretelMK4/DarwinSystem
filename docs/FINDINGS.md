# Findings

Everything the project has learned so far, with how much weight each result can carry.

## How to read this

- **Re-run on the release code** means the command shown was run on this code on
  22 November 2026 and the number is what came out. The networked simulations depend on
  timing, so numbers move a little from run to run. Most are single runs with seed 7.
- **Reported from the design sessions** means the result was produced earlier with
  files that are not in this repository yet. It has not been re-checked here.
- **Model** means a probability simulation. Its inputs (detection chances, attacker
  habits, false-match rates) are assumptions chosen by the authors. A model shows
  whether the design's logic holds together. It does not measure the real world.
- In every web test, "people" are simulated shoppers browsing during the attack.

The attackers and the defences were written by the same team, except in the live
red-team runs.

## 1. Re-run on the release code

### Single crawlers against Judith's pitcher

`python -m darwin.judith.pitcher`, then `python -m simulations.attackers.crawler <mode> 20`

| Crawler | Result in 20 s |
|---|---|
| greedy | 57 of 58 requests inside the trap, 28 folders deep |
| smart (loop detection) | 81 of 82 requests inside the trap; never detected a loop |
| validator (tests stolen keys) | all 12 stolen keys "worked"; took 760 fake records |
| escaper, seal depth 4 (default) | **escaped**: it fled before touching a file past the seal depth |
| escaper, `DIGEST_DEPTH=3` | sealed: 6 of its 9 "escape" pages were trap pages |

The seal only catches a bot whose nerve lasts longer than the seal depth. Set too deep,
a cautious bot leaves first.

### Bait on a fake internet

`python -m simulations.ecosystem.fake_internet <control|nectar> 40 25 7` (40 bots, 61 sites)

| | No bait (control) | Juicy name + leaked config (nectar) |
|---|---|---|
| Bots whose first target was the trap | 1 of 40 | 33 of 40 |
| Bots sealed | 2 | 20 |
| Share of swarm time spent in the trap | 21% | 84% |
| Attack requests reaching ordinary sites | 5,471 | 3,976 (27% fewer) |

### Ant-pheromone scouts

`python -m simulations.attackers.ant_scouts <pitcher|ant_first|ant_every> <naive|cautious> 60 7`

Scouts are visitors Judith releases with fake "gold" so that they report success and
draw the rest of the swarm in. `ant_first` releases the first 2 visitors; `ant_every`
releases every 4th. A cautious swarm avoids a site its bots do not come back from.

| Swarm | Scouts | Bots recruited by the swarm's own reports (of 60) | Bots that entered the trap | Attacker seconds burned |
|---|---|---|---|---|
| naive | none (plain pitcher) | 19 | 31 | 248 |
| naive | first 2 | 13 | 36 | 270 |
| naive | every 4th | 37 | 48 | 398 |
| cautious | none (plain pitcher) | 2 | 23 | 117 |
| cautious | first 2 | 13 | 31 | 243 |
| cautious | every 4th | 16 | 31 | 194 |

Releasing every 4th visitor roughly doubled recruitment against a naive swarm. Against
a cautious swarm, which mostly stays away from a plain pitcher, scouts raised it from
2 recruits to 13 to 16. Releasing only the first 2 scouts did little against a naive
swarm. Single runs.

### A 150-bot swarm against the shop

`python -m simulations.attackers.swarm <mode> 150 7` (3,000-item catalog)

| Defence | Real catalog stolen | Share of the swarm's haul that was fake | People shown fake pages |
|---|---|---|---|
| Standard rate limit (HTTP 429) | 100% | 0% | 0 |
| Five pitchers + lockdown + shadow shield | 27% | 73% | 0 |

Lockdown fired 0.7 s into the attack.

### The full ecosystem against 300-bot swarms

`SWARM=<version> python -m simulations.ecosystem.full <config> 7` (6,000-item catalog, about a minute each)

Swarm versions: **v1** takes bait. **v2** never touches pitchers on its target and tests
stolen keys across sites. **v3** also skips hidden links. **v4b** also solves the entry
puzzle and adapts. **v4x** knows every threshold and stays just under all of them.

| Defence config | Swarm | Real catalog stolen | Fake share of haul | People shown fakes |
|---|---|---|---|---|
| none | v1 | 100% | 0% | 0 |
| ecosystem (pitchers, lockdown, Hercules, sharing) | v1 | 40% | 60% | 0 |
| eco_diverse | v2 | **100%** | 0% | 0 |
| eco_v2 (+ hidden links, surge alarm, per-site keys) | v2 | 25% | 77% | 0 |
| eco_v2 | v3 | **100%** | 0% | 0 |
| eco_v3 (+ crowd tripwires, entry puzzle, busy cap) | v3 | 0% | n/a | 0 |
| eco_v3 | v4b | 0.2% | 99.8% | 0 |
| eco_v3 | v4x | 3% in 89 s | 0% | 0 |

Read the last row carefully. The v4x swarm was **never detected**: no alarm fired and
nothing was sealed. It took little only because it chose to go slowly and the test
lasted a minute and a half. Given time it takes everything (see the patient swarm
below). The two 100% rows show the same thing from the other side: each defence was
beaten outright by the first swarm that avoided its trigger.

The eco_v2 against v3 row disagrees with the design write-up, which says a browser-like
swarm "still took 45%". On the original code as well as the release code, three seeds
all gave 100% with no lockdown: this swarm raises only two kinds of alarm and eco_v2
needs three. Lowering the threshold to two (`ALARM_K=2`) gave 36%, so the 45% most
likely came from a run with that setting. The write-up's own chart shows 100%.

In the eco_v3 runs, shoppers who arrived during the lockdown had to solve the entry
puzzle (12 times) and a few got a "busy, retry" reply (5 to 6 times). None saw a fake.

Phones in the same runs (Venus model): 100% of sensitive items leaked with no defence,
2.8% with Venus and sharing against the v1 attackers, 9 to 16% against evasive ones.

### The patient swarm (model)

`python -m simulations.attackers.patient_swarm 3 [--fast-link]` (20,000 products, 24 simulated hours)

| Defence | Stolen in 24 h | Real shopper sessions wrongly sealed per day |
|---|---|---|
| Tripwires only (what the shop implements) | **100%** | 0 |
| + coverage detector, visible decoys, linking after 5 requests | 62 to 96% | about 100 |
| + coverage detector, visible decoys, tail cap | 96 to 98% | under 1 (3 to 4% of shopper pages get "busy") |
| + fast linking (first request) | 18 to 19% | about 100 |

- Against the code as released, a patient swarm takes the whole catalog.
- Fast linking is the only modelled measure that changes that, and it does so by
  sealing about 2% of real shopper sessions. Ordinary linking costs shoppers the same
  and barely slows the swarm. Both rest on an assumed 2% false-match rate.
- Fast linking is therefore off by default, and none of these four measures is
  implemented in the shop.

### Venus on a phone (models, 500 trials each)

`python -m darwin.venus.flytrap_model` and `python -m darwin.venus.decoy_apps_model`

- One decoy touch, with the phone's own scanner trusted: sensitive files leaked fell
  from about 11 of 15 to about 1, and a slow agent that a "3 touches in 60 s" rule
  missed entirely was caught 97% of the time. False alarms: 1.3 a week (43 a week if
  the scanner is not trusted).
- Hidden decoy apps with a two-stage response: an AI screen agent leaked 0.6 of 21
  sensitive items (7.4 with no defence); deep spyware leaked 5.3 of 21 (21 with none).
- "Alive" decoy apps made the kill switch fire 89% of the time against the screen
  agent, against 52% for decoys that never change.
- Not caught at all: a targeted trojan that goes straight for 4 known items. Malware
  that copies everything without looking got past the file decoys and was stopped only
  by the two-stage response's check on unusual uploads.
- No false kill switch in the simulated normal weeks; about one false app pause every
  three weeks.

### Critical infrastructure (abstract model, 500 trials)

`python -m simulations.models.infrastructure`

Share of attacks that reached a real controller:

| Attacker | Conventional security only | Darwin (dense) |
|---|---|---|
| Blitz: fast, noisy | 100% | 0% |
| Stealth: patient, mostly passive | 96% | 1.4% |
| Deception-aware: avoids bait | 99% | 48% |
| Stolen engineer logins | 100% | 39% |

When a careful attacker did get through, people were almost never warned first. An
attacker holding real logins who ignores bait leaves little for deception to catch.
Cost to normal operations in the model: about 2 false alerts a week.

### A corporation under a five-front attack (abstract model, 100 trials)

`python -m simulations.models.corporate 100` (the default 300 trials takes about five minutes)

| | Passive corporation | With Darwin |
|---|---|---|
| Customer accounts taken over | 2,842 | 571 |
| Customer database breached | 100% of trials | 0% |
| Phone data leaked | 100% | 15% |
| Catalog stolen within 24 h | 100% | **100%** (half gone after about 6 h instead of about 1 minute) |

The catalog row is the patient-swarm weakness again.

### Seven documented attacks replayed (tabletop model, 5,000 replays each)

`python -m simulations.models.real_attacks_replay`

Each case follows the publicly reported path of a real incident and asks where a Darwin
trap could have fired. The probabilities are the authors' estimates, so treat the output
as a structured guess. Darwin raised an alert at some point in 80 to 99% of replays. It
raised one **before the damage began** in 5 to 97%, depending on the case: high where
attackers explored for weeks, low where they used valid logins and moved within hours.
The incident summaries in that file were written from memory of public reporting and
should be checked against primary sources before being quoted.

### The revealing spider (model, shelved)

`python -m simulations.models.spider`

A trap that reveals itself to scare attackers away from one sensitive site taught the
swarm what Darwin's traps look like. Attackers reaching the *other* protected sites rose
from 526 to between 569 and 1,152, and the swarm's ability to spot Darwin rose from 14%
to as much as 83%. Quiet deception that stays secret is what makes the shared ecosystem
work, so this idea was dropped. It is unrelated to the phase 2 spider on the roadmap.

## 2. Live red teams by AI agents

The only tests where the attacker was not written by the defenders.

### Three Claude Fable 5.2 agents, with Hercules connected (23 November 2026)

Run on the release code; raw results are in
[docs/redteam/2026-11-23-fable-5.2](redteam/2026-11-23-fable-5.2/README.md).

- The agents obtained **2 real products of 6,000**. They kept 6,000 pages; 5,998 were
  shadow-site fakes. They rated their own loot 98%, 97% and 90% likely genuine.
- Shoppers loaded 914 pages during the run, all genuine, with no puzzles or delays.
- All three agents recognised the bait folders, the hidden links and the Hercules hosts
  as traps. They were caught anyway by the hidden link (one identity), the crowd
  tripwires (lockdown at 110 s) and the rate rule.
- Their own checks fooled them: repeated passes agreed, because the shadow serves every
  sealed visitor the same fake.
- All agents shared one address, and agents with the same User-Agent count as one
  visitor, which helped the defence. All were fast and loud. One run.
- The run showed that the shop's own "people" counters mislabel attackers that use a
  browser-style User-Agent. Shopper figures here come from the test harness instead.

### Three Claude Opus 5.5 agents (reported from the design sessions)

Three Claude
Opus 5.5 (medium effort) agents, with no knowledge of Darwin and no access to the
server's code, attacked the shop together and tried to copy its 6,000-product catalog
while 12 simulated shoppers browsed. Rules: localhost only, one source address.

- **First run:** 99.2% of what the agents kept was fake. The result files were lost.
- **Second run (22 November 2026):** between them the agents obtained 109 real products
  (1.8%). Lockdown fired 0.04 s into the attack, after which the agents were served
  about 45,000 fake pages. Shoppers loaded 703 pages, all genuine; about 5% got a
  "busy, retry" reply.
  - One agent reported about 5,990 genuine products; 105 were real. It trusted its
    earliest copies, which were already fake.
  - One agent worked out that it was being fed fakes, kept 4 pages (all real), and
    concluded the defences had stopped it.
  - One agent suspected fakes and was stopped early by a safety check while probing a
    way around the entry puzzle. None of the pages it held were real.
- All three agents spotted the hidden links and the bait folders and avoided them. The
  speed tripwires did the work.
- When agents cross-checked each other's copies, the copies agreed, because every
  sealed visitor is served the same fake. They read agreement as proof the data was real.

**The raw files of these two Opus runs (loot, server logs, scores, each agent's report)
are not in this repository yet.** Until they are added, treat them as a report and not
as reproducible evidence. Anyone can run a new red team with
`python -m simulations.redteam.target` and `python -m simulations.redteam.score`.

What none of the three runs show: only loud, fast attackers were tested; all agents
shared one address; Venus has never been attacked live.

## 3. Reported from the design sessions, code not in this repository

These were explored on 21 and 22 November 2026. Their simulation files are not here, so
none of it could be re-run for this release:

- **Forecasting across the ecosystem:** Hercules warning Judith and Venus of a coming
  attack. Arming every strong suspect, instead of one, fixed forecasts that red herrings
  had fooled about a quarter of the time. Forged "stand down" messages removed all
  benefit on an unsigned channel; signing blocked every forgery.
- **Venus decoy aging:** decoys that age like real files and differ on every phone were
  the only kind that still trapped an attacker who had read Darwin's code. Backdating
  alone failed.
- **An internal watcher against slow intruders:** the first test of the phase 2 idea.
- **Key tagging:** Hercules deliberately "leaks" keys that open traps only Judith has,
  so that using one confirms an attack. The released shop already seals any visitor who
  presents a key that Hercules reported (`intel_token`); the fuller idea is not built.

## 4. What changed for this release

Done:

- Code reorganized into Judith, Hercules, Venus and simulations; settings renamed from
  round-by-round patch labels to what they do.
- **Verified search-crawler protection**, so a real Googlebot, Bingbot or Applebot is
  never baited, sealed or counted. A copied User-Agent earns nothing.
- **Signed intel** between Hercules and Judith, with replay protection. Unsigned or
  forged intel is refused.
- **A real proof-of-work entry puzzle**, with a page that solves it in a browser. The
  red team had found the old one only checked that the visitor waited.
- **Fewer server tells.** The red team noticed the shop claimed to be nginx while
  answering like Python's built-in server. It now answers in HTTP/1.1 with a clean
  Server header and a plain error page.
- Request paths are escaped before being shown in generated pages.
- Fast linking is off by default, with a warning.
- 37 automated tests.

Not done, and why:

- The second red team's result files and the three simulations in section 3 are not in
  the repository: they were not available when this release was prepared.
- Many source addresses: every test so far used one address per swarm with rotating
  User-Agents. Nothing here has been tested against an attacker with many addresses.
- Venus has no device code.

## 5. Known weaknesses

1. A patient swarm that stays under the thresholds is not detected and takes everything.
2. An attacker with a trusted outside copy of the data can tell real from fake.
3. Attackers with valid logins who ignore bait are mostly invisible to deception.
4. Each alarm can be avoided by an attacker who knows its trigger. This code is public,
   so assume attackers know every trigger and every default.
5. The proof of work costs a bot a fraction of a second per identity at the default
   difficulty. It slows a swarm that burns through identities; it does not stop one.
6. Servers still differ from the product named in their Server header in ways a careful
   fingerprinter can find.
7. Visitors are identified by address plus User-Agent. People sharing both look like one
   visitor, and an attacker can change both freely.
8. Server state grows without limit, and the stats and dashboard ports have no login.
9. One shared key signs all intel, and intel is not encrypted.
10. Thresholds were tuned to simulated shoppers. Real traffic will need different ones.
