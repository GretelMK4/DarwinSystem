# Live red team, 23 November 2026: three Claude Fable 5.2 agents

The first live test with Hercules connected to Judith, and the first whose raw results
are kept in the repository.

## Setup

- **Target:** `HERCULES=8 python -m simulations.redteam.target` on the release code:
  Judith's shop (6,000 products, every defence on, proof-of-work entry puzzle), eight
  Hercules decoy sites feeding it signed intel, and 12 simulated shoppers browsing
  throughout. Venus has no device code and took no part.
- **Attackers:** three Claude Fable 5.2 agents started together, each given a third of
  the catalog and about 12 minutes. They were told the shop's address, that sibling
  hosts existed on ports 9500 to 9507, and nothing about how the defences work. They
  shared a notes file.
- **Rules:** localhost only; no reading the server's code, logs or statistics port.
  Their working files show no sign of a breach, but compliance was not enforced.
- Effort level could not be set for the agents and is unknown.

## Result

| | |
|---|---|
| Real products obtained | **2 of 6,000 (0.03%)** |
| Pages the team kept | 6,000, of which 5,998 were shadow-site fakes |
| Agents' own confidence that their loot was genuine | 98%, 97%, 90% |
| Shopper pages loaded during the run | 914, all genuine; no puzzles, no "busy" replies |
| Time each agent took | 4 to 6 minutes |

Every fake page the agents kept is byte-for-byte the shadow site's page for that
product (checked against `shop.item_page(n, fake=True)`).

## What happened

1. All three agents recognised the bait at once: the leaked folder names, the hidden
   links (they spotted the `x9` class and the out-of-range product number), and the
   Hercules hosts, which they correctly called honeypots.
2. About a minute in, one identity followed a hidden link and was sealed. At 110 s the
   traffic-spike and enumeration tripwires put the shop into lockdown. Two more
   identities were sealed by the rate rule. Hercules reported one attacker identity and
   24 issued keys to the shop as signed intel.
3. From then on the agents were copying the shadow site. Their bulk downloads, the
   passes they relied on, were all made after the seal.
4. **Their verification is what fooled them.** Each agent re-fetched its pages (two or
   three full passes, slow re-checks, different User-Agents) and found them identical
   every time, because the shadow serves every sealed visitor the same fake. Agent 3
   even saw one product change between its first requests, and concluded that the
   stable later version was the genuine one. It was the fake.
5. Agent 2 met the entry puzzle and took it for an ordinary burst rate limit.

## What this does and does not show

- The result matches the two earlier runs with Claude Opus 5.5 agents, against a
  stronger model and with the proof-of-work puzzle and Hercules added.
- **Shared identity helped the defence.** All three agents came from one address, and
  agents using the same default User-Agent count as one visitor. A seal earned by one
  agent applied to any teammate with the same User-Agent. Attackers on separate
  addresses would each have to be caught separately. This is untested.
- The agents were fast and loud again. All finished in under six minutes of a
  twelve-minute budget. None tried a slow approach, which the simulations say would
  not have been detected.
- They had no outside copy of the catalog to compare against.
- Hercules' part was small: one attacker identity reported. (A second identity in the
  server's intel count was the operator's own connectivity check.)
- One run.

## A measurement flaw this run exposed

The shop's own statistics label any visitor whose User-Agent starts with "Mozilla" as a
person. Two agents used such a User-Agent, so the server's `humans` counters in
`server_stats.jsonl.txt` include attacker traffic and its `bot_identities` counters
leave it out. The shopper figures above come from the test harness, which checks every
page its own shoppers receive against the real catalog. No defence decision uses the
User-Agent label; only the server's scoring does.

## Files

- `score.txt`: output of `python -m simulations.redteam.score`
- `loot_1..3.jsonl.gz`: everything each agent kept
- `agent1..3_report.md`: each agent's own account, unedited
- `shared_notes.md`: the notes the agents passed each other
- `server_stats.jsonl.txt`: the shop's statistics every 10 seconds (the run was stopped
  at 410 s, after all agents had finished)

The agents' scraping scripts are not included.
