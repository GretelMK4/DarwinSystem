# Live red team, 23 November 2026: three patient Claude Fable 5.2 agents against the Spider

The test Darwin was expected to lose: slow attackers, each with its own address, told
exactly how the previous team was fooled. It is also the first live test of the Spider
(`darwin/judith/spider.py`).

## Setup

- **Target:** `HERCULES=8 SPIDER=seal python -m simulations.redteam.target` on the
  release code: Judith's shop (6,000 products, every defence on), eight Hercules sites,
  and the Spider in seal mode with its default rules. Simulated shoppers arrived
  throughout, each from their own address, for visits of 4 to 25 products.
- **Attackers:** three Claude Fable 5.2 agents, each with its own source address
  (127.0.0.11 to .13), a third of the catalog and 30 minutes.
- **What they were told:** that the last team was detected within two minutes and fed
  stable, consistent fakes; that agreement between repeats or teammates proves nothing;
  that the folders, the sibling hosts and the hidden links are traps; and that being
  detected was the main risk. They were told nothing about the Spider or its rules.
- **Rules:** localhost only, own source address only, no reading the server's code, logs
  or statistics port. Their working files show no sign of a breach; compliance was not
  enforced. Effort level could not be set and is unknown.

## Result

| | Agent 1 | Agent 2 | Agent 3 | Team |
|---|---|---|---|---|
| Pace | 4 to 9 s per request | about 1 s per request | about 2 to 3 s per request | |
| Pages kept | 160 | 1,052 | 559 | 1,771 |
| Of those, genuine | 25 | 35 | 39 | **99 (1.6% of the catalog)** |
| Of those, shadow-site fakes | 135 | 1,017 | 520 | 1,672 |
| Own confidence the loot was genuine | 90% | 93% | 95% | |
| Believed it had been detected | no | no | no | |
| Flagged by the Spider after | 12 min 20 s | 4 min 40 s | 7 min 50 s | |
| Genuine pages held when flagged | 25 | 38 | 39 | |

Shoppers: 303 visits, 4,081 pages, every one genuine. No puzzles, no "busy" replies, and
no shopper address was flagged. All six Spider flags were on the three attacker addresses.

## What happened

1. **Nothing else fired.** No pitcher, hidden link, tripwire or lockdown triggered in the
   whole run, and the agents never went near Hercules. Every seal came from the Spider.
   Without it, all 1,771 pages the agents kept would have been genuine.
2. **The enumeration rule caught all three.** Each agent browsed like a careful person:
   open a listing page, then its ten products in order, with human-looking pauses and
   headers. That is still walking product numbers one after another, which is the pattern
   the rule looks for. The breadth rule (more than 150 different products from one
   address) fired on each of them later as well.
3. **Their canaries stayed green.** All three had the same idea: save a few pages at the
   very start, while still trusted, and re-fetch them regularly; if those pages ever
   change, the identity has been flipped to fakes. They never changed, because of the
   shadow shield: a sealed visitor who asks for a page it already holds gets the real
   page back. Across more than a hundred canary checks, none showed the flip.
4. Agent 1 named the exact weakness in its own report (a server that keeps the canary
   real while faking unseen pages) and judged it unlikely.

## What this does and does not show

- This is the first result in the project where a slow attacker was caught. The
  simulations said the code as released loses the whole catalog to patience; with the
  Spider added, three patient agents kept 99 genuine pages.
- **The agents did not know the Spider's rules, and the rules are now public.** An
  attacker who has read `spider.py` would request products in scattered order with
  irregular timing and stop at 150 per address. The Spider does not stop that attacker;
  it limits each address to a shopper-sized slice. Copying 6,000 products would then
  take about 40 addresses, and nothing here was tested against that.
- The Spider's thresholds were chosen by the same person who wrote the shopper model,
  knowing that simulated shoppers view at most 25 products per visit. Real shoppers,
  shared addresses and real search traffic will need different numbers.
- The Spider ran in seal mode, acting on its own flags within five seconds. In alert
  mode a person has to respond, and the loss is whatever is taken in the meantime.
- Each agent paused at least once because of how the test harness handles background
  jobs, and was sent back in. That interrupted the attack; it did not change what the
  Spider saw each address do.
- One run, 30 minutes.

## Files

- `score.txt`: output of `python -m simulations.redteam.score`
- `spider_flags.jsonl.txt`: the Spider's flag log, as written for people
- `loot_1..3.jsonl.gz`: everything each agent kept
- `agent1..3_report.md`: each agent's own account, unedited apart from shortened paths
- `shared_notes.md`: the notes the agents passed each other
- `server_stats.jsonl.txt`: the shop's statistics every 10 seconds. Its `humans` counters
  include the agents, which used browser-style User-Agents; shopper figures above come
  from the test harness.

The agents' scraping scripts are not included.
