# Phase 3: protected communication between the plants

Status: **prototype and simulation.** The new channel is a library
(`darwin/comms.py`) with tests. It is not yet wired into Judith's shop, Hercules or
Venus, which still use the v0.1 channel (`darwin/intel.py`). The plan is to adjust the
design from the results below first.

## The design

- **One way only.** A Hercules only sends. Judith and Venus only receive from Hercules.
  Nothing flows back, so a compromised receiver cannot reach a sender.
- **A key per Hercules.** Each Hercules signs with its own private key. Receivers hold
  only the public keys of the senders they approve, so breaking into a receiver gives an
  attacker nothing to forge with, and a stolen Hercules key forges that one Hercules.
- **Receivers inspect what they are sent**, the way the Spider inspects visitors:

  1. **Corroboration sets the size of the response.** Nothing happens on one Hercules'
     word. Sealing a visitor needs two witnesses: two Hercules, or one Hercules plus
     something the receiver saw for itself. A lockdown (Judith) or arming (Venus) needs
     two different Hercules reporting a sweep. A visitor named by only one Hercules goes
     on a watch list. Hercules sites see different attackers, so differing reports are
     normal; the test is whether a report is corroborated.
  2. **Missing messages are evidence.** Senders number their messages and send a
     heartbeat every 30 seconds. A gap in the numbers or a silence is flagged.
  3. **Judith and Venus pass each other the original signed messages**, one way each,
     unchanged, and never pass on something that was itself passed on. Each checks the
     Hercules signature herself. Comparing the two views exposes a sender that told
     them different things and a receiver whose own channel is being cut.
  4. **Public-key signatures** (Ed25519), which need the `cryptography` package.
  5. **Intel is bounded**, because Hercules reports what attackers choose to show it.
     Seals earned from intel expire after an hour. On an address the owner has marked
     as shared by many people, intel only puts a visitor on a watch list. One sender
     can name at most 200 visitors an hour.

- **Venus gets warnings, not visitor data.** Surge reports and heartbeats go to both
  receivers. Visitor identities and issued fake keys go to Judith only.

## The test

`python -m simulations.models.comms` (50 runs per row; a few minutes)

Five Hercules sites, Judith and Venus. The signatures are real; the network, clock and
attackers are simulated. Each scenario is one way to abuse the channel, run against the
v0.1 channel and the new one. Results are counts, not estimates.

### What the new channel stops

| Abuse | v0.1 channel | Phase 3 channel |
|---|---|---|
| Forged messages, no key | rejected | rejected |
| **One stolen key**, naming 500 innocent shoppers | false lockdown; 500 sealed, permanently | nothing: no lockdown, nobody sealed |
| A real sweep while two of three reporting sites are blocked from Judith | Judith locks down on the one report that got through, and never learns she was being blocked | Judith locks down using the copies Venus passed her, and flags the blocking within 50 seconds |
| Judith cut off from everything | nothing happens, and Judith does not know | no lockdown, but Judith flags "blind" after 105 seconds |
| A compromised Judith lies to Venus (altered, invented and hour-old messages) | not applicable: Venus is not connected | every lie rejected; Venus still warned of the real sweep by her own direct copies |
| A compromised Hercules tells Judith "sweep" and Venus "all quiet" under one message number | not applicable | both catch it at their next exchange; the sender is distrusted and the lockdown it helped cause is withdrawn |
| An attacker behind an address shared with real shoppers shows itself to four Hercules sites | 8 real shoppers sealed permanently | attacker watched, nobody sealed (with the rule off: 8 shoppers sealed for an hour) |
| Recorded messages replayed two hours later | rejected | rejected |
| One message in ten lost, real sweep | lockdown in every run; Venus not connected | lockdown in every run; Venus warned in 98%; the loss itself flagged in every run |

### The quorum setting

The default is **two witnesses to seal a visitor, two Hercules to lock down** ("2 / 2").
It was chosen from this comparison:

| Setting (seal / lockdown) | One stolen key | Two stolen keys | Real sweep of 3 sites | Real sweep of 2 sites | Lone attacker on 1 site |
|---|---|---|---|---|---|
| 1 / 2 | 200 innocents sealed 1 h | false lockdown, 400 sealed 1 h | caught | caught | sealed |
| **2 / 2 (default)** | **nothing** | false lockdown, 200 sealed 1 h | caught | caught | watched |
| 3 / 3 | nothing | nothing | caught | **missed** | watched |

What 2 / 2 costs, measured:

- **A lone attacker who touches one Hercules is watched, not sealed.** He is sealed as
  soon as a second witness appears: a second Hercules (sealed in every run), or
  something Judith sees him do herself (sealed in every run). Judith's own sighting
  alone, with no Hercules report, seals nobody.
- **Fewer swarm identities are sealed from intel alone**, because only those seen by two
  sites qualify: about 20 of 40 in a three-site sweep and 10 of 40 in a two-site sweep,
  against 35 and 30 with a quorum of one. The lockdown itself still fires in every run,
  and in a lockdown Judith's own rules take over.

What 2 / 2 does not fix:

- **Two stolen keys still win.** Used together they cause a false lockdown, arm Venus
  falsely, and get 200 innocent shoppers sealed for an hour. Only 3 / 3 stopped that,
  and 3 / 3 missed every two-site sweep.
- **"Something Judith sees herself" must be something shoppers rarely do.** An attacker
  with one stolen key can name an innocent shopper and wait. If that shopper then does
  whatever counts as Judith's own sighting, the two together seal him for an hour. What
  qualifies as a sighting is not decided yet.

### Other things the test showed

- **The silence alarm is slightly too eager.** With one message in ten lost and nobody
  attacking, a "silent" flag appeared in about one run in five. Waiting five missed
  heartbeats (160 seconds) removed them, at the cost of noticing a real cut a minute
  later. The default is unchanged for now.
- **The shared-address rule only works for addresses the owner has listed.** An
  unlisted shared address behaves like the "rule off" row above.
- **A cut-off Judith knows she is blind but still cannot see the attack.** The flag is
  for people; nothing automatic follows from it yet.

## Not covered by this test

- Wiring into the real servers, and how keys are issued, stored, rotated and revoked.
- Encryption. Messages are signed, not secret.
- An attacker who controls the clock of a receiver.
- Whether several Hercules sites are truly independent. Sites that share a host or an
  operator share their fate, and a quorum of them proves little.
- Fake-key reports are accepted from a single sender. A deployment must make sure a
  fake key can never collide with a genuine one.
- Venus is still a model, so "Venus" here is a second receiver, not a phone. Many Venus
  phones relaying to each other and acting as independent witnesses is phase 4.
