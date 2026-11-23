# Responsible-use charter

The Darwin System is defensive. Using it, extending it or contributing to it means
keeping to these rules.

## 1. Defensive only

Darwin makes your own systems confusing, slow and expensive to attack, and it warns
people early. It does nothing else. Do not use this code or its ideas to build attack
tools, to scrape other people's sites, or to hide an attack.

## 2. No hack-back

Darwin never touches an attacker's systems. It does not scan them, exploit them, send
them harmful files, or try to identify the person behind them. Striking back is illegal
for private defenders in most places, and attackers usually work through hijacked
machines that belong to innocent people.

Everything a Darwin trap serves is inert: generated text and random strings. A fake key
does nothing anywhere except on the trap that issued it.

## 3. Owned infrastructure only

Run Darwin only on servers, networks and devices that you own or that you are
authorized in writing to defend. Never point a simulated attacker from this repository
at a system that is not yours. The attacker models here are written to talk to
`127.0.0.1`; keep it that way.

Testing on real critical systems (energy, water, health, transport, industrial control)
needs an authorized red-team exercise run by qualified people. The infrastructure model
in this repository is an abstract model with no real protocols, exploits or commands.

## 4. Fictional brands only

Decoy sites, decoy apps and bait files use invented company names. Do not make a decoy
that imitates a real company, product, bank, government body or person. A convincing
fake of a real brand can mislead real people and harm that brand, whatever the intent.

Bait may use the generic variable names a real config file would contain (for example
`DB_PASSWORD`), with random values. It must never contain a real credential, a real
person's data, or anything copied from a real system.

## 5. Real people come first

A trap that hurts a real visitor has failed, even if it also caught an attacker.

- Every rule must be tested against simulated people as well as attackers. A rule that
  shows fake pages to real shoppers does not ship.
- Verified search crawlers are never trapped.
- Hidden decoys must stay hidden from assistive technology too (for example
  `display:none`, which screen readers skip), so that no person is led into a trap.
- Seals expire. A shared or reused IP address must not be punished forever.

## 6. Visitor data and privacy

The traps record who touched them: IP address, User-Agent header, the paths requested,
and timing. Under laws such as the GDPR and the CCPA this can be personal data, even
when the visitor is very likely a bot.

If you run Darwin on real traffic:

- Say so in your privacy notice: that security logs are kept and why.
- Keep the logs only as long as you need them, and restrict who can read them.
- Collect nothing beyond what the request already carries. No fingerprinting scripts,
  no tracking of people across sites.
- Share intel only about what touched a decoy with no legitimate use. Before sharing
  identities outside your own organization, get legal advice.
- Set `TRAP_LOG=` (empty) to turn the pitcher's request log off.

This charter is not legal advice. Rules on deception, logging and computer misuse differ
between countries; check the ones that apply to you.

## 7. Honest claims

Describe Darwin as what it is: a research prototype tested in simulations. Do not
present simulation results as proof of protection, and do not sell a deployment as a
guarantee. Deception adds warning time and wastes attackers' effort. It does not
replace patching, strong logins, backups or monitoring.
