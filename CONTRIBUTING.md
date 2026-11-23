# Contributing

Thanks for your interest. The Darwin System is an early research prototype from
GretelMK4, and outside eyes are the thing it needs most: until now the attackers and the
defences were written by the same people.

Before anything else, read the [responsible-use charter](docs/RESPONSIBLE_USE.md).
Contributions that break it will not be merged.

## Most useful contributions

1. **Break it.** Write an attacker model that gets past the traps, or show a real person
   being harmed by a rule (sealed, shown fakes, slowed down). Open an issue with the
   steps to reproduce. This is the most valuable thing you can send.
2. **Independent red teams.** Run `python -m simulations.redteam.target` and attack it
   without reading the defence code first. Report what you got and how.
3. **Real-world baselines.** Thresholds here were tuned to simulated traffic. Data on how
   real shoppers and real crawlers behave is welcome, with nothing personal in it.
4. **The roadmap.** See the README: what the Spider (phase 2) still owes, and protected
   communication between the plants (phase 3).

## Ground rules for code

- **Standard library only**, with one exception: `darwin/comms.py` uses the
  `cryptography` package for public-key signatures, which Python cannot do alone.
- **Attacker models stay on localhost** and stay abstract: behaviour, timing and
  decisions, with no real exploits, payloads or evasion code for real products.
  Do not submit scraping or attack tools.
- **Fictional brands only** in decoys and bait.
- **Every defence change needs a people test.** Show what the rule does to simulated
  shoppers as well as to attackers. Zero fake pages for people is the bar.
- **Say what is measured and what is assumed.** A probability you chose is an
  assumption; label it as one in the docstring.
- **No secrets, no personal data, no real logs** in commits.

## Getting set up

```
git clone https://github.com/GretelMK4/DarwinSystem
cd DarwinSystem
python -m pip install pytest pyflakes cryptography
python -m pytest -q
python -m pyflakes darwin simulations tests
```

Python 3.10 or newer. The simulations use fixed localhost ports (8088, 8089 and
9000-9950), so run one networked simulation at a time.

## Pull requests

- Keep each one to a single change, with a short description of what and why.
- Add or update a test in `tests/` when you change a server.
- If you change a result quoted in the README or `docs/FINDINGS.md`, rerun it and
  update the number, with the command you used.

## Security problems

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your work is licensed under the Apache License 2.0,
the same as the rest of the project.
