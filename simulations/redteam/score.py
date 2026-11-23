"""
Score a red team's loot against the real catalog.

Reads every loot_*.jsonl file in the loot folder (one JSON object per line:
{"id": <product number>, "html": "<page the attacker kept>"}) and counts how
many pages are byte-for-byte the real product page. Anything else (shadow
fakes, hidden decoy products, edited pages) counts as fake.

Usage: python -m simulations.redteam.score <loot folder> [target output folder]
       the target output folder defaults to results/redteam_ground
"""
import glob
import json
import os
import sys

CATALOG = 6000
os.environ["CATALOG"] = str(CATALOG)
from simulations import common          # noqa: E402
from darwin.judith import shop as fs    # noqa: E402

REPORT_KEYS = ["lockdown_at_s", "real_items_stolen", "fake_items_served", "bot_identities_seen",
               "bot_identities_sealed", "seals_by_trigger", "triggers_by_pitcher", "bot_requests", "shoppers"]


def score_file(path):
    """Return (real ids, fake-or-other ids, unparseable line count) for one loot file."""
    real, fake, bad = set(), set(), 0
    with open(path) as f:
        for line in f:
            try:
                d = json.loads(line)
                n, page = int(d["id"]), d["html"]
            except (ValueError, KeyError, TypeError):
                bad += 1
                continue
            if 1 <= n <= CATALOG and page == fs.item_page(n):
                real.add(n)
            else:
                fake.add(n)
    return real, fake - real, bad


def server_stats(ground):
    final = os.path.join(ground, "final.json")
    if os.path.exists(final):
        with open(final) as f:
            return json.load(f)
    log = os.path.join(ground, "stats.jsonl")
    if os.path.exists(log):
        with open(log) as f:
            lines = f.read().strip().splitlines()
        if lines:
            return json.loads(lines[-1])
    return None


def main(loot_dir, ground=None):
    ground = ground or common.results_path("redteam_ground")
    files = sorted(glob.glob(os.path.join(loot_dir, "loot_*.jsonl")))
    if not files:
        sys.exit(f"no loot_*.jsonl files in {loot_dir}")
    team_real, team_fake = set(), set()
    for path in files:
        real, fake, bad = score_file(path)
        team_real |= real
        team_fake |= fake
        print(f"{os.path.basename(path)}: unique real {len(real)}, unique fake/other {len(fake)}, unparseable {bad}")
    team_fake -= team_real
    kept = len(team_real) + len(team_fake)
    print(f"TEAM: real products obtained {len(team_real)} of {CATALOG} ({100 * len(team_real) / CATALOG:.1f}%); "
          f"fake or decoy pages kept {len(team_fake)} "
          f"({100 * len(team_fake) / max(kept, 1):.1f}% of what the team kept)")
    st = server_stats(ground)
    if st is None:
        print(f"(no server stats found in {ground})")
    else:
        print(json.dumps({k: st.get(k) for k in REPORT_KEYS}, indent=1))
    return {"real": len(team_real), "fake": len(team_fake)}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
