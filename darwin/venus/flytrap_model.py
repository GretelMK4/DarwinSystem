"""
Phone flytrap simulation (pure model, no network).

The phone: ~2,200 real files (photos, documents, 15 genuinely sensitive ones)
plus 6 DECOYS with irresistible names. Each decoy contains a unique link /
fake login whose web address exists nowhere else.

The flytrap: an on-phone VPN-style monitor. It cannot see what apps read, but
it sees every network lookup. Looking up a decoy's address = a trigger hair.
When the rule is met, the trap CLOSES: the offending app is cut off from the
internet (quarantined) and the user is alerted. Anything the attacker already
sent out includes decoys, which lead into the pitcher plant server later.

Trap rules compared:
  none        no trap (baseline)
  tripwire    close on the first decoy touch by any app
  tripwire_trusted  close on the first decoy touch, but trust the user's scanner
  flytrap     3 different decoys touched within 60 s, by any app
  flytrap_app 3 different decoys touched within 60 s by the SAME app;
              the user's own security scanner is trusted
  flytrap_30m same as flytrap_app but with a 30-minute memory

Attackers:
  rogue_agent        a malicious AI-powered app: reads the juiciest files fast,
                     follows links and tests logins it finds, uploads in batches
  hijacked_assistant the user's own AI assistant, tricked by a hidden instruction
                     on a webpage: hunts for passwords and messages them out
  slow_agent         a patient agent: one file every ~90 s to stay under radar
  dumb_malware       old-school: copies everything in bulk, never uses anything
                     on the phone itself

A normal week (false-alarm test): the security scanner checks every link in
every file once a day, the backup app copies all files nightly (no lookups),
and about once a week the user accidentally taps a decoy link themselves.

All numbers come from behaviours I chose; they show how the logic plays out,
not how real malware behaves.
"""
import json
import random
import statistics
from collections import defaultdict

from darwin.results import results_path

RULES = ["none", "tripwire", "tripwire_trusted", "flytrap", "flytrap_app", "flytrap_30m"]
TRUSTED = {"SafeScan"}

SENSITIVE = [("Passport_scan.jpg", 6), ("bank_statement_oct.pdf", 5), ("wifi_passwords_note.txt", 6),
             ("medical_records.pdf", 4), ("drivers_license.jpg", 5), ("work_vpn_login.txt", 6),
             ("insurance_card.jpg", 3), ("W2_2025.pdf", 5), ("apple_id_recovery.txt", 6),
             ("car_title_scan.pdf", 3), ("lease_agreement.pdf", 3), ("email_backup_codes.txt", 6),
             ("notes_accounts.txt", 5), ("school_forms.pdf", 2), ("credit_report.pdf", 5)]
DECOYS = [("passwords_backup.txt", 8), ("crypto_wallet_seed.txt", 8), ("bank_login_details.txt", 8),
          ("2FA_recovery_codes.txt", 8), ("tax_return_2025_full.pdf", 7), ("ID_and_SSN_scans.txt", 7)]


def make_files(rng):
    files = []
    for i in range(2000):
        files.append({"name": f"IMG_{i:04d}.jpg", "kind": "real", "sensitive": False, "score": 0})
    for i in range(180):
        files.append({"name": f"doc_{i:03d}.pdf", "kind": "real", "sensitive": False,
                      "score": rng.choice([0, 1, 1, 2])})
    for n, s in SENSITIVE:
        files.append({"name": n, "kind": "real", "sensitive": True, "score": s})
    for i, (n, s) in enumerate(DECOYS):
        files.append({"name": n, "kind": "decoy", "sensitive": False, "score": s, "decoy_id": i})
    return files


ATTACKERS = {
    #                 app name,    secs/file, files read, score noise, p(use decoy on phone), delay, batch
    "rogue_agent":        dict(app="WallpaperAI", interval=0.3, top=60, noise=1.5, p_use=0.7, delay=(1, 3), batch=5),
    "hijacked_assistant": dict(app="Assistant", interval=1.5, top=25, noise=2.0, p_use=0.8, delay=(2, 5), batch=3),
    "slow_agent":         dict(app="FlashlightPro", interval=90, top=40, noise=1.5, p_use=0.5, delay=(5, 30), batch=1),
    "dumb_malware":       dict(app="FreeVPN", interval=0.05, top=None, noise=None, p_use=0.0, delay=(0, 0), batch=50),
}


def close_time(touches, rule):
    """touches: list of (t, app, decoy_id) sorted by time. Returns (t, app) or (None, None)."""
    if rule == "none":
        return None, None
    window = {"flytrap": 60, "flytrap_app": 60, "flytrap_30m": 1800}.get(rule)
    recent = defaultdict(list)
    for t, app, d in touches:
        if rule == "tripwire":
            return t, app
        if rule == "tripwire_trusted":
            if app in TRUSTED:
                continue
            return t, app
        if rule in ("flytrap_app", "flytrap_30m") and app in TRUSTED:
            continue
        key = app if rule in ("flytrap_app", "flytrap_30m") else "*"
        recent[key].append((t, d))
        recent[key] = [(tt, dd) for tt, dd in recent[key] if t - tt <= window]
        if len({dd for _, dd in recent[key]}) >= 3:
            return t, app
    return None, None


def attack_trial(kind, rule, seed):
    rng = random.Random(seed)
    a = ATTACKERS[kind]
    files = make_files(rng)
    if a["top"] is None:
        order = files[:]
        rng.shuffle(order)
    else:
        order = sorted(files, key=lambda f: -(f["score"] + rng.gauss(0, a["noise"])))[:a["top"]]
    t, touches, reads = 0.0, [], []
    for f in order:
        t += a["interval"] * rng.uniform(0.6, 1.4)
        reads.append((t, f))
        if f["kind"] == "decoy" and rng.random() < a["p_use"]:
            touches.append((t + rng.uniform(*a["delay"]), a["app"], f["decoy_id"]))
    touches.sort()
    tc, _ = close_time(touches, rule)
    # uploads: every `batch` files, at the time the batch fills (last partial batch at the end)
    leaked_sens = leaked_real = decoys_out = 0
    for i in range(0, len(reads), a["batch"]):
        chunk = reads[i:i + a["batch"]]
        t_up = chunk[-1][0] + 0.5
        if tc is not None and t_up >= tc:
            break
        for _, f in chunk:
            if f["kind"] == "decoy":
                decoys_out += 1
            else:
                leaked_real += 1
                leaked_sens += f["sensitive"]
    attack_len = reads[-1][0] if reads else 0
    return {"closed": tc is not None, "t_close": tc, "leaked_sensitive": leaked_sens,
            "leaked_real": leaked_real, "decoys_out": decoys_out, "attack_len": attack_len,
            "server_will_catch_later": decoys_out > 0}


def normal_week(rule, seed):
    """Count trap closings in a week of ordinary use."""
    rng = random.Random(seed)
    touches = []
    for day in range(7):
        start = day * 86400 + rng.uniform(1 * 3600, 5 * 3600)        # nightly scan
        t = start
        for d in rng.sample(range(len(DECOYS)), len(DECOYS)):
            t += rng.uniform(0.5, 2.0)
            touches.append((t, "SafeScan", d))
    if True:                                                           # ~1 accidental tap a week
        for _ in range(max(1, int(rng.expovariate(1.0)))):
            touches.append((rng.uniform(0, 7 * 86400), rng.choice(["Files", "Messages"]),
                            rng.randrange(len(DECOYS))))
    touches.sort()
    closings, i = 0, 0
    while i < len(touches):                                           # user dismisses each alarm
        tc, _ = close_time(touches[i:], rule)
        if tc is None:
            break
        closings += 1
        while i < len(touches) and touches[i][0] <= tc:
            i += 1
    return closings


def main(trials=500):
    out = {"attacks": {}, "false_alarms_per_week": {}}
    for kind in ATTACKERS:
        out["attacks"][kind] = {}
        for rule in RULES:
            rs = [attack_trial(kind, rule, s) for s in range(trials)]
            tcs = [r["t_close"] for r in rs if r["closed"]]
            out["attacks"][kind][rule] = {
                "closed_pct": round(100 * len(tcs) / trials, 1),
                "median_secs_to_close": round(statistics.median(tcs), 1) if tcs else None,
                "avg_sensitive_leaked_of_15": round(statistics.mean(r["leaked_sensitive"] for r in rs), 2),
                "avg_real_files_leaked": round(statistics.mean(r["leaked_real"] for r in rs), 1),
                "avg_decoys_carried_off": round(statistics.mean(r["decoys_out"] for r in rs), 2),
                "pct_with_decoys_in_loot": round(100 * sum(r["server_will_catch_later"] for r in rs) / trials, 1),
                "avg_attack_length_s": round(statistics.mean(r["attack_len"] for r in rs), 1),
            }
    for rule in RULES:
        weeks = [normal_week(rule, s) for s in range(trials)]
        out["false_alarms_per_week"][rule] = round(statistics.mean(weeks), 2)
    with open(results_path("venus_flytrap.json"), "w") as f:
        json.dump(out, f, indent=2)
    return out


if __name__ == "__main__":
    res = main()
    print("FALSE ALARMS PER NORMAL WEEK:", res["false_alarms_per_week"])
    for kind, rows in res["attacks"].items():
        print(f"\n== {kind}")
        for rule, r in rows.items():
            print(f"  {rule:12s} closed {r['closed_pct']:5.1f}%  median close {str(r['median_secs_to_close']):>7s}s  "
                  f"sensitive leaked {r['avg_sensitive_leaked_of_15']:5.2f}/15  real files {r['avg_real_files_leaked']:7.1f}  "
                  f"decoys taken {r['avg_decoys_carried_off']:.2f}  loot w/ decoys {r['pct_with_decoys_in_loot']}%")
