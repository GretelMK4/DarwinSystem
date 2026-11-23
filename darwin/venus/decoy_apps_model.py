"""
Hidden decoy apps + kill switch: phone simulation (pure model, no network).

The phone
  - shared storage: ~2,200 real files, 15 of them sensitive
  - 30 real apps, 6 of them high-value (bank, wallet, email, passwords,
    health, messages)            -> 21 sensitive things in total
  - 5 HIDDEN DECOY APPS with fictional brands (Vaultline Wallet, Northgate
    Bank, KeyNest Passwords, Ledgerly Crypto, MediVault Health). Not on the
    home screen. "Alive": they refresh fake data and fake update history.
  - 3 planted LEAKS in Downloads (a fake wallet export, a fake recovery file,
    a fake session token) belonging to the decoy apps, each with a unique link.

Trigger hairs (the trap watches for)
  leak used     a leaked link/token is looked up or tried (seen by the VPN;
                it knows which app did it)
  decoy opened  a hidden decoy app is launched. The user never sees it, so
                it's never the user, except by rare accident via Settings.
                Culprit known if it's an accessibility/screen-control app.
  decoy read    a decoy's private data files are read directly (only deep
                spyware can do this); the decoy watches its own files.
                Culprit unknown.
  big upload    (two-stage only) a NEW app that has never uploaded much
                suddenly sends >200 MB within 5 minutes

Responses compared
  none         no trap
  file_trip    earlier design: first leak used -> cut off that app
  kill3        your design: 3 different decoys triggered within 30 min ->
               whole phone's internet cut, user alerted
  two_stage    first attributable hair -> pause that app instantly;
               3 different hairs (incl. big upload) within 30 min -> kill switch

Attackers
  rogue_app         malicious AI app with storage access: reads juicy files,
                    uses any logins/links it finds
  targeted_trojan   banking malware abusing accessibility; only goes after a
                    built-in list of REAL bank/wallet apps
  ai_screen_agent   a hijacked AI assistant that can control the screen; opens
                    the most valuable-looking apps, including hidden ones it
                    finds in Settings; checks whether apps look "used"
  root_spyware      deep spyware: reads every app's data directly
  bulk_copier       copies all of shared storage, never uses anything

All behaviours are simple models I chose; they show how the logic plays out.
"""
import json
import random
import statistics
from collections import defaultdict

from darwin.results import results_path

RESPONSES = ["none", "file_trip", "kill3", "two_stage"]
WINDOW = 1800
VOL_MB, VOL_WINDOW = 200, 300
TRUSTED = {"SafeScan", "Backup"}

SENSITIVE_FILES = 15
REAL_APPS = ([("FirstCoast Bank", 8, True), ("Wallet", 7, True), ("Email", 7, True),
              ("Passwords", 8, True), ("Health", 6, True), ("Messages", 6, True)] +
             [(f"app_{i}", random.Random(i).choice([0, 1, 2, 3]), False) for i in range(24)])
DECOY_APPS = ["Vaultline Wallet", "Northgate Bank", "KeyNest Passwords", "Ledgerly Crypto", "MediVault Health"]
LEAKS = [("vaultline_wallet_export.json", 0), ("keynest_recovery_codes.txt", 2), ("northgate_session_token.txt", 1)]


def shared_files(rng):
    fs = [{"kind": "real", "sensitive": False, "score": 0, "mb": 3.0} for _ in range(2000)]
    fs += [{"kind": "real", "sensitive": False, "score": rng.choice([0, 1, 1, 2]), "mb": 0.5} for _ in range(180)]
    fs += [{"kind": "real", "sensitive": True, "score": rng.choice([3, 4, 5, 5, 6, 6]), "mb": 0.5}
           for _ in range(SENSITIVE_FILES)]
    fs += [{"kind": "leak", "sensitive": False, "score": 8, "mb": 0.1, "decoy": d} for _, d in LEAKS]
    return fs


class Trial:
    def __init__(self, rng):
        self.rng = rng
        self.hairs = []        # (t, hair_id, culprit or None)
        self.uploads = []      # (t, app, mb, sensitive_count)

    def hair(self, t, hid, culprit, kind="app"):
        self.hairs.append((t, hid, culprit, kind))

    def upload(self, t, app, mb, sens):
        self.uploads.append((t, app, mb, sens))


# ---------------- attackers ----------------

def rogue_app(tr):
    rng, app, t = tr.rng, "WallpaperAI", 0.0
    order = sorted(shared_files(rng), key=lambda f: -(f["score"] + rng.gauss(0, 1.5)))[:60]
    batch = []
    for f in order:
        t += 0.3 * rng.uniform(0.6, 1.4)
        batch.append(f)
        if f["kind"] == "leak" and rng.random() < 0.7:
            tr.hair(t + rng.uniform(1, 3), f"decoy{f['decoy']}", app, "leak")
        if len(batch) == 5:
            tr.upload(t + 0.5, app, sum(x["mb"] for x in batch), sum(x["sensitive"] for x in batch))
            batch = []
    if batch:
        tr.upload(t + 0.5, app, sum(x["mb"] for x in batch), sum(x["sensitive"] for x in batch))


def targeted_trojan(tr):
    rng, app, t = tr.rng, "PDFReaderPlus", 0.0
    targets = [a for a in REAL_APPS if a[0] in ("FirstCoast Bank", "Wallet", "Email", "Passwords")]
    for name, val, hv in targets:                      # waits for the user to open them, then overlays
        t += rng.uniform(600, 7200)
        tr.upload(t + 2, app, 0.2, 1)


def ai_screen_agent(tr, alive=True):
    rng, app, t = tr.rng, "Assistant", 0.0
    if rng.random() < 0.5:                             # peeks in Downloads first
        order = sorted(shared_files(rng), key=lambda f: -(f["score"] + rng.gauss(0, 2)))[:10]
        sens = 0
        for f in order:
            t += 1.5 * rng.uniform(0.6, 1.4)
            sens += f["sensitive"]
            if f["kind"] == "leak" and rng.random() < 0.6:
                tr.hair(t + rng.uniform(2, 5), f"decoy{f['decoy']}", app, "leak")
        tr.upload(t + 1, app, 1.0, sens)
    apps = [(n, v, hv, False) for n, v, hv in REAL_APPS] + [(n, 8, False, True) for n in DECOY_APPS]
    ranked = sorted(apps, key=lambda a: -(a[1] + rng.gauss(0, 1.5)))[:12]
    p_spot = 0.1 if alive else 0.6                     # does a decoy look unused / fake?
    suspicious = False
    for name, val, hv, decoy in ranked:
        if decoy and suspicious and rng.random() < 0.7:
            continue                                   # learned to skip apps that look fake
        t += 10 * rng.uniform(0.6, 1.4)
        if decoy:
            i = DECOY_APPS.index(name)
            tr.hair(t, f"decoy{i}", app if rng.random() < 0.8 else None)
            if rng.random() < p_spot:
                suspicious = True
                if rng.random() < 0.3:
                    return                             # "this phone is booby-trapped", leaves
        else:
            tr.upload(t + 1, app, 0.5, int(hv))


def root_spyware(tr):
    rng, app, t = tr.rng, "system_daemon", 0.0
    apps = [(n, v, hv, False) for n, v, hv in REAL_APPS] + [(n, 8, False, True) for n in DECOY_APPS]
    for name, val, hv, decoy in sorted(apps, key=lambda a: -(a[1] + rng.gauss(0, 1.0))):
        t += 0.5 * rng.uniform(0.6, 1.4)
        if decoy:
            if rng.random() < 0.7:                     # decoy notices its files being read
                tr.hair(t, f"decoy{DECOY_APPS.index(name)}", None)
        else:
            tr.upload(t + 0.3, app, 2.0, int(hv))
    for i in range(0, SENSITIVE_FILES, 5):
        t += 0.5
        tr.upload(t, app, 2.5, 5)


def bulk_copier(tr):
    rng, app, t = tr.rng, "FreeVPN", 0.0
    fs = shared_files(rng)
    rng.shuffle(fs)
    for i in range(0, len(fs), 50):
        chunk = fs[i:i + 50]
        t += 0.05 * len(chunk)
        tr.upload(t, app, sum(f["mb"] for f in chunk), sum(f["sensitive"] for f in chunk))


ATTACKERS = {"rogue_app": rogue_app, "targeted_trojan": targeted_trojan,
             "ai_screen_agent": ai_screen_agent, "root_spyware": root_spyware, "bulk_copier": bulk_copier}


# ---------------- defence logic ----------------

def volume_hairs(uploads, known_heavy=()):
    hairs, recent = [], defaultdict(list)
    for t, app, mb, _ in sorted(uploads):
        if app in TRUSTED or app in known_heavy:
            continue
        recent[app].append((t, mb))
        recent[app] = [(tt, m) for tt, m in recent[app] if t - tt <= VOL_WINDOW]
        if sum(m for _, m in recent[app]) > VOL_MB:
            hairs.append((t, f"vol:{app}", app, "volume"))
            recent[app] = []
    return hairs


def respond(response, hairs, uploads, known_heavy=()):
    """Returns (kill_time, {app: pause_time})."""
    if response == "none":
        return None, {}
    if response == "file_trip":
        for t, hid, culprit, kind in sorted(hairs):
            if kind == "leak" and culprit and culprit not in TRUSTED:   # decoy files only
                return None, {culprit: t}
        return None, {}
    allh = list(hairs)
    if response == "two_stage":
        allh += volume_hairs(uploads, known_heavy)
    allh.sort()
    pauses, seen = {}, []
    for t, hid, culprit, kind in allh:
        if culprit in TRUSTED:
            continue
        if response == "two_stage" and culprit and culprit not in pauses:
            pauses[culprit] = t
        seen.append((t, hid))
        seen = [(tt, h) for tt, h in seen if t - tt <= WINDOW]
        if len({h for _, h in seen}) >= 3:
            return t, pauses
    return None, pauses


def attack_trial(kind, response, seed, alive=True):
    rng = random.Random(seed)
    tr = Trial(rng)
    if kind == "ai_screen_agent":
        ai_screen_agent(tr, alive)
    else:
        ATTACKERS[kind](tr)
    kill, pauses = respond(response, tr.hairs, tr.uploads)
    leaked = 0
    for t, app, mb, sens in tr.uploads:
        if kill is not None and t >= kill:
            continue
        if app in pauses and t >= pauses[app]:
            continue
        leaked += sens
    times = ([kill] if kill is not None else []) + list(pauses.values())
    first = min(times) if times else None
    return {"leaked": leaked, "kill": kill, "paused": bool(pauses), "stopped_at": first,
            "hairs": len({h for _, h, _, _ in tr.hairs})}


def normal_week(response, seed):
    rng = random.Random(seed)
    hairs, uploads = [], []
    for day in range(7):
        uploads.append((day * 86400 + 3 * 3600, "Backup", 900.0, 0))
    for _ in range(rng.choice([0, 1, 1, 2])):                       # user posts a big video
        uploads.append((rng.uniform(0, 7 * 86400), "SocialApp", rng.uniform(300, 800), 0))
    for _ in range(int(rng.random() < 0.3)):                        # accidental tap on a leak file
        hairs.append((rng.uniform(0, 7 * 86400), f"decoy{rng.randrange(3)}", rng.choice(["Files", "Messages"]), "leak"))
    if rng.random() < 0.02:                                          # finds a hidden app in Settings
        hairs.append((rng.uniform(0, 7 * 86400), f"decoy{rng.randrange(5)}", "Settings", "app"))
    kill, pauses = respond(response, hairs, uploads, known_heavy={"SocialApp"})
    return int(kill is not None), len(pauses)


def main(trials=500):
    res = {"attacks": {}, "normal_week": {}}
    rows = list(ATTACKERS) + ["ai_screen_agent (decoys NOT alive)"]
    for kind in rows:
        res["attacks"][kind] = {}
        for r in RESPONSES:
            real_kind = kind.split(" ")[0]
            alive = "NOT alive" not in kind
            rs = [attack_trial(real_kind, r, s, alive) for s in range(trials)]
            stops = [x["stopped_at"] for x in rs if x["stopped_at"] is not None]
            res["attacks"][kind][r] = {
                "avg_sensitive_leaked_of_21": round(statistics.mean(x["leaked"] for x in rs), 2),
                "kill_switch_fired_pct": round(100 * sum(x["kill"] is not None for x in rs) / trials, 1),
                "stopped_pct": round(100 * len(stops) / trials, 1),
                "median_secs_to_first_response": round(statistics.median(stops), 1) if stops else None,
            }
    for r in RESPONSES:
        wk = [normal_week(r, s) for s in range(trials * 4)]
        res["normal_week"][r] = {"false_kill_switch_per_week": round(statistics.mean(k for k, _ in wk), 3),
                                 "false_app_pauses_per_week": round(statistics.mean(p for _, p in wk), 3)}
    with open(results_path("venus_decoy_apps.json"), "w") as f:
        json.dump(res, f, indent=2)
    return res


if __name__ == "__main__":
    res = main()
    print("NORMAL WEEK:", json.dumps(res["normal_week"]))
    for kind, rows in res["attacks"].items():
        print(f"\n== {kind}")
        for r, v in rows.items():
            print(f"  {r:10s} leaked {v['avg_sensitive_leaked_of_21']:5.2f}/21  kill fired {v['kill_switch_fired_pct']:5.1f}%  "
                  f"stopped {v['stopped_pct']:5.1f}%  first response {v['median_secs_to_first_response']}s")
