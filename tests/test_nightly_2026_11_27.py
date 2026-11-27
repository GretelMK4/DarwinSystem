"""Regression tests from the 2026-11-27 nightly lab. Each attacker built tonight stays here."""
import random

from darwin.judith import shop


def _public_code_fake(n):
    """What an attacker could compute from the public code before the shadow secret (release behaviour)."""
    r = random.Random("FAKE" + str(n))
    name = f"{r.choice(shop.ADJ)} {r.choice(shop.NOUN)} {r.randint(100, 999)}"
    return name


def test_second_opinion_cannot_recompute_the_shadow_from_public_code():
    hits = sum(_public_code_fake(n) in shop.item_page(n, fake=True) for n in range(1, 501))
    assert hits <= 5                      # chance collisions only (1 in 9,000 per product)


def test_shadow_is_stable_and_keyed_by_the_secret(monkeypatch):
    assert shop.item_page(42, fake=True) == shop.item_page(42, fake=True)
    assert shop.item_page(42, fake=True) != shop.item_page(42)
    a = shop._load_shadow_secret({"DARWIN_SHADOW_SECRET": "a" * 32})
    assert a == b"a" * 32


def test_shadow_secret_persists_across_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr(shop, "results_path", lambda name: str(tmp_path / name))
    first = shop._load_shadow_secret({})
    assert shop._load_shadow_secret({}) == first and len(first) >= 32
    assert (tmp_path / "shadow_secret").stat().st_mode & 0o077 == 0


# ---------------- Spider seals: lifetime and shared addresses (20261125-3, -4, -8) ----------------

from darwin.judith.spider import Policy, Spider   # noqa: E402


def _carrier(s, t=0.0, households=60, uas=60):
    """Shoppers behind one carrier address, each with its own browser version, 3 products each."""
    for h in range(households):
        for k in range(3):
            t += 40
            s.observe("100.64.0.1", f"Mozilla/5.0 build-{h % uas}", 1 + (h * 7 + k * 911) % 2900, t)
    return t


def test_attacker_on_a_carrier_address_is_sealed_alone():
    s = Spider(Policy({"SPIDER_METRONOME_CV": "0"}))
    t = _carrier(s)
    for i in range(160):                                   # one copier behind the same carrier address, alone over BREADTH
        t += 41 + i % 9
        s.observe("100.64.0.1", "python-requests/2.32", 3000 - i, t)
    seals = sorted(x for f in s.inspect(now=t) for x in f.get("seal", []))
    assert seals == ["100.64.0.1|python-requests/2.32"]                 # the crowd itself is flagged, not sealed


def test_ua_rotation_on_one_address_still_seals_the_address():
    s = Spider(Policy({"SPIDER_BREADTH": "50"}))
    for i in range(51):
        s.observe("10.9.9.9", f"browser-{i % 5}", (i * 613) % 6000 + 1, i * (20 + i % 7))
    flag = [f for f in s.inspect(now=2000) if f["rule"] == "breadth"][0]
    assert flag["seal"] == ["10.9.9.9"]


def test_spider_seal_expires_and_can_be_raised_again(monkeypatch):
    monkeypatch.setattr(shop, "SPIDER_MODE", "seal")
    monkeypatch.setattr(shop, "SPIDER_SEALED", {})
    sp = Spider(Policy({"SPIDER_BREADTH": "50", "SPIDER_SEAL_TTL": "3600"}), on_flag=shop.spider_flag)
    monkeypatch.setattr(shop, "SPIDER", sp)
    for i in range(51):
        sp.observe("10.9.9.9", "UA", (i * 613) % 6000 + 1, i * 21.0 + (i % 7))
    assert [f["rule"] for f in sp.inspect(now=1200)] == ["breadth"]
    assert shop.spider_sealed("10.9.9.9", "10.9.9.9|UA", 1300)
    assert not shop.spider_sealed("10.9.9.9", "10.9.9.9|UA", 1200 + 3601)        # 6 h by default, 1 h here
    assert sp.inspect(now=1250) == []                                              # not raised twice ...
    assert [f["rule"] for f in sp.inspect(now=1200 + 3601)] == ["breadth"]         # ... until the seal ran out


def test_crowd_address_without_a_copier_is_not_sealed():
    s = Spider(Policy({"SPIDER_METRONOME_CV": "0"}))
    t = _carrier(s, households=80)
    assert all(not f.get("seal") for f in s.inspect(now=t))


def test_cgnat_households_are_spared_and_the_copier_capped():
    from simulations.nightly import n20261127 as night
    before, after = night.run("cgnat", 0, fixed=False), night.run("cgnat", 0, fixed=True)
    assert before["household_fp_rate"] > 0.5                     # release: the whole carrier sees fakes
    assert after["household_fp_rate"] < 0.1 and after["bot_products_stolen"] <= 160
    assert night.run("cgnat_quiet", 0, fixed=True)["household_fp_rate"] == 0
    assert night.run("second_opinion", 0, fixed=True)["detected_offline"] == 0


def test_ua_rotator_cannot_hide_as_a_crowd():
    from simulations.nightly import n20261127 as night
    assert night.run("rotator400", 0, fixed=False)["bot_products_stolen"] <= 160   # release: sealed at BREADTH
    r = night.run("rotator400", 0, fixed=True)
    assert r["address_sealed"] and r["bot_products_stolen"] <= 620                # bounded by CROWD_BREADTH


def test_seal_does_not_change_pitcher_timing():
    """Researcher scenario 1 (latency tell), on the real shop server on localhost."""
    from simulations.nightly import n20261127 as night
    r = night.run_latency(7, fixed=True, samples=6)
    assert r["agents"] >= 1 and r["seal_visible"] == 0


# ---------------- checkable fake keys (20261125E-11) ----------------

def test_minted_tokens_check_only_under_their_key():
    from darwin import intel
    k1, k2 = intel.new_key().encode(), intel.new_key().encode()
    t = intel.mint_token(k1, random.Random(3))
    assert len(t) == 28 and t.isalnum()
    assert intel.token_ok(k1, t) and not intel.token_ok(k2, t)
    assert not intel.token_ok(k1, t[:-1] + ("A" if t[-1] != "A" else "B"))
    assert not intel.token_ok(k1, "x" * 28) and not intel.token_ok(k1, None)


def test_honeyfarm_mints_checkable_keys_when_given_one():
    from darwin import intel
    from darwin.hercules import honeyfarm
    key = intel.new_key().encode()
    farm = honeyfarm.Hercules(1, diverse=True, seed=2, token_key=key)
    text = farm.dotenv(farm.sites[0])
    tok = text.split("sk_live_", 1)[1].split()[0]
    assert intel.token_ok(key, tok)


def test_compromised_plant_cannot_get_real_customer_keys_sealed():
    from simulations.nightly import n20261127 as night
    assert night.run("token_frame", 0, fixed=False)["real_customer_keys_accepted"] == 500
    r = night.run("token_frame", 0, fixed=True)
    assert r["real_customer_keys_accepted"] == 0 and r["honest_fake_keys_accepted"] == 100


def test_friction_guard_model_shows_no_fakes_but_does_not_stop_theft():
    """Lab 2026-11-27: the fleet guard with friction instead of fakes (harness model only). It removes every
    fake (nothing for a control to compare) but a swarm that pays the proof-of-work copies everything."""
    from simulations.nightly import evening
    evening.EXTRA_ENV["SPIDER_GUARD_ACTION"] = "friction"
    try:
        r = evening.run("vantage", 0, fixed=True)
    finally:
        evening.EXTRA_ENV.pop("SPIDER_GUARD_ACTION")
    assert r["fakes_exposed_by_control"] == 0 and r["shopper_fp_rate"] == 0
    assert r["bot_challenges_solved"] > 0 and r["stolen_share"] == 1.0
