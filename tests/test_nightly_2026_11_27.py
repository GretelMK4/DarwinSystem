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


CROWD = {"SPIDER_CROWD_ALERT": "on"}       # opt-in since analyst A2/A5 (2026-11-27)


def test_attacker_on_a_carrier_address_is_sealed_alone():
    s = Spider(Policy({"SPIDER_METRONOME_CV": "0", **CROWD}))
    t = _carrier(s)
    for i in range(160):                                   # one copier behind the same carrier address, alone over BREADTH
        t += 41 + i % 9
        s.observe("100.64.0.1", "python-requests/2.32", 1 + (i * 613) % 2900, t)
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
    s = Spider(Policy({"SPIDER_METRONOME_CV": "0", **CROWD}))
    t = _carrier(s, households=80)
    assert all(not f.get("seal") for f in s.inspect(now=t))


def test_cgnat_households_are_spared_and_the_copier_capped(monkeypatch):
    from simulations.nightly import n20261127 as night
    before = night.run("cgnat", 0, fixed=False)
    assert before["household_fp_rate"] > 0.5                     # release: the whole carrier sees fakes
    monkeypatch.setattr(night, "EXTRA_ENV", dict(CROWD))           # crowd mode, opt-in
    after = night.run("cgnat", 0, fixed=True)
    assert after["household_fp_rate"] < 0.1 and after["bot_products_stolen"] <= 160
    assert night.run("cgnat_quiet", 0, fixed=True)["household_fp_rate"] == 0
    assert night.run("second_opinion", 0, fixed=True)["detected_offline"] == 0


def test_metronome_seals_even_a_crowd():
    s = Spider(Policy({"SPIDER_BREADTH": "100000", **CROWD}))
    for i in range(60):
        s.observe("10.7.7.7", f"build-{i % 30}", 1 + (i * 397) % 2900, i * 10.0)    # clockwork, 30 browsers
    seals = [x for f in s.inspect(now=600) if f["rule"] == "metronome" for x in f["seal"]]
    assert seals == ["10.7.7.7"]


def test_ua_rotator_cannot_hide_as_a_crowd():
    """Analyst A2: by default the branch must be no worse than release against a UA rotator."""
    from simulations.nightly import n20261127 as night
    assert night.run("rotator400", 0, fixed=False)["bot_products_stolen"] <= 160   # release: sealed at BREADTH
    r = night.run("rotator400", 0, fixed=True)
    assert r["address_sealed"] and r["bot_products_stolen"] <= 160


def test_seal_does_not_change_pitcher_timing():
    """Researcher scenario 1 (latency tell), on the real shop server on localhost."""
    from simulations.nightly import n20261127 as night
    # A wall-clock measurement on a shared CI box: a busy CPU can stretch one sample and read as a tell. A real
    # tell (the old drip tripled at the seal) shows on every try, so up to 3 tries with fresh visitors (new seed)
    # must give one clean run; and the old drip must still be caught, so the retry cannot hide a regression.
    runs = []
    for seed in (7, 8, 9):
        runs.append(night.run_latency(seed, fixed=True, samples=6))
        assert runs[-1]["agents"] >= 1
        if runs[-1]["seal_visible"] == 0:
            break
    assert runs[-1]["seal_visible"] == 0, [r["ratios"] for r in runs]
    old = night.run_latency(17, fixed=False, samples=6)
    assert old["agents"] >= 1 and old["seal_visible"] >= 1, old["ratios"]


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


# ---------------- the real shop: Spider seals expire, fakes stay consistent, no 404 tell ----------------

def test_spider_seal_expires_in_the_real_shop_and_fakes_stay_consistent(monkeypatch):
    """Analyst A1 and A7: the client record used to stay sealed forever; after expiry the same visitor must
    not see the real page of a product it was shown fake."""
    import http.client
    import threading
    import time
    monkeypatch.setattr(shop, "SPIDER_MODE", "seal")
    monkeypatch.setattr(shop, "SPIDER_SEALED", {})
    monkeypatch.setattr(shop, "FAKE_SEEN", {})
    monkeypatch.setitem(shop.STATE, "lockdown_at", None)
    monkeypatch.setattr(shop, "TRIGGERS", [])
    sp = Spider(Policy({"SPIDER_SEAL_TTL": "1"}))
    monkeypatch.setattr(shop, "SPIDER", sp)
    srv = shop.ShopServer(("127.0.0.1", 0), shop.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def get(path, ua="Mozilla/5.0 (household-77)"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", path, headers={"User-Agent": ua})
        r = conn.getresponse()
        body = r.read().decode()
        conn.close()
        return r.status, body
    try:
        shop.SPIDER_SEALED["127.0.0.1"] = time.time() + 60.0
        assert get("/shop/item/1501")[1] != shop.item_page(1501)          # sealed: fake
        shop.SPIDER_SEALED["127.0.0.1"] = time.time() - 1.0                # seal runs out (no sleep: not timing-bound)
        assert get("/shop/item/1502")[1] == shop.item_page(1502)          # seal ran out: real again
        assert get("/shop/item/1501")[1] != shop.item_page(1501)          # ... but 1501 stays as it was seen
        assert get("/shop/item/1501", "another-browser")[1] != shop.item_page(1501)   # by any browser (B4)
        assert get("/backup/db/users_2024.sql", "Mozilla/5.0 (household-77)")[0] == 200
        shop.SPIDER_SEALED["127.0.0.1"] = time.time() + 60.0                # B5: spider seal, then a pitcher
        get("/shop/item/1600", "Mozilla/5.0 (household-88)")                # ... seal starts (spider)
        get("/backup/db/users_2024.sql", "Mozilla/5.0 (household-88)")      # ... then real bait evidence
        shop.SPIDER_SEALED["127.0.0.1"] = time.time() - 1.0                # ... the spider seal runs out
        get("/shop/item/1601", "Mozilla/5.0 (household-88)")                # ... and the next visit keeps the pitcher seal
        assert shop.CLIENTS["127.0.0.1|Mozilla/5.0 (household-88)"]["sealed_at"] is not None
        shop.SPIDER_SEALED["127.0.0.1"] = time.time() + 5.0
        assert get("/nope/xyz")[0] == 404                                  # sealed: same 404 as anyone
    finally:
        srv.shutdown()
        srv.server_close()


def test_short_shadow_secret_is_refused():
    import pytest
    with pytest.raises(SystemExit):
        shop._load_shadow_secret({"DARWIN_SHADOW_SECRET": "1"})


def test_crowd_mode_only_where_the_address_is_known_to_be_shared():
    """Analyst A5: crowd status from evidence about the address (CGNAT space by default), not UA count."""
    from simulations.nightly import n20261127 as night
    assert night.run("cgnat_quiet", 1, fixed=True)["household_fp_rate"] == 0          # 100.64.0.0/10
    assert night.run("rotator25", 1, fixed=True)["bot_products_stolen"] <= 160         # public address
    assert night.run("rotator_cgnat", 1, fixed=True)["bot_products_stolen"] <= 620     # known residual
    sp = Spider(Policy({}))
    assert sp.crowd_address("100.64.7.7") and not sp.crowd_address("203.0.113.5")
    assert not sp.crowd_address("not-an-ip")


def test_many_identities_never_seals_on_its_own():
    """Review B1: 25 browsers viewing one product each from a public address is a people-only signal."""
    s = Spider(Policy({}))
    for i in range(25):
        s.observe("203.0.113.7", f"browser-{i}", 1 + i * 97, i * 60.0)
    flags = s.inspect(now=2000)
    assert [f["rule"] for f in flags] == ["many_identities"] and flags[0]["seal"] == []


def test_ipv4_mapped_carrier_address_is_a_crowd():
    sp = Spider(Policy({}))
    assert sp.crowd_address("::ffff:100.64.0.1") and not sp.crowd_address("::ffff:203.0.113.5")


def test_cgnat_on_a_public_carrier_address_is_still_protected_from_many_identities():
    from simulations.nightly import n20261127 as night
    assert night.run("cgnat_public_quiet", 0, fixed=True)["household_fp_rate"] == 0


def test_honeylink_numbers_are_not_computable_from_the_code():
    """Nov 25 finding 20261125-11: hidden-link products used to be CATALOG + page."""
    ids = [shop.honey_item(p) for p in range(1, shop.PAGES + 1)]
    assert len(set(ids)) == shop.PAGES and all(n > shop.CATALOG for n in ids)
    assert sum(n == shop.CATALOG + p for p, n in enumerate(ids, 1)) <= 1
    assert shop.honey_id(f"/shop/item/{ids[0]}") == ids[0] if shop.HONEYLINKS else True
