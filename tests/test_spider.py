"""The Spider's rules, with a controlled clock."""
from darwin.judith.spider import Policy, Spider


def policy(**overrides):
    return Policy({"SPIDER_" + k.upper(): str(v) for k, v in overrides.items()})


def rules(flags):
    return sorted(f["rule"] for f in flags)


def test_ordinary_shoppers_raise_nothing():
    s = Spider(policy())
    products = [311, 4502, 311, 87, 2999, 1500, 87, 5210, 77, 3141, 42, 4502]
    gaps = [3.1, 7.4, 4.0, 5.5, 3.3, 7.9, 6.2, 4.4, 3.8, 5.1, 6.6, 4.9]
    t = 0.0
    for visitor in range(30):
        for n, gap in zip(products, gaps):
            t += gap
            s.observe(f"10.0.0.{visitor}", "Mozilla/5.0", n + visitor, t)
    assert s.inspect(now=t) == []


def test_breadth_flags_a_slow_copier_once():
    s = Spider(policy(breadth=50))
    for i in range(51):
        s.observe("10.9.9.9", "Mozilla/5.0", (i * 613) % 6000 + 1, i * (20 + i % 7))    # slow, irregular, scattered
    flags = s.inspect(now=2000)
    assert rules(flags) == ["breadth"] and flags[0]["subject"] == "10.9.9.9" and "51" in flags[0]["evidence"]
    assert s.inspect(now=2001) == []


def test_changing_user_agent_does_not_reset_the_ledger():
    s = Spider(policy(breadth=50))
    for i in range(51):
        s.observe("10.9.9.9", f"browser-{i % 5}", (i * 613) % 6000 + 1, i * (20 + i % 7))
    assert rules(s.inspect(now=2000)) == ["breadth"]


def test_enumeration_and_metronome():
    s = Spider(policy())
    for i in range(40):
        s.observe("10.1.1.1", "x", 1000 + i, i * (11 + i % 5))            # number by number, irregular timing
        s.observe("10.2.2.2", "x", (i * 613) % 6000 + 1, i * 30.0)        # scattered, but clockwork
    flags = s.inspect(now=2000)
    assert {(f["subject"], f["rule"]) for f in flags} == {("10.1.1.1", "enumeration"), ("10.2.2.2", "metronome")}


def test_many_identities_from_one_address():
    s = Spider(policy(max_identities=5))
    for i in range(7):
        s.observe("10.3.3.3", f"agent-{i}", 10 + i * 100, i * 40.0 + i * i)
    assert rules(s.inspect(now=500)) == ["many_identities"]


def test_old_views_are_forgotten():
    s = Spider(policy(breadth=50, window=3600))
    for i in range(51):
        s.observe("10.9.9.9", "x", (i * 613) % 6000 + 1, i * (20 + i % 7))
    assert s.inspect(now=10 ** 6) == []


def test_changed_component_is_flagged(tmp_path):
    f = tmp_path / "component.py"
    f.write_text("approved")
    seen = []
    s = Spider(policy(), flag_log=str(tmp_path / "flags.jsonl"), on_flag=seen.append)
    s.watch_files([str(f)])
    assert s.inspect() == []
    f.write_text("tampered")
    flags = s.inspect()
    assert rules(flags) == ["component_changed"] and seen == flags
    assert "component_changed" in (tmp_path / "flags.jsonl").read_text()
    f.unlink()
    assert s.inspect() == []                                              # already flagged; not raised twice


# ---------------- fleet rule (nightly 2026-11-25 evening) ----------------

def _shoppers(s, t0, t1, rng, popular=50):
    t = t0
    while t < t1:
        t += rng.expovariate(1 / 20)
        s.observe(f"home-{rng.randrange(100000)}", "Mozilla/5.0", 1 + int(rng.paretovariate(1.2)) % popular, t)
    return t


def test_fleet_rule_catches_a_spread_out_swarm_and_guards_only_cold_tail_requests():
    import random
    rng = random.Random(1)
    s = Spider(policy(bucket=600, fleet_warmup=3, fleet_floor=20, period=60))
    t = 0.0
    for k in range(6):                                      # learn a quiet baseline
        t = _shoppers(s, t, t + 600, rng)
        assert s.inspect(now=t) == []
    for i in range(300):                                    # 300 addresses x 1 rare product each
        t += 1.5
        s.observe(f"proxy-{i}", "Mozilla/5.0", 1000 + i, t)
    flags = s.inspect(now=t)
    assert rules(flags) == ["fleet_tail"]
    assert s.guarded("proxy-new", 5000, now=t + 1)          # cold address, never-viewed product
    assert not s.guarded("proxy-new", 2, now=t + 1)         # a popular product is never guarded
    assert not s.guarded("proxy-new", 5000, now=t + s.policy.fleet_guard + 1)


def test_fleet_rule_waits_for_warmup_and_can_be_turned_off():
    s = Spider(policy(bucket=600, fleet_warmup=3, fleet_floor=20))
    for i in range(300):
        s.observe(f"proxy-{i}", "Mozilla/5.0", 1000 + i, float(i))
    assert s.inspect(now=300.0) == []                       # no baseline yet: never trips
    off = Spider(Policy({"SPIDER_FLEET": "off"}))
    off.observe("a", "ua", 1, 0.0)
    assert off.inspect(now=1.0) == [] and not off.guarded("a", 2, now=1.0)


def test_fleet_baseline_cannot_be_taught_quickly():
    s = Spider(policy(bucket=10, fleet_warmup=0, fleet_floor=1000, fleet_growth=1.1, fleet_alpha=1.0))
    base = 0
    for slot in range(1, 6):                                # quiet 10 products per slot, then a jump to 500
        n = 10 if slot < 5 else 500
        for i in range(n):
            s.observe(f"a{slot}-{i}", "ua", slot * 10000 + i, slot * 10 + i / 1000)
        s.inspect(now=slot * 10 + 9.99)
        s.inspect(now=slot * 10 + 10.0)
        base = s.baseline
    assert base <= 10 * 1.1 + 1e-9                          # learned at most +10% from the jump
