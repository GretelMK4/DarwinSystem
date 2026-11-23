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
