"""Every attacker the nightly lab builds stays as a regression test (2026-11-25 evening)."""
from simulations.nightly import evening


def test_hydra_is_slowed_without_hurting_shoppers_much():
    r = evening.run("hydra", 0, fixed=True)
    assert r["stolen_share"] < 0.7 and r["shopper_fp_rate"] < 0.05
    assert evening.run("shoppers", 0, fixed=True)["shopper_fp_rate"] == 0


def test_hydra_release_baseline_still_steals_everything():
    assert evening.run("hydra", 0, fixed=False)["stolen_share"] == 1.0   # documents the open gap per address


def test_intel_attacks_fail_on_the_branch():
    assert evening.run("forged_witness", 0, True)["shoppers_sealed_1h"] == 0
    assert evening.run("forged_witness", 0, True)["real_bots_known_1h"] == 1
    assert evening.run("cross_replay", 0, True)["replays_accepted_by_judith"] == 0
    assert evening.run("intel_flood", 0, True)["real_bots_known"] == 1
    assert evening.run("echo_double", 0, True)["shoppers_sealed"] == 0
    assert evening.run("pollution", 0, True)["households_sealed_2d"] == 0
