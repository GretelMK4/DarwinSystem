"""Phase 3 channel: per-sender keys, corroboration, missing-message detection, relays, bounded intel."""
import pytest

pytest.importorskip("cryptography")

from darwin import comms  # noqa: E402

SHARED = "10.50.0.1"


def setup(n=4, streams=comms.STREAMS, **policy):
    senders = [comms.Sender(f"hercules-{i + 1}") for i in range(n)]
    approved = {s.id: s.public_key for s in senders}
    r = comms.Receiver("judith", approved, streams, comms.Policy(**policy), lambda a: a == SHARED)
    return senders, r, approved


def kinds(r):
    return [f["flag"] for f in r.flags]


def test_only_approved_keys_are_heard():
    (h1, *_), r, _ = setup()
    assert r.receive(h1.surge(10), 10) == "accepted"
    impostor = comms.Sender("hercules-1")                      # right name, wrong key
    assert r.receive(impostor.surge(10), 10) == "rejected: bad signature"
    assert r.receive(comms.Sender("hercules-9").surge(10), 10) == "rejected: sender not approved"
    tampered = dict(h1.surge(11), payload={"targets": ["bank"]})
    assert r.receive(tampered, 11) == "rejected: bad signature"
    assert r.receive(h1.surge(12), 12 + 121) == "rejected: stale"
    assert r.receive({"nonsense": True}, 12) == "rejected: malformed"
    assert r.receive(None, 12) == "rejected: malformed"


def test_a_receiver_cannot_forge_what_it_can_verify():
    """Receivers hold public keys only: nothing in a Receiver can sign."""
    _, r, approved = setup()
    assert all(len(pk) == 64 for pk in approved.values())      # 32-byte public keys
    assert not any(hasattr(k, "sign") for k in r._keys.values())


def test_nothing_happens_on_one_site_alone():
    (h1, h2, *_), r, _ = setup()
    r.receive(h1.surge(10), 10)
    r.receive(h1.surge(11), 11)                                # the same site repeating itself adds nothing
    r.receive(h1.intel(12, ["203.0.113.5|bot"]), 12)
    assert not r.in_lockdown(13)
    assert not r.is_sealed("203.0.113.5|bot", 13) and "203.0.113.5|bot" in r.watch
    r.receive(h2.surge(20), 20)
    r.receive(h2.intel(21, ["203.0.113.5|bot"]), 21)
    assert r.in_lockdown(22) and r.is_sealed("203.0.113.5|bot", 22)
    assert [a["action"] for a in r.actions].count("lockdown") == 1


def test_the_receivers_own_sighting_counts_as_a_witness_but_not_alone():
    (h1, *_), r, _ = setup()
    r.local_evidence("203.0.113.7|quiet", 5)
    assert not r.is_sealed("203.0.113.7|quiet", 6)             # her own mild suspicion is not enough
    r.receive(h1.intel(10, ["203.0.113.7|quiet", "203.0.113.8|other"]), 10)
    assert r.is_sealed("203.0.113.7|quiet", 11)                # one Hercules + her own eyes
    assert not r.is_sealed("203.0.113.8|other", 11)
    r.local_evidence(f"{SHARED}|Chrome", 12)
    r.receive(h1.intel(13, [f"{SHARED}|Chrome"]), 13)
    assert not r.is_sealed(f"{SHARED}|Chrome", 14)             # the shared-address rule still holds


def test_a_quorum_of_one_can_be_chosen():
    (h1, *_), r, _ = setup(seal_quorum=1)
    r.receive(h1.intel(12, ["203.0.113.5|bot"]), 12)
    assert r.is_sealed("203.0.113.5|bot", 13)


def test_intel_seals_expire():
    (h1, h2, *_), r, _ = setup(seal_ttl=600)
    r.receive(h1.intel(10, ["203.0.113.5|bot"]), 10)
    assert not r.is_sealed("203.0.113.5|bot", 11) and "203.0.113.5|bot" in r.watch
    r.receive(h2.intel(20, ["203.0.113.5|bot"]), 20)
    assert r.is_sealed("203.0.113.5|bot", 21)
    assert not r.is_sealed("203.0.113.5|bot", 20 + 601)


def test_shared_address_is_watched_never_sealed_by_intel():
    senders, r, _ = setup()
    for i, h in enumerate(senders):                            # even when every site agrees
        r.receive(h.intel(10 + i, [f"{SHARED}|Chrome"]), 10 + i)
    assert not r.is_sealed(f"{SHARED}|Chrome", 20) and f"{SHARED}|Chrome" in r.watch


def test_one_sender_can_only_name_so_many_visitors():
    (h1, *_), r, _ = setup(sender_identity_cap=50, seal_quorum=1)
    r.receive(h1.intel(10, [f"198.51.100.{i}|ua" for i in range(200)]), 10)
    assert sum(r.is_sealed(i, 11) for i in list(r.sealed)) == 50
    assert "over_cap" in kinds(r)


def test_gaps_and_silence_are_flagged():
    (h1, h2, *_), r, _ = setup(n=2)
    r.receive(h1.heartbeat(0), 0)
    r.receive(h2.heartbeat(0), 0)
    h1.surge(30)                                               # sent, never delivered
    r.receive(h1.heartbeat(60), 60)
    r.tick(60)
    assert kinds(r) == []                                      # inside the grace period
    r.tick(120)
    assert "gap" in kinds(r) and "silent" in kinds(r)          # h1 #2 lost; h2 silent for 120 s
    assert "blind" not in kinds(r)
    r.tick(300)
    assert "blind" in kinds(r)                                 # now every sender is silent


def test_heartbeat_reveals_missing_intel():
    (h1, *_), r, _ = setup()
    h1.intel(5, ["203.0.113.5|bot"])                           # lost on the way
    r.receive(h1.heartbeat(30), 30)
    r.tick(100)
    assert any(f["flag"] == "gap" and "intel #1" in f["subject"] for f in r.flags)


def test_relay_carries_originals_and_is_never_relayed_again():
    senders, judith, approved = setup()
    venus = comms.Receiver("venus", approved, ("warning",), comms.Policy())
    h1, h2 = senders[0], senders[1]
    for env in (h1.surge(10), h2.surge(11), h1.intel(12, ["203.0.113.5|bot"])):
        judith.receive(env, 12)
    out = judith.relay_out()
    assert [e["kind"] for e in out] == ["surge", "surge"]      # warnings only: no visitor data goes to Venus
    for env in out:
        assert venus.receive(env, 13, relayed_by="judith") == "accepted"
    assert venus.in_lockdown(14)                               # two Hercules signatures, checked by Venus herself
    assert venus.relay_out() == []                             # relayed messages are not passed on again
    assert venus.receive(h1.intel(15, ["x|y"]), 15) == "rejected: wrong stream"
    venus.tick(13 + 46)
    assert "missing_direct" in kinds(venus)                    # Venus got them only through Judith


def test_a_lying_relay_gets_nowhere():
    senders, _, approved = setup()
    venus = comms.Receiver("venus", approved, ("warning",), comms.Policy())
    genuine = senders[0].heartbeat(10)
    assert venus.receive(dict(genuine, kind="surge", payload={"targets": []}), 10, relayed_by="judith") \
        == "rejected: bad signature"
    assert venus.receive(comms.Sender("hercules-2").surge(10), 10, relayed_by="judith") == "rejected: bad signature"
    assert not venus.in_lockdown(11) and venus.actions == []


def test_two_stories_under_one_number_distrusts_the_sender_and_withdraws_its_effects():
    (h1, h2, *_), r, _ = setup(seal_quorum=1)
    r.receive(h1.surge(10), 10)
    lie = h2._message("surge", {"targets": []}, 10, seq=1)
    other = h2._message("heartbeat", {"intel_seq": 0}, 10, seq=1)
    r.receive(lie, 10)
    r.receive(h2.intel(11, ["198.51.100.9|innocent"]), 11)
    assert r.in_lockdown(12) and r.is_sealed("198.51.100.9|innocent", 12)
    assert r.receive(other, 13, relayed_by="venus") == "duplicate"
    assert "equivocation" in kinds(r)
    assert not r.in_lockdown(14) and not r.is_sealed("198.51.100.9|innocent", 14)
    r.receive(h2.surge(20), 20)                                # a distrusted sender no longer counts
    assert not r.in_lockdown(21)


def test_exact_duplicates_are_harmless():
    (h1, h2, *_), r, _ = setup()
    env = h1.surge(10)
    assert r.receive(env, 10) == "accepted"
    assert r.receive(env, 11) == "duplicate" and r.receive(env, 12, relayed_by="venus") == "duplicate"
    assert not r.in_lockdown(13) and r.flags == []


def test_unknown_policy_setting_is_refused():
    with pytest.raises(TypeError):
        comms.Policy(seal_qorum=2)
