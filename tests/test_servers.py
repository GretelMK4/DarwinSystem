"""
Judith's servers, started in-process on free localhost ports.

Covers the launch-critical behaviour: people get the real site, bots that take
bait are sealed into the shadow site, verified search crawlers are never
trapped, a copied crawler User-Agent earns nothing, request paths are never
echoed as HTML, and only signed intel is accepted.
"""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from darwin import crawlers, intel
from darwin.judith import pitcher, shop

GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
KEY = b"test-key-" * 4


def fake_verifier(verified: bool):
    """A CrawlerVerifier whose DNS says localhost is (or is not) a Google crawler."""
    def rdns(ip):
        if not verified:
            raise OSError("no PTR record")
        return "crawl-test.googlebot.com"
    return crawlers.CrawlerVerifier(reverse_dns=rdns, forward_dns=lambda host: {"127.0.0.1"})


def serve(server_class, handler):
    srv = server_class(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def get(url, ua, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": ua, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def get_from(address, url, ua):
    """GET from a chosen loopback source address (any 127.x.y.z address works on Linux)."""
    import http.client
    from urllib.parse import urlsplit
    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10, source_address=(address, 0))
    try:
        conn.request("GET", u.path, headers={"User-Agent": ua, "Connection": "close"})
        r = conn.getresponse()
        return r.status, r.read().decode()
    finally:
        conn.close()


def post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


@pytest.fixture(scope="module")
def shop_url():
    shop.HONEYLINKS = True
    shop.DRIP = 0.0
    srv, url = serve(shop.ShopServer, shop.Handler)
    yield url
    srv.shutdown()


@pytest.fixture(scope="module")
def admin_url():
    shop.INTEL_ON, shop.INTEL_VERIFIER = True, intel.Verifier(KEY)
    srv, url = serve(ThreadingHTTPServer, shop.Admin)
    yield url
    srv.shutdown()


@pytest.fixture(scope="module")
def pitcher_url(tmp_path_factory):
    pitcher.DRIP = 0.0
    pitcher.LOG = str(tmp_path_factory.mktemp("log") / "trap_log.jsonl")
    srv, url = serve(ThreadingHTTPServer, pitcher.TrapHandler)
    yield url
    srv.shutdown()


# ---------------- the shop ----------------

def test_shopper_gets_the_real_site(shop_url):
    ua = "Mozilla/5.0 (shopper-real)"
    assert get(f"{shop_url}/", ua)[0] == 200
    for n in (1, 42, shop.CATALOG):
        assert get(f"{shop_url}/shop/item/{n}", ua) == (200, shop.item_page(n))
    assert get(f"{shop_url}/shop/item/{shop.CATALOG + shop.PAGES + 1}", ua)[0] == 404


def test_hidden_link_seals_into_a_consistent_shadow(shop_url):
    honey = f"/shop/item/{shop.CATALOG + 1}"
    assert honey in get(f"{shop_url}/shop/?page=1", "bot-a")[1]
    pages = {}
    for ua in ("bot-a", "bot-b"):
        assert get(shop_url + honey, ua)[0] == 200                       # looks like any product page
        pages[ua] = get(f"{shop_url}/shop/item/777", ua)[1]
    assert pages["bot-a"] != shop.item_page(777)                          # fake ...
    assert pages["bot-a"] == pages["bot-b"]                               # ... and the same fake for every bot
    assert get(f"{shop_url}/shop/item/777", "Mozilla/5.0 (shopper-2)")[1] == shop.item_page(777)


def test_pitcher_file_seals_prey_but_not_scouts(shop_url):
    uas = [f"bot-digger-{i}" for i in range(shop.SCOUT_EVERY + 1)]         # at least one scout, several prey
    for ua in uas:
        get(f"{shop_url}/backup/a/b/secrets_1.json", ua)
    with shop.LOCK:
        clients = [shop.CLIENTS[f"127.0.0.1|{ua}"] for ua in uas]
    roles = {c["role"] for c in clients}
    assert roles == {"scout", "prey"}
    assert all((c["sealed_at"] is not None) == (c["role"] == "prey") for c in clients)


def test_verified_crawler_is_never_trapped(shop_url, monkeypatch):
    monkeypatch.setattr(shop, "CRAWLERS", fake_verifier(True))
    honey = f"/shop/item/{shop.CATALOG + 1}"
    assert "<!--" not in get(f"{shop_url}/", GOOGLE_UA)[1]                 # no bait comment
    assert honey not in get(f"{shop_url}/shop/?page=1", GOOGLE_UA)[1]      # no hidden link
    assert get(shop_url + honey, GOOGLE_UA)[0] == 404
    for trap in ("/backup/", "/.git/config", "/.env", "/api/v1/accounts"):
        assert get(shop_url + trap, GOOGLE_UA)[0] == 404
    for n in range(1, 120):                                                # crawl far past every rate limit
        assert get(f"{shop_url}/shop/item/{n}", GOOGLE_UA) == (200, shop.item_page(n))
    assert f"127.0.0.1|{GOOGLE_UA}" not in shop.CLIENTS
    assert shop.STATE["lockdown_at"] is None


def test_copied_crawler_user_agent_earns_nothing(shop_url, monkeypatch):
    monkeypatch.setattr(shop, "CRAWLERS", fake_verifier(False))
    ua = GOOGLE_UA + " spoof"
    get(f"{shop_url}/shop/item/{shop.CATALOG + 2}", ua)                    # follows a hidden link
    assert get(f"{shop_url}/shop/item/5", ua)[1] != shop.item_page(5)      # sealed like any other bot


# ---------------- signed intel ----------------

def test_only_signed_intel_is_accepted(shop_url, admin_url):
    forged = {"identities": ["Mozilla/5.0 (innocent)"], "tokens": [], "surge": True}
    assert post(f"{admin_url}/intel", forged) == 403                        # no signature
    assert post(f"{admin_url}/intel", intel.sign(forged, b"wrong-key-" * 4)) == 403
    tampered = intel.sign({"identities": [], "tokens": [], "surge": False}, KEY)
    tampered["payload"] = forged
    assert post(f"{admin_url}/intel", tampered) == 403
    assert "Mozilla/5.0 (innocent)" not in shop.INTEL_IDS
    assert not any(p == "hercules_surge" for _, p in shop.TRIGGERS)

    good = intel.sign({"identities": ["127.0.0.1|bot-seen-on-hercules", "127.0.0.77|Common Browser UA"], "tokens": ["k" * 28], "surge": False}, KEY)
    assert post(f"{admin_url}/intel", good) == 200
    assert post(f"{admin_url}/intel", good) == 403                          # replay
    assert "127.0.0.1|bot-seen-on-hercules" in shop.INTEL_IDS
    assert get(f"{shop_url}/shop/item/9", "bot-seen-on-hercules")[1] != shop.item_page(9)
    assert post(f"{admin_url}/elsewhere", good) == 404
    # an identity is address + User-Agent: an attacker who shows a popular browser's User-Agent to
    # Hercules must not get every real shopper with that browser sealed
    assert get(f"{shop_url}/shop/item/9", "Common Browser UA")[1] == shop.item_page(9)
    assert get_from("127.0.0.77", f"{shop_url}/shop/item/9", "Common Browser UA")[1] != shop.item_page(9)


# ---------------- the pitcher ----------------

def test_pitcher_seals_past_the_point_of_no_return(pitcher_url):
    ua = "bot-pitcher"
    assert "Acme Widgets" in get(f"{pitcher_url}/", ua)[1]
    assert get(f"{pitcher_url}/missing", ua)[0] == 404
    deep = "/backup/" + "/".join("d" * (pitcher.DIGEST_DEPTH - 1)) + "/tokens_1.txt"
    assert get(pitcher_url + deep, ua)[0] == 200
    assert get(f"{pitcher_url}/missing", ua)[0] == 200                      # sealed: no 404s, ever
    assert 'href="/docs/"' in get(f"{pitcher_url}/", ua)[1]                 # even "/" is the trap now
    assert get(f"{pitcher_url}/missing", "Mozilla/5.0 (person)")[0] == 404  # other visitors unaffected


def test_fake_api_accepts_only_planted_keys(pitcher_url):
    assert get(f"{pitcher_url}/api/v1/accounts", "bot-api", {"Authorization": "Bearer made-up"})[0] == 401
    key = json.loads(get(f"{pitcher_url}/backup/x/secrets_3.json", "bot-api")[1])["api_key"]
    st, body = get(f"{pitcher_url}/api/v1/accounts", "bot-api", {"Authorization": f"Bearer {key}"})
    assert st == 200 and json.loads(body)["has_more"] is True


def test_request_path_is_never_echoed_as_html(pitcher_url):
    body = get(pitcher_url + '/backup/"><script>alert(1)</script>/', "bot-x")[1]
    assert "<script>" not in body and "&lt;script&gt;" in body


def test_pitcher_ignores_verified_crawlers(pitcher_url, monkeypatch):
    monkeypatch.setattr(pitcher, "CRAWLERS", fake_verifier(True))
    assert get(f"{pitcher_url}/backup/", GOOGLE_UA)[0] == 404
    assert get(f"{pitcher_url}/.env", GOOGLE_UA)[0] == 404
    home = get(f"{pitcher_url}/", GOOGLE_UA)
    assert home[0] == 200 and "<!--" not in home[1]
    assert f"127.0.0.1|{GOOGLE_UA}" not in pitcher.CLIENTS


# ---------------- the Spider ----------------

def test_spider_seals_a_slow_copier_and_leaves_shoppers_alone(shop_url, monkeypatch):
    from darwin.judith import spider as spider_mod
    # this test sends requests at machine speed, so the clockwork-timing rule is switched off here;
    # tests/test_spider.py covers it with a controlled clock
    watcher = spider_mod.Spider(spider_mod.Policy({"SPIDER_METRONOME_CV": "0"}), on_flag=shop.spider_flag)
    monkeypatch.setattr(shop, "SPIDER", watcher)
    monkeypatch.setattr(shop, "SPIDER_MODE", "seal")
    monkeypatch.setitem(shop.STATE, "lockdown_at", None)                  # earlier tests may have locked the shop down
    monkeypatch.setattr(shop, "TRIGGERS", [])
    copier, shopper = "127.0.0.31", "127.0.0.32"
    limit = watcher.policy.breadth
    for n in range(1, 60):                                                # an ordinary visit
        get_from(shopper, f"{shop_url}/shop/item/{n * 97 % 2900 + 1}", "Mozilla/5.0 (shopper)")
    for n in range(1, limit + 2):                                         # far too slow to trip a rate rule in real life
        assert get_from(copier, f"{shop_url}/shop/item/{n * 37 % 2900 + 1}", "Mozilla/5.0 (patient)")[0] == 200
    flags = watcher.inspect()
    assert [(f["subject"], f["rule"]) for f in flags] == [(copier, "breadth")]
    assert shop.SPIDER_FLAGS[-1]["real_products_held_when_flagged"] == limit + 1
    assert get_from(copier, f"{shop_url}/shop/item/2444", "Mozilla/5.0 (patient)")[1] != shop.item_page(2444)
    assert get_from(copier, f"{shop_url}/shop/item/2445", "a brand new User-Agent")[1] != shop.item_page(2445)
    assert get_from(shopper, f"{shop_url}/shop/item/2444", "Mozilla/5.0 (shopper)")[1] == shop.item_page(2444)
    assert watcher.inspect() == []                                        # each flag is raised once


# ---------------- server fingerprint ----------------

def test_servers_do_not_announce_python(shop_url, pitcher_url):
    for url in (shop_url, pitcher_url):
        with urllib.request.urlopen(urllib.request.Request(url + "/", headers={"User-Agent": "Mozilla/5.0 (fp)"})) as r:
            assert r.headers["Server"] == "nginx/1.24.0"                    # no trailing space, no "Python/3.x"
            assert r.version == 11                                           # HTTP/1.1
        req = urllib.request.Request(url + "/", method="DELETE", headers={"User-Agent": "Mozilla/5.0 (fp)"})
        try:
            urllib.request.urlopen(req)
            raise AssertionError("expected an error status")
        except urllib.error.HTTPError as e:
            assert "Python" not in e.read().decode() and "Python" not in str(e.headers)


# ---------------- entry challenge (keep last: it puts the shop into lockdown) ----------------

def test_proof_of_work_functions():
    answer = shop.solve_challenge(f"{shop.CHALLENGE_PREFIX}tok123:12")
    token, counter = answer.split(":")
    assert token == "tok123" and shop.challenge_solved(token, counter, 12)
    assert not shop.challenge_solved(token, str(int(counter) + 1), 20)
    assert not shop.challenge_answered({shop.CHALLENGE_HEADER: "tok123:not-a-number"}, "tok123")
    assert not shop.challenge_answered({shop.CHALLENGE_HEADER: answer}, "another-token")


def test_browser_page_solves_the_same_puzzle(tmp_path, monkeypatch):
    """Run the challenge page's own JavaScript under Node and check its answer with the server's verifier."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    monkeypatch.setattr(shop, "CHALLENGE_BITS", 10)
    _, _, page = shop.challenge_response("browsertoken", wants_html=True)
    script = page.split("<script>")[1].split("</script>")[0]
    runner = tmp_path / "run.js"
    runner.write_text("globalThis.document = { set cookie(v) { console.log(v); } };\n"
                      "globalThis.location = { reload() {} };\n" + script)
    out = subprocess.run([node, str(runner)], capture_output=True, text=True, timeout=60).stdout.strip()
    cookie = out.split(";")[0]
    assert cookie.startswith(shop.CHALLENGE_COOKIE + "=")
    assert shop.challenge_answered({"Cookie": cookie}, "browsertoken")


def test_newcomer_must_solve_the_puzzle_during_lockdown(shop_url, monkeypatch):
    import time
    monkeypatch.setattr(shop, "TRIPWIRES", True)
    monkeypatch.setattr(shop, "CHALLENGE_BITS", 10)
    monkeypatch.setitem(shop.STATE, "lockdown_at", time.time())
    ua = "Mozilla/5.0 (arrived-mid-attack)"
    st, body = get(f"{shop_url}/shop/item/11", ua)
    assert st == 403 and body.startswith(shop.CHALLENGE_PREFIX)
    token = body[len(shop.CHALLENGE_PREFIX):].split(":")[0]
    assert get(f"{shop_url}/shop/item/11", ua, {shop.CHALLENGE_HEADER: f"{token}:0"})[0] == 403   # wrong answer
    st, page = get(f"{shop_url}/shop/item/11", ua, {"Accept": "text/html"})
    assert st == 403 and token in page and "<script>" in page                # browsers get the solver page
    answer = shop.solve_challenge(body)
    assert get(f"{shop_url}/shop/item/11", ua, {shop.CHALLENGE_HEADER: answer}) == (200, shop.item_page(11))
    time.sleep(1.1)                                                           # probation pace rule: 2 pages within 1 s seals
    assert get(f"{shop_url}/shop/item/12", ua) == (200, shop.item_page(12))  # solved once, not asked again


def test_fleet_guard_serves_the_shadow_to_a_guarded_request(shop_url):
    class Guarded:                                           # a Spider whose fleet guard covers product 7
        def __init__(self):
            self.noted = []

        def observe(self, *a, **k):
            pass

        def guarded(self, address, product, now=None):
            return product == 7

        def note_shadow(self, product, now=None):
            self.noted.append(product)
    old, shop.SPIDER = shop.SPIDER, Guarded()
    try:
        ua = "Mozilla/5.0 (fleet-guard)"
        assert get(f"{shop_url}/shop/item/7", ua)[1] == shop.item_page(7, fake=True)
        assert get(f"{shop_url}/shop/item/8", ua)[1] == shop.item_page(8)
        assert shop.SPIDER.noted == [7]
    finally:
        shop.SPIDER = old
