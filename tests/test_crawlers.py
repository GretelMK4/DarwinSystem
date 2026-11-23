"""Crawler verification: a User-Agent alone never earns trust; the DNS round trip must agree."""
from darwin.crawlers import CrawlerVerifier

GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
REAL_IP, FAKE_IP = "66.249.66.1", "203.0.113.9"


def make(reverse, forward, calls=None):
    def rdns(ip):
        if calls is not None:
            calls.append(ip)
        if ip not in reverse:
            raise OSError("no PTR record")
        return reverse[ip]
    return CrawlerVerifier(reverse_dns=rdns, forward_dns=lambda host: forward.get(host, set()))


def test_real_crawler_verified():
    v = make({REAL_IP: "crawl-66-249-66-1.googlebot.com"}, {"crawl-66-249-66-1.googlebot.com": {REAL_IP}})
    assert v.is_verified(REAL_IP, GOOGLE_UA)


def test_ordinary_visitor_needs_no_lookup():
    calls = []
    v = make({}, {}, calls)
    assert not v.is_verified(REAL_IP, "Mozilla/5.0 (Windows NT 10.0) Firefox/130.0")
    assert calls == []


def test_spoofed_user_agent_rejected():
    assert not make({FAKE_IP: "host.attacker.example"}, {}).is_verified(FAKE_IP, GOOGLE_UA)
    assert not make({}, {}).is_verified(FAKE_IP, GOOGLE_UA)                      # no reverse DNS at all


def test_lookalike_domain_rejected():
    v = make({FAKE_IP: "evilgooglebot.com"}, {"evilgooglebot.com": {FAKE_IP}})
    assert not v.is_verified(FAKE_IP, GOOGLE_UA)
    v = make({FAKE_IP: "crawl.googlebot.com.attacker.example"}, {"crawl.googlebot.com.attacker.example": {FAKE_IP}})
    assert not v.is_verified(FAKE_IP, GOOGLE_UA)


def test_forged_reverse_dns_rejected():
    """The attacker controls their own PTR record, but not Google's forward zone."""
    v = make({FAKE_IP: "crawl-1.googlebot.com"}, {"crawl-1.googlebot.com": {REAL_IP}})
    assert not v.is_verified(FAKE_IP, GOOGLE_UA)


def test_result_is_cached_and_expires():
    calls = []
    v = make({REAL_IP: "crawl-1.googlebot.com"}, {"crawl-1.googlebot.com": {REAL_IP}}, calls)
    assert v.is_verified(REAL_IP, GOOGLE_UA, now=0) and v.is_verified(REAL_IP, GOOGLE_UA, now=10)
    assert len(calls) == 1
    assert v.is_verified(REAL_IP, GOOGLE_UA, now=10 ** 7)
    assert len(calls) == 2
