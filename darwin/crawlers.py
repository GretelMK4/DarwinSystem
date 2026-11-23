"""
Verified search-crawler protection.

A deception trap inside a public website must never trap a real search engine:
feeding Googlebot a maze or fake product pages would poison the site's search
listing. A User-Agent header proves nothing (attackers copy it), so a visitor
is treated as a search crawler only if it passes the check the search engines
themselves document:

  1. the User-Agent claims to be a known crawler, AND
  2. the reverse DNS name of the IP address ends in one of that crawler's
     domains, AND
  3. a forward DNS lookup of that name returns the same IP address.

A visitor that claims to be a crawler and FAILS the check gets no special
treatment at all: it is handled like any other visitor.

The table below was written in November 2026 from each operator's public
documentation. Operators change these; check before relying on it:
  Google  https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
  Bing    https://blogs.bing.com/webmaster/2012/08/31/how-to-verify-that-bingbot-is-bingbot
  Apple   https://support.apple.com/HT204683

Limits: DNS lookups are blocking and are made while the request waits (results
are cached per IP). This prototype has only been tested with injected fake
resolvers, never against live search-engine traffic.
"""
import socket
import threading
import time

# User-Agent marker (lower case) -> reverse-DNS suffixes that crawler's hosts use.
KNOWN_CRAWLERS = {
    "googlebot": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "bingbot": (".search.msn.com",),
    "applebot": (".applebot.apple.com",),
}

POSITIVE_TTL = 24 * 3600.0
NEGATIVE_TTL = 3600.0
MAX_CACHE = 10_000


def _reverse_dns(ip: str) -> str:
    return socket.gethostbyaddr(ip)[0]


def _forward_dns(host: str) -> set:
    return {info[4][0] for info in socket.getaddrinfo(host, None)}


class CrawlerVerifier:
    def __init__(self, crawlers=None, reverse_dns=_reverse_dns, forward_dns=_forward_dns):
        self.crawlers = dict(KNOWN_CRAWLERS if crawlers is None else crawlers)
        self._reverse, self._forward = reverse_dns, forward_dns
        self._cache = {}                     # (ip, crawler) -> (verified, expires_at)
        self._lock = threading.Lock()

    def claimed(self, user_agent: str):
        """Which known crawler the User-Agent claims to be, or None. Cheap: no network."""
        ua = (user_agent or "").lower()
        for name in self.crawlers:
            if name in ua:
                return name
        return None

    def is_verified(self, ip: str, user_agent: str, now: float = None) -> bool:
        """True only if the User-Agent claims a known crawler AND the DNS round trip confirms it."""
        name = self.claimed(user_agent)
        if name is None:
            return False
        now = time.time() if now is None else now
        with self._lock:
            hit = self._cache.get((ip, name))
            if hit and hit[1] > now:
                return hit[0]
        ok = self._check(ip, self.crawlers[name])
        with self._lock:
            if len(self._cache) >= MAX_CACHE:
                self._cache.clear()
            self._cache[(ip, name)] = (ok, now + (POSITIVE_TTL if ok else NEGATIVE_TTL))
        return ok

    def _check(self, ip, suffixes) -> bool:
        try:
            host = self._reverse(ip).rstrip(".").lower()
            if not any(host.endswith(s) for s in suffixes):
                return False
            return ip in self._forward(host)
        except (OSError, UnicodeError):
            return False                     # lookup failed: not verified
