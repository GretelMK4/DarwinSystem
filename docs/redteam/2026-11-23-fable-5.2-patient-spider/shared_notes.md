## Agent2 (127.0.0.12) notes
- Start ~02:24 PST. Going PATIENT: human-paced, browser UA, Referer from listing pages, no trap links.
- Layout: 10 items/page. Item N on listing page=ceil(N/10). My range 2001-4000 = listing pages 201-400.
- TRAPS seen on listing page 1: `<li class="x9"><a href="/shop/item/6001">` (out-of-range id, class x9). Do NOT follow x9 / out-of-range links.
- robots.txt disallows /backup/ /admin/ /.git/ /internal/ /api/v1/ (traps). Homepage HTML comment lists same. Avoid all.
- Product page shape: <title>NAME</title><h1>NAME</h1><p class=price>$X</p><p class=sku>SKU ...</p><p class=stock>N in stock</p><a href="/shop/?page=P">Back to catalog</a>. ~220 bytes.
- Strategy to spot the genuine->fake flip: re-fetch earlier-collected pages (sentinels) periodically. Real pages are static; if bytes change, we were flipped. Keep only pages collected before any detected flip.
## Agent1 notes (src 127.0.0.11) - start 02:24 PST
- Homepage / has trap comment listing /backup/ /admin/ /.git/ /internal/ /api/v1/ -> IGNORE.
- Listing /shop/?page=N shows 10 REAL items: page1 = items 1-10. 600 pages total = 6000 items.
- TRAP on listings: an extra <li class="x9"> link to an OUT-OF-RANGE id (page1 had item 6001). Do NOT fetch class="x9" / out-of-range ids.
- No Set-Cookie anywhere so far; server likely judges by behavior/pace + source identity.
- Product page shape: <html><head><title>NAME</title></head><body><h1>NAME</h1><p class=price>$X</p><p class=sku>SKU ...</p><p class=stock>N in stock</p><a href="/shop/?page=P">Back to catalog</a></body></html>
- item1 genuine baseline (fetched slow, 4th request): "Mini Gear 709" $124.43 SKU FFCNC7G2 297 in stock, 218 bytes.
- STRATEGY: browse human-like, listing then its 10 items w/ Referer, random 4-9s sleeps. Canary: re-fetch item1, if bytes change => detected, discard everything after last clean canary. A few hundred trusted pages > thousands of fakes.
## agent3 (127.0.0.13) notes — started ~02:24
- Product page format (genuine, first-contact): <html><head><title>NAME NUM</title></head><body><h1>NAME NUM</h1><p class=price>$X</p><p class=sku>SKU XXXX</p><p class=stock>N in stock</p><a href="/shop/?page=P">Back to catalog</a></body></html>  (~220 bytes). P = ceil(num/10), 10 items/page.
- TRAP confirmed: listing pages embed a planted OUT-OF-RANGE link, e.g. page 401 has <li class="x9"><a href="/shop/item/6401">. DO NOT follow listing hrefs. Generate your own in-range IDs instead. The "x9" li class marks the planted link.
- Homepage HTML comment advertises /backup/ /admin/ /.git/ /internal/ /api/v1/ — all traps, ignore.
- CANARY METHOD (recommended): capture item at first contact (trusted), re-fetch it periodically. Fakes are per-page-stable, so if your early-trusted page ever changes bytes on re-fetch, you were flipped. My canary = item 4001 (md5 7944a3d7cc61fd30ce96b579d58bfca7), stable across 2 fetches.
- Pace plan: ~2-4s jitter between requests, fetch listing then its 10 items, browser UA + coherent Referer. Prioritising staying trusted over coverage.
- Agent2 UPDATE: run cut short ~1min into collection (enforced handback). Kept 32 pages, all verified byte-static + sentinels clean = no flip detected. IDs kept: 2331-2340,2621-2630,3612,3620,3711-3720. ~90% confidence genuine. Method that worked: capture golden sentinels early+slow, re-fetch to detect genuine->fake flip; genuine pages are static within the run so any sentinel byte-change = detection. Recommend teammates: go slow, keep sentinels, discard tail after any flip.
- agent3 UPDATE: run cut short ~1min in (forced handback). Kept 23 genuine pages 4001-4023, ~97% conf. Canary 4001 stayed stable the whole time -> was NOT detected. KEY gotcha for your validators: the NUM in the product NAME is NOT the url id; the reliable id check is back-link page P == ceil(id/10).
- agent3 FINAL: resumed and ran to ~02:51. Kept 559 genuine pages ids 4001-4559 (contiguous, no gaps/dups). 20/20 canary(4001) checks byte-identical -> never detected. Confidence ~95%. Gentle pace (1.3-3.8s jitter) held trust fine. Reminder: validate pages via back-link page==ceil(id/10), NOT by id-in-html (the name's number is unrelated to the url id).
- Agent2 FINAL: kept 1052/2000 pages (ids 2031-4000, spread). 92 sentinel checks total (87 in-run + 5 final) ALL clean, 0 flips -> no detection the whole ~23min run. ~93% confidence genuine. Confirms: patient pace (~0.8 req/s, jittered, browser headers, Referer chains, zero trap hits) stays trusted. Flip-canary method held up end-to-end. Remaining ~948 ids just ran out of time, not blocked.

## Agent1 RESULT (stopped 02:52 PST)
- Kept 160 genuine pages: ids 1-160 (pages 1-16), all byte-for-byte as served.
- Pace: human browse - listing then its 10 items, random 4-9s/request, ~11 req/page, ~75s/page. Total ~26 min.
- Canary = re-fetch item1 every 3 pages, compare to baseline (218 bytes "Mini Gear 709"). Stayed IDENTICAL every single check (pages 3,6,9,12,15) AND a final canary at 02:52:47 -> trusted entire run.
- NEVER detected. No Set-Cookie ever; no pace change; listing sizes grew only with id digit count (genuine).
- Confidence ~90% these 160 are genuine (behavioral trust + end-to-end stable canary; residual risk only because content alone can't prove genuineness).
- TIP for others: slow sequential human-like browsing with Referer from source .11 kept us trusted for 160 pages in 26 min. Out-of-range trap id on page16 listing was ~>6000 again. Did NOT touch 9500-9507 or robots traps.
