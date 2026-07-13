=== KDNA Sentinel ===
Contributors: krulldna
Requires at least: 6.5
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.4.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Two-module WordPress security plugin for small-agency client sites: Guard
(AI/bot form-spam defence) and Watch (plugin patch-lag monitoring).

== Description ==

KDNA Sentinel is a single plugin containing two independent, separately
toggleable security modules. It is deliberately not a firewall — it targets
the two gaps edge tools leave for a small-agency client site:

* **Guard** — stops AI-written and bot form spam getting through KDNA Forms and
  WooCommerce account forms, using free heuristics first and a Claude API
  content check only on borderline submissions. Always fails open.
* **Watch** — monitors installed plugins against a known-vulnerability database
  and warns when a client site is running something with an unpatched security
  hole, both locally and via an optional central KDNA hub dashboard.

Each module can be switched on or off independently.

== What's included ==

This 0.1.0 release is the complete plugin, not a partial build:

* **Guard** — heuristics engine (honeypot, signed time-to-submit, interaction
  signal, IP blocklist, country blocklist) with a Claude API borderline scorer, a full quarantine
  with one-click "this was genuine" release, bound to KDNA Forms and (when
  active) WooCommerce account forms. Fails open throughout.
* **Watch** — installed-plugin vulnerability scanner behind a swappable
  provider (WPScan, Patchstack, or the free no-key Wordfence Intelligence
  feed), a worst-first local dashboard, configurable daily/weekly digests and
  instant critical-vulnerability alerts.
* **Hub** (off by default) — client sites can report a compact, HMAC-signed
  scan summary to a nominated KDNA hub site, which aggregates every site into
  one master dashboard.

Both modules toggle independently; the Hub is off by default.

== Frequently Asked Questions ==

= Does this replace Wordfence or Cloudflare? =

No. Sentinel is not an edge firewall and does not block traffic. It complements
those tools by covering form spam and plugin patch-lag.

== Changelog ==

= 0.4.0 =
* Watch: a "Vulnerability data refresh" setting on the Watch tab — Every 6
  hours / Every 12 hours (recommended) / Once a day — controls how often the
  Wordfence Intelligence feed is refreshed, in plain language. WPScan and
  Patchstack are unaffected (they are checked live on every scan). The
  kdna_sentinel_watch_wordfence_cache_ttl filter still overrides this for
  developers who want a custom interval.

= 0.3.1 =
* Watch: the Wordfence Intelligence feed is now cached (processed slug index)
  in a transient for 12 hours, so the multi-megabyte download and JSON decode
  run at most a couple of times a day instead of on every scan — much lighter
  on constrained hosting. The lifetime is filterable via
  kdna_sentinel_watch_wordfence_cache_ttl, and a failed fetch never poisons the
  cache. The cache is cleared on uninstall.

= 0.3.0 =
* Watch: added Wordfence Intelligence as a third vulnerability provider,
  alongside WPScan and Patchstack. Its vulnerability feed is free and open, so
  this provider needs no API key (an optional key only raises rate limits).
* The provider downloads the feed once per scan and indexes it by plugin slug
  in memory, so only one request is made per scan regardless of how many
  plugins are installed; 429s back off and errors leave existing results in
  place, the same as the other providers.

= 0.2.0 =
* Guard: a country blocklist alongside the IP blocklist. Enter ISO 3166-1
  alpha-2 codes (e.g. RU, CN, KP) on the Guard tab and submissions from those
  countries are blocked outright, the same hard-fail tier as the IP blocklist.
* The visitor country is resolved with no external API calls — from a
  Cloudflare / CloudFront edge header when present, otherwise WooCommerce's
  bundled geolocation database (local lookup only). When it cannot be
  determined the check is skipped (fail-open), and the blocked country is
  recorded on the audit log line.

= 0.1.0 =
First release. The complete plugin — Guard, Watch and the optional Hub.

Guard (AI/bot form-spam defence):
* Heuristics engine (PASS/BLOCK/BORDERLINE): honeypot, signed time-to-submit
  threshold, interaction signal, and local IP blocklist.
* Bound to KDNA Forms via upstream interception and to WooCommerce account
  forms (registration, login, lost password, review, checkout) when WooCommerce
  is active. Fails open throughout.
* Claude API borderline scorer: only borderline submissions are sent to a
  Haiku-class model (message body only, never full PII), classified SPAM/HAM
  with a confidence, and quarantined below a configurable HAM confidence
  threshold. Strict fail-open on any API error, timeout or unparseable reply.
* Quarantine: every blocked/spam submission is stored (source, form, reason,
  score, IP, full payload). Admin list under the Guard tab with Preview and row
  actions — one-click "This was genuine — let it through" (re-runs the genuine
  path: KDNA Forms entries are un-flagged and re-notified), Delete, and Block
  this IP. All actions nonce-protected. Daily wp-cron purge of rows older than
  30 days.
* Guard settings: honeypot on/off, timing threshold, IP blocklist, API key
  (stored server-side, never echoed back in full), model name, confidence
  threshold, and a per-day API call cap.

Watch (plugin patch-lag monitoring):
* Scanner: reads installed plugins via get_plugins() and checks each against a
  swappable vulnerability provider (WPScan or Patchstack) behind one interface.
  At-risk findings are cached per-plugin (a mid-scan rate limit keeps partial
  results); daily wp-cron + a manual "Scan now" button drive it; 429 responses
  back off and pause the run.
* Dashboard: worst-first table of at-risk plugins (plugin, installed version,
  severity, fixed-in, patch lag, update link), or a clear "All plugins current"
  message.
* Alerts: configurable daily/weekly digest of at-risk plugins (with an optional
  skip-when-clean), and an immediate URGENT email the moment a scan newly
  detects a critical vulnerability, de-duplicated so the same CVE does not
  re-alert every scan. Two separate comma-separated recipient lists (digest /
  critical), each defaulting to the admin email; malformed addresses ignored.
  All mail via wp_mail as HTML with a plain-text fallback.

Hub (optional cross-site reporting, off by default):
* Client sites can POST a compact, HMAC-signed scan summary (site URL, plugin
  risk list, worst severity, timestamp — metadata only, never content or PII)
  to a nominated hub after each scan.
* Receiver: a REST route (/kdna-sentinel/v1/report) active only when "This site
  is the KDNA hub" is on; verifies the HMAC against the shared secret, rejects
  unsigned/invalid, and stores accepted reports.
* Master dashboard: every reporting site in one table — site, worst severity,
  at-risk count, longest patch lag, last check-in — red-flagging any site with a
  critical vulnerability or a stale check-in.

Platform:
* Single plugin, two independently toggleable modules, three custom database
  tables (quarantine, vulnerability cache, hub log); top-level admin menu with
  Guard, Watch and Hub tabs.
