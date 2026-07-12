=== KDNA Sentinel ===
Contributors: krulldna
Requires at least: 6.5
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.1.0
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

== Build status ==

This is an in-progress build delivered in stages.

* Stage 0 — Repo archaeology & interception strategy: complete.
* Stage 1 — Plugin skeleton, settings, module toggles, custom tables: complete.
* Stage 2 — Guard heuristics engine + form bindings: complete.
* Stage 3 — Guard Claude API borderline scorer: complete.
* Stage 4 — Guard quarantine + one-click release: complete.
* Stage 5 — Watch scanner + local dashboard: complete.
* Stage 6 — Watch email digest + instant critical alert: complete.

Guard (Stages 0–4) is feature-complete. Watch reads installed plugins and
checks them against a swappable vulnerability provider (WPScan or Patchstack),
caches at-risk findings, shows a worst-first dashboard, and now emails a
configurable daily/weekly digest plus an immediate URGENT alert the moment a
scan newly detects a critical vulnerability — each to its own recipient list.
Hub reporting (Stage 7) is still to come.

== Frequently Asked Questions ==

= Does this replace Wordfence or Cloudflare? =

No. Sentinel is not an edge firewall and does not block traffic. It complements
those tools by covering form spam and plugin patch-lag.

== Changelog ==

= 0.6.0 =
* Watch alerts: configurable daily/weekly digest of at-risk plugins (with an
  optional skip-when-clean), and an immediate URGENT email the moment a scan
  newly detects a critical vulnerability, de-duplicated so the same CVE does not
  re-alert every scan.
* Two separate comma-separated recipient lists (digest / critical), each
  defaulting to the WordPress admin email; malformed addresses are ignored.
* All mail via wp_mail as HTML with a plain-text fallback.

= 0.5.0 =
* Watch scanner: reads installed plugins via get_plugins() and checks each
  against a swappable vulnerability provider (WPScan or Patchstack) behind one
  interface. At-risk findings are cached (per-plugin, so a mid-scan rate limit
  keeps partial results); daily wp-cron + a manual "Scan now" button drive it;
  429 responses back off and pause the run.
* Watch dashboard: worst-first table of at-risk plugins (plugin, installed
  version, severity, fixed-in, patch lag, update link), or a clear
  "All plugins current" message.
* Schema v2: adds fixed_at to the vuln cache to compute patch lag (auto-upgraded
  on existing installs).

= 0.4.0 =
* Guard quarantine: every blocked/spam submission is stored (source, form,
  reason, score, IP, full payload). Admin list under the Guard tab with Preview
  and row actions — one-click "This was genuine — let it through" (re-runs the
  genuine path: KDNA Forms entries are un-flagged and re-notified), Delete, and
  Block this IP. All actions nonce-protected.
* Daily wp-cron purge of quarantine rows older than 30 days.

= 0.3.0 =
* Guard Claude API borderline scorer: only borderline submissions are sent to a
  Haiku-class model (message body only, never full PII), classified SPAM/HAM
  with a confidence, and quarantined below a configurable HAM confidence
  threshold. Strict fail-open on any API error, timeout or unparseable reply.
* Guard settings: API key (stored server-side, never echoed back in full),
  model name, confidence threshold, and a per-day API call cap.

= 0.2.0 =
* Guard heuristics engine (PASS/BLOCK/BORDERLINE): honeypot, signed time-to-
  submit threshold, interaction signal, and local IP blocklist.
* Guard bound to KDNA Forms via upstream interception and to WooCommerce
  account forms (registration, login, lost password, review, checkout) when
  WooCommerce is active. Fail-open throughout.
* Guard settings: honeypot on/off, timing threshold, IP blocklist.

= 0.1.0 =
* Initial skeleton: top-level admin menu with Guard, Watch and Hub tabs, master
  enable/disable toggles for Guard and Watch, and the three custom database
  tables (quarantine, vuln cache, hub log).
