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

Guard's free detection layer is wired into KDNA Forms (via upstream
interception, no KDNA Forms changes) and WooCommerce account forms. Blocked
submissions are logged for now; quarantine storage arrives in Stage 4. Borderline
submissions are flagged but not yet API-scored (Stage 3). Watch has no logic yet.

== Frequently Asked Questions ==

= Does this replace Wordfence or Cloudflare? =

No. Sentinel is not an edge firewall and does not block traffic. It complements
those tools by covering form spam and plugin patch-lag.

== Changelog ==

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
