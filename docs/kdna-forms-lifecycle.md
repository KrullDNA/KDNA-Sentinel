# KDNA Forms — Submission Lifecycle & Guard Interception Strategy

**Stage 0 deliverable.** Documents how KDNA Forms receives and validates a
submission, and decides *how* the Guard module will intercept it.

> **Reference note:** KDNA Forms ships in this repo only as a read-only
> reference copy (`reference/kdna-forms-1.2.0.zip`). It was extracted to a
> scratch directory for analysis and **was not modified**. The real plugin
> lives on client sites; this copy cannot update it. Nothing in
> `reference/` was touched (verified via `git status`).

---

## 0. TL;DR — the recommendation

**PATH B (upstream interception) is viable and is the chosen path. No patch
to KDNA Forms is required.**

Guard binds to the plugin's own, purpose-built spam extension filter:

```php
// Fires for EVERY submission method (standard POST, AJAX, REST API),
// after validation succeeds and after the entry is built, but BEFORE any
// notification email is sent or post is created.
add_filter( 'kdnaform_entry_is_spam', 'KDNA_Sentinel_Guard::evaluate', 20, 3 );
// callback signature: ( bool $is_spam, array $form, array $entry )
```

Returning `true` from this filter natively causes KDNA Forms to:

- mark the entry `spam`,
- **skip** `send_form_submission_notifications()` (no email to the site owner),
- **skip** `create_post()`,

i.e. the spam submission is halted before it reaches the client — with **zero
changes to KDNA Forms**. Guard additionally copies the payload into its own
quarantine table and can label itself via `KDNACommon::set_spam_filter()`.

Path A (patching KDNA Forms) is therefore **not** used, and
`docs/kdna-forms-patch.md` is intentionally **not** created.

---

## 1. What KDNA Forms actually is

KDNA Forms 1.2.0 is a **rebranded Gravity Forms** codebase (class prefix
`KDNA*` e.g. `KDNAForms`, `KDNAFormDisplay`, `KDNACommon`, `KDNAAPI`,
`KDNAFormsModel`; hook prefix `kdnaform_`; text domain `kdnaforms`; legacy
`gform_*` / `rg_*` request keys retained for JS compatibility). This matters
because the submission architecture is Gravity Forms' well-known pipeline, and
its documented spam-filter extension point (`kdnaform_entry_is_spam`, GF's
`gform_entry_is_spam`) is exactly what Guard needs.

- Main file: `kdna-forms.php` (class `KDNAForms`).
- Submission engine: `form_display.php` (class `KDNAFormDisplay`).
- Model / DB: `forms_model.php` (`KDNAFormsModel`).
- Shared helpers + spam eval: `common.php` (`KDNACommon`).
- Public API: `includes/api.php` (`KDNAAPI`).

---

## 2. The entry point(s)

There is **no single dedicated AJAX action or `admin_post` handler** for form
submissions. Instead every front-end submission is dispatched from the `wp`
action and funnelled into one method, `KDNAFormDisplay::process_form()`.

### 2a. Standard (non-AJAX) submission
`kdna-forms.php:188-189`
```php
add_action( 'wp',         array( 'KDNAForms', 'maybe_process_form' ), 9 );
add_action( 'admin_init', array( 'KDNAForms', 'maybe_process_form' ), 9 );
```
`KDNAForms::maybe_process_form()` (`kdna-forms.php:878`):
- returns early if the submission method is AJAX (that path is handled
  separately, below);
- on `$_POST['gform_submit']`, validates the form id via
  `KDNAFormDisplay::is_submit_form_id_valid()` and calls
  `KDNAFormDisplay::process_form( $form_id, SUBMISSION_INITIATED_BY_WEBFORM )`.

### 2b. AJAX submission
`kdna-forms.php:614`
```php
add_action( 'wp', array( 'KDNAForms', 'ajax_parse_request' ), 10 );
```
`KDNAForms::ajax_parse_request()` (`kdna-forms.php:2328`) loads
`form_display.php` and dispatches the AJAX POST into the **same**
`KDNAFormDisplay::process_form()`. (The submit page is the same URL; the
request is a normal POST carrying `gform_ajax`.)

### 2c. REST API submission
Route registered by `class-controller-form-submissions.php`
(`POST /wp-json/gf/v2/forms/<id>/submissions`). Its handler calls
`KDNAAPI::submit_form()` (`includes/api.php:1685`), which at
`includes/api.php:1706` calls **the same**
`KDNAFormDisplay::process_form( $form_id, $initiated_by )`.

### The single chokepoint
```
maybe_process_form()  (standard POST)  ┐
ajax_parse_request()  (AJAX)           ├─▶ KDNAFormDisplay::process_form()
KDNAAPI::submit_form() (REST API)       ┘        │
                                                 ▼
                                       KDNAFormDisplay::handle_submission()
                                                 │
                                                 ▼
                                       KDNACommon::is_spam_entry()
                                                 │
                                     apply_filters( 'kdnaform_entry_is_spam', … )
```
Because all three methods converge on `process_form()` → `handle_submission()`
→ `is_spam_entry()`, a filter on `kdnaform_entry_is_spam` covers **100% of
submission paths** with one binding.

---

## 3. The exact point a submission is deemed valid (before email/store)

Inside `KDNAFormDisplay::process_form()` (`form_display.php:44`):

1. `kdnaform_pre_process` filter (form object, pre-processing) — `:53`.
2. `self::validate( $form, $field_values, $page_number, … )` — `:120`. This is
   field/required/format validation and fires the `kdnaform_validation` filter
   (`form_display.php:2567`). Native **honeypot** and **speed check** run here
   (see §5). Returns `$is_valid`.
3. If `$is_valid && $page_number === 0` (final page reached, validation passed)
   the submission is considered **valid and ready to commit** (`:145`).
   At this point, in order:
   - `kdnaform_abort_submission_with_confirmation` **filter** (`:161`) — an
     early abort hook explicitly described in-code as *"useful for Spam Filters
     that want to abort submissions… Display confirmation but doesn't process
     the form."* If any callback returns `true`, the form shows its confirmation
     and **nothing is stored or emailed**.
   - `kdnaform_pre_submission` action (`:179`) and
     `kdnaform_pre_submission_filter` filter (`:191`).
   - `self::handle_submission( $form, $lead, $ajax )` (`:203`) — commits the
     entry and sends notifications.

Inside `handle_submission()` (`form_display.php:1942`):

4. `KDNAFormsModel::save_lead( $form, $lead )` — entry written to the DB
   (`:1970`).
5. **`$is_spam = KDNACommon::is_spam_entry( $lead, $form )`** (`:1975`) — this is
   the spam decision. It fires:
   ```php
   // common.php:4654  KDNACommon::is_spam_entry()
   $is_spam = gf_apply_filters(
       array( 'kdnaform_entry_is_spam', $form_id ),
       $is_spam, $form, $entry            // ← ( bool, form, entry )
   );
   ```
   (Also the per-form variant `kdnaform_entry_is_spam_{form_id}`.) Akismet
   attaches here at priority 90; Guard should attach earlier, e.g. priority 20.
6. If spam: entry status set to `spam`, spam note added
   (`create_spam_entry_note`), and — critically — at `:2028`:
   ```php
   if ( ! $is_spam ) {
       KDNACommon::create_post( $form, $lead );
       KDNACommon::send_form_submission_notifications( $form, $lead ); // the email
   }
   ```
   So a `true` verdict **suppresses the notification email and post creation.**

**Guard's chosen interception point is step 5**
(`kdnaform_entry_is_spam`). It is (a) reached by every submission method, (b)
positioned after validation with a fully-parsed entry in hand, and (c) natively
wired to suppress the outgoing email when it returns `true`.

> Note: at step 5 the entry row already exists (saved at step 4) and is simply
> flagged `spam` — analogous to how KDNA Forms/Gravity Forms + Akismet behave.
> This is desirable for Guard: the flagged entry gives us a stable
> `$entry['id']` to record, and **release becomes trivial** (unflag + send
> notifications) — see §7.

---

## 4. Fields available at the interception point

The `kdnaform_entry_is_spam` callback receives `( $is_spam, $form, $entry )`,
and the PHP superglobals (`$_POST`, `$_SERVER`) are still live. Available data:

| Data | Where | Notes |
|------|-------|-------|
| Form id | `$form['id']`, `$entry['form_id']` | integer |
| Form title / fields schema | `$form['title']`, `$form['fields']` | each field has `id`, `type`, `label` |
| All submitted field values (named) | `$entry[ <field_id> ]` | keyed by field id; e.g. `$entry['1.3']` first name, `$entry['3']` message textarea. Map by field **type** (`email`, `name`, `textarea`) for provider-agnostic name/email/message extraction |
| Email | the `email`-type field in `$form['fields']` → `$entry[$id]` | |
| Name | the `name`-type field (multi-input `id.3`/`id.6`) | |
| Message body | the `textarea`/`message`-type field | this is what Guard sends to the Claude scorer — **message body only** |
| Submitter IP | `$entry['ip']` (honours `kdnaform_ip_address` / anonymised setting) or `KDNACommon::get_ip()` | |
| Timestamp | `$entry['date_created']` (set on save) + server time | |
| Source URL | `$entry['source_url']` | |
| User agent | `$entry['user_agent']` | |
| Raw POST | `$_POST` (`input_<id>` keys, `gform_submit`, `gform_ajax`, `gform_submission_speeds`) | needed to read **Guard's own** injected honeypot / timestamp fields |

Everything Guard's heuristics and scorer need — message text, email, IP,
timing, honeypot state, form id — is present at this single point.

---

## 5. Existing actions/filters KDNA Forms already fires (relevant subset)

Submission pipeline hooks (all prefixed `kdnaform_`):

| Hook | Type | When | Guard use |
|------|------|------|-----------|
| `kdnaform_pre_process` | filter | very start of `process_form` | — |
| `kdnaform_validation` | filter | during field validation | — (native honeypot/speed run here) |
| `kdnaform_abort_submission_with_confirmation` | filter | valid submission, pre-store | **alternative** halt point (see §6) |
| `kdnaform_pre_submission` | action | pre-store | — |
| `kdnaform_pre_submission_filter` | filter | pre-store | — |
| **`kdnaform_entry_is_spam`** | **filter** | **inside handle_submission, post-save, pre-notify** | **PRIMARY Guard hook** |
| `kdnaform_entry_is_spam_{form_id}` | filter | per-form variant | optional per-form tuning |
| `kdnaform_entry_created` | action | after entry saved | — |
| `kdnaform_after_submission` | action | after notifications | — |
| `kdnaform_get_form_filter` | filter | filters the whole form HTML string on render | **Guard injects its honeypot + timestamp field here** |

Spam-support helpers Guard will reuse:
- `KDNACommon::set_spam_filter( $form_id, 'KDNA Sentinel Guard', $reason )` —
  records Guard as the flagging filter + reason (surfaces in the entry note).
- `KDNACommon::send_form_submission_notifications( $form, $entry )` — the exact
  notification path Guard re-invokes on **release** (§7).

**Native anti-spam already present** (so Guard supplements, not duplicates):
- Honeypot: `includes/honeypot/class-kdna-honeypot-handler.php` —
  `is_honeypot_enabled()`, `get_honeypot_field()`.
- Speed/timing check: same handler, `is_speed_check_enabled()`, hidden field
  `gform_submission_speeds` (`form_display.php:1852`).
- Akismet integration on `kdnaform_entry_is_spam` @ priority 90.

Guard uses its **own** prefixed honeypot/timestamp fields
(`kdna_sentinel_hp`, `kdna_sentinel_ts`) injected via `kdnaform_get_form_filter`
so there is no collision with the native fields, and it works even if the site
owner has the native honeypot switched off.

---

## 6. PATH B vs PATH A — decision

### PATH B — Upstream interception  ✅ CHOSEN
- **Hook:** `add_filter( 'kdnaform_entry_is_spam', <cb>, 20, 3 )` (priority 20 to
  run before Akismet's 90; callback `( $is_spam, $form, $entry )`).
- **Halt mechanism:** return `true` → KDNA Forms marks the entry `spam` and
  skips `send_form_submission_notifications()` + `create_post()`. Guard then
  writes the payload to its quarantine table and (optionally) calls
  `KDNACommon::set_spam_filter()` for the audit note.
- **Honeypot/timing injection:** `add_filter( 'kdnaform_get_form_filter', <cb>, 10, 2 )`
  to append Guard's hidden honeypot input + render timestamp before `</form>`;
  read back from `$_POST` inside the spam callback.
- **Coverage:** standard POST, AJAX, and REST API — all covered by one binding.
- **Zero modification** to KDNA Forms. No redeploy across client sites, no
  version-mismatch risk. Fully satisfies the Path B test.

Fail-open: if Guard's own evaluation throws/errors, the callback returns the
incoming `$is_spam` unchanged (default `false`) → the submission proceeds
normally. A genuine enquiry is never lost because Guard errored.

**Alternative within Path B (documented, not chosen):**
`kdnaform_abort_submission_with_confirmation` halts *before* the entry is stored
at all (nothing written to KDNA Forms' entry table). It is rejected as the
primary because (a) it only receives `$form` — Guard would have to reconstruct
field values from `$_POST` rather than reading a parsed `$entry`, and (b) with
no persisted entry, one-click **release** would require replaying the full POST
through `handle_submission()`, which is fragile. `kdnaform_entry_is_spam` gives
a parsed entry and a clean release path, so it wins.

### PATH A — Patch KDNA Forms  ❌ NOT NEEDED
A hookable entry point exists (`kdnaform_entry_is_spam`), so the fallback of
adding `apply_filters( 'kdna_forms_validate_submission', … )` to the plugin is
**not** required. `docs/kdna-forms-patch.md` is intentionally not created.

---

## 7. Release ("this was genuine — let it through") — feasibility

Because Guard blocks via `kdnaform_entry_is_spam`, the entry already exists in
KDNA Forms flagged `spam`, and Guard records its `$entry['id']` + full payload
in the quarantine table. Release (Stage 4) is therefore a clean re-run of the
genuine path:

1. `KDNAFormsModel::update_entry_property( $entry_id, 'status', 'active' )` —
   un-flag.
2. `KDNACommon::send_form_submission_notifications( $form, $entry )` — send the
   notification email(s) exactly as an un-flagged submission would have.
3. (Optionally) `KDNACommon::create_post( $form, $entry )` if the form maps to a
   post, matching native behaviour.

This reproduces the original processing path without touching KDNA Forms.

---

## 8. WooCommerce account forms — native hooks Guard will bind

Guard binds these **only when `class_exists( 'WooCommerce' )`** (degrade
gracefully otherwise). Each hook lets Guard inspect and block by injecting a
validation error / marking spam. Guard reuses its heuristics + (borderline)
Claude scorer, and quarantines blocked submissions the same way.

| WC form | Primary hook | Signature / block mechanism | Fields available |
|---------|--------------|-----------------------------|------------------|
| **Registration** | `woocommerce_process_registration_errors` (filter) | `( WP_Error $errors, $username, $password, $email )` → add error to block; or action `woocommerce_register_post` (`$username,$email,$errors`) | username, email, IP (`WC_Geolocation`/`$_SERVER`), timestamp |
| **Login** | `woocommerce_process_login_errors` (filter) | `( WP_Error $errors, $username, $password )` → return `WP_Error` to block | username/email, IP, timestamp |
| **Lost password** | `lostpassword_post` (WP core action, fires for the WC form) | `( WP_Error $errors, $user_data )` → `$errors->add()` to block; optionally `allow_password_reset` filter | user login/email, IP, timestamp |
| **Product review** | `preprocess_comment` (filter, capture) + `pre_comment_approved` (filter, verdict) | inspect `$commentdata` where `comment_type === 'review'`; return `'spam'`/`'trash'`/`0` from `pre_comment_approved` to withhold | author, email, url, `comment_content`, IP (`comment_author_IP`), timestamp, `comment_post_ID` (product) |
| **Checkout** | `woocommerce_after_checkout_validation` (action) | `( array $data, WP_Error $errors )` → `$errors->add()` to block; (`woocommerce_checkout_process` as no-arg alternative via `wc_add_notice(...,'error')`) | billing name/email/phone/address, order notes, IP, timestamp |

Notes:
- Honeypot/timestamp injection for WC forms: Guard prints its hidden fields via
  the matching render hooks — `woocommerce_register_form`,
  `woocommerce_login_form`, `woocommerce_lostpassword_form`,
  `comment_form_after_fields` / review form, and
  `woocommerce_after_order_notes` (checkout) — then validates them in the block
  hooks above.
- Blocking a WC form surfaces a normal WooCommerce validation notice to the
  visitor; Guard still quarantines the payload for review/release.
- Coverage of login/registration/lost-password/review/checkout matches the
  brief's "all Woo forms" requirement.

---

## 9. Acceptance-test mapping (Stage 0)

- ✅ `docs/kdna-forms-lifecycle.md` exists and names the real submission entry
  point: `KDNAFormDisplay::process_form()` (dispatched from `wp` via
  `maybe_process_form` / `ajax_parse_request`, and from REST via
  `KDNAAPI::submit_form`).
- ✅ States Path B is viable, with the exact hook + priority:
  `kdnaform_entry_is_spam`, priority 20, callback `( $is_spam, $form, $entry )`,
  halt = return `true`.
- ✅ `reference/` is unmodified (extraction was to a scratch dir; `git status`
  clean).
- ✅ Path A not forced → no `docs/kdna-forms-patch.md` written.
