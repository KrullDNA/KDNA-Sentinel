<?php
/**
 * Guard form bindings.
 *
 * Path B upstream interception (confirmed in Stage 0): Guard hooks KDNA Forms'
 * own kdnaform_entry_is_spam filter to halt spam before notification, and
 * injects its honeypot / timing / interaction fields via kdnaform_get_form_filter.
 * KDNA Forms is never modified. WooCommerce account forms are bound to their
 * native validation hooks, only when WooCommerce is active.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard_Hooks
 */
class KDNA_Sentinel_Guard_Hooks {

	/**
	 * Injected field names.
	 */
	const FIELD_HONEYPOT    = 'kdna_sentinel_hp';
	const FIELD_TIMESTAMP   = 'kdna_sentinel_ts';
	const FIELD_INTERACTION = 'kdna_sentinel_int';

	/**
	 * The heuristics engine.
	 *
	 * @var KDNA_Sentinel_Guard_Heuristics
	 */
	private $heuristics;

	/**
	 * Whether the honeypot is enabled (mirrors the setting).
	 *
	 * @var bool
	 */
	private $honeypot_enabled;

	/**
	 * Guards against printing the interaction script more than once per page.
	 *
	 * @var bool
	 */
	private $script_printed = false;

	/**
	 * Constructor.
	 *
	 * @param KDNA_Sentinel_Guard_Heuristics $heuristics       Engine.
	 * @param bool                           $honeypot_enabled Honeypot on/off.
	 */
	public function __construct( KDNA_Sentinel_Guard_Heuristics $heuristics, $honeypot_enabled ) {
		$this->heuristics       = $heuristics;
		$this->honeypot_enabled = (bool) $honeypot_enabled;
	}

	/**
	 * Registers all bindings.
	 *
	 * @return void
	 */
	public function register() {
		// --- KDNA Forms (Path B) ------------------------------------------
		// Inject Guard's hidden fields into every rendered form.
		add_filter( 'kdnaform_get_form_filter', array( $this, 'inject_kdna_forms_fields' ), 10, 2 );
		// Intercept at the native spam decision, before notification/post.
		add_filter( 'kdnaform_entry_is_spam', array( $this, 'evaluate_kdna_forms' ), 20, 3 );

		// --- WooCommerce (only if active) ---------------------------------
		if ( class_exists( 'WooCommerce' ) ) {
			$this->register_woocommerce();
		}
	}

	/*
	 * =====================================================================
	 * KDNA Forms
	 * =====================================================================
	 */

	/**
	 * Appends Guard's hidden fields to a rendered KDNA form.
	 *
	 * @param string $form_string The form HTML.
	 * @param array  $form        The form object (unused).
	 * @return string
	 */
	public function inject_kdna_forms_fields( $form_string, $form = array() ) {
		if ( ! is_string( $form_string ) || false === strpos( $form_string, '</form>' ) ) {
			return $form_string;
		}

		$fields = $this->hidden_fields_markup();

		// Insert before the final closing form tag.
		$pos = strrpos( $form_string, '</form>' );
		if ( false === $pos ) {
			return $form_string;
		}

		return substr( $form_string, 0, $pos ) . $fields . substr( $form_string, $pos );
	}

	/**
	 * Guard callback on kdnaform_entry_is_spam.
	 *
	 * @param bool  $is_spam Incoming spam flag.
	 * @param array $form    The form object.
	 * @param array $entry   The entry being processed.
	 * @return bool
	 */
	public function evaluate_kdna_forms( $is_spam, $form = array(), $entry = array() ) {
		// Respect any earlier spam decision (e.g. Akismet, native honeypot).
		if ( $is_spam ) {
			return true;
		}

		try {
			$context = $this->build_context();
			$verdict = $this->heuristics->evaluate( $context );

			$meta = array(
				'source'  => 'kdna_forms',
				'form_id' => isset( $form['id'] ) ? (string) $form['id'] : '',
				'ip'      => $context['ip'],
				'message' => $this->extract_kdna_message( $form, $entry ),
				'payload' => is_array( $entry ) ? $entry : array(),
			);

			return $this->resolve( $verdict, $meta, $is_spam );
		} catch ( Exception $e ) {
			// Fail-open: never lose a genuine enquiry because Guard errored.
			$this->log_fail_open( 'kdna_forms', $e->getMessage() );
			return $is_spam;
		}
	}

	/*
	 * =====================================================================
	 * WooCommerce
	 * =====================================================================
	 */

	/**
	 * Binds WooCommerce account-form hooks.
	 *
	 * @return void
	 */
	private function register_woocommerce() {
		// Field injection on each form.
		add_action( 'woocommerce_register_form', array( $this, 'print_fields' ) );
		add_action( 'woocommerce_login_form', array( $this, 'print_fields' ) );
		add_action( 'woocommerce_lostpassword_form', array( $this, 'print_fields' ) );
		add_action( 'woocommerce_after_order_notes', array( $this, 'print_fields' ) );
		add_action( 'comment_form_logged_in_after', array( $this, 'print_fields' ) );
		add_action( 'comment_form_after_fields', array( $this, 'print_fields' ) );

		// Validation / interception.
		add_filter( 'woocommerce_registration_errors', array( $this, 'evaluate_wc_registration' ), 20, 3 );
		add_filter( 'woocommerce_process_login_errors', array( $this, 'evaluate_wc_login' ), 20, 3 );
		add_action( 'lostpassword_post', array( $this, 'evaluate_wc_lostpassword' ), 20, 1 );
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'evaluate_wc_checkout' ), 20, 2 );
		add_filter( 'pre_comment_approved', array( $this, 'evaluate_review' ), 20, 2 );
	}

	/**
	 * WooCommerce registration validation.
	 *
	 * @param WP_Error $errors   Error accumulator.
	 * @param string   $username Submitted username.
	 * @param string   $email    Submitted email.
	 * @return WP_Error
	 */
	public function evaluate_wc_registration( $errors, $username = '', $email = '' ) {
		return $this->evaluate_wc_error_form(
			$errors,
			'woocommerce_registration',
			array( 'username' => $username, 'email' => $email ),
			'' // No free-text message on registration.
		);
	}

	/**
	 * WooCommerce login validation.
	 *
	 * @param WP_Error $errors   Error accumulator.
	 * @param string   $username Submitted username.
	 * @param string   $password Submitted password (never stored/logged).
	 * @return WP_Error
	 */
	public function evaluate_wc_login( $errors, $username = '', $password = '' ) {
		return $this->evaluate_wc_error_form(
			$errors,
			'woocommerce_login',
			array( 'username' => $username ),
			'' // No free-text message on login.
		);
	}

	/**
	 * WooCommerce / core lost-password validation.
	 *
	 * @param WP_Error $errors Error accumulator (passed by reference by WP).
	 * @return void
	 */
	public function evaluate_wc_lostpassword( $errors ) {
		if ( ! ( $errors instanceof WP_Error ) ) {
			return;
		}
		$this->evaluate_wc_error_form( $errors, 'woocommerce_lostpassword', array() );
	}

	/**
	 * WooCommerce checkout validation.
	 *
	 * @param array    $data   Posted checkout data.
	 * @param WP_Error $errors Error accumulator.
	 * @return void
	 */
	public function evaluate_wc_checkout( $data, $errors ) {
		if ( ! ( $errors instanceof WP_Error ) ) {
			return;
		}

		$payload = array();
		if ( is_array( $data ) ) {
			foreach ( array( 'billing_email', 'billing_first_name', 'billing_last_name', 'order_comments' ) as $key ) {
				if ( isset( $data[ $key ] ) ) {
					$payload[ $key ] = $data[ $key ];
				}
			}
		}

		// Only the order note is free-text content worth scoring.
		$message = isset( $payload['order_comments'] ) ? (string) $payload['order_comments'] : '';

		$this->evaluate_wc_error_form( $errors, 'woocommerce_checkout', $payload, $message );
	}

	/**
	 * Shared handler for WooCommerce forms that block via a WP_Error.
	 *
	 * @param WP_Error $errors  Error accumulator.
	 * @param string   $source  Source slug.
	 * @param array    $payload Non-sensitive payload for quarantine.
	 * @param string   $message Free-text message body to score (may be empty).
	 * @return WP_Error
	 */
	private function evaluate_wc_error_form( $errors, $source, array $payload, $message = '' ) {
		if ( ! ( $errors instanceof WP_Error ) ) {
			return $errors;
		}

		try {
			$context = $this->build_context();
			$verdict = $this->heuristics->evaluate( $context );

			$meta = array(
				'source'  => $source,
				'form_id' => '',
				'ip'      => $context['ip'],
				'message' => (string) $message,
				'payload' => $payload,
			);

			$is_spam = $this->resolve( $verdict, $meta, false );
			if ( $is_spam ) {
				$errors->add(
					'kdna_sentinel_blocked',
					__( 'Your submission was flagged as automated and could not be processed. Please contact us if this is a mistake.', 'kdna-sentinel' )
				);
			}
		} catch ( Exception $e ) {
			// Fail-open: let the submission proceed.
			$this->log_fail_open( $source, $e->getMessage() );
		}

		return $errors;
	}

	/**
	 * Product-review interception via pre_comment_approved.
	 *
	 * Only acts on WooCommerce reviews; ordinary comments are left untouched.
	 *
	 * @param int|string $approved    Current approval state.
	 * @param array      $commentdata Comment data.
	 * @return int|string
	 */
	public function evaluate_review( $approved, $commentdata = array() ) {
		if ( ! is_array( $commentdata ) || 'review' !== ( isset( $commentdata['comment_type'] ) ? $commentdata['comment_type'] : '' ) ) {
			return $approved;
		}

		// Do not re-flag what WordPress already marked spam/trash.
		if ( 'spam' === $approved || 'trash' === $approved ) {
			return $approved;
		}

		try {
			$context = $this->build_context();
			$verdict = $this->heuristics->evaluate( $context );

			$content = isset( $commentdata['comment_content'] ) ? (string) $commentdata['comment_content'] : '';

			$meta = array(
				'source'  => 'woocommerce_review',
				'form_id' => isset( $commentdata['comment_post_ID'] ) ? (string) $commentdata['comment_post_ID'] : '',
				'ip'      => $context['ip'],
				'message' => $content,
				'payload' => array(
					'author'  => isset( $commentdata['comment_author'] ) ? $commentdata['comment_author'] : '',
					'email'   => isset( $commentdata['comment_author_email'] ) ? $commentdata['comment_author_email'] : '',
					'content' => $content,
				),
			);

			$is_spam = $this->resolve( $verdict, $meta, false );
			if ( $is_spam ) {
				return 'spam';
			}
		} catch ( Exception $e ) {
			$this->log_fail_open( 'woocommerce_review', $e->getMessage() );
		}

		return $approved;
	}

	/*
	 * =====================================================================
	 * Shared logic
	 * =====================================================================
	 */

	/**
	 * Turns a verdict into a spam boolean and dispatches side effects.
	 *
	 * BLOCK  -> quarantine handoff + block (true).
	 * BORDERLINE -> Stage 3 filter decides; defaults to let-through (Stage 2).
	 * PASS   -> let through, unchanged.
	 *
	 * @param KDNA_Sentinel_Guard_Verdict $verdict Verdict.
	 * @param array                       $meta    Source/form/ip/payload.
	 * @param bool                        $default Incoming spam flag to preserve on pass.
	 * @return bool
	 */
	private function resolve( KDNA_Sentinel_Guard_Verdict $verdict, array $meta, $default ) {
		if ( $verdict->is_block() ) {
			$this->handle_block( $verdict, $meta );
			return true;
		}

		if ( $verdict->is_borderline() ) {
			$this->log_verdict( 'BORDERLINE', $verdict, $meta, false );

			/**
			 * Lets the Stage 3 API scorer decide a borderline submission.
			 *
			 * @param bool                        $is_spam Default false (let through).
			 * @param KDNA_Sentinel_Guard_Verdict $verdict The heuristic verdict.
			 * @param array                       $meta    Source/form/ip/payload.
			 */
			$is_spam = (bool) apply_filters( 'kdna_sentinel_guard_borderline_is_spam', false, $verdict, $meta );

			if ( $is_spam ) {
				/**
				 * Lets the scorer attach its confidence to the verdict so the
				 * quarantine store (Stage 4) can record a score.
				 *
				 * @param float|null                  $score   Default score.
				 * @param KDNA_Sentinel_Guard_Verdict $verdict The heuristic verdict.
				 * @param array                       $meta    Source/form/ip/message.
				 */
				$score = apply_filters( 'kdna_sentinel_guard_borderline_score', $verdict->score(), $verdict, $meta );
				if ( null !== $score ) {
					$verdict = $verdict->with_score( (float) $score );
				}

				$this->handle_block( $verdict, $meta );
				return true;
			}

			return $default;
		}

		return $default;
	}

	/**
	 * Handles a blocked submission: log now, quarantine in Stage 4.
	 *
	 * @param KDNA_Sentinel_Guard_Verdict $verdict Verdict.
	 * @param array                       $meta    Source/form/ip/payload.
	 * @return void
	 */
	private function handle_block( KDNA_Sentinel_Guard_Verdict $verdict, array $meta ) {
		$this->log_verdict( 'BLOCK', $verdict, $meta );

		/**
		 * Fires when Guard blocks a submission. Stage 4's quarantine store
		 * hooks this to persist the full payload.
		 *
		 * @param KDNA_Sentinel_Guard_Verdict $verdict Verdict.
		 * @param array                       $meta    Source/form/ip/payload.
		 */
		do_action( 'kdna_sentinel_guard_blocked', $verdict, $meta );
	}

	/**
	 * Extracts only the free-text message field(s) from a KDNA Forms entry.
	 *
	 * Deliberately returns just message-type content — never name, email or
	 * other PII — so the API scorer receives the minimum needed to classify.
	 *
	 * @param array $form  The form object.
	 * @param array $entry The entry object.
	 * @return string
	 */
	private function extract_kdna_message( $form, $entry ) {
		if ( ! is_array( $entry ) || empty( $form['fields'] ) || ! is_array( $form['fields'] ) ) {
			return '';
		}

		$message_types = array( 'textarea', 'message', 'post_content', 'post_excerpt' );
		$parts         = array();

		foreach ( $form['fields'] as $field ) {
			$type = $this->field_prop( $field, 'type' );
			$id   = $this->field_prop( $field, 'id' );

			if ( in_array( $type, $message_types, true ) && '' !== (string) $id && isset( $entry[ $id ] ) ) {
				$value = $entry[ $id ];
				if ( is_string( $value ) && '' !== trim( $value ) ) {
					$parts[] = trim( $value );
				}
			}
		}

		return implode( "\n\n", $parts );
	}

	/**
	 * Reads a property from a field that may be an object or an array.
	 *
	 * @param mixed  $field Field.
	 * @param string $prop  Property name.
	 * @return mixed
	 */
	private function field_prop( $field, $prop ) {
		if ( is_object( $field ) ) {
			return isset( $field->$prop ) ? $field->$prop : '';
		}
		if ( is_array( $field ) ) {
			return isset( $field[ $prop ] ) ? $field[ $prop ] : '';
		}

		return '';
	}

	/**
	 * Builds a normalised context from the current request.
	 *
	 * @return array
	 */
	private function build_context() {
		return array(
			'honeypot_filled' => $this->honeypot_filled(),
			'elapsed'         => $this->elapsed_seconds(),
			'has_interaction' => $this->has_interaction(),
			'ip'              => $this->get_ip(),
		);
	}

	/**
	 * Whether the honeypot field came back non-empty.
	 *
	 * @return bool
	 */
	private function honeypot_filled() {
		if ( ! isset( $_POST[ self::FIELD_HONEYPOT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return false;
		}

		$value = wp_unslash( $_POST[ self::FIELD_HONEYPOT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		return is_string( $value ) && '' !== trim( $value );
	}

	/**
	 * Seconds between form render and submit, or null if unavailable/untrusted.
	 *
	 * The timestamp is signed at render time so a bot cannot forge an old value
	 * to slip past the fast-submit check.
	 *
	 * @return int|null
	 */
	private function elapsed_seconds() {
		if ( empty( $_POST[ self::FIELD_TIMESTAMP ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return null;
		}

		$raw = wp_unslash( $_POST[ self::FIELD_TIMESTAMP ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_string( $raw ) || false === strpos( $raw, '.' ) ) {
			return null;
		}

		$dot = strrpos( $raw, '.' );
		$ts  = substr( $raw, 0, $dot );
		$sig = substr( $raw, $dot + 1 );

		if ( ! ctype_digit( $ts ) || ! hash_equals( $this->sign_timestamp( $ts ), $sig ) ) {
			return null; // Tampered or malformed: treat timing as unknown (soft).
		}

		$elapsed = time() - (int) $ts;

		return $elapsed >= 0 ? $elapsed : null;
	}

	/**
	 * Whether the interaction signal was set (JS ran and the visitor interacted).
	 *
	 * @return bool
	 */
	private function has_interaction() {
		if ( ! isset( $_POST[ self::FIELD_INTERACTION ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return false;
		}

		return '1' === (string) wp_unslash( $_POST[ self::FIELD_INTERACTION ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	}

	/**
	 * Best-effort submitter IP.
	 *
	 * @return string
	 */
	private function get_ip() {
		if ( class_exists( 'WC_Geolocation' ) ) {
			$ip = WC_Geolocation::get_ip_address();
			if ( ! empty( $ip ) ) {
				return $ip;
			}
		}

		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP );
			if ( false !== $ip ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * Signs a timestamp value.
	 *
	 * @param string $ts Timestamp (digits).
	 * @return string
	 */
	private function sign_timestamp( $ts ) {
		return wp_hash( 'kdna_sentinel_ts|' . $ts );
	}

	/**
	 * Builds the hidden-field markup Guard injects into a form.
	 *
	 * @return string
	 */
	public function hidden_fields_markup() {
		$ts    = time();
		$token = $ts . '.' . $this->sign_timestamp( (string) $ts );

		$out = '';

		if ( $this->honeypot_enabled ) {
			// Off-screen, tab-skipped, aria-hidden: invisible to humans, tempting to bots.
			$out .= '<div style="position:absolute!important;left:-9999px!important;top:-9999px!important;height:1px;width:1px;overflow:hidden;" aria-hidden="true">';
			$out .= '<label>' . esc_html__( 'Leave this field empty', 'kdna-sentinel' ) . '</label>';
			$out .= '<input type="text" name="' . esc_attr( self::FIELD_HONEYPOT ) . '" value="" tabindex="-1" autocomplete="off" />';
			$out .= '</div>';
		}

		$out .= '<input type="hidden" name="' . esc_attr( self::FIELD_TIMESTAMP ) . '" value="' . esc_attr( $token ) . '" />';
		$out .= '<input type="hidden" name="' . esc_attr( self::FIELD_INTERACTION ) . '" value="0" class="kdna-sentinel-int" />';
		$out .= $this->interaction_script();

		return $out;
	}

	/**
	 * Prints the hidden fields directly (WooCommerce form action callbacks).
	 *
	 * @return void
	 */
	public function print_fields() {
		echo $this->hidden_fields_markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * A tiny inline script (printed once) that flags interaction and is safe
	 * with page caching. Only emitted where a Guard-protected form exists.
	 *
	 * @return string
	 */
	private function interaction_script() {
		if ( $this->script_printed ) {
			return '';
		}
		$this->script_printed = true;

		return "<script>(function(){var f=function(){document.querySelectorAll('.kdna-sentinel-int').forEach(function(i){i.value='1';});" .
			"['keydown','mousedown','touchstart','pointerdown'].forEach(function(e){document.removeEventListener(e,f,true);});};" .
			"['keydown','mousedown','touchstart','pointerdown'].forEach(function(e){document.addEventListener(e,f,true);});})();</script>";
	}

	/*
	 * =====================================================================
	 * Logging (never logs submission content / PII)
	 * =====================================================================
	 */

	/**
	 * Logs a verdict to the error log (testable seam until quarantine lands).
	 *
	 * @param string                      $level   BLOCK|BORDERLINE.
	 * @param KDNA_Sentinel_Guard_Verdict $verdict Verdict.
	 * @param array                       $meta    Source/form/ip.
	 * @return void
	 */
	private function log_verdict( $level, KDNA_Sentinel_Guard_Verdict $verdict, array $meta, $force = true ) {
		$this->log(
			sprintf(
				'%s source=%s form=%s ip=%s signals=%s reason=%s',
				$level,
				isset( $meta['source'] ) ? $meta['source'] : '',
				isset( $meta['form_id'] ) ? $meta['form_id'] : '',
				isset( $meta['ip'] ) ? $meta['ip'] : '',
				implode( ',', $verdict->signals() ),
				$verdict->reason()
			),
			$force
		);
	}

	/**
	 * Logs a fail-open event (auditable, per the privacy guardrails).
	 *
	 * @param string $source Source slug.
	 * @param string $detail Error detail.
	 * @return void
	 */
	private function log_fail_open( $source, $detail ) {
		$this->log( sprintf( 'FAIL-OPEN source=%s detail=%s', $source, $detail ) );
	}

	/**
	 * Writes a prefixed line to the PHP error log.
	 *
	 * Security-relevant events (blocks, fail-open) are always recorded for
	 * auditability; informational events (borderline) log only under WP_DEBUG.
	 *
	 * @param string $message Message.
	 * @param bool   $force   Always log when true.
	 * @return void
	 */
	private function log( $message, $force = true ) {
		if ( $force || ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) {
			error_log( 'KDNA Sentinel Guard: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
