<?php
/**
 * Guard heuristics engine (the free detection layer).
 *
 * Given a normalised context (honeypot state, time-to-submit, interaction
 * signal, IP), returns a verdict of PASS, BLOCK or BORDERLINE. No API calls,
 * no I/O — pure decision logic so it is trivially testable.
 *
 * Decision model:
 *   Hard fails (definitive bot signals) -> BLOCK immediately:
 *     - honeypot hidden field filled
 *     - IP on the local blocklist
 *     - submitted faster than the timing threshold
 *   Soft anomalies (suspicious but a genuine visitor could trip them) with no
 *   hard fail -> BORDERLINE (Stage 3 sends these to the API scorer):
 *     - no reliable timing data
 *     - no interaction signal (e.g. JS never ran)
 *   Otherwise -> PASS.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard_Heuristics
 */
class KDNA_Sentinel_Guard_Heuristics {

	/**
	 * Whether the honeypot check is active.
	 *
	 * @var bool
	 */
	private $honeypot_enabled;

	/**
	 * Time-to-submit threshold in seconds (0 disables the timing check).
	 *
	 * @var int
	 */
	private $threshold;

	/**
	 * Normalised IP blocklist (exact-match strings).
	 *
	 * @var array
	 */
	private $ip_blocklist;

	/**
	 * Constructor.
	 *
	 * @param bool  $honeypot_enabled Honeypot check on/off.
	 * @param int   $threshold        Timing threshold in seconds.
	 * @param array $ip_blocklist     Array of blocked IP strings.
	 */
	public function __construct( $honeypot_enabled, $threshold, array $ip_blocklist ) {
		$this->honeypot_enabled = (bool) $honeypot_enabled;
		$this->threshold        = max( 0, (int) $threshold );
		$this->ip_blocklist     = $ip_blocklist;
	}

	/**
	 * Evaluates a normalised submission context.
	 *
	 * @param array $context {
	 *     @type bool     $honeypot_filled True when the honeypot field was non-empty.
	 *     @type int|null $elapsed         Seconds between render and submit, or null if unknown/untrusted.
	 *     @type bool     $has_interaction True when an interaction signal was present.
	 *     @type string   $ip              Submitter IP.
	 * }
	 * @return KDNA_Sentinel_Guard_Verdict
	 */
	public function evaluate( array $context ) {
		$honeypot_filled = ! empty( $context['honeypot_filled'] );
		$elapsed         = isset( $context['elapsed'] ) && null !== $context['elapsed'] ? (int) $context['elapsed'] : null;
		$has_interaction = ! empty( $context['has_interaction'] );
		$ip              = isset( $context['ip'] ) ? (string) $context['ip'] : '';

		// --- Hard fails -> BLOCK ------------------------------------------
		if ( $this->honeypot_enabled && $honeypot_filled ) {
			return KDNA_Sentinel_Guard_Verdict::block(
				__( 'Honeypot field was filled.', 'kdna-sentinel' ),
				array( 'honeypot' )
			);
		}

		if ( '' !== $ip && $this->is_ip_blocked( $ip ) ) {
			return KDNA_Sentinel_Guard_Verdict::block(
				__( 'Submitter IP is on the local blocklist.', 'kdna-sentinel' ),
				array( 'ip_blocklist' )
			);
		}

		if ( $this->threshold > 0 && null !== $elapsed && $elapsed >= 0 && $elapsed < $this->threshold ) {
			return KDNA_Sentinel_Guard_Verdict::block(
				sprintf(
					/* translators: 1: elapsed seconds, 2: threshold seconds. */
					__( 'Submitted too fast (%1$ds, under the %2$ds threshold).', 'kdna-sentinel' ),
					$elapsed,
					$this->threshold
				),
				array( 'too_fast' )
			);
		}

		// --- Soft anomalies -> BORDERLINE ---------------------------------
		$soft = array();

		if ( $this->threshold > 0 && null === $elapsed ) {
			$soft[] = 'no_timing';
		}

		if ( ! $has_interaction ) {
			$soft[] = 'no_interaction';
		}

		if ( ! empty( $soft ) ) {
			return KDNA_Sentinel_Guard_Verdict::borderline(
				__( 'Soft anomalies present; needs a closer look.', 'kdna-sentinel' ),
				$soft
			);
		}

		// --- Clean --------------------------------------------------------
		return KDNA_Sentinel_Guard_Verdict::pass();
	}

	/**
	 * Whether an IP is on the blocklist (exact match).
	 *
	 * @param string $ip Candidate IP.
	 * @return bool
	 */
	private function is_ip_blocked( $ip ) {
		return in_array( $ip, $this->ip_blocklist, true );
	}

	/**
	 * Parses a raw blocklist textarea into an array of valid IPs.
	 *
	 * @param string $raw Newline/comma separated IP list.
	 * @return array
	 */
	public static function parse_ip_blocklist( $raw ) {
		if ( ! is_string( $raw ) || '' === trim( $raw ) ) {
			return array();
		}

		$parts = preg_split( '/[\r\n,]+/', $raw );
		$ips   = array();

		foreach ( $parts as $part ) {
			$part = trim( $part );
			if ( '' !== $part && false !== filter_var( $part, FILTER_VALIDATE_IP ) ) {
				$ips[] = $part;
			}
		}

		return array_values( array_unique( $ips ) );
	}
}
