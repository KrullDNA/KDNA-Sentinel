<?php
/**
 * Guard module bootstrap.
 *
 * Loaded by the core module loader only when the Guard master toggle is on.
 * Builds the heuristics engine from settings and registers the form bindings.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard
 */
final class KDNA_Sentinel_Guard {

	/**
	 * Singleton instance.
	 *
	 * @var KDNA_Sentinel_Guard|null
	 */
	private static $instance = null;

	/**
	 * The form-bindings controller.
	 *
	 * @var KDNA_Sentinel_Guard_Hooks
	 */
	private $hooks;

	/**
	 * Boots the module (idempotent).
	 *
	 * @return KDNA_Sentinel_Guard
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->boot();
		}

		return self::$instance;
	}

	/**
	 * Loads dependencies, builds the engine, registers bindings.
	 *
	 * @return void
	 */
	private function boot() {
		require_once KDNA_SENTINEL_DIR . 'includes/guard/class-guard-verdict.php';
		require_once KDNA_SENTINEL_DIR . 'includes/guard/class-guard-heuristics.php';
		require_once KDNA_SENTINEL_DIR . 'includes/guard/class-guard-hooks.php';

		$core = KDNA_Sentinel_Core::instance();

		$honeypot_enabled = (bool) $core->get_setting( 'guard_honeypot_enabled', 1 );
		$threshold        = (int) $core->get_setting( 'guard_timing_threshold', 2 );
		$ip_blocklist     = KDNA_Sentinel_Guard_Heuristics::parse_ip_blocklist(
			(string) $core->get_setting( 'guard_ip_blocklist', '' )
		);

		$heuristics = new KDNA_Sentinel_Guard_Heuristics( $honeypot_enabled, $threshold, $ip_blocklist );

		$this->hooks = new KDNA_Sentinel_Guard_Hooks( $heuristics, $honeypot_enabled );
		$this->hooks->register();
	}
}
