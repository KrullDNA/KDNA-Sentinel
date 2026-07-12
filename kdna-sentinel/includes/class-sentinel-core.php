<?php
/**
 * Core bootstrap: settings registry and module loader.
 *
 * Loads whichever modules (Guard, Watch) are toggled on and exposes the
 * shared settings/table helpers the rest of the plugin builds on.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Core
 */
final class KDNA_Sentinel_Core {

	/**
	 * Single option array holding every Sentinel setting.
	 */
	const OPTION = 'kdna_sentinel_settings';

	/**
	 * Singleton instance.
	 *
	 * @var KDNA_Sentinel_Core|null
	 */
	private static $instance = null;

	/**
	 * Cached settings array.
	 *
	 * @var array|null
	 */
	private $settings = null;

	/**
	 * The settings controller.
	 *
	 * @var KDNA_Sentinel_Settings|null
	 */
	private $settings_page = null;

	/**
	 * Returns (and on first call, builds) the singleton.
	 *
	 * @return KDNA_Sentinel_Core
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->init();
		}

		return self::$instance;
	}

	/**
	 * Wires up hooks.
	 *
	 * @return void
	 */
	private function init() {
		load_plugin_textdomain( 'kdna-sentinel', false, dirname( KDNA_SENTINEL_BASENAME ) . '/languages' );

		// Apply any pending schema upgrade in the admin.
		add_action( 'admin_init', array( 'KDNA_Sentinel_Activator', 'maybe_upgrade' ) );

		// Settings UI (admin only).
		if ( is_admin() ) {
			require_once KDNA_SENTINEL_DIR . 'includes/class-sentinel-settings.php';
			$this->settings_page = new KDNA_Sentinel_Settings( $this );
			$this->settings_page->hooks();
		}

		// Load enabled modules once all plugins are available.
		$this->load_modules();
	}

	/**
	 * Loads each module whose master toggle is on and whose files exist.
	 *
	 * Module code is added in later stages; file_exists guards keep the
	 * skeleton activatable in the meantime.
	 *
	 * @return void
	 */
	private function load_modules() {
		if ( $this->is_module_enabled( 'guard' ) ) {
			$guard = KDNA_SENTINEL_DIR . 'includes/guard/class-guard.php';
			if ( file_exists( $guard ) ) {
				require_once $guard;
				if ( class_exists( 'KDNA_Sentinel_Guard' ) ) {
					KDNA_Sentinel_Guard::instance();
				}
			}
		}

		if ( $this->is_module_enabled( 'watch' ) ) {
			$watch = KDNA_SENTINEL_DIR . 'includes/watch/class-watch.php';
			if ( file_exists( $watch ) ) {
				require_once $watch;
				if ( class_exists( 'KDNA_Sentinel_Watch' ) ) {
					KDNA_Sentinel_Watch::instance();
				}
			}
		}

		// The hub receiver is loaded whenever this site is flagged as the hub,
		// independent of the Guard/Watch toggles (added in Stage 7).
		if ( $this->get_setting( 'hub_is_hub', false ) ) {
			$hub = KDNA_SENTINEL_DIR . 'includes/hub/class-hub-endpoint.php';
			if ( file_exists( $hub ) ) {
				require_once $hub;
				if ( class_exists( 'KDNA_Sentinel_Hub_Endpoint' ) ) {
					KDNA_Sentinel_Hub_Endpoint::instance();
				}
			}
		}
	}

	/*
	 * ---------------------------------------------------------------------
	 * Settings registry
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Default settings. Later stages extend this map with their own keys.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			// Master toggles.
			'guard_enabled'          => 0,
			'watch_enabled'          => 0,

			// Guard heuristics.
			'guard_honeypot_enabled' => 1,
			'guard_timing_threshold' => 2,
			'guard_ip_blocklist'     => '',
		);
	}

	/**
	 * Returns the full settings array, merged over defaults.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( null === $this->settings ) {
			$stored = get_option( self::OPTION, array() );
			if ( ! is_array( $stored ) ) {
				$stored = array();
			}
			$this->settings = wp_parse_args( $stored, self::default_settings() );
		}

		return $this->settings;
	}

	/**
	 * Returns a single setting value.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback when the key is absent.
	 * @return mixed
	 */
	public function get_setting( $key, $default = null ) {
		$settings = $this->get_settings();

		return array_key_exists( $key, $settings ) ? $settings[ $key ] : $default;
	}

	/**
	 * Whether a module's master toggle is on.
	 *
	 * @param string $module 'guard' or 'watch'.
	 * @return bool
	 */
	public function is_module_enabled( $module ) {
		return (bool) $this->get_setting( $module . '_enabled', 0 );
	}

	/**
	 * Clears the cached settings (call after an update).
	 *
	 * @return void
	 */
	public function flush_settings_cache() {
		$this->settings = null;
	}

	/*
	 * ---------------------------------------------------------------------
	 * Table helper
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Returns the prefixed table name for a Sentinel table.
	 *
	 * @param string $name One of: quarantine, vuln_cache, hub_log.
	 * @return string
	 */
	public static function table( $name ) {
		global $wpdb;

		return $wpdb->prefix . 'kdna_sentinel_' . $name;
	}
}
