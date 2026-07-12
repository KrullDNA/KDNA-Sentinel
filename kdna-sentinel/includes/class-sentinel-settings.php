<?php
/**
 * Admin menu, tabs and settings persistence.
 *
 * Renders the single top-level "KDNA Sentinel" menu with Guard, Watch and Hub
 * tabs. Guard and Watch each expose a master enable/disable toggle stored in
 * the shared kdna_sentinel_settings option. No detection logic here.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Settings
 */
class KDNA_Sentinel_Settings {

	/**
	 * Settings API group / page slug.
	 */
	const GROUP = 'kdna_sentinel_settings_group';

	/**
	 * Admin page slug.
	 */
	const PAGE = 'kdna-sentinel';

	/**
	 * Core instance.
	 *
	 * @var KDNA_Sentinel_Core
	 */
	private $core;

	/**
	 * Hook suffix of the settings page (for targeted asset enqueue).
	 *
	 * @var string
	 */
	private $hook_suffix = '';

	/**
	 * Available tabs: slug => label callback is resolved in get_tabs().
	 *
	 * @var array
	 */
	private $tabs = array();

	/**
	 * Constructor.
	 *
	 * @param KDNA_Sentinel_Core $core Core instance.
	 */
	public function __construct( KDNA_Sentinel_Core $core ) {
		$this->core = $core;
	}

	/**
	 * Registers admin hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Returns the tab slug => label map.
	 *
	 * @return array
	 */
	public function get_tabs() {
		if ( empty( $this->tabs ) ) {
			$this->tabs = array(
				'guard' => __( 'Guard', 'kdna-sentinel' ),
				'watch' => __( 'Watch', 'kdna-sentinel' ),
				'hub'   => __( 'Hub', 'kdna-sentinel' ),
			);
		}

		return $this->tabs;
	}

	/**
	 * Registers the top-level admin menu.
	 *
	 * @return void
	 */
	public function register_menu() {
		$this->hook_suffix = add_menu_page(
			__( 'KDNA Sentinel', 'kdna-sentinel' ),
			__( 'KDNA Sentinel', 'kdna-sentinel' ),
			'manage_options',
			self::PAGE,
			array( $this, 'render_page' ),
			'dashicons-shield',
			76
		);
	}

	/**
	 * Registers the single settings option with a sanitising callback.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			self::GROUP,
			KDNA_Sentinel_Core::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => KDNA_Sentinel_Core::default_settings(),
			)
		);
	}

	/**
	 * Sanitises submitted settings and merges them over what is already stored.
	 *
	 * Each tab submits only its own fields, so a merge keeps the other tabs'
	 * values intact. Checkboxes always submit a hidden "0" companion, so an
	 * unchecked toggle reliably persists as off.
	 *
	 * @param mixed $input Raw submitted values.
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$existing = get_option( KDNA_Sentinel_Core::OPTION, array() );
		if ( ! is_array( $existing ) ) {
			$existing = array();
		}

		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$clean = array();

		// Boolean flags (master toggles + Guard honeypot).
		foreach ( array( 'guard_enabled', 'watch_enabled', 'guard_honeypot_enabled' ) as $flag ) {
			if ( array_key_exists( $flag, $input ) ) {
				$clean[ $flag ] = empty( $input[ $flag ] ) ? 0 : 1;
			}
		}

		// Guard timing threshold: whole seconds, 0 disables the check.
		if ( array_key_exists( 'guard_timing_threshold', $input ) ) {
			$clean['guard_timing_threshold'] = min( 300, absint( $input['guard_timing_threshold'] ) );
		}

		// Guard IP blocklist: keep only valid IPs, one per line.
		if ( array_key_exists( 'guard_ip_blocklist', $input ) ) {
			require_once KDNA_SENTINEL_DIR . 'includes/guard/class-guard-heuristics.php';
			$ips                          = KDNA_Sentinel_Guard_Heuristics::parse_ip_blocklist( (string) wp_unslash( $input['guard_ip_blocklist'] ) );
			$clean['guard_ip_blocklist']  = implode( "\n", $ips );
		}

		// Guard model name (loose validation).
		if ( array_key_exists( 'guard_model', $input ) ) {
			$model                = preg_replace( '/[^a-zA-Z0-9._\-]/', '', (string) wp_unslash( $input['guard_model'] ) );
			$clean['guard_model'] = ( '' !== $model ) ? $model : 'claude-haiku-4-5';
		}

		// Guard confidence threshold, clamped to 0..1.
		if ( array_key_exists( 'guard_confidence_threshold', $input ) ) {
			$clean['guard_confidence_threshold'] = max( 0.0, min( 1.0, (float) $input['guard_confidence_threshold'] ) );
		}

		// Guard per-day API call cap (0 = unlimited).
		if ( array_key_exists( 'guard_daily_cap', $input ) ) {
			$clean['guard_daily_cap'] = absint( $input['guard_daily_cap'] );
		}

		// Guard API key: never round-tripped to the browser. Remove-on-request,
		// otherwise store a newly entered key, otherwise preserve the stored one
		// (a blank submit leaves the key unset in $clean, so the merge keeps it).
		if ( ! empty( $input['guard_api_key_remove'] ) ) {
			$clean['guard_api_key'] = '';
		} elseif ( isset( $input['guard_api_key'] ) ) {
			$key = trim( (string) wp_unslash( $input['guard_api_key'] ) );
			if ( '' !== $key ) {
				$clean['guard_api_key'] = sanitize_text_field( $key );
			}
		}

		// Watch provider (whitelisted).
		if ( array_key_exists( 'watch_provider', $input ) ) {
			$provider                 = sanitize_key( wp_unslash( $input['watch_provider'] ) );
			$clean['watch_provider']  = in_array( $provider, array( 'wpscan', 'patchstack' ), true ) ? $provider : 'wpscan';
		}

		// Watch API key: same masking rules as the Guard key.
		if ( ! empty( $input['watch_api_key_remove'] ) ) {
			$clean['watch_api_key'] = '';
		} elseif ( isset( $input['watch_api_key'] ) ) {
			$wkey = trim( (string) wp_unslash( $input['watch_api_key'] ) );
			if ( '' !== $wkey ) {
				$clean['watch_api_key'] = sanitize_text_field( $wkey );
			}
		}

		$merged = array_merge( $existing, $clean );

		// Keep the in-memory copy in sync with what was just saved.
		$this->core->flush_settings_cache();

		add_settings_error(
			KDNA_Sentinel_Core::OPTION,
			'kdna_sentinel_saved',
			__( 'Settings saved.', 'kdna-sentinel' ),
			'updated'
		);

		return $merged;
	}

	/**
	 * Enqueues admin CSS/JS only on the Sentinel settings screen.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( $hook !== $this->hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'kdna-sentinel-admin',
			KDNA_SENTINEL_URL . 'admin/admin-style.css',
			array(),
			KDNA_SENTINEL_VERSION
		);

		wp_enqueue_script(
			'kdna-sentinel-admin',
			KDNA_SENTINEL_URL . 'assets/js/admin.js',
			array(),
			KDNA_SENTINEL_VERSION,
			true
		);
	}

	/**
	 * Resolves the current tab from the request, defaulting to Guard.
	 *
	 * @return string
	 */
	public function current_tab() {
		$tabs = $this->get_tabs();
		// Read-only navigation param; no state change, so nonce is not required.
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'guard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		return isset( $tabs[ $tab ] ) ? $tab : 'guard';
	}

	/**
	 * Builds the URL for a given tab.
	 *
	 * @param string $tab Tab slug.
	 * @return string
	 */
	public function tab_url( $tab ) {
		return add_query_arg(
			array(
				'page' => self::PAGE,
				'tab'  => $tab,
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Renders the settings page shell and the active tab view.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'kdna-sentinel' ) );
		}

		$core        = $this->core;
		$settings    = $this->core->get_settings();
		$active_tab  = $this->current_tab();
		$tabs        = $this->get_tabs();

		include KDNA_SENTINEL_DIR . 'admin/views/settings-page.php';
	}
}
