<?php
/**
 * Handles activation, deactivation and schema creation.
 *
 * Tables are created via dbDelta on activation and re-checked on upgrade.
 * They are removed only on uninstall (uninstall.php), never on deactivation.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Activator
 */
class KDNA_Sentinel_Activator {

	/**
	 * Option key holding the installed schema version.
	 */
	const DB_VERSION_OPTION = 'kdna_sentinel_db_version';

	/**
	 * Runs on plugin activation: create tables and seed default settings.
	 *
	 * @return void
	 */
	public static function activate() {
		self::create_tables();
		self::seed_default_settings();
		update_option( self::DB_VERSION_OPTION, KDNA_SENTINEL_DB_VERSION );

		// Schedule the daily quarantine purge.
		if ( ! wp_next_scheduled( 'kdna_sentinel_guard_purge' ) ) {
			wp_schedule_event( time(), 'daily', 'kdna_sentinel_guard_purge' );
		}
	}

	/**
	 * Runs on plugin deactivation.
	 *
	 * Intentionally non-destructive: no tables dropped, no settings removed.
	 * Only transient/scheduled state should be cleared here (none yet).
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'kdna_sentinel_guard_purge' );
	}

	/**
	 * Re-runs dbDelta when the stored schema version is behind the code.
	 *
	 * Called on admin_init so upgrades apply without a manual reactivation.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( get_option( self::DB_VERSION_OPTION ) === KDNA_SENTINEL_DB_VERSION ) {
			return;
		}

		self::create_tables();
		self::seed_default_settings();
		update_option( self::DB_VERSION_OPTION, KDNA_SENTINEL_DB_VERSION );
	}

	/**
	 * Creates the three custom tables via dbDelta.
	 *
	 * @return void
	 */
	private static function create_tables() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();

		$quarantine = KDNA_Sentinel_Core::table( 'quarantine' );
		$vuln_cache = KDNA_Sentinel_Core::table( 'vuln_cache' );
		$hub_log    = KDNA_Sentinel_Core::table( 'hub_log' );

		// Guard: held (blocked/spam) submissions awaiting review or release.
		$sql_quarantine = "CREATE TABLE {$quarantine} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			form_source varchar(50) NOT NULL DEFAULT '',
			form_id varchar(50) NOT NULL DEFAULT '',
			payload longtext NOT NULL,
			reason varchar(255) NOT NULL DEFAULT '',
			score float DEFAULT NULL,
			ip varchar(100) NOT NULL DEFAULT '',
			created_at datetime NOT NULL,
			released tinyint(1) NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			KEY form_id (form_id),
			KEY created_at (created_at),
			KEY released (released)
		) {$charset_collate};";

		// Watch: cached vulnerability-scan results per installed plugin.
		$sql_vuln_cache = "CREATE TABLE {$vuln_cache} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			plugin_slug varchar(191) NOT NULL DEFAULT '',
			installed_ver varchar(50) NOT NULL DEFAULT '',
			vuln_id varchar(100) NOT NULL DEFAULT '',
			severity varchar(20) NOT NULL DEFAULT '',
			fixed_in varchar(50) NOT NULL DEFAULT '',
			detected_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY plugin_slug (plugin_slug),
			KEY severity (severity)
		) {$charset_collate};";

		// Hub: received check-in reports (only used when this site is the hub).
		$sql_hub_log = "CREATE TABLE {$hub_log} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			site_url varchar(255) NOT NULL DEFAULT '',
			payload longtext NOT NULL,
			received_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY site_url (site_url)
		) {$charset_collate};";

		dbDelta( $sql_quarantine );
		dbDelta( $sql_vuln_cache );
		dbDelta( $sql_hub_log );
	}

	/**
	 * Seeds the settings option with defaults, preserving anything already set.
	 *
	 * @return void
	 */
	private static function seed_default_settings() {
		$existing = get_option( KDNA_Sentinel_Core::OPTION, array() );
		if ( ! is_array( $existing ) ) {
			$existing = array();
		}

		$settings = wp_parse_args( $existing, KDNA_Sentinel_Core::default_settings() );
		update_option( KDNA_Sentinel_Core::OPTION, $settings );
	}
}
