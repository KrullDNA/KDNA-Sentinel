<?php
/**
 * Watch scanner: reads installed plugins, checks them against a vulnerability
 * provider, caches at-risk findings, and prepares the dashboard.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Watch_Scanner
 */
class KDNA_Sentinel_Watch_Scanner {

	/**
	 * Option holding the last-scan status.
	 */
	const STATUS_OPTION = 'kdna_sentinel_watch_status';

	/**
	 * Severity ranking for worst-first sorting.
	 *
	 * @var array
	 */
	private static $rank = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
		'unknown'  => 0,
	);

	/**
	 * Configured provider slug.
	 *
	 * @var string
	 */
	private $provider_slug;

	/**
	 * Provider API key.
	 *
	 * @var string
	 */
	private $api_key;

	/**
	 * Constructor.
	 *
	 * @param string $provider_slug Provider slug.
	 * @param string $api_key       API key.
	 */
	public function __construct( $provider_slug, $api_key ) {
		$this->provider_slug = (string) $provider_slug;
		$this->api_key       = (string) $api_key;
	}

	/**
	 * Vuln-cache table name.
	 *
	 * @return string
	 */
	private function table() {
		return KDNA_Sentinel_Core::table( 'vuln_cache' );
	}

	/**
	 * Runs a scan across all installed plugins.
	 *
	 * Cache is replaced per plugin, so a mid-scan rate-limit leaves already
	 * scanned plugins fresh and the rest as previously cached.
	 *
	 * @return array The status recorded.
	 */
	public function scan() {
		if ( '' === trim( $this->api_key ) ) {
			return $this->record_status( 'no_key', __( 'No vulnerability API key set.', 'kdna-sentinel' ), 0, 0 );
		}

		require_once KDNA_SENTINEL_DIR . 'includes/watch/class-watch-providers.php';
		$provider = KDNA_Sentinel_Watch_Providers::make( $this->provider_slug, $this->api_key );

		$plugins  = $this->installed_plugins();
		$scanned  = 0;
		$rate_hit = false;

		foreach ( $plugins as $slug => $info ) {
			$result = $provider->get_plugin_vulnerabilities( $slug );
			$status = isset( $result['status'] ) ? $result['status'] : 'error';

			if ( 'rate_limited' === $status ) {
				$rate_hit = true;
				break; // Back off: stop hitting the API this run.
			}

			if ( 'ok' === $status ) {
				$applicable = $this->applicable_vulns( $info['version'], $result['vulns'] );
				$this->replace_cache( $slug, $info['version'], $applicable );
				$scanned++;
			} elseif ( 'not_found' === $status ) {
				// No known vulns for this plugin — clear any stale cache.
				$this->clear_cache( $slug );
				$scanned++;
			}
			// 'error'/'no_key' for a single plugin: leave its cache untouched.
		}

		$at_risk = $this->count_at_risk();

		if ( $rate_hit ) {
			$status = $this->record_status( 'rate_limited', __( 'Rate limited by the API; scan paused. Partial results saved.', 'kdna-sentinel' ), $at_risk, $scanned );
		} else {
			$status = $this->record_status( 'ok', __( 'Scan complete.', 'kdna-sentinel' ), $at_risk, $scanned );
		}

		/**
		 * Fires after a scan completes (cron or manual). The alerts layer hooks
		 * this to send instant critical alerts on newly-detected CVEs.
		 *
		 * @param KDNA_Sentinel_Watch_Scanner $scanner The scanner.
		 * @param array                       $status  The recorded status.
		 */
		do_action( 'kdna_sentinel_watch_scan_complete', $this, $status );

		return $status;
	}

	/**
	 * Reads installed plugins as slug => { version, file, name }.
	 *
	 * @return array
	 */
	public function installed_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = $this->slug_from_file( $file );
			if ( '' === $slug ) {
				continue;
			}
			$out[ $slug ] = array(
				'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'file'    => $file,
				'name'    => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
			);
		}

		return $out;
	}

	/**
	 * Derives a wordpress.org-style slug from a plugin file path.
	 *
	 * @param string $file e.g. "akismet/akismet.php" or "hello.php".
	 * @return string
	 */
	private function slug_from_file( $file ) {
		$dir = dirname( $file );
		if ( '.' !== $dir && '' !== $dir ) {
			return $dir;
		}

		return preg_replace( '/\.php$/', '', basename( $file ) );
	}

	/**
	 * Filters provider vulns to those affecting the installed version.
	 *
	 * @param string $installed Installed version.
	 * @param array  $vulns     Provider vulns.
	 * @return array
	 */
	private function applicable_vulns( $installed, $vulns ) {
		$out = array();
		foreach ( (array) $vulns as $v ) {
			if ( $this->is_vulnerable( $installed, isset( $v['fixed_in'] ) ? $v['fixed_in'] : '' ) ) {
				$out[] = $v;
			}
		}

		return $out;
	}

	/**
	 * Whether an installed version is affected by a vuln fixed in $fixed_in.
	 *
	 * @param string $installed Installed version.
	 * @param string $fixed_in  Version the vuln is fixed in ('' = no fix).
	 * @return bool
	 */
	public function is_vulnerable( $installed, $fixed_in ) {
		$fixed_in  = (string) $fixed_in;
		$installed = (string) $installed;

		if ( '' === $fixed_in ) {
			return true; // No fix available: still vulnerable.
		}
		if ( '' === $installed ) {
			return true; // Unknown installed version: be cautious.
		}

		return version_compare( $installed, $fixed_in, '<' );
	}

	/*
	 * =====================================================================
	 * Cache
	 * =====================================================================
	 */

	/**
	 * Replaces the cached findings for one plugin.
	 *
	 * @param string $slug      Plugin slug.
	 * @param string $installed Installed version.
	 * @param array  $vulns     Applicable vulns.
	 * @return void
	 */
	private function replace_cache( $slug, $installed, $vulns ) {
		$this->clear_cache( $slug );

		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );

		foreach ( $vulns as $v ) {
			$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$this->table(),
				array(
					'plugin_slug'   => substr( (string) $slug, 0, 191 ),
					'installed_ver' => substr( (string) $installed, 0, 50 ),
					'vuln_id'       => substr( (string) $v['vuln_id'], 0, 100 ),
					'severity'      => substr( (string) $v['severity'], 0, 20 ),
					'fixed_in'      => substr( (string) $v['fixed_in'], 0, 50 ),
					'fixed_at'      => isset( $v['fixed_at'] ) ? $v['fixed_at'] : null,
					'detected_at'   => $now,
				),
				array( '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
			);
		}
	}

	/**
	 * Removes cached rows for a plugin.
	 *
	 * @param string $slug Plugin slug.
	 * @return void
	 */
	private function clear_cache( $slug ) {
		global $wpdb;

		$wpdb->delete( $this->table(), array( 'plugin_slug' => (string) $slug ), array( '%s' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Counts cached at-risk rows.
	 *
	 * @return int
	 */
	public function count_at_risk() {
		global $wpdb;
		$table = $this->table();

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Returns all cached rows.
	 *
	 * @return array
	 */
	public function get_cached() {
		global $wpdb;
		$table = $this->table();

		return (array) $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/*
	 * =====================================================================
	 * Status
	 * =====================================================================
	 */

	/**
	 * Records and returns the scan status.
	 *
	 * @param string $result  ok|rate_limited|error|no_key.
	 * @param string $message Human message.
	 * @param int    $at_risk At-risk plugin count.
	 * @param int    $scanned Plugins scanned.
	 * @return array
	 */
	private function record_status( $result, $message, $at_risk, $scanned ) {
		$status = array(
			'result'   => $result,
			'message'  => $message,
			'at_risk'  => (int) $at_risk,
			'scanned'  => (int) $scanned,
			'last_run' => gmdate( 'Y-m-d H:i:s' ),
		);

		update_option( self::STATUS_OPTION, $status, false );

		return $status;
	}

	/**
	 * Returns the last-scan status, or null if never scanned.
	 *
	 * @return array|null
	 */
	public function get_status() {
		$status = get_option( self::STATUS_OPTION, null );

		return is_array( $status ) ? $status : null;
	}

	/*
	 * =====================================================================
	 * Dashboard
	 * =====================================================================
	 */

	/**
	 * Builds the dashboard rows (enriched + sorted worst-first).
	 *
	 * @return array
	 */
	public function get_dashboard_items() {
		$rows    = $this->get_cached();
		$plugins = $this->installed_plugins();

		// Map slug => plugin info for name + update link.
		$items = array();
		foreach ( $rows as $row ) {
			$slug = $row['plugin_slug'];
			$info = isset( $plugins[ $slug ] ) ? $plugins[ $slug ] : array( 'name' => $slug, 'file' => '' );

			$row['plugin_name'] = $info['name'];
			$row['plugin_file'] = $info['file'];
			$row['patch_lag']   = $this->patch_lag_days( $row['fixed_at'] );
			$row['rank']        = isset( self::$rank[ $row['severity'] ] ) ? self::$rank[ $row['severity'] ] : 0;

			$items[] = $row;
		}

		// Worst-first: severity desc, then longest patch lag desc.
		usort(
			$items,
			static function ( $a, $b ) {
				if ( $a['rank'] !== $b['rank'] ) {
					return $b['rank'] - $a['rank'];
				}
				$la = ( null === $a['patch_lag'] ) ? -1 : $a['patch_lag'];
				$lb = ( null === $b['patch_lag'] ) ? -1 : $b['patch_lag'];

				return $lb - $la;
			}
		);

		return $items;
	}

	/**
	 * Days since the fix was available, or null if unknown.
	 *
	 * @param string|null $fixed_at UTC datetime.
	 * @return int|null
	 */
	private function patch_lag_days( $fixed_at ) {
		if ( empty( $fixed_at ) ) {
			return null;
		}
		$ts = strtotime( $fixed_at . ' UTC' );
		if ( ! $ts ) {
			return null;
		}

		return max( 0, (int) floor( ( time() - $ts ) / DAY_IN_SECONDS ) );
	}

	/**
	 * Builds a direct update link for a plugin file when an update is available.
	 *
	 * @param string $plugin_file Plugin file path.
	 * @return string
	 */
	public function update_link( $plugin_file ) {
		if ( '' === $plugin_file ) {
			return self_admin_url( 'plugins.php' );
		}

		$updates = get_site_transient( 'update_plugins' );
		if ( is_object( $updates ) && ! empty( $updates->response[ $plugin_file ] ) ) {
			return wp_nonce_url(
				self_admin_url( 'update.php?action=upgrade-plugin&plugin=' . rawurlencode( $plugin_file ) ),
				'upgrade-plugin_' . $plugin_file
			);
		}

		return self_admin_url( 'plugins.php' );
	}
}
