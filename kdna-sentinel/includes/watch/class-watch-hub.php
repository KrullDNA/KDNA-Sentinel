<?php
/**
 * Watch hub client — optional report-in.
 *
 * Off by default. When "Report to KDNA hub" is enabled, after each scan this
 * POSTs a compact, HMAC-signed metadata summary (site URL, plugin risk list,
 * worst severity, timestamp) to the hub's REST endpoint. Never sends submission
 * content or personal data — only plugin/version/vuln metadata.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Watch_Hub
 */
class KDNA_Sentinel_Watch_Hub {

	/**
	 * REST path appended to the hub base URL.
	 */
	const REST_PATH = 'wp-json/kdna-sentinel/v1/report';

	/**
	 * Severity order, worst first.
	 *
	 * @var array
	 */
	private static $order = array( 'critical', 'high', 'medium', 'low', 'unknown' );

	/**
	 * Core.
	 *
	 * @var KDNA_Sentinel_Core
	 */
	private $core;

	/**
	 * Constructor.
	 *
	 * @param KDNA_Sentinel_Core $core Core.
	 */
	public function __construct( $core ) {
		$this->core = $core;
	}

	/**
	 * Registers the after-scan report.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'kdna_sentinel_watch_scan_complete', array( $this, 'report' ), 30, 2 );
	}

	/**
	 * Reports the current scan summary to the hub.
	 *
	 * @param KDNA_Sentinel_Watch_Scanner|null $scanner Scanner.
	 * @param array|null                       $status  Scan status (unused).
	 * @return void
	 */
	public function report( $scanner = null, $status = null ) {
		if ( ! $this->core->get_setting( 'hub_report_enabled', 0 ) ) {
			return;
		}

		$url    = trim( (string) $this->core->get_setting( 'hub_url', '' ) );
		$secret = (string) $this->core->get_setting( 'hub_secret', '' );

		if ( '' === $url || '' === $secret || ! $scanner ) {
			return; // Not configured — nothing to do.
		}

		$body = wp_json_encode( $this->build_summary( $scanner->get_dashboard_items() ) );
		$sig  = hash_hmac( 'sha256', $body, $secret );

		wp_remote_post(
			trailingslashit( $url ) . self::REST_PATH,
			array(
				'timeout'  => 5,
				'blocking' => false, // Fire-and-forget so a scan is never slowed.
				'headers'  => array(
					'Content-Type'     => 'application/json',
					'X-KDNA-Signature' => $sig,
				),
				'body'     => $body,
			)
		);
	}

	/**
	 * Builds the metadata-only summary. No submission content, no PII.
	 *
	 * @param array $items Dashboard items.
	 * @return array
	 */
	private function build_summary( $items ) {
		$plugins = array();
		$worst   = '';
		$max_lag = 0;

		foreach ( $items as $i ) {
			$plugins[] = array(
				'slug'      => $i['plugin_slug'],
				'name'      => $i['plugin_name'],
				'installed' => $i['installed_ver'],
				'severity'  => $i['severity'],
				'fixed_in'  => $i['fixed_in'],
				'patch_lag' => $i['patch_lag'],
			);

			$worst = $this->worse_of( $worst, $i['severity'] );

			if ( null !== $i['patch_lag'] && (int) $i['patch_lag'] > $max_lag ) {
				$max_lag = (int) $i['patch_lag'];
			}
		}

		return array(
			'site'              => home_url(),
			'worst_severity'    => $worst,
			'at_risk'           => count( $items ),
			'longest_patch_lag' => $max_lag,
			'plugins'           => $plugins,
			'timestamp'         => gmdate( 'c' ),
		);
	}

	/**
	 * Returns whichever of two severities is worse.
	 *
	 * @param string $a First (may be '').
	 * @param string $b Second.
	 * @return string
	 */
	private function worse_of( $a, $b ) {
		if ( '' === $a ) {
			return $b;
		}
		$ia = array_search( $a, self::$order, true );
		$ib = array_search( $b, self::$order, true );
		$ia = ( false === $ia ) ? count( self::$order ) : $ia;
		$ib = ( false === $ib ) ? count( self::$order ) : $ib;

		return ( $ib < $ia ) ? $b : $a;
	}
}
