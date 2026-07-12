<?php
/**
 * Hub receiver + master dashboard.
 *
 * Active only when "This site is the KDNA hub" is enabled. Registers the REST
 * route that reporting client sites POST to, verifies the HMAC signature
 * against the stored shared secret, stores accepted reports, and renders the
 * aggregate dashboard of every reporting site.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Hub_Endpoint
 */
final class KDNA_Sentinel_Hub_Endpoint {

	/**
	 * REST namespace + route.
	 */
	const NAMESPACE = 'kdna-sentinel/v1';
	const ROUTE     = '/report';

	/**
	 * A check-in older than this many days is "stale".
	 */
	const STALE_DAYS = 2;

	/**
	 * Singleton.
	 *
	 * @var KDNA_Sentinel_Hub_Endpoint|null
	 */
	private static $instance = null;

	/**
	 * @return KDNA_Sentinel_Hub_Endpoint
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->register();
		}

		return self::$instance;
	}

	/**
	 * Registers the REST route.
	 *
	 * @return void
	 */
	private function register() {
		add_action( 'rest_api_init', array( $this, 'register_route' ) );
	}

	/**
	 * @return void
	 */
	public function register_route() {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_report' ),
				// Machine traffic is authenticated by the HMAC in handle_report().
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * hub_log table name.
	 *
	 * @return string
	 */
	private function table() {
		return KDNA_Sentinel_Core::table( 'hub_log' );
	}

	/**
	 * Handles an incoming report: verify HMAC, then store.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function handle_report( $request ) {
		$secret = (string) KDNA_Sentinel_Core::instance()->get_setting( 'hub_secret', '' );
		if ( '' === $secret ) {
			return new WP_REST_Response( array( 'error' => 'hub_not_configured' ), 503 );
		}

		$body = $request->get_body();
		$sig  = (string) $request->get_header( 'X-KDNA-Signature' );

		if ( '' === $sig ) {
			return new WP_REST_Response( array( 'error' => 'missing_signature' ), 401 );
		}

		$expected = hash_hmac( 'sha256', $body, $secret );
		if ( ! hash_equals( $expected, $sig ) ) {
			return new WP_REST_Response( array( 'error' => 'invalid_signature' ), 401 );
		}

		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || empty( $data['site'] ) ) {
			return new WP_REST_Response( array( 'error' => 'invalid_payload' ), 400 );
		}

		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$this->table(),
			array(
				'site_url'    => substr( esc_url_raw( $data['site'] ), 0, 255 ),
				'payload'     => $body,
				'received_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s' )
		);

		return new WP_REST_Response( array( 'ok' => true ), 200 );
	}

	/**
	 * Latest report per reporting site, newest first.
	 *
	 * @return array
	 */
	public function get_latest_reports() {
		global $wpdb;
		$table = $this->table();

		$rows = (array) $wpdb->get_results( "SELECT * FROM {$table} ORDER BY received_at DESC", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		$seen   = array();
		$latest = array();
		foreach ( $rows as $row ) {
			if ( ! isset( $seen[ $row['site_url'] ] ) ) {
				$seen[ $row['site_url'] ] = true;
				$latest[]                 = $row;
			}
		}

		return $latest;
	}

	/**
	 * Whether a check-in timestamp is stale.
	 *
	 * @param string $received_at UTC datetime.
	 * @return bool
	 */
	private function is_stale( $received_at ) {
		$ts = strtotime( $received_at . ' UTC' );

		return ! $ts || ( time() - $ts ) > ( self::STALE_DAYS * DAY_IN_SECONDS );
	}

	/**
	 * Renders the hub dashboard table into the Hub tab.
	 *
	 * @return void
	 */
	public function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$reports = $this->get_latest_reports();

		echo '<hr class="kdna-sentinel-sep" />';
		echo '<h2>' . esc_html__( 'Hub dashboard', 'kdna-sentinel' ) . '</h2>';

		if ( empty( $reports ) ) {
			echo '<p class="description">' . esc_html__( 'No sites have reported in yet.', 'kdna-sentinel' ) . '</p>';
			return;
		}

		echo '<table class="widefat striped kdna-sentinel-vuln-table" style="margin-top:12px;"><thead><tr>';
		echo '<th>' . esc_html__( 'Site', 'kdna-sentinel' ) . '</th>';
		echo '<th>' . esc_html__( 'Worst severity', 'kdna-sentinel' ) . '</th>';
		echo '<th>' . esc_html__( 'At-risk plugins', 'kdna-sentinel' ) . '</th>';
		echo '<th>' . esc_html__( 'Longest patch lag', 'kdna-sentinel' ) . '</th>';
		echo '<th>' . esc_html__( 'Last check-in', 'kdna-sentinel' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $reports as $row ) {
			$data     = json_decode( (string) $row['payload'], true );
			$worst    = is_array( $data ) && ! empty( $data['worst_severity'] ) ? (string) $data['worst_severity'] : 'unknown';
			$at_risk  = is_array( $data ) && isset( $data['at_risk'] ) ? (int) $data['at_risk'] : 0;
			$lag      = is_array( $data ) && isset( $data['longest_patch_lag'] ) ? (int) $data['longest_patch_lag'] : 0;
			$stale    = $this->is_stale( $row['received_at'] );
			$critical = ( 'critical' === $worst );
			$flag     = ( $critical || $stale );

			$flags = array();
			if ( $critical ) {
				$flags[] = esc_html__( 'CRITICAL', 'kdna-sentinel' );
			}
			if ( $stale ) {
				$flags[] = esc_html__( 'STALE', 'kdna-sentinel' );
			}

			printf(
				'<tr%s><td><strong>%s</strong>%s</td><td><span class="kdna-sev kdna-sev-%s">%s</span></td><td>%d</td><td>%s</td><td>%s</td></tr>',
				$flag ? ' style="background:#fcf0f1;"' : '',
				esc_html( $row['site_url'] ),
				$flags ? ' <span class="kdna-flag">' . implode( ' ', $flags ) . '</span>' : '', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_attr( $worst ),
				esc_html( ucfirst( $worst ) ),
				$at_risk,
				$lag > 0 ? esc_html( sprintf( /* translators: %d: days. */ _n( '%d day', '%d days', $lag, 'kdna-sentinel' ), $lag ) ) : '&mdash;',
				esc_html( human_time_diff( strtotime( $row['received_at'] . ' UTC' ), time() ) . ' ' . __( 'ago', 'kdna-sentinel' ) )
			);
		}

		echo '</tbody></table>';
	}
}
