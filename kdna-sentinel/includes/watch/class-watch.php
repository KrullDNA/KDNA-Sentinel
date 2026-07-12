<?php
/**
 * Watch module bootstrap.
 *
 * Loaded by the core module loader only when the Watch master toggle is on.
 * Builds the scanner and registers the daily scan cron and the manual
 * "Scan now" action.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Watch
 */
final class KDNA_Sentinel_Watch {

	/**
	 * Daily scan cron hook.
	 */
	const SCAN_CRON = 'kdna_sentinel_watch_scan';

	/**
	 * admin-post action for the manual scan.
	 */
	const SCAN_ACTION = 'kdna_sentinel_watch_scan_now';

	/**
	 * Singleton.
	 *
	 * @var KDNA_Sentinel_Watch|null
	 */
	private static $instance = null;

	/**
	 * The scanner.
	 *
	 * @var KDNA_Sentinel_Watch_Scanner
	 */
	private $scanner;

	/**
	 * @return KDNA_Sentinel_Watch
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->boot();
		}

		return self::$instance;
	}

	/**
	 * Loads dependencies, builds the scanner, registers hooks.
	 *
	 * @return void
	 */
	private function boot() {
		require_once KDNA_SENTINEL_DIR . 'includes/watch/class-watch-scanner.php';

		$core = KDNA_Sentinel_Core::instance();

		$this->scanner = new KDNA_Sentinel_Watch_Scanner(
			(string) $core->get_setting( 'watch_provider', 'wpscan' ),
			(string) $core->get_setting( 'watch_api_key', '' )
		);

		// Daily scan (self-heals the schedule).
		if ( ! wp_next_scheduled( self::SCAN_CRON ) ) {
			wp_schedule_event( time(), 'daily', self::SCAN_CRON );
		}
		add_action( self::SCAN_CRON, array( $this, 'run_scan' ) );

		// Manual "Scan now".
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::SCAN_ACTION, array( $this, 'handle_manual_scan' ) );
		}
	}

	/**
	 * The scanner (for the dashboard view).
	 *
	 * @return KDNA_Sentinel_Watch_Scanner
	 */
	public function scanner() {
		return $this->scanner;
	}

	/**
	 * Cron callback.
	 *
	 * @return void
	 */
	public function run_scan() {
		$this->scanner->scan();
	}

	/**
	 * Handles the manual scan (nonce + capability gated), then redirects back.
	 *
	 * @return void
	 */
	public function handle_manual_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'kdna-sentinel' ) );
		}

		check_admin_referer( self::SCAN_ACTION );

		$status = $this->scanner->scan();
		$notice = isset( $status['result'] ) ? 'scan_' . $status['result'] : 'scan_error';

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'kdna-sentinel',
					'tab'         => 'watch',
					'kdna_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
