<?php
/**
 * Guard quarantine store, release and maintenance.
 *
 * Persists every blocked/spam submission, drives the admin list view and its
 * row actions (release / delete / block IP), and runs the daily 30-day purge.
 *
 * Release re-runs the genuine processing path: for KDNA Forms it un-flags the
 * stored entry and re-sends its notifications; for other sources it notifies
 * the site admin with the captured details (WooCommerce account/checkout/review
 * completion can't be safely replayed from a privacy-limited payload), and a
 * kdna_sentinel_guard_release filter lets integrators fully handle any source.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard_Quarantine
 */
final class KDNA_Sentinel_Guard_Quarantine {

	/**
	 * Cron hook that runs the purge.
	 */
	const PURGE_HOOK = 'kdna_sentinel_guard_purge';

	/**
	 * admin-post action for row actions.
	 */
	const ACTION = 'kdna_sentinel_quarantine';

	/**
	 * Rows are kept for this many days.
	 */
	const RETENTION_DAYS = 30;

	/**
	 * Singleton.
	 *
	 * @var KDNA_Sentinel_Guard_Quarantine|null
	 */
	private static $instance = null;

	/**
	 * @return KDNA_Sentinel_Guard_Quarantine
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Registers hooks. Safe to call on every request.
	 *
	 * @return void
	 */
	public function register() {
		// Store on every block/spam verdict (only fires when Guard is active).
		add_action( 'kdna_sentinel_guard_blocked', array( $this, 'store' ), 10, 2 );

		// Daily purge (self-heals the schedule if missing).
		if ( ! wp_next_scheduled( self::PURGE_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::PURGE_HOOK );
		}
		add_action( self::PURGE_HOOK, array( $this, 'purge' ) );

		// Row-action handler (admin only).
		if ( is_admin() ) {
			add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_action' ) );
		}
	}

	/**
	 * Fully-qualified table name.
	 *
	 * @return string
	 */
	private function table() {
		return KDNA_Sentinel_Core::table( 'quarantine' );
	}

	/*
	 * =====================================================================
	 * Store
	 * =====================================================================
	 */

	/**
	 * Persists a blocked submission.
	 *
	 * @param mixed $verdict The verdict object (reason()/score()).
	 * @param array $meta    Source/form/ip/payload.
	 * @return void
	 */
	public function store( $verdict, $meta ) {
		global $wpdb;

		if ( ! is_array( $meta ) ) {
			return;
		}

		$reason = '';
		$score  = null;
		if ( is_object( $verdict ) && method_exists( $verdict, 'reason' ) ) {
			$reason = (string) $verdict->reason();
			$score  = $verdict->score();
		}

		$payload = isset( $meta['payload'] ) ? $meta['payload'] : array();

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$this->table(),
			array(
				'form_source' => substr( (string) ( isset( $meta['source'] ) ? $meta['source'] : '' ), 0, 50 ),
				'form_id'     => substr( (string) ( isset( $meta['form_id'] ) ? $meta['form_id'] : '' ), 0, 50 ),
				'payload'     => wp_json_encode( $payload ),
				'reason'      => substr( $reason, 0, 255 ),
				'score'       => ( null === $score ) ? null : (float) $score,
				'ip'          => substr( (string) ( isset( $meta['ip'] ) ? $meta['ip'] : '' ), 0, 100 ),
				'created_at'  => gmdate( 'Y-m-d H:i:s' ),
				'released'    => 0,
			),
			array( '%s', '%s', '%s', '%s', '%f', '%s', '%s', '%d' )
		);
	}

	/*
	 * =====================================================================
	 * Queries
	 * =====================================================================
	 */

	/**
	 * Counts held (unreleased) rows.
	 *
	 * @return int
	 */
	public function count() {
		global $wpdb;

		$table = $this->table();

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE released = 0" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Returns a page of held rows, newest first.
	 *
	 * @param int $per_page Rows per page.
	 * @param int $offset   Offset.
	 * @return array
	 */
	public function get_items( $per_page, $offset ) {
		global $wpdb;

		$table = $this->table();

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE released = 0 ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				max( 1, (int) $per_page ),
				max( 0, (int) $offset )
			),
			ARRAY_A
		);
	}

	/**
	 * Fetches a single row.
	 *
	 * @param int $id Row id.
	 * @return array|null
	 */
	public function get_item( $id ) {
		global $wpdb;

		$table = $this->table();
		$row   = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		return $row ? $row : null;
	}

	/*
	 * =====================================================================
	 * Actions
	 * =====================================================================
	 */

	/**
	 * Handles a nonce-protected row action from admin-post.php.
	 *
	 * @return void
	 */
	public function handle_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'kdna-sentinel' ) );
		}

		$do = isset( $_GET['do'] ) ? sanitize_key( wp_unslash( $_GET['do'] ) ) : '';
		$id = isset( $_GET['item'] ) ? absint( $_GET['item'] ) : 0;

		check_admin_referer( self::ACTION . '_' . $do . '_' . $id );

		$notice = 'error';
		switch ( $do ) {
			case 'release':
				$notice = $this->release( $id ) ? 'released' : 'release_failed';
				break;
			case 'delete':
				$this->delete( $id );
				$notice = 'deleted';
				break;
			case 'block_ip':
				$notice = $this->block_ip( $id ) ? 'blocked' : 'error';
				break;
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'kdna-sentinel',
					'tab'         => 'guard',
					'kdna_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Deletes a row.
	 *
	 * @param int $id Row id.
	 * @return void
	 */
	public function delete( $id ) {
		global $wpdb;

		$wpdb->delete( $this->table(), array( 'id' => (int) $id ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Adds a row's IP to the Guard blocklist.
	 *
	 * @param int $id Row id.
	 * @return bool
	 */
	public function block_ip( $id ) {
		$item = $this->get_item( $id );
		if ( ! $item ) {
			return false;
		}

		$ip = isset( $item['ip'] ) ? trim( (string) $item['ip'] ) : '';
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$settings = get_option( KDNA_Sentinel_Core::OPTION, array() );
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}

		$raw  = isset( $settings['guard_ip_blocklist'] ) ? (string) $settings['guard_ip_blocklist'] : '';
		$list = array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', $raw ) ) );

		if ( ! in_array( $ip, $list, true ) ) {
			$list[]                        = $ip;
			$settings['guard_ip_blocklist'] = implode( "\n", $list );
			update_option( KDNA_Sentinel_Core::OPTION, $settings );
			KDNA_Sentinel_Core::instance()->flush_settings_cache();
		}

		return true;
	}

	/**
	 * Releases a held submission and re-runs its genuine processing path.
	 *
	 * @param int $id Row id.
	 * @return bool
	 */
	public function release( $id ) {
		$item = $this->get_item( $id );
		if ( ! $item ) {
			return false;
		}

		// Mark released first so it cannot be re-blocked or double-released.
		$this->mark_released( $id );

		/**
		 * Lets an integrator fully handle release for any source. Return a
		 * boolean to short-circuit the default handling; return null to fall
		 * through to it.
		 *
		 * @param bool|null $handled Default null (fall through).
		 * @param array     $item    The quarantine row.
		 */
		$handled = apply_filters( 'kdna_sentinel_guard_release', null, $item );
		if ( null !== $handled ) {
			return (bool) $handled;
		}

		if ( 'kdna_forms' === $item['form_source'] ) {
			return $this->release_kdna_forms( $item );
		}

		return $this->notify_admin( $item );
	}

	/**
	 * Marks a row released.
	 *
	 * @param int $id Row id.
	 * @return void
	 */
	private function mark_released( $id ) {
		global $wpdb;

		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$this->table(),
			array( 'released' => 1 ),
			array( 'id' => (int) $id ),
			array( '%d' ),
			array( '%d' )
		);
	}

	/**
	 * Re-processes a KDNA Forms submission through the genuine path.
	 *
	 * The entry was saved (flagged spam) when Guard intercepted it, so release
	 * un-flags it and re-sends its notifications — exactly as an un-flagged
	 * submission would have.
	 *
	 * @param array $item The quarantine row.
	 * @return bool
	 */
	private function release_kdna_forms( array $item ) {
		$entry = json_decode( (string) $item['payload'], true );
		if ( ! is_array( $entry ) ) {
			return $this->notify_admin( $item );
		}

		$entry_id = isset( $entry['id'] ) ? absint( $entry['id'] ) : 0;
		$form_id  = isset( $entry['form_id'] ) ? absint( $entry['form_id'] ) : absint( $item['form_id'] );

		if ( $entry_id && class_exists( 'KDNAFormsModel' ) && class_exists( 'KDNACommon' ) && class_exists( 'KDNAAPI' ) ) {
			$form = KDNAAPI::get_form( $form_id );
			KDNAFormsModel::update_entry_property( $entry_id, 'status', 'active' );
			if ( $form ) {
				KDNACommon::send_form_submission_notifications( $form, $entry );
			}
			return true;
		}

		// KDNA Forms not available (or entry not persisted) — don't lose it.
		return $this->notify_admin( $item );
	}

	/**
	 * Emails the site admin the captured submission so it is never lost.
	 *
	 * @param array $item The quarantine row.
	 * @return bool
	 */
	private function notify_admin( array $item ) {
		$to      = get_option( 'admin_email' );
		$subject = __( 'KDNA Sentinel: released quarantined submission', 'kdna-sentinel' );

		$lines   = array();
		$lines[] = __( 'A quarantined submission was marked genuine and released.', 'kdna-sentinel' );
		$lines[] = '';
		$lines[] = sprintf( '%s: %s', __( 'Source', 'kdna-sentinel' ), (string) $item['form_source'] );
		$lines[] = sprintf( '%s: %s', __( 'Form', 'kdna-sentinel' ), (string) $item['form_id'] );
		$lines[] = sprintf( '%s: %s', __( 'IP', 'kdna-sentinel' ), (string) $item['ip'] );
		$lines[] = sprintf( '%s: %s', __( 'Reason', 'kdna-sentinel' ), (string) $item['reason'] );
		$lines[] = '';
		$lines[] = __( 'Submission:', 'kdna-sentinel' );

		$payload = json_decode( (string) $item['payload'], true );
		if ( is_array( $payload ) ) {
			foreach ( $payload as $key => $value ) {
				if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
					$lines[] = sprintf( '  %s: %s', $key, (string) $value );
				}
			}
		}

		return (bool) wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	/*
	 * =====================================================================
	 * Purge
	 * =====================================================================
	 */

	/**
	 * Deletes rows older than the retention window (released or not).
	 *
	 * @return int Rows deleted.
	 */
	public function purge() {
		global $wpdb;

		$table  = $this->table();
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( self::RETENTION_DAYS * DAY_IN_SECONDS ) );

		return (int) $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	/*
	 * =====================================================================
	 * Presentation helpers (shared with the list table)
	 * =====================================================================
	 */

	/**
	 * Human-readable label for a source slug.
	 *
	 * @param string $source Source slug.
	 * @return string
	 */
	public function source_label( $source ) {
		$labels = array(
			'kdna_forms'                => __( 'KDNA Forms', 'kdna-sentinel' ),
			'woocommerce_registration'  => __( 'Woo registration', 'kdna-sentinel' ),
			'woocommerce_login'         => __( 'Woo login', 'kdna-sentinel' ),
			'woocommerce_lostpassword'  => __( 'Woo lost password', 'kdna-sentinel' ),
			'woocommerce_checkout'      => __( 'Woo checkout', 'kdna-sentinel' ),
			'woocommerce_review'        => __( 'Woo review', 'kdna-sentinel' ),
		);

		return isset( $labels[ $source ] ) ? $labels[ $source ] : (string) $source;
	}

	/**
	 * Best-effort "from" (an email, else the first non-empty value).
	 *
	 * @param array $item The quarantine row.
	 * @return string
	 */
	public function format_from( array $item ) {
		$payload = json_decode( (string) $item['payload'], true );
		if ( ! is_array( $payload ) ) {
			return '';
		}

		foreach ( $payload as $value ) {
			if ( is_string( $value ) && false !== strpos( $value, '@' ) && false !== filter_var( $value, FILTER_VALIDATE_EMAIL ) ) {
				return $value;
			}
		}

		foreach ( $payload as $value ) {
			if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
				$value = (string) $value;
				return ( strlen( $value ) > 60 ) ? substr( $value, 0, 60 ) . '…' : $value;
			}
		}

		return '';
	}

	/**
	 * Builds a nonce-protected admin-post URL for a row action.
	 *
	 * @param string $do   Action (release|delete|block_ip).
	 * @param int    $id   Row id.
	 * @return string
	 */
	public function action_url( $do, $id ) {
		$url = add_query_arg(
			array(
				'action' => self::ACTION,
				'do'     => $do,
				'item'   => (int) $id,
			),
			admin_url( 'admin-post.php' )
		);

		return wp_nonce_url( $url, self::ACTION . '_' . $do . '_' . (int) $id );
	}

	/**
	 * Renders the quarantine list table into the Guard tab.
	 *
	 * @return void
	 */
	public function render_list() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
		require_once KDNA_SENTINEL_DIR . 'includes/guard/class-guard-quarantine-list-table.php';

		$table = new KDNA_Sentinel_Guard_Quarantine_List_Table( $this );
		$table->prepare_items();

		echo '<hr class="kdna-sentinel-sep" />';
		echo '<h2>' . esc_html__( 'Quarantine', 'kdna-sentinel' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Submissions Guard held. Preview each one, and release any genuine enquiry to process it as if it had passed.', 'kdna-sentinel' ) . '</p>';

		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="kdna-sentinel" />';
		echo '<input type="hidden" name="tab" value="guard" />';
		$table->display();
		echo '</form>';
	}
}
