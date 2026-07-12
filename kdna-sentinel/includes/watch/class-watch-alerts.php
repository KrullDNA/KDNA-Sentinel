<?php
/**
 * Watch alerts: digest email + instant critical alert.
 *
 * The digest is a daily/weekly summary of all current at-risk plugins. The
 * instant alert fires the moment a scan newly detects a CRITICAL vulnerability,
 * de-duplicated so the same CVE does not re-alert every scan. Digest and
 * critical alerts go to their own comma-separated recipient lists (each
 * defaulting to the WordPress admin email). All mail is HTML with a plain-text
 * fallback.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Watch_Alerts
 */
class KDNA_Sentinel_Watch_Alerts {

	/**
	 * Daily digest cron hook (frequency is decided inside the handler).
	 */
	const DIGEST_CRON = 'kdna_sentinel_watch_digest';

	/**
	 * Option: date the digest was last sent (Y-m-d).
	 */
	const LAST_DIGEST_OPTION = 'kdna_sentinel_watch_last_digest';

	/**
	 * Option: vuln_ids already alerted on (for de-duplication).
	 */
	const ALERTED_OPTION = 'kdna_sentinel_watch_alerted';

	/**
	 * Core.
	 *
	 * @var KDNA_Sentinel_Core
	 */
	private $core;

	/**
	 * Scanner (for current findings).
	 *
	 * @var KDNA_Sentinel_Watch_Scanner
	 */
	private $scanner;

	/**
	 * Constructor.
	 *
	 * @param KDNA_Sentinel_Core          $core    Core.
	 * @param KDNA_Sentinel_Watch_Scanner $scanner Scanner.
	 */
	public function __construct( $core, $scanner ) {
		$this->core    = $core;
		$this->scanner = $scanner;
	}

	/**
	 * Registers hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'kdna_sentinel_watch_scan_complete', array( $this, 'check_instant_alerts' ) );

		if ( ! wp_next_scheduled( self::DIGEST_CRON ) ) {
			wp_schedule_event( time(), 'daily', self::DIGEST_CRON );
		}
		add_action( self::DIGEST_CRON, array( $this, 'maybe_send_digest' ) );
	}

	/*
	 * =====================================================================
	 * Instant critical alerts
	 * =====================================================================
	 */

	/**
	 * Sends an instant alert for any newly-detected critical vulnerability.
	 *
	 * @return void
	 */
	public function check_instant_alerts() {
		if ( ! $this->core->get_setting( 'watch_instant_alerts', 1 ) ) {
			return;
		}

		$items     = $this->scanner->get_dashboard_items();
		$criticals = array_values(
			array_filter(
				$items,
				static function ( $i ) {
					return 'critical' === $i['severity'];
				}
			)
		);

		$current_ids = array();
		foreach ( $criticals as $c ) {
			$current_ids[] = $c['vuln_id'];
		}

		$alerted = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $alerted ) ) {
			$alerted = array();
		}

		$new = array();
		foreach ( $criticals as $c ) {
			if ( ! in_array( $c['vuln_id'], $alerted, true ) ) {
				$new[] = $c;
			}
		}

		if ( ! empty( $new ) ) {
			$recipients = $this->parse_recipients(
				(string) $this->core->get_setting( 'watch_critical_recipients', '' ),
				get_option( 'admin_email' )
			);
			$this->send(
				$recipients,
				$this->critical_subject( count( $new ) ),
				$this->critical_html( $new ),
				$this->critical_text( $new )
			);
		}

		// Self-cleaning: persist exactly the current criticals so a CVE that is
		// resolved and later reappears alerts again.
		update_option( self::ALERTED_OPTION, $current_ids, false );
	}

	/*
	 * =====================================================================
	 * Digest
	 * =====================================================================
	 */

	/**
	 * Cron handler: sends the digest when due for the configured frequency.
	 *
	 * @return void
	 */
	public function maybe_send_digest() {
		$frequency = ( 'daily' === $this->core->get_setting( 'watch_digest_frequency', 'weekly' ) ) ? 'daily' : 'weekly';
		$last      = (string) get_option( self::LAST_DIGEST_OPTION, '' );
		$today     = gmdate( 'Y-m-d' );

		if ( 'daily' === $frequency ) {
			if ( $last === $today ) {
				return; // Already sent today.
			}
		} else {
			$last_ts = $last ? strtotime( $last . ' UTC' ) : 0;
			if ( $last_ts && ( time() - $last_ts ) < ( 7 * DAY_IN_SECONDS ) ) {
				return; // Less than a week since the last weekly digest.
			}
		}

		if ( $this->send_digest() ) {
			update_option( self::LAST_DIGEST_OPTION, $today, false );
		}
	}

	/**
	 * Builds and sends the digest. Returns false when skipped.
	 *
	 * @return bool
	 */
	public function send_digest() {
		$items = $this->scanner->get_dashboard_items();

		if ( empty( $items ) && $this->core->get_setting( 'watch_digest_skip_if_clean', 1 ) ) {
			return false; // Nothing at risk and skip-if-clean is on.
		}

		$recipients = $this->parse_recipients(
			(string) $this->core->get_setting( 'watch_digest_recipients', '' ),
			get_option( 'admin_email' )
		);

		return $this->send(
			$recipients,
			$this->digest_subject( count( $items ) ),
			$this->digest_html( $items ),
			$this->digest_text( $items )
		);
	}

	/*
	 * =====================================================================
	 * Recipients + mailer
	 * =====================================================================
	 */

	/**
	 * Parses a comma/newline list into valid emails, ignoring malformed ones.
	 * Falls back to the WordPress admin email when none are valid.
	 *
	 * @param string $raw      Raw list.
	 * @param string $fallback Fallback address.
	 * @return array
	 */
	private function parse_recipients( $raw, $fallback ) {
		$out = array();
		foreach ( preg_split( '/[,\r\n]+/', (string) $raw ) as $email ) {
			$email = trim( $email );
			if ( '' !== $email && is_email( $email ) ) {
				$out[] = $email;
			}
		}

		if ( empty( $out ) && $fallback && is_email( $fallback ) ) {
			$out[] = $fallback;
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Sends an HTML email with a plain-text alternative.
	 *
	 * @param array  $recipients Recipients.
	 * @param string $subject    Subject.
	 * @param string $html       HTML body.
	 * @param string $text       Plain-text alternative.
	 * @return bool
	 */
	private function send( $recipients, $subject, $html, $text ) {
		if ( empty( $recipients ) ) {
			return false;
		}

		$headers = array( 'Content-Type: text/html; charset=UTF-8' );

		$set_alt = static function ( $phpmailer ) use ( $text ) {
			if ( is_object( $phpmailer ) ) {
				$phpmailer->AltBody = $text;
			}
		};

		add_action( 'phpmailer_init', $set_alt );
		$ok = wp_mail( $recipients, $subject, $html, $headers );
		remove_action( 'phpmailer_init', $set_alt );

		return (bool) $ok;
	}

	/*
	 * =====================================================================
	 * Templates
	 * =====================================================================
	 */

	/**
	 * @param int $count At-risk count.
	 * @return string
	 */
	private function digest_subject( $count ) {
		if ( 0 === $count ) {
			return sprintf(
				/* translators: %s: site name. */
				__( '[%s] Plugin security digest — all clear', 'kdna-sentinel' ),
				get_bloginfo( 'name' )
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: at-risk count. */
			__( '[%1$s] Plugin security digest — %2$d at risk', 'kdna-sentinel' ),
			get_bloginfo( 'name' ),
			$count
		);
	}

	/**
	 * @param int $count New critical count.
	 * @return string
	 */
	private function critical_subject( $count ) {
		return sprintf(
			/* translators: 1: site name, 2: count. */
			_n(
				'[URGENT] %1$s — %2$d critical plugin vulnerability',
				'[URGENT] %1$s — %2$d critical plugin vulnerabilities',
				$count,
				'kdna-sentinel'
			),
			get_bloginfo( 'name' ),
			$count
		);
	}

	/**
	 * HTML wrapper.
	 *
	 * @param string $heading Heading.
	 * @param string $intro   Intro line.
	 * @param string $body    Body HTML.
	 * @return string
	 */
	private function wrap( $heading, $intro, $body ) {
		return '<div style="font-family:Arial,Helvetica,sans-serif;color:#1d2327;max-width:640px;">'
			. '<h2 style="color:#1f3a5f;margin:0 0 8px;">' . esc_html( $heading ) . '</h2>'
			. '<p style="margin:0 0 16px;">' . esc_html( $intro ) . '</p>'
			. $body
			. '<p style="color:#787c82;font-size:12px;margin-top:24px;">'
			. esc_html__( 'Sent by KDNA Sentinel', 'kdna-sentinel' ) . ' &mdash; ' . esc_html( home_url() )
			. '</p></div>';
	}

	/**
	 * Renders a table of at-risk items.
	 *
	 * @param array $items Items.
	 * @return string
	 */
	private function items_table( $items ) {
		$th   = 'style="text-align:left;padding:6px 10px;border-bottom:2px solid #1f3a5f;font-size:13px;"';
		$td   = 'style="padding:6px 10px;border-bottom:1px solid #e0e0e0;font-size:13px;"';
		$rows = '';

		foreach ( $items as $i ) {
			$lag = ( null === $i['patch_lag'] )
				? '&mdash;'
				: sprintf(
					/* translators: %d: days. */
					esc_html( _n( '%d day', '%d days', (int) $i['patch_lag'], 'kdna-sentinel' ) ),
					(int) $i['patch_lag']
				);

			$rows .= '<tr>'
				. '<td ' . $td . '>' . esc_html( $i['plugin_name'] ) . '</td>'
				. '<td ' . $td . '>' . esc_html( $i['installed_ver'] ) . '</td>'
				. '<td ' . $td . '>' . esc_html( ucfirst( $i['severity'] ) ) . '</td>'
				. '<td ' . $td . '>' . ( $i['fixed_in'] ? esc_html( $i['fixed_in'] ) : '&mdash;' ) . '</td>'
				. '<td ' . $td . '>' . $lag . '</td>'
				. '</tr>';
		}

		return '<table style="border-collapse:collapse;width:100%;"><thead><tr>'
			. '<th ' . $th . '>' . esc_html__( 'Plugin', 'kdna-sentinel' ) . '</th>'
			. '<th ' . $th . '>' . esc_html__( 'Installed', 'kdna-sentinel' ) . '</th>'
			. '<th ' . $th . '>' . esc_html__( 'Severity', 'kdna-sentinel' ) . '</th>'
			. '<th ' . $th . '>' . esc_html__( 'Fixed in', 'kdna-sentinel' ) . '</th>'
			. '<th ' . $th . '>' . esc_html__( 'Patch lag', 'kdna-sentinel' ) . '</th>'
			. '</tr></thead><tbody>' . $rows . '</tbody></table>';
	}

	/**
	 * @param array $items Items.
	 * @return string
	 */
	private function digest_html( $items ) {
		if ( empty( $items ) ) {
			return $this->wrap(
				__( 'Plugin security digest', 'kdna-sentinel' ),
				__( 'Good news — all plugins are current with no known vulnerabilities.', 'kdna-sentinel' ),
				''
			);
		}

		return $this->wrap(
			__( 'Plugin security digest', 'kdna-sentinel' ),
			sprintf(
				/* translators: %d: count. */
				_n( '%d plugin on this site has a known vulnerability:', '%d plugins on this site have known vulnerabilities:', count( $items ), 'kdna-sentinel' ),
				count( $items )
			),
			$this->items_table( $items )
		);
	}

	/**
	 * @param array $items Items.
	 * @return string
	 */
	private function digest_text( $items ) {
		if ( empty( $items ) ) {
			return __( 'All plugins are current with no known vulnerabilities.', 'kdna-sentinel' );
		}

		$lines = array( __( 'Plugins with known vulnerabilities:', 'kdna-sentinel' ), '' );
		foreach ( $items as $i ) {
			$lag     = ( null === $i['patch_lag'] ) ? '-' : ( (int) $i['patch_lag'] . 'd' );
			$lines[] = sprintf(
				'- %s %s [%s] fixed in %s (patch lag %s)',
				$i['plugin_name'],
				$i['installed_ver'],
				strtoupper( $i['severity'] ),
				$i['fixed_in'] ? $i['fixed_in'] : '?',
				$lag
			);
		}
		$lines[] = '';
		$lines[] = home_url();

		return implode( "\n", $lines );
	}

	/**
	 * @param array $items New critical items.
	 * @return string
	 */
	private function critical_html( $items ) {
		return $this->wrap(
			__( 'URGENT: critical plugin vulnerability', 'kdna-sentinel' ),
			__( 'A scan just detected a critical vulnerability in a plugin on this site. Update as soon as possible.', 'kdna-sentinel' ),
			$this->items_table( $items )
		);
	}

	/**
	 * @param array $items New critical items.
	 * @return string
	 */
	private function critical_text( $items ) {
		$lines = array(
			__( 'URGENT: critical plugin vulnerability detected.', 'kdna-sentinel' ),
			'',
		);
		foreach ( $items as $i ) {
			$lines[] = sprintf(
				'- %s %s — fixed in %s',
				$i['plugin_name'],
				$i['installed_ver'],
				$i['fixed_in'] ? $i['fixed_in'] : '?'
			);
		}
		$lines[] = '';
		$lines[] = home_url();

		return implode( "\n", $lines );
	}
}
