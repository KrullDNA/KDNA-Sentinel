<?php
/**
 * Vulnerability-data providers for Watch.
 *
 * One interface, swappable implementations (WPScan, Patchstack), selected in
 * the Watch tab. Each provider looks up a plugin slug and returns a normalised
 * result so the scanner is provider-agnostic.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The provider contract.
 */
interface KDNA_Sentinel_Vuln_Provider {

	/**
	 * Looks up known vulnerabilities for a plugin slug.
	 *
	 * @param string $slug wordpress.org plugin slug.
	 * @return array {
	 *     @type string $status      One of: ok, not_found, rate_limited, error, no_key.
	 *     @type int    $retry_after Seconds to wait (rate_limited only).
	 *     @type array  $vulns       Normalised vuln records (ok only). Each:
	 *                               { vuln_id, title, severity, fixed_in, fixed_at }.
	 * }
	 */
	public function get_plugin_vulnerabilities( $slug );

	/**
	 * Machine slug of the provider.
	 *
	 * @return string
	 */
	public function slug();
}

/**
 * Shared normalisation helpers.
 */
abstract class KDNA_Sentinel_Vuln_Provider_Base implements KDNA_Sentinel_Vuln_Provider {

	/**
	 * API key.
	 *
	 * @var string
	 */
	protected $api_key;

	/**
	 * Request timeout (seconds).
	 *
	 * @var int
	 */
	protected $timeout = 15;

	/**
	 * Constructor.
	 *
	 * @param string $api_key API key.
	 */
	public function __construct( $api_key ) {
		$this->api_key = (string) $api_key;
	}

	/**
	 * Maps a CVSS score to a severity band.
	 *
	 * @param float $score CVSS score.
	 * @return string
	 */
	protected function severity_from_score( $score ) {
		$score = (float) $score;
		if ( $score >= 9.0 ) {
			return 'critical';
		}
		if ( $score >= 7.0 ) {
			return 'high';
		}
		if ( $score >= 4.0 ) {
			return 'medium';
		}
		if ( $score > 0.0 ) {
			return 'low';
		}

		return 'unknown';
	}

	/**
	 * Normalises a severity string to one of the known bands.
	 *
	 * @param string $value Raw severity.
	 * @return string
	 */
	protected function normalize_severity( $value ) {
		$value = strtolower( trim( (string) $value ) );
		if ( in_array( $value, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
			return $value;
		}

		return 'unknown';
	}

	/**
	 * Normalises a date string to UTC 'Y-m-d H:i:s', or null.
	 *
	 * @param mixed $value Date-ish value.
	 * @return string|null
	 */
	protected function normalize_date( $value ) {
		if ( empty( $value ) || ! is_string( $value ) ) {
			return null;
		}
		$ts = strtotime( $value );

		return $ts ? gmdate( 'Y-m-d H:i:s', $ts ) : null;
	}

	/**
	 * Reads Retry-After from a response, defaulting to 60s.
	 *
	 * @param array|WP_Error $response Response.
	 * @return int
	 */
	protected function retry_after( $response ) {
		$header = wp_remote_retrieve_header( $response, 'retry-after' );
		$after  = is_numeric( $header ) ? (int) $header : 60;

		return max( 1, $after );
	}
}

/**
 * WPScan API v3 provider (primary).
 */
class KDNA_Sentinel_WPScan_Provider extends KDNA_Sentinel_Vuln_Provider_Base {

	const ENDPOINT = 'https://wpscan.com/api/v3/plugins/';

	/**
	 * @return string
	 */
	public function slug() {
		return 'wpscan';
	}

	/**
	 * @param string $slug Plugin slug.
	 * @return array
	 */
	public function get_plugin_vulnerabilities( $slug ) {
		if ( '' === trim( $this->api_key ) ) {
			return array( 'status' => 'no_key', 'vulns' => array() );
		}

		$response = wp_remote_get(
			self::ENDPOINT . rawurlencode( $slug ),
			array(
				'timeout' => $this->timeout,
				'headers' => array(
					'Authorization' => 'Token token=' . $this->api_key,
					'Accept'        => 'application/json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array( 'status' => 'error', 'vulns' => array() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 404 === $code ) {
			return array( 'status' => 'not_found', 'vulns' => array() );
		}
		if ( 429 === $code ) {
			return array( 'status' => 'rate_limited', 'retry_after' => $this->retry_after( $response ), 'vulns' => array() );
		}
		if ( 200 !== $code ) {
			return array( 'status' => 'error', 'vulns' => array() );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! isset( $data[ $slug ] ) || ! is_array( $data[ $slug ] ) ) {
			return array( 'status' => 'not_found', 'vulns' => array() );
		}

		$raw   = isset( $data[ $slug ]['vulnerabilities'] ) && is_array( $data[ $slug ]['vulnerabilities'] )
			? $data[ $slug ]['vulnerabilities'] : array();
		$vulns = array();

		foreach ( $raw as $v ) {
			if ( ! is_array( $v ) ) {
				continue;
			}

			$severity = 'unknown';
			if ( isset( $v['cvss'] ) && is_array( $v['cvss'] ) ) {
				if ( ! empty( $v['cvss']['severity'] ) ) {
					$severity = $this->normalize_severity( $v['cvss']['severity'] );
				} elseif ( isset( $v['cvss']['score'] ) ) {
					$severity = $this->severity_from_score( $v['cvss']['score'] );
				}
			}

			$date = '';
			foreach ( array( 'published_date', 'created_at', 'updated_at' ) as $k ) {
				if ( ! empty( $v[ $k ] ) ) {
					$date = $v[ $k ];
					break;
				}
			}

			$vulns[] = array(
				'vuln_id'  => isset( $v['id'] ) ? (string) $v['id'] : md5( wp_json_encode( $v ) ),
				'title'    => isset( $v['title'] ) ? (string) $v['title'] : '',
				'severity' => $severity,
				'fixed_in' => isset( $v['fixed_in'] ) && null !== $v['fixed_in'] ? (string) $v['fixed_in'] : '',
				'fixed_at' => $this->normalize_date( $date ),
			);
		}

		return array( 'status' => 'ok', 'vulns' => $vulns );
	}
}

/**
 * Patchstack API provider (alternative).
 *
 * Best-effort field mapping against a generic response shape — verify against
 * the live Patchstack API before relying on it in production. WPScan is the
 * tested/primary provider.
 */
class KDNA_Sentinel_Patchstack_Provider extends KDNA_Sentinel_Vuln_Provider_Base {

	const ENDPOINT = 'https://api.patchstack.com/v3/plugins/';

	/**
	 * @return string
	 */
	public function slug() {
		return 'patchstack';
	}

	/**
	 * @param string $slug Plugin slug.
	 * @return array
	 */
	public function get_plugin_vulnerabilities( $slug ) {
		if ( '' === trim( $this->api_key ) ) {
			return array( 'status' => 'no_key', 'vulns' => array() );
		}

		$response = wp_remote_get(
			self::ENDPOINT . rawurlencode( $slug ) . '/vulnerabilities',
			array(
				'timeout' => $this->timeout,
				'headers' => array(
					'Authorization' => 'Bearer ' . $this->api_key,
					'Accept'        => 'application/json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array( 'status' => 'error', 'vulns' => array() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 404 === $code ) {
			return array( 'status' => 'not_found', 'vulns' => array() );
		}
		if ( 429 === $code ) {
			return array( 'status' => 'rate_limited', 'retry_after' => $this->retry_after( $response ), 'vulns' => array() );
		}
		if ( 200 !== $code ) {
			return array( 'status' => 'error', 'vulns' => array() );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return array( 'status' => 'not_found', 'vulns' => array() );
		}

		// Accept either a bare list or a {data:[...]} envelope.
		$raw = isset( $data['data'] ) && is_array( $data['data'] ) ? $data['data'] : $data;

		$vulns = array();
		foreach ( $raw as $v ) {
			if ( ! is_array( $v ) ) {
				continue;
			}

			$fixed_in = '';
			foreach ( array( 'patched_in', 'fixed_in', 'patched_version' ) as $k ) {
				if ( ! empty( $v[ $k ] ) ) {
					$fixed_in = (string) $v[ $k ];
					break;
				}
			}

			$date = '';
			foreach ( array( 'patch_date', 'disclosure_date', 'published_at', 'created_at' ) as $k ) {
				if ( ! empty( $v[ $k ] ) ) {
					$date = $v[ $k ];
					break;
				}
			}

			$id = '';
			foreach ( array( 'id', 'uuid', 'cve' ) as $k ) {
				if ( ! empty( $v[ $k ] ) ) {
					$id = (string) $v[ $k ];
					break;
				}
			}

			$vulns[] = array(
				'vuln_id'  => '' !== $id ? $id : md5( wp_json_encode( $v ) ),
				'title'    => isset( $v['title'] ) ? (string) $v['title'] : ( isset( $v['name'] ) ? (string) $v['name'] : '' ),
				'severity' => $this->normalize_severity( isset( $v['severity'] ) ? $v['severity'] : '' ),
				'fixed_in' => $fixed_in,
				'fixed_at' => $this->normalize_date( $date ),
			);
		}

		return array( 'status' => 'ok', 'vulns' => $vulns );
	}
}

/**
 * Provider factory.
 */
class KDNA_Sentinel_Watch_Providers {

	/**
	 * Builds the configured provider.
	 *
	 * @param string $provider Provider slug.
	 * @param string $api_key  API key.
	 * @return KDNA_Sentinel_Vuln_Provider
	 */
	public static function make( $provider, $api_key ) {
		if ( 'patchstack' === $provider ) {
			return new KDNA_Sentinel_Patchstack_Provider( $api_key );
		}

		return new KDNA_Sentinel_WPScan_Provider( $api_key );
	}

	/**
	 * Available providers: slug => label.
	 *
	 * @return array
	 */
	public static function choices() {
		return array(
			'wpscan'     => __( 'WPScan', 'kdna-sentinel' ),
			'patchstack' => __( 'Patchstack', 'kdna-sentinel' ),
		);
	}
}
