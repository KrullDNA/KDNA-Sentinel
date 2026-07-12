<?php
/**
 * Vulnerability-data providers for Watch.
 *
 * One interface, swappable implementations (WPScan, Patchstack, Wordfence),
 * selected in the Watch tab. Each provider looks up a plugin slug and returns a
 * normalised result so the scanner is provider-agnostic.
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

	/**
	 * Whether this provider needs an API key to function.
	 *
	 * @return bool
	 */
	public function requires_key();
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
	 * Providers require an API key unless they override this.
	 *
	 * @return bool
	 */
	public function requires_key() {
		return true;
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
 * Wordfence Intelligence provider (free, no key required).
 *
 * Unlike the per-slug WPScan/Patchstack APIs, Wordfence publishes one open feed
 * of the whole production vulnerability dataset. This provider downloads it once
 * per scan, indexes it by plugin slug in memory, and answers each per-slug
 * lookup from that index — so the scanner interface is unchanged and only one
 * HTTP request is made per scan run (not one per installed plugin).
 *
 * Trade-off: that single request is a multi-megabyte download, so on very
 * constrained hosting WPScan/Patchstack (small per-slug requests) stay lighter.
 * An API key is optional: unauthenticated access works; a key raises limits.
 *
 * @link https://www.wordfence.com/help/wordfence-intelligence/wordfence-intelligence-vulnerability-data-api/
 */
class KDNA_Sentinel_Wordfence_Provider extends KDNA_Sentinel_Vuln_Provider_Base {

	const ENDPOINT = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production';

	/**
	 * The whole feed is a large download; give it room.
	 *
	 * @var int
	 */
	protected $timeout = 30;

	/**
	 * slug => array of normalised vuln records, built on first lookup.
	 *
	 * @var array|null
	 */
	private $index = null;

	/**
	 * Outcome of the one-time feed fetch: ''|ok|error|rate_limited.
	 *
	 * @var string
	 */
	private $fetch_status = '';

	/**
	 * Seconds to back off (rate_limited only).
	 *
	 * @var int
	 */
	private $retry_secs = 60;

	/**
	 * @return string
	 */
	public function slug() {
		return 'wordfence';
	}

	/**
	 * The feed is open; no key needed.
	 *
	 * @return bool
	 */
	public function requires_key() {
		return false;
	}

	/**
	 * @param string $slug Plugin slug.
	 * @return array
	 */
	public function get_plugin_vulnerabilities( $slug ) {
		if ( null === $this->index ) {
			$this->load_index();
		}

		if ( 'ok' !== $this->fetch_status ) {
			$out = array( 'status' => $this->fetch_status, 'vulns' => array() );
			if ( 'rate_limited' === $this->fetch_status ) {
				$out['retry_after'] = $this->retry_secs;
			}
			return $out;
		}

		if ( isset( $this->index[ $slug ] ) ) {
			return array( 'status' => 'ok', 'vulns' => $this->index[ $slug ] );
		}

		return array( 'status' => 'not_found', 'vulns' => array() );
	}

	/**
	 * Downloads the feed once and indexes plugin vulnerabilities by slug.
	 *
	 * @return void
	 */
	private function load_index() {
		$this->index = array();

		$headers = array( 'Accept' => 'application/json' );
		if ( '' !== trim( $this->api_key ) ) {
			$headers['Authorization'] = 'Bearer ' . $this->api_key;
		}

		$response = wp_remote_get(
			self::ENDPOINT,
			array(
				'timeout' => $this->timeout,
				'headers' => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fetch_status = 'error';
			return;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 429 === $code ) {
			$this->fetch_status = 'rate_limited';
			$this->retry_secs   = $this->retry_after( $response );
			return;
		}
		if ( 200 !== $code ) {
			$this->fetch_status = 'error';
			return;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			$this->fetch_status = 'error';
			return;
		}

		foreach ( $data as $record ) {
			if ( ! is_array( $record ) || empty( $record['software'] ) || ! is_array( $record['software'] ) ) {
				continue;
			}

			$vuln_id  = isset( $record['id'] ) ? (string) $record['id'] : '';
			$title    = isset( $record['title'] ) ? (string) $record['title'] : '';
			$severity = $this->wf_severity( $record );

			$date = '';
			foreach ( array( 'published', 'updated', 'created' ) as $k ) {
				if ( ! empty( $record[ $k ] ) ) {
					$date = $record[ $k ];
					break;
				}
			}

			foreach ( $record['software'] as $sw ) {
				if ( ! is_array( $sw ) || 'plugin' !== ( isset( $sw['type'] ) ? $sw['type'] : '' ) ) {
					continue;
				}
				$sw_slug = isset( $sw['slug'] ) ? (string) $sw['slug'] : '';
				if ( '' === $sw_slug ) {
					continue;
				}

				$this->index[ $sw_slug ][] = array(
					'vuln_id'  => '' !== $vuln_id ? $vuln_id : md5( wp_json_encode( $record ) ),
					'title'    => $title,
					'severity' => $severity,
					'fixed_in' => $this->wf_fixed_in( $sw ),
					'fixed_at' => $this->normalize_date( $date ),
				);
			}
		}

		$this->fetch_status = 'ok';
	}

	/**
	 * Maps a Wordfence record's CVSS block to a severity band.
	 *
	 * @param array $record Vulnerability record.
	 * @return string
	 */
	private function wf_severity( $record ) {
		if ( isset( $record['cvss'] ) && is_array( $record['cvss'] ) ) {
			if ( ! empty( $record['cvss']['rating'] ) ) {
				return $this->normalize_severity( $record['cvss']['rating'] );
			}
			if ( isset( $record['cvss']['score'] ) ) {
				return $this->severity_from_score( $record['cvss']['score'] );
			}
		}

		return 'unknown';
	}

	/**
	 * Best-effort "fixed in" version for a software entry.
	 *
	 * Prefers an explicit patched version; otherwise treats the exclusive upper
	 * bound of an affected-version range ("affected up to but not including X")
	 * as the fix. Returns '' when no fix is known.
	 *
	 * @param array $sw Software entry.
	 * @return string
	 */
	private function wf_fixed_in( $sw ) {
		if ( ! empty( $sw['patched_versions'] ) && is_array( $sw['patched_versions'] ) ) {
			$versions = array_values( array_filter( array_map( 'strval', $sw['patched_versions'] ) ) );
			if ( ! empty( $versions ) ) {
				usort( $versions, 'version_compare' );
				return (string) $versions[0];
			}
		}

		if ( ! empty( $sw['affected_versions'] ) && is_array( $sw['affected_versions'] ) ) {
			$fix = '';
			foreach ( $sw['affected_versions'] as $range ) {
				if ( ! is_array( $range ) ) {
					continue;
				}
				$to = isset( $range['to_version'] ) ? (string) $range['to_version'] : '';
				if ( '' !== $to && '*' !== $to && empty( $range['to_inclusive'] ) ) {
					if ( '' === $fix || version_compare( $to, $fix, '>' ) ) {
						$fix = $to;
					}
				}
			}
			return $fix;
		}

		return '';
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
		if ( 'wordfence' === $provider ) {
			return new KDNA_Sentinel_Wordfence_Provider( $api_key );
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
			'wordfence'  => __( 'Wordfence Intelligence (free, no key)', 'kdna-sentinel' ),
		);
	}

	/**
	 * Provider slugs that do not require an API key.
	 *
	 * @return array
	 */
	public static function keyless() {
		return array( 'wordfence' );
	}
}
