<?php
/**
 * Guard API scorer — Claude borderline check.
 *
 * Only BORDERLINE submissions reach here (via the
 * kdna_sentinel_guard_borderline_is_spam filter). PASS and BLOCK never call the
 * API. Sends only the message body to a Haiku-class model, parses a strict
 * {verdict, confidence} JSON reply defensively, and FAILS OPEN on any error,
 * timeout or unparseable response — a genuine enquiry is never lost because an
 * API call failed. A per-day call cap bounds cost under a spam flood.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard_Scorer
 */
class KDNA_Sentinel_Guard_Scorer {

	/**
	 * Messages API endpoint.
	 */
	const ENDPOINT = 'https://api.anthropic.com/v1/messages';

	/**
	 * Anthropic API version header.
	 */
	const API_VERSION = '2023-06-01';

	/**
	 * Option holding the rolling per-day call count.
	 */
	const USAGE_OPTION = 'kdna_sentinel_guard_api_usage';

	/**
	 * Cap on message characters sent to the API (bounds tokens/cost/PII).
	 */
	const MAX_MESSAGE_CHARS = 4000;

	/**
	 * Output token cap — a JSON verdict is tiny.
	 */
	const MAX_TOKENS = 64;

	/**
	 * Tight system prompt: JSON only, no prose.
	 */
	const SYSTEM_PROMPT = 'You are a spam classifier for website contact-form messages. Classify the user message as SPAM (unsolicited, bot or AI-written promotional content, scams, SEO/link spam) or HAM (a genuine human enquiry). Reply with ONLY a single minified JSON object and nothing else: {"verdict":"SPAM"|"HAM","confidence":<number between 0 and 1>}. No prose, no markdown, no code fences.';

	/**
	 * Stored API key.
	 *
	 * @var string
	 */
	private $api_key;

	/**
	 * Model name.
	 *
	 * @var string
	 */
	private $model;

	/**
	 * Minimum HAM confidence required to let a submission through.
	 *
	 * @var float
	 */
	private $threshold;

	/**
	 * Per-day API call cap (0 = unlimited).
	 *
	 * @var int
	 */
	private $daily_cap;

	/**
	 * Request timeout in seconds.
	 *
	 * @var int
	 */
	private $timeout;

	/**
	 * Confidence from the most recent scored-spam decision (for quarantine).
	 *
	 * @var float|null
	 */
	private $last_confidence = null;

	/**
	 * Constructor.
	 *
	 * @param string $api_key   API key.
	 * @param string $model     Model name.
	 * @param float  $threshold HAM confidence threshold.
	 * @param int    $daily_cap Per-day call cap (0 = unlimited).
	 * @param int    $timeout   Request timeout in seconds.
	 */
	public function __construct( $api_key, $model, $threshold, $daily_cap, $timeout = 5 ) {
		$this->api_key   = (string) $api_key;
		$this->model     = $model ? (string) $model : 'claude-haiku-4-5';
		$this->threshold = max( 0.0, min( 1.0, (float) $threshold ) );
		$this->daily_cap = max( 0, (int) $daily_cap );
		$this->timeout   = max( 1, (int) $timeout );
	}

	/**
	 * Registers the Stage 3 seams exposed by Guard's hooks layer.
	 *
	 * @return void
	 */
	public function register() {
		add_filter( 'kdna_sentinel_guard_borderline_is_spam', array( $this, 'evaluate_borderline' ), 10, 3 );
		add_filter( 'kdna_sentinel_guard_borderline_score', array( $this, 'last_confidence' ), 10, 1 );
	}

	/**
	 * Filter callback: decides a BORDERLINE submission via the API.
	 *
	 * @param bool  $is_spam Incoming default (false = let through).
	 * @param mixed $verdict The heuristic verdict (unused here).
	 * @param array $meta    Source/form/ip/message.
	 * @return bool
	 */
	public function evaluate_borderline( $is_spam, $verdict = null, $meta = array() ) {
		if ( $is_spam ) {
			return true;
		}

		$this->last_confidence = null;

		try {
			if ( '' === trim( $this->api_key ) ) {
				return $is_spam; // No key: nothing to call, let through.
			}

			$message = isset( $meta['message'] ) ? trim( (string) $meta['message'] ) : '';
			if ( '' === $message ) {
				// No free-text content to classify — let through.
				return $is_spam;
			}

			if ( ! $this->consume_quota() ) {
				$this->log( 'API skipped: daily call cap reached (fail-open, submission allowed).' );
				return $is_spam;
			}

			$result = $this->score( $this->truncate( $message ) );

			if ( null === $result ) {
				$this->log( 'API skipped: unreachable, timed out, or unparseable response (fail-open, submission allowed).' );
				return $is_spam;
			}

			$let_through = ( 'HAM' === $result['verdict'] && $result['confidence'] >= $this->threshold );

			if ( $let_through ) {
				return $is_spam; // Confident HAM: let through.
			}

			// SPAM, or HAM below the confidence threshold: quarantine.
			$this->last_confidence = $result['confidence'];
			$this->log(
				sprintf(
					'API verdict=%s confidence=%.2f threshold=%.2f -> quarantine.',
					$result['verdict'],
					$result['confidence'],
					$this->threshold
				)
			);

			return true;
		} catch ( Exception $e ) {
			// Fail-open on any internal error.
			$this->log( 'Scorer error (fail-open, submission allowed): ' . $e->getMessage() );
			return $is_spam;
		}
	}

	/**
	 * Filter callback: exposes the last scored-spam confidence to quarantine.
	 *
	 * @param mixed $score Incoming default score.
	 * @return float|null
	 */
	public function last_confidence( $score = null ) {
		return ( null !== $this->last_confidence ) ? $this->last_confidence : $score;
	}

	/**
	 * Calls the API and returns a normalised verdict, or null on any failure.
	 *
	 * @param string $message Message body (already truncated).
	 * @return array|null {verdict: 'SPAM'|'HAM', confidence: float}
	 */
	private function score( $message ) {
		$body = array(
			'model'      => $this->model,
			'max_tokens' => self::MAX_TOKENS,
			'system'     => self::SYSTEM_PROMPT,
			'messages'   => array(
				array(
					'role'    => 'user',
					'content' => $message,
				),
			),
		);

		$response = wp_remote_post(
			self::ENDPOINT,
			array(
				'timeout' => $this->timeout,
				'headers' => array(
					'content-type'      => 'application/json',
					'x-api-key'         => $this->api_key,
					'anthropic-version' => self::API_VERSION,
				),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return null;
		}

		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['content'] ) || ! is_array( $data['content'] ) ) {
			return null;
		}

		$text = '';
		foreach ( $data['content'] as $block ) {
			if ( is_array( $block ) && isset( $block['type'], $block['text'] ) && 'text' === $block['type'] ) {
				$text = (string) $block['text'];
				break;
			}
		}

		if ( '' === $text ) {
			return null;
		}

		return $this->parse_verdict( $text );
	}

	/**
	 * Defensively extracts {verdict, confidence} from model text.
	 *
	 * @param string $text Model reply text.
	 * @return array|null
	 */
	private function parse_verdict( $text ) {
		$text = trim( $text );

		// Strip any accidental code fences.
		$text = preg_replace( '/^```[a-zA-Z]*\s*/', '', $text );
		$text = preg_replace( '/\s*```$/', '', $text );

		$start = strpos( $text, '{' );
		$end   = strrpos( $text, '}' );
		if ( false === $start || false === $end || $end < $start ) {
			return null;
		}

		$obj = json_decode( substr( $text, $start, $end - $start + 1 ), true );
		if ( ! is_array( $obj ) || ! isset( $obj['verdict'] ) ) {
			return null;
		}

		$verdict = strtoupper( trim( (string) $obj['verdict'] ) );
		if ( 'SPAM' !== $verdict && 'HAM' !== $verdict ) {
			return null;
		}

		$confidence = isset( $obj['confidence'] ) ? (float) $obj['confidence'] : 0.0;
		if ( $confidence > 1 ) {
			$confidence = $confidence / 100; // Tolerate a 0-100 scale.
		}
		$confidence = max( 0.0, min( 1.0, $confidence ) );

		return array(
			'verdict'    => $verdict,
			'confidence' => $confidence,
		);
	}

	/**
	 * Reserves one call against the per-day cap.
	 *
	 * @return bool True if a call may proceed.
	 */
	private function consume_quota() {
		if ( $this->daily_cap <= 0 ) {
			return true; // Unlimited.
		}

		$usage = get_option( self::USAGE_OPTION, array() );
		if ( ! is_array( $usage ) ) {
			$usage = array();
		}

		$today = gmdate( 'Y-m-d' );
		if ( ! isset( $usage['date'] ) || $usage['date'] !== $today ) {
			$usage = array(
				'date'  => $today,
				'count' => 0,
			);
		}

		if ( (int) $usage['count'] >= $this->daily_cap ) {
			return false;
		}

		$usage['count'] = (int) $usage['count'] + 1;
		update_option( self::USAGE_OPTION, $usage, false );

		return true;
	}

	/**
	 * Truncates a message to the character cap (multibyte-safe).
	 *
	 * @param string $message Message.
	 * @return string
	 */
	private function truncate( $message ) {
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $message, 0, self::MAX_MESSAGE_CHARS );
		}

		return substr( $message, 0, self::MAX_MESSAGE_CHARS );
	}

	/**
	 * Logs a scorer event. Always recorded — fail-open events must be auditable.
	 *
	 * @param string $message Message.
	 * @return void
	 */
	private function log( $message ) {
		error_log( 'KDNA Sentinel Guard Scorer: ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}
