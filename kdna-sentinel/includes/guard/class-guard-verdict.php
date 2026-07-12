<?php
/**
 * Guard verdict value object.
 *
 * The single result type the heuristics engine (and, later, the API scorer)
 * returns, and the object submissions are rejected through. Immutable once
 * built.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class KDNA_Sentinel_Guard_Verdict
 */
class KDNA_Sentinel_Guard_Verdict {

	const PASS       = 'PASS';
	const BLOCK      = 'BLOCK';
	const BORDERLINE = 'BORDERLINE';

	/**
	 * One of PASS, BLOCK, BORDERLINE.
	 *
	 * @var string
	 */
	private $result;

	/**
	 * Human-readable reason (for notes/logs). Never contains submission PII.
	 *
	 * @var string
	 */
	private $reason;

	/**
	 * Optional numeric score (set by the API scorer in Stage 3). Null otherwise.
	 *
	 * @var float|null
	 */
	private $score;

	/**
	 * Machine-readable signal slugs that led to the verdict.
	 *
	 * @var array
	 */
	private $signals;

	/**
	 * Constructor.
	 *
	 * @param string     $result  Verdict constant.
	 * @param string     $reason  Human-readable reason.
	 * @param array      $signals Signal slugs.
	 * @param float|null $score   Optional score.
	 */
	public function __construct( $result, $reason = '', array $signals = array(), $score = null ) {
		$this->result  = $result;
		$this->reason  = $reason;
		$this->signals = $signals;
		$this->score   = $score;
	}

	/**
	 * Clean-pass factory.
	 *
	 * @return self
	 */
	public static function pass() {
		return new self( self::PASS );
	}

	/**
	 * Hard-fail factory.
	 *
	 * @param string $reason  Reason.
	 * @param array  $signals Signals.
	 * @return self
	 */
	public static function block( $reason, array $signals = array() ) {
		return new self( self::BLOCK, $reason, $signals );
	}

	/**
	 * Borderline factory.
	 *
	 * @param string $reason  Reason.
	 * @param array  $signals Signals.
	 * @return self
	 */
	public static function borderline( $reason, array $signals = array() ) {
		return new self( self::BORDERLINE, $reason, $signals );
	}

	/**
	 * @return string
	 */
	public function result() {
		return $this->result;
	}

	/**
	 * @return string
	 */
	public function reason() {
		return $this->reason;
	}

	/**
	 * @return array
	 */
	public function signals() {
		return $this->signals;
	}

	/**
	 * @return float|null
	 */
	public function score() {
		return $this->score;
	}

	/**
	 * Returns a copy with the score set (scorer output, Stage 3).
	 *
	 * @param float|null $score Score.
	 * @return self
	 */
	public function with_score( $score ) {
		return new self( $this->result, $this->reason, $this->signals, $score );
	}

	/**
	 * @return bool
	 */
	public function is_pass() {
		return self::PASS === $this->result;
	}

	/**
	 * @return bool
	 */
	public function is_block() {
		return self::BLOCK === $this->result;
	}

	/**
	 * @return bool
	 */
	public function is_borderline() {
		return self::BORDERLINE === $this->result;
	}
}
