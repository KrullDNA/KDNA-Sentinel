<?php
/**
 * Quarantine admin list table.
 *
 * Loaded lazily (after wp-admin/includes/class-wp-list-table.php) by
 * KDNA_Sentinel_Guard_Quarantine::render_list().
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	return;
}

/**
 * Class KDNA_Sentinel_Guard_Quarantine_List_Table
 */
class KDNA_Sentinel_Guard_Quarantine_List_Table extends WP_List_Table {

	/**
	 * Quarantine controller (data + URL building).
	 *
	 * @var KDNA_Sentinel_Guard_Quarantine
	 */
	private $store;

	/**
	 * Constructor.
	 *
	 * @param KDNA_Sentinel_Guard_Quarantine $store Controller.
	 */
	public function __construct( $store ) {
		$this->store = $store;

		parent::__construct(
			array(
				'singular' => 'kdna_quarantine_item',
				'plural'   => 'kdna_quarantine_items',
				'ajax'     => false,
			)
		);
	}

	/**
	 * @return array
	 */
	public function get_columns() {
		return array(
			'date'   => __( 'Date', 'kdna-sentinel' ),
			'source' => __( 'Source form', 'kdna-sentinel' ),
			'from'   => __( 'From', 'kdna-sentinel' ),
			'reason' => __( 'Reason', 'kdna-sentinel' ),
			'score'  => __( 'Score', 'kdna-sentinel' ),
		);
	}

	/**
	 * Message when there is nothing held.
	 *
	 * @return void
	 */
	public function no_items() {
		esc_html_e( 'Nothing in quarantine.', 'kdna-sentinel' );
	}

	/**
	 * Loads the current page of items.
	 *
	 * @return void
	 */
	public function prepare_items() {
		$per_page = 20;
		$current  = $this->get_pagenum();
		$total    = $this->store->count();

		$this->items = $this->store->get_items( $per_page, ( $current - 1 ) * $per_page );

		$this->set_pagination_args(
			array(
				'total_items' => $total,
				'per_page'    => $per_page,
				'total_pages' => (int) ceil( $total / $per_page ),
			)
		);

		$this->_column_headers = array( $this->get_columns(), array(), array(), 'date' );
	}

	/**
	 * Fallback column renderer.
	 *
	 * @param array  $item        Row.
	 * @param string $column_name Column.
	 * @return string
	 */
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'source':
				return esc_html( $this->store->source_label( $item['form_source'] ) );
			case 'from':
				return esc_html( $this->store->format_from( $item ) );
			case 'reason':
				return esc_html( $item['reason'] );
			case 'score':
				return ( null === $item['score'] || '' === $item['score'] )
					? '&mdash;'
					: esc_html( number_format( (float) $item['score'], 2 ) );
			default:
				return '';
		}
	}

	/**
	 * Primary "date" column: timestamp, row actions and the preview panel.
	 *
	 * @param array $item Row.
	 * @return string
	 */
	public function column_date( $item ) {
		$id   = (int) $item['id'];
		$when = esc_html( mysql2date( 'Y-m-d H:i', $item['created_at'] . ' UTC' ) );

		$actions = array(
			'preview' => sprintf(
				'<a href="#" class="kdna-preview-toggle" data-item="%d">%s</a>',
				$id,
				esc_html__( 'Preview', 'kdna-sentinel' )
			),
			'release' => sprintf(
				'<a href="%s" onclick="return confirm(%s);">%s</a>',
				esc_url( $this->store->action_url( 'release', $id ) ),
				"'" . esc_js( __( 'Release this submission and process it as genuine?', 'kdna-sentinel' ) ) . "'",
				esc_html__( 'This was genuine — let it through', 'kdna-sentinel' )
			),
			'block'   => sprintf(
				'<a href="%s">%s</a>',
				esc_url( $this->store->action_url( 'block_ip', $id ) ),
				esc_html__( 'Block this IP', 'kdna-sentinel' )
			),
			'delete'  => sprintf(
				'<a href="%s" class="submitdelete" onclick="return confirm(%s);">%s</a>',
				esc_url( $this->store->action_url( 'delete', $id ) ),
				"'" . esc_js( __( 'Delete this quarantined submission permanently?', 'kdna-sentinel' ) ) . "'",
				esc_html__( 'Delete', 'kdna-sentinel' )
			),
		);

		return $when . $this->row_actions( $actions ) . $this->preview_panel( $item );
	}

	/**
	 * Hidden preview panel with the full stored payload.
	 *
	 * @param array $item Row.
	 * @return string
	 */
	private function preview_panel( $item ) {
		$id      = (int) $item['id'];
		$payload = json_decode( (string) $item['payload'], true );

		$out  = '<div class="kdna-preview-panel" id="kdna-preview-' . $id . '" style="display:none;">';
		$out .= '<dl class="kdna-preview-list">';

		if ( is_array( $payload ) && ! empty( $payload ) ) {
			foreach ( $payload as $key => $value ) {
				if ( is_array( $value ) ) {
					$value = wp_json_encode( $value );
				}
				if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
					$out .= '<dt>' . esc_html( (string) $key ) . '</dt>';
					$out .= '<dd>' . esc_html( (string) $value ) . '</dd>';
				}
			}
		} else {
			$out .= '<dd>' . esc_html__( '(no stored payload)', 'kdna-sentinel' ) . '</dd>';
		}

		$out .= '</dl></div>';

		return $out;
	}
}
