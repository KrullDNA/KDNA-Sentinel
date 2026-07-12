<?php
/**
 * Settings page shell: title, tab navigation, active tab view.
 *
 * @package KDNA_Sentinel
 *
 * @var KDNA_Sentinel_Settings $this       Settings controller.
 * @var KDNA_Sentinel_Core     $core       Core instance.
 * @var array                  $settings   Full settings array.
 * @var array                  $tabs       Tab slug => label.
 * @var string                 $active_tab Current tab slug.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap kdna-sentinel-wrap">
	<h1 class="kdna-sentinel-title">
		<span class="dashicons dashicons-shield" aria-hidden="true"></span>
		<?php esc_html_e( 'KDNA Sentinel', 'kdna-sentinel' ); ?>
	</h1>

	<p class="kdna-sentinel-tagline">
		<?php esc_html_e( 'Form-spam defence (Guard) and plugin patch-lag monitoring (Watch). Each module toggles independently.', 'kdna-sentinel' ); ?>
	</p>

	<?php settings_errors( KDNA_Sentinel_Core::OPTION ); ?>

	<h2 class="nav-tab-wrapper kdna-sentinel-tabs">
		<?php foreach ( $tabs as $slug => $label ) : ?>
			<a href="<?php echo esc_url( $this->tab_url( $slug ) ); ?>"
				class="nav-tab <?php echo ( $slug === $active_tab ) ? 'nav-tab-active' : ''; ?>">
				<?php echo esc_html( $label ); ?>
			</a>
		<?php endforeach; ?>
	</h2>

	<div class="kdna-sentinel-tab-content">
		<?php
		$view = KDNA_SENTINEL_DIR . 'admin/views/tab-' . $active_tab . '.php';
		if ( file_exists( $view ) ) {
			include $view;
		}
		?>
	</div>
</div>
