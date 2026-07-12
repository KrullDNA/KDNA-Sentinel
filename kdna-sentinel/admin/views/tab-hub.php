<?php
/**
 * Hub tab: placeholder.
 *
 * The optional cross-site report-in (client side) and master dashboard (hub
 * side) are built in Stage 7. Nothing here persists yet.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="kdna-sentinel-panel">
	<h2><?php esc_html_e( 'Hub — optional central reporting', 'kdna-sentinel' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Client sites can optionally report their Watch scan results to a nominated KDNA hub site, which aggregates every site into one dashboard. This is fully optional and off by default.', 'kdna-sentinel' ); ?>
	</p>
	<p>
		<?php esc_html_e( 'Hub reporting and the master dashboard are configured in a later build stage. No cross-site requests leave this site.', 'kdna-sentinel' ); ?>
	</p>
</div>
