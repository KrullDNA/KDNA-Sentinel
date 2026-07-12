<?php
/**
 * Watch tab: master enable toggle.
 *
 * Scanner, vuln API key, alert recipients and digest settings are added in
 * Stages 5–6.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$watch_enabled = ! empty( $settings['watch_enabled'] );
?>
<form method="post" action="options.php" class="kdna-sentinel-form">
	<?php settings_fields( KDNA_Sentinel_Settings::GROUP ); ?>

	<h2><?php esc_html_e( 'Watch — plugin patch-lag monitoring', 'kdna-sentinel' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Checks installed plugins against a known-vulnerability database and warns when a site is running something with an unpatched security hole.', 'kdna-sentinel' ); ?>
	</p>

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Watch module', 'kdna-sentinel' ); ?></th>
			<td>
				<?php // Hidden companion guarantees the key is always submitted, even when unchecked. ?>
				<input type="hidden" name="<?php echo esc_attr( KDNA_Sentinel_Core::OPTION ); ?>[watch_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox"
						name="<?php echo esc_attr( KDNA_Sentinel_Core::OPTION ); ?>[watch_enabled]"
						value="1" <?php checked( $watch_enabled ); ?> />
					<?php esc_html_e( 'Enable Watch', 'kdna-sentinel' ); ?>
				</label>
				<p class="description">
					<?php esc_html_e( 'When off, no scanning runs. Scanner, alerts and the risk dashboard appear here once Watch is built out.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
