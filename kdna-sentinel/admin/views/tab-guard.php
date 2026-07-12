<?php
/**
 * Guard tab: master enable toggle.
 *
 * Detection settings (timing threshold, honeypot, IP blocklist, API key,
 * quarantine) are added in Stages 2–4.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$guard_enabled = ! empty( $settings['guard_enabled'] );
?>
<form method="post" action="options.php" class="kdna-sentinel-form">
	<?php settings_fields( KDNA_Sentinel_Settings::GROUP ); ?>

	<h2><?php esc_html_e( 'Guard — form-spam defence', 'kdna-sentinel' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Stops AI-written and bot form spam on KDNA Forms and WooCommerce account forms. Free heuristics first; a Claude API check only on borderline submissions; always fail-open.', 'kdna-sentinel' ); ?>
	</p>

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Guard module', 'kdna-sentinel' ); ?></th>
			<td>
				<?php // Hidden companion guarantees the key is always submitted, even when unchecked. ?>
				<input type="hidden" name="<?php echo esc_attr( KDNA_Sentinel_Core::OPTION ); ?>[guard_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox"
						name="<?php echo esc_attr( KDNA_Sentinel_Core::OPTION ); ?>[guard_enabled]"
						value="1" <?php checked( $guard_enabled ); ?> />
					<?php esc_html_e( 'Enable Guard', 'kdna-sentinel' ); ?>
				</label>
				<p class="description">
					<?php esc_html_e( 'When off, no form submissions are inspected. Detection settings appear here once Guard is built out.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
