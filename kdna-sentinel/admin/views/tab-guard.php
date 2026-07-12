<?php
/**
 * Guard tab: master toggle + heuristics settings.
 *
 * API scorer (Stage 3) and quarantine (Stage 4) settings are added later.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$guard_enabled   = ! empty( $settings['guard_enabled'] );
$honeypot_on     = ! empty( $settings['guard_honeypot_enabled'] );
$threshold       = isset( $settings['guard_timing_threshold'] ) ? (int) $settings['guard_timing_threshold'] : 2;
$ip_blocklist    = isset( $settings['guard_ip_blocklist'] ) ? (string) $settings['guard_ip_blocklist'] : '';
$option          = KDNA_Sentinel_Core::OPTION;
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
				<input type="hidden" name="<?php echo esc_attr( $option ); ?>[guard_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[guard_enabled]" value="1" <?php checked( $guard_enabled ); ?> />
					<?php esc_html_e( 'Enable Guard', 'kdna-sentinel' ); ?>
				</label>
				<p class="description">
					<?php esc_html_e( 'When off, no form submissions are inspected.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>

		<tr>
			<th scope="row"><?php esc_html_e( 'Honeypot', 'kdna-sentinel' ); ?></th>
			<td>
				<input type="hidden" name="<?php echo esc_attr( $option ); ?>[guard_honeypot_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[guard_honeypot_enabled]" value="1" <?php checked( $honeypot_on ); ?> />
					<?php esc_html_e( 'Inject a hidden honeypot field and block any submission that fills it', 'kdna-sentinel' ); ?>
				</label>
			</td>
		</tr>

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-threshold"><?php esc_html_e( 'Time-to-submit threshold', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<input type="number" min="0" max="300" step="1" id="kdna-sentinel-threshold"
					name="<?php echo esc_attr( $option ); ?>[guard_timing_threshold]"
					value="<?php echo esc_attr( $threshold ); ?>" class="small-text" />
				<?php esc_html_e( 'seconds', 'kdna-sentinel' ); ?>
				<p class="description">
					<?php esc_html_e( 'Submissions completed faster than this are blocked as automated. Default 2. Set 0 to disable the timing check.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-ip-blocklist"><?php esc_html_e( 'IP blocklist', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<textarea id="kdna-sentinel-ip-blocklist" class="large-text code" rows="5"
					name="<?php echo esc_attr( $option ); ?>[guard_ip_blocklist]"
					placeholder="203.0.113.10&#10;2001:db8::1"><?php echo esc_textarea( $ip_blocklist ); ?></textarea>
				<p class="description">
					<?php esc_html_e( 'One IP address per line. Submissions from these IPs are blocked outright. Invalid entries are dropped on save.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>
