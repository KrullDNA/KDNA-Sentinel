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
$country_blocklist = isset( $settings['guard_country_blocklist'] ) ? (string) $settings['guard_country_blocklist'] : '';
$api_key         = isset( $settings['guard_api_key'] ) ? (string) $settings['guard_api_key'] : '';
$api_key_set     = ( '' !== $api_key );
$api_key_last4   = $api_key_set ? substr( $api_key, -4 ) : '';
$model           = isset( $settings['guard_model'] ) ? (string) $settings['guard_model'] : 'claude-haiku-4-5';
$conf_threshold  = isset( $settings['guard_confidence_threshold'] ) ? (float) $settings['guard_confidence_threshold'] : 0.5;
$daily_cap       = isset( $settings['guard_daily_cap'] ) ? (int) $settings['guard_daily_cap'] : 100;
$option          = KDNA_Sentinel_Core::OPTION;
?>
<?php
// Row-action result notice (release / delete / block IP / purge).
$kdna_notice = isset( $_GET['kdna_notice'] ) ? sanitize_key( wp_unslash( $_GET['kdna_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$kdna_notices = array(
	'released'       => array( 'updated', __( 'Submission released and processed as genuine.', 'kdna-sentinel' ) ),
	'release_failed' => array( 'error', __( 'The submission was released, but could not be re-processed automatically.', 'kdna-sentinel' ) ),
	'deleted'        => array( 'updated', __( 'Quarantined submission deleted.', 'kdna-sentinel' ) ),
	'blocked'        => array( 'updated', __( 'IP added to the Guard blocklist.', 'kdna-sentinel' ) ),
	'error'          => array( 'error', __( 'That action could not be completed.', 'kdna-sentinel' ) ),
);
if ( isset( $kdna_notices[ $kdna_notice ] ) ) {
	printf(
		'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
		esc_attr( $kdna_notices[ $kdna_notice ][0] ),
		esc_html( $kdna_notices[ $kdna_notice ][1] )
	);
}
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

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-country-blocklist"><?php esc_html_e( 'Country blocklist', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<textarea id="kdna-sentinel-country-blocklist" class="large-text code" rows="4"
					name="<?php echo esc_attr( $option ); ?>[guard_country_blocklist]"
					placeholder="RU&#10;CN&#10;KP"><?php echo esc_textarea( $country_blocklist ); ?></textarea>
				<p class="description">
					<?php esc_html_e( 'One two-letter ISO country code per line (e.g. RU, CN, KP). Submissions from these countries are blocked outright. Entries that are not valid two-letter codes are dropped on save.', 'kdna-sentinel' ); ?>
				</p>
				<p class="description">
					<?php esc_html_e( 'The visitor country is read from a CDN header (Cloudflare / CloudFront) when present, otherwise from WooCommerce\'s bundled geolocation database. When the country cannot be determined, this check is skipped (fail-open).', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<h2><?php esc_html_e( 'Claude API borderline scorer', 'kdna-sentinel' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Only borderline submissions (passed the hard checks but with soft anomalies) are sent to the Claude API, and only the message body is sent — never the full submission or other personal data. On any API error the submission is let through (fail-open).', 'kdna-sentinel' ); ?>
	</p>

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row">
				<label for="kdna-sentinel-api-key"><?php esc_html_e( 'Anthropic API key', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<input type="password" id="kdna-sentinel-api-key" class="regular-text" autocomplete="off"
					name="<?php echo esc_attr( $option ); ?>[guard_api_key]" value="" />
				<p class="description">
					<?php
					if ( $api_key_set ) {
						/* translators: %s: last four characters of the stored API key. */
						printf( esc_html__( 'A key is stored (ending %s). Leave blank to keep it, or enter a new key to replace it.', 'kdna-sentinel' ), '<code>&bull;&bull;&bull;&bull;' . esc_html( $api_key_last4 ) . '</code>' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					} else {
						esc_html_e( 'Enter your Anthropic API key. Without a key, borderline submissions are simply let through.', 'kdna-sentinel' );
					}
					?>
				</p>
				<?php if ( $api_key_set ) : ?>
					<label class="kdna-sentinel-toggle">
						<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[guard_api_key_remove]" value="1" />
						<?php esc_html_e( 'Remove the stored API key', 'kdna-sentinel' ); ?>
					</label>
				<?php endif; ?>
			</td>
		</tr>

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-model"><?php esc_html_e( 'Model', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<input type="text" id="kdna-sentinel-model" class="regular-text code"
					name="<?php echo esc_attr( $option ); ?>[guard_model]" value="<?php echo esc_attr( $model ); ?>" />
				<p class="description">
					<?php esc_html_e( 'A fast, low-cost Haiku-class model is recommended. Default: claude-haiku-4-5.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-confidence"><?php esc_html_e( 'HAM confidence threshold', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<input type="number" min="0" max="1" step="0.05" id="kdna-sentinel-confidence" class="small-text"
					name="<?php echo esc_attr( $option ); ?>[guard_confidence_threshold]" value="<?php echo esc_attr( $conf_threshold ); ?>" />
				<p class="description">
					<?php esc_html_e( 'A borderline submission is let through only when the API judges it genuine (HAM) with at least this confidence (0–1). Below it, the submission is quarantined. Default: 0.5.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>

		<tr>
			<th scope="row">
				<label for="kdna-sentinel-daily-cap"><?php esc_html_e( 'Daily API call cap', 'kdna-sentinel' ); ?></label>
			</th>
			<td>
				<input type="number" min="0" step="1" id="kdna-sentinel-daily-cap" class="small-text"
					name="<?php echo esc_attr( $option ); ?>[guard_daily_cap]" value="<?php echo esc_attr( $daily_cap ); ?>" />
				<p class="description">
					<?php esc_html_e( 'Maximum API calls per day, so a spam flood cannot run up cost. Once reached, borderline submissions are let through for the rest of the day. Set 0 for no limit. Default: 100.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>

<?php
if ( class_exists( 'KDNA_Sentinel_Guard_Quarantine' ) ) {
	KDNA_Sentinel_Guard_Quarantine::instance()->render_list();
}
?>
