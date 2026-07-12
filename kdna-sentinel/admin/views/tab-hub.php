<?php
/**
 * Hub tab: optional cross-site reporting (client side) + master dashboard
 * (hub side). Off by default.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$report_enabled = ! empty( $settings['hub_report_enabled'] );
$hub_url        = isset( $settings['hub_url'] ) ? (string) $settings['hub_url'] : '';
$secret         = isset( $settings['hub_secret'] ) ? (string) $settings['hub_secret'] : '';
$secret_set     = ( '' !== $secret );
$secret_last4   = $secret_set ? substr( $secret, -4 ) : '';
$is_hub         = ! empty( $settings['hub_is_hub'] );
$option         = KDNA_Sentinel_Core::OPTION;
?>
<form method="post" action="options.php" class="kdna-sentinel-form">
	<?php settings_fields( KDNA_Sentinel_Settings::GROUP ); ?>

	<h2><?php esc_html_e( 'Hub — optional central reporting', 'kdna-sentinel' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Client sites can report their Watch scan results to a nominated KDNA hub site, which aggregates every site into one dashboard. Fully optional and off by default. Only plugin/version/vulnerability metadata is transmitted — never submission content or personal data. All hub traffic is HMAC-signed with the shared secret.', 'kdna-sentinel' ); ?>
	</p>

	<h3><?php esc_html_e( 'This site reports to a hub (client)', 'kdna-sentinel' ); ?></h3>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Report to KDNA hub', 'kdna-sentinel' ); ?></th>
			<td>
				<input type="hidden" name="<?php echo esc_attr( $option ); ?>[hub_report_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[hub_report_enabled]" value="1" <?php checked( $report_enabled ); ?> />
					<?php esc_html_e( 'After each scan, send a signed summary to the hub', 'kdna-sentinel' ); ?>
				</label>
				<p class="description"><?php esc_html_e( 'Requires Watch to be enabled (reporting happens after a scan).', 'kdna-sentinel' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="kdna-sentinel-hub-url"><?php esc_html_e( 'Hub URL', 'kdna-sentinel' ); ?></label></th>
			<td>
				<input type="url" id="kdna-sentinel-hub-url" class="regular-text"
					name="<?php echo esc_attr( $option ); ?>[hub_url]" value="<?php echo esc_attr( $hub_url ); ?>"
					placeholder="https://hub.example.com" />
				<p class="description"><?php esc_html_e( 'The base URL of the KDNA hub site.', 'kdna-sentinel' ); ?></p>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="kdna-sentinel-hub-secret"><?php esc_html_e( 'Shared secret', 'kdna-sentinel' ); ?></label></th>
			<td>
				<input type="password" id="kdna-sentinel-hub-secret" class="regular-text" autocomplete="off"
					name="<?php echo esc_attr( $option ); ?>[hub_secret]" value="" />
				<p class="description">
					<?php
					if ( $secret_set ) {
						/* translators: %s: last four characters of the stored secret. */
						printf( esc_html__( 'A secret is stored (ending %s). Leave blank to keep it.', 'kdna-sentinel' ), '<code>&bull;&bull;&bull;&bull;' . esc_html( $secret_last4 ) . '</code>' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					} else {
						esc_html_e( 'The same secret must be set on the client and the hub. Used to HMAC-sign and verify reports.', 'kdna-sentinel' );
					}
					?>
				</p>
				<?php if ( $secret_set ) : ?>
					<label class="kdna-sentinel-toggle">
						<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[hub_secret_remove]" value="1" />
						<?php esc_html_e( 'Remove the stored secret', 'kdna-sentinel' ); ?>
					</label>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<h3><?php esc_html_e( 'This site is the hub (receiver)', 'kdna-sentinel' ); ?></h3>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'This site is the KDNA hub', 'kdna-sentinel' ); ?></th>
			<td>
				<input type="hidden" name="<?php echo esc_attr( $option ); ?>[hub_is_hub]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[hub_is_hub]" value="1" <?php checked( $is_hub ); ?> />
					<?php esc_html_e( 'Receive and aggregate reports from client sites', 'kdna-sentinel' ); ?>
				</label>
				<p class="description">
					<?php esc_html_e( 'When on, this site exposes the report endpoint at /wp-json/kdna-sentinel/v1/report and shows the dashboard below. Reports must be signed with the shared secret above.', 'kdna-sentinel' ); ?>
				</p>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>

<?php
// Master dashboard — only when this site is the hub.
if ( $is_hub && class_exists( 'KDNA_Sentinel_Hub_Endpoint' ) ) {
	KDNA_Sentinel_Hub_Endpoint::instance()->render_dashboard();
}
