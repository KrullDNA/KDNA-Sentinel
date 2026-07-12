<?php
/**
 * Watch tab: master toggle, provider settings, scan control + dashboard.
 *
 * Alerts (Stage 6) and hub reporting (Stage 7) are added later.
 *
 * @package KDNA_Sentinel
 *
 * @var array $settings Full settings array.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once KDNA_SENTINEL_DIR . 'includes/watch/class-watch-providers.php';

$watch_enabled = ! empty( $settings['watch_enabled'] );
$provider      = isset( $settings['watch_provider'] ) ? (string) $settings['watch_provider'] : 'wpscan';
$api_key       = isset( $settings['watch_api_key'] ) ? (string) $settings['watch_api_key'] : '';
$api_key_set   = ( '' !== $api_key );
$api_key_last4 = $api_key_set ? substr( $api_key, -4 ) : '';
$option        = KDNA_Sentinel_Core::OPTION;

// Action-result notice (manual scan).
$kdna_notice  = isset( $_GET['kdna_notice'] ) ? sanitize_key( wp_unslash( $_GET['kdna_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$watch_notices = array(
	'scan_ok'           => array( 'updated', __( 'Scan complete.', 'kdna-sentinel' ) ),
	'scan_rate_limited' => array( 'error', __( 'Rate limited by the API; scan paused. Partial results were saved.', 'kdna-sentinel' ) ),
	'scan_no_key'       => array( 'error', __( 'Set a vulnerability API key before scanning.', 'kdna-sentinel' ) ),
	'scan_error'        => array( 'error', __( 'The scan could not be completed.', 'kdna-sentinel' ) ),
);
if ( isset( $watch_notices[ $kdna_notice ] ) ) {
	printf(
		'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
		esc_attr( $watch_notices[ $kdna_notice ][0] ),
		esc_html( $watch_notices[ $kdna_notice ][1] )
	);
}
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
				<input type="hidden" name="<?php echo esc_attr( $option ); ?>[watch_enabled]" value="0" />
				<label class="kdna-sentinel-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[watch_enabled]" value="1" <?php checked( $watch_enabled ); ?> />
					<?php esc_html_e( 'Enable Watch', 'kdna-sentinel' ); ?>
				</label>
				<p class="description"><?php esc_html_e( 'When off, no scanning runs.', 'kdna-sentinel' ); ?></p>
			</td>
		</tr>

		<tr>
			<th scope="row"><label for="kdna-sentinel-watch-provider"><?php esc_html_e( 'Vulnerability provider', 'kdna-sentinel' ); ?></label></th>
			<td>
				<select id="kdna-sentinel-watch-provider" name="<?php echo esc_attr( $option ); ?>[watch_provider]">
					<?php foreach ( KDNA_Sentinel_Watch_Providers::choices() as $slug => $label ) : ?>
						<option value="<?php echo esc_attr( $slug ); ?>" <?php selected( $provider, $slug ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
				<p class="description"><?php esc_html_e( 'Which vulnerability database to query. Both take an API key below.', 'kdna-sentinel' ); ?></p>
			</td>
		</tr>

		<tr>
			<th scope="row"><label for="kdna-sentinel-watch-key"><?php esc_html_e( 'Provider API key', 'kdna-sentinel' ); ?></label></th>
			<td>
				<input type="password" id="kdna-sentinel-watch-key" class="regular-text" autocomplete="off"
					name="<?php echo esc_attr( $option ); ?>[watch_api_key]" value="" />
				<p class="description">
					<?php
					if ( $api_key_set ) {
						/* translators: %s: last four characters of the stored API key. */
						printf( esc_html__( 'A key is stored (ending %s). Leave blank to keep it.', 'kdna-sentinel' ), '<code>&bull;&bull;&bull;&bull;' . esc_html( $api_key_last4 ) . '</code>' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					} else {
						esc_html_e( 'Enter your provider API key. Without a key, no scan runs.', 'kdna-sentinel' );
					}
					?>
				</p>
				<?php if ( $api_key_set ) : ?>
					<label class="kdna-sentinel-toggle">
						<input type="checkbox" name="<?php echo esc_attr( $option ); ?>[watch_api_key_remove]" value="1" />
						<?php esc_html_e( 'Remove the stored API key', 'kdna-sentinel' ); ?>
					</label>
				<?php endif; ?>
			</td>
		</tr>
	</table>

	<?php submit_button(); ?>
</form>

<?php
// ---- Scan control + dashboard (only meaningful when Watch is on) ----------
if ( ! $watch_enabled || ! class_exists( 'KDNA_Sentinel_Watch' ) ) {
	echo '<p class="description">' . esc_html__( 'Enable Watch and save to scan installed plugins.', 'kdna-sentinel' ) . '</p>';
	return;
}

$scanner = KDNA_Sentinel_Watch::instance()->scanner();
$status  = $scanner->get_status();
$items   = $scanner->get_dashboard_items();
?>
<hr class="kdna-sentinel-sep" />

<h2><?php esc_html_e( 'Vulnerability dashboard', 'kdna-sentinel' ); ?></h2>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="kdna-sentinel-scan-form">
	<input type="hidden" name="action" value="<?php echo esc_attr( KDNA_Sentinel_Watch::SCAN_ACTION ); ?>" />
	<?php wp_nonce_field( KDNA_Sentinel_Watch::SCAN_ACTION ); ?>
	<?php submit_button( __( 'Scan now', 'kdna-sentinel' ), 'secondary', 'kdna-scan-now', false ); ?>
	<?php if ( $status && ! empty( $status['last_run'] ) ) : ?>
		<span class="description" style="margin-left:10px;">
			<?php
			printf(
				/* translators: 1: relative time, 2: number of plugins scanned. */
				esc_html__( 'Last scan: %1$s ago (%2$d plugins checked).', 'kdna-sentinel' ),
				esc_html( human_time_diff( strtotime( $status['last_run'] . ' UTC' ), time() ) ),
				(int) $status['scanned']
			);
			?>
		</span>
	<?php endif; ?>
</form>

<?php if ( empty( $items ) ) : ?>
	<div class="notice notice-success inline" style="margin-top:12px;">
		<p><strong><?php esc_html_e( 'All plugins current, no known vulnerabilities.', 'kdna-sentinel' ); ?></strong></p>
	</div>
<?php else : ?>
	<table class="widefat striped kdna-sentinel-vuln-table" style="margin-top:12px;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Plugin', 'kdna-sentinel' ); ?></th>
				<th><?php esc_html_e( 'Installed', 'kdna-sentinel' ); ?></th>
				<th><?php esc_html_e( 'Severity', 'kdna-sentinel' ); ?></th>
				<th><?php esc_html_e( 'Fixed in', 'kdna-sentinel' ); ?></th>
				<th><?php esc_html_e( 'Patch lag', 'kdna-sentinel' ); ?></th>
				<th><?php esc_html_e( 'Action', 'kdna-sentinel' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $items as $item ) : ?>
				<tr>
					<td><strong><?php echo esc_html( $item['plugin_name'] ); ?></strong><br /><span class="description"><?php echo esc_html( $item['plugin_slug'] ); ?></span></td>
					<td><?php echo esc_html( $item['installed_ver'] ); ?></td>
					<td><span class="kdna-sev kdna-sev-<?php echo esc_attr( $item['severity'] ); ?>"><?php echo esc_html( ucfirst( $item['severity'] ) ); ?></span></td>
					<td><?php echo $item['fixed_in'] ? esc_html( $item['fixed_in'] ) : '&mdash;'; ?></td>
					<td>
						<?php
						if ( null === $item['patch_lag'] ) {
							echo '&mdash;';
						} else {
							/* translators: %d: number of days. */
							printf( esc_html( _n( '%d day', '%d days', (int) $item['patch_lag'], 'kdna-sentinel' ) ), (int) $item['patch_lag'] );
						}
						?>
					</td>
					<td><a class="button button-small" href="<?php echo esc_url( $scanner->update_link( $item['plugin_file'] ) ); ?>"><?php esc_html_e( 'Update', 'kdna-sentinel' ); ?></a></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>
