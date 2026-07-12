<?php
/**
 * Uninstall handler.
 *
 * Removes custom tables and options. Runs only on plugin deletion, never on
 * deactivation.
 *
 * @package KDNA_Sentinel
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$kdna_sentinel_tables = array(
	$wpdb->prefix . 'kdna_sentinel_quarantine',
	$wpdb->prefix . 'kdna_sentinel_vuln_cache',
	$wpdb->prefix . 'kdna_sentinel_hub_log',
);

foreach ( $kdna_sentinel_tables as $kdna_sentinel_table ) {
	// Table name is built from a trusted prefix + literal; cannot be parameterised.
	$wpdb->query( "DROP TABLE IF EXISTS {$kdna_sentinel_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
}

delete_option( 'kdna_sentinel_settings' );
delete_option( 'kdna_sentinel_db_version' );
