<?php
/**
 * Plugin Name:       KDNA Sentinel
 * Plugin URI:        https://krulldna.com/kdna-sentinel
 * Description:       Two-module security plugin for small-agency WordPress sites: Guard (AI/bot form-spam defence) and Watch (plugin patch-lag monitoring). Each module toggles independently.
 * Version:           0.3.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            Krull Design & Advertising
 * Author URI:        https://krulldna.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       kdna-sentinel
 * Domain Path:       /languages
 *
 * @package KDNA_Sentinel
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * -------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------
 */
define( 'KDNA_SENTINEL_VERSION', '0.3.0' );

// Bump when the custom table schema changes so upgrades re-run dbDelta.
define( 'KDNA_SENTINEL_DB_VERSION', '2' );

define( 'KDNA_SENTINEL_FILE', __FILE__ );
define( 'KDNA_SENTINEL_DIR', plugin_dir_path( __FILE__ ) );
define( 'KDNA_SENTINEL_URL', plugin_dir_url( __FILE__ ) );
define( 'KDNA_SENTINEL_BASENAME', plugin_basename( __FILE__ ) );

/*
 * -------------------------------------------------------------------------
 * Includes (bootstrap only — all real work lives under includes/)
 * -------------------------------------------------------------------------
 */
require_once KDNA_SENTINEL_DIR . 'includes/class-sentinel-activator.php';
require_once KDNA_SENTINEL_DIR . 'includes/class-sentinel-core.php';

/*
 * -------------------------------------------------------------------------
 * Activation / deactivation hooks
 * -------------------------------------------------------------------------
 * Custom tables are created on activation and removed only on uninstall
 * (see uninstall.php), never on deactivation.
 */
register_activation_hook( __FILE__, array( 'KDNA_Sentinel_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'KDNA_Sentinel_Activator', 'deactivate' ) );

/*
 * -------------------------------------------------------------------------
 * Boot
 * -------------------------------------------------------------------------
 */
add_action( 'plugins_loaded', array( 'KDNA_Sentinel_Core', 'instance' ) );
