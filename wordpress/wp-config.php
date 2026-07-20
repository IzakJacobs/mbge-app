<?php
//Begin Really Simple Security key
define('RSSSL_KEY', '12yvBTg3lhHPrcFFfmvlyXLIFRkGdXEBvOcxZvYvhJEmDeXil7wgeH4TabXpcr7P');
//END Really Simple Security key
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'gembcoza_wp_pedgf' );

/** Database username */
define( 'DB_USER', 'gembcoza_wp_nolsu' );

/** Database password */
define( 'DB_PASSWORD', '4Ew_6ZPG!AM?U3u4' );

/** Database hostname */
define( 'DB_HOST', 'localhost:3306' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY', 'saz%768uZg[TGNda6pyK04xl4;N0j%8ps1OEkmH%I1M/KqP7hU0ahx3RCDoY%Em*');
define('SECURE_AUTH_KEY', 'q_DvKcw!PUe;dkgFFd]&r9]/P+G55nyduvWbz4zQGZi1PCjbz!R&Gx(+R]O#_[(D');
define('LOGGED_IN_KEY', 'X5Al(~ZL9PUvG;~4vdP:-dFUfGYKbUri1nd3Gt69&IOqabwBI|]PijrxcF9VO%UM');
define('NONCE_KEY', 'woP)Wn5GuXPV)8@[mWg;73QUjqNfSrHBYfO4h~iydeggwa-K_ASDxDp_z+|nxLWN');
define('AUTH_SALT', '_K4Yh#r/JxcvV/Nyw[gG)LjE@-@YuDnhIqw]klUAZ(xeE+goKS0UQ[R#[6%ejJ-~');
define('SECURE_AUTH_SALT', '[%T#pfCD%SOvAd|~7~H!V5HCz5-]dGo@CU02iyoZhc[mzg1td0G+TEUP!w:bhbp2');
define('LOGGED_IN_SALT', '(M|7]/1Gl6!ek0etM5:eLNSV*X;RxPyXnVe#RmoqFua)bcHfye3XBQY7O)aJHi5b');
define('NONCE_SALT', '0gX&+PZma]a7]xUIdpn6irOyZ_VhvUHIYeOV49THC|/hyn6Pe0tEDFte8Bu_(Xt[');


/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'VLJSMS_';

/* Add any custom values between this line and the "stop editing" line. */

define('WP_ALLOW_MULTISITE', true);
/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
if ( ! defined( 'WP_DEBUG' ) ) {
	define( 'WP_DEBUG', false );
}

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
