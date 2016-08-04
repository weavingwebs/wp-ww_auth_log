<?php
/**
* Plugin Name: WP WW Auth Log
* Description: Write all login attempts to a file (Based on wp-fail2ban)
* Text Domain: wp-ww_auth_log
* Version: 0.0.2
* Author: Weaving Webs Ltd
* License: GPL2
* SPDX-License-Identifier: GPL-2.0
*/

/**
* Log helper.
**/
function ww_auth_log__log($message) {
	$root = ABSPATH;

	// wordpress always forces the timezone to UTC, if fail2ban's clock is not UTC
	// then it will ignore all entries. Just hope php.ini is set correctly.
	$date = new \DateTime('now', new \DateTimeZone(ini_get('date.timezone')));

	$message = strtr('!date !host !message from !ip', array(
		'!date' => $date->format('M j H:i:s'),
		'!host' => gethostname(),
    '!message' => $message,
		'!ip' => $_SERVER['REMOTE_ADDR'],
	));
  error_log($message."\n", 3, $root.'../logs/wordpress_auth.log');
}

/*
 * @since 2.2.0
 */
add_action( 'xmlrpc_call',
	function($call) {
		if ('pingback.ping' == $call) {
			ww_auth_log__log('Pingback requested');
		}
	}
);

/*
 * @since 1.0.0
 */
add_action( 'wp_login',
	function($user_login, $user) {
		ww_auth_log__log("Accepted password for $user_login");
	},10,2);

/*
 * @since 1.0.0
 */
add_action( 'wp_login_failed',
	function($username)	{
		$msg = (wp_cache_get($username, 'userlogins'))
			? "Authentication failure for $username"
			: "Authentication attempt for unknown user $username";
		ww_auth_log__log($msg);
	});

/*
 * @since 3.0.0
 */
add_action( 'xmlrpc_login_error',
	function($error, $user)
	{
		ww_auth_log__log('XML-RPC authentication failure');

		// kill the request
		ob_end_clean();
		header('HTTP/1.0 403 Forbidden');
		header('Content-Type: text/plain');
		exit('Forbidden');
	},10,2);

/*
 * @since 3.0.0
 */
add_filter( 'xmlrpc_pingback_error',
	function($ixr_error)
	{
		if (48 === $ixr_error->code) {
			return $ixr_error;
		}
		ww_auth_log__log('Pingback error '.$ixr_error->code.' generated');
	},5);
