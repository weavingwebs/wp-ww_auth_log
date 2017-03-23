<?php

namespace WWAuthLog;

/**
 * WordPress WW Auth Logger.
 */
class WWAuthLogger {

  /**
   * @var string DB_VERSION
   *  The latest version of our database tables.
   */
  const DB_VERSION = '0.1.0';

  /**
   * @var string LOGIN_ATTEMPTS_TABLE
   *  The name of the login attempts table (excluding prefix).
   */
  const LOGIN_ATTEMPTS_TABLE = 'ww_auth_log__login_attempts';

  /**
   * @var int LOGIN_DISABLE_THRESHOLD
   *  The number of attempts within LOGIN_DISABLE_WINDOW that should trigger
   *  the login to be disabled.
   */
  const LOGIN_DISABLE_THRESHOLD = 20;

  /**
   * @var int LOGIN_DISABLE_WINDOW
   *  The number of minutes since now that should be considered when checking
   *    LOGIN_DISABLE_THRESHOLD.
   */
  const LOGIN_DISABLE_WINDOW = 20;

  /**
   * @var int LOGIN_DISABLE_TIME
   *  The number of minutes that login should be disabled for after the
   *  threshold is hit.
   */
  const LOGIN_DISABLE_TIME = 20;

  /**
   * @var string $log_path
   *  The filepath to write the log entries to.
   */
  protected $log_path;

  /**
   * @var string $hostname
   *  The hostname to write to the logs.
   */
  protected $hostname;

  /**
   * @var \DateTimeZone $timezone
   *  The timezone to use for log timestamps.
   */
  protected $timezone;

  /**
   * Public constructor.
   */
  public function __construct() {
    $this->log_path = ABSPATH . '../logs/wordpress_auth.log';
    $this->hostname = gethostname();

  	// Wordpress always forces the timezone to UTC, if fail2ban's clock is not
    // UTC then it will ignore all entries. Just hope php.ini is set to the
    // same timezone as the host.
  	$this->timezone = new \DateTimeZone(ini_get('date.timezone'));
  }

  /**
   * Initialise the Wordpress Hooks.
   */
  public function wpInit() {
    add_action('wp_login', array($this, 'wp_login'), 10, 2);
    add_action('wp_login_failed', array($this, 'wp_login_failed'));
    add_action('xmlrpc_call', array($this, 'xmlrpc_call'));
    add_action('xmlrpc_login_error', array($this, 'xmlrpc_login_error'), 10, 2);
    add_filter('xmlrpc_pingback_error', array($this, 'xmlrpc_pingback_error'), 5);
    add_action('plugins_loaded', array($this, 'plugins_loaded'));
    add_action('login_init', array($this, 'killIfLoginDisabled'));
    add_filter('authenticate', array($this, 'killIfLoginDisabled'));

    // Register the installer. NOTE: this function must be passed the filepath
    // to the main plugin file (The one with 'Plugin Name:').
    register_activation_hook(__DIR__ . '/wp-ww_auth_log.php', array($this, 'install'));
  }

  /**
   * Write to the log file.
   *
   * @param string $message
   *  The message to write to the log. The date, hostname and IP will be added
   *  automatically.
   */
  public function log($message) {
  	$date = new \DateTime('now', $this->timezone);

  	$log_entry = strtr('!date !host !message from !ip', array(
  		'!date' => $date->format('M j H:i:s Y'),
  		'!host' => gethostname(),
      '!message' => $message,
  		'!ip' => $_SERVER['REMOTE_ADDR'],
  	));
    error_log($log_entry."\n", 3, $this->log_path);
  }

  /**
   * Create/update the database tables required by the logger.
   */
  public function install() {
    // Include the db functions.
    global $wpdb;
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    $charset_collate = $wpdb->get_charset_collate();

    // Create the login attempts table.
  	$table_name = $wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE;
  	$sql = "CREATE TABLE $table_name (
  		time int NOT NULL,
  		username varchar(255) NOT NULL,
  		ip varchar(45) NOT NULL,
  		KEY time (time)
  	) $charset_collate;";
  	dbDelta($sql);

    // Update version.
  	update_option('ww_auth_log__db_version', static::DB_VERSION);
  }

  /**
   * Record a failed login.
   *
   * @param string $username
   */
  public function recordFailedLogin($username) {
    // Write the failure to login attempts.
    global $wpdb;
    $now = time();
    $result = $wpdb->insert(
      $wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE,
      array(
        'time' => $now,
        'username' => $username,
        'ip' => $_SERVER['REMOTE_ADDR'],
      )
    );

    // Check the insert worked.
    if (!$result) {
      error_log('Warning: wp-ww_auth_log failed to write the login failure');
    }

    // Check our table for the number of failed logins in the last X minutes.
    $since = $now - (60 * static::LOGIN_DISABLE_WINDOW);
    $table = $wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE;
    $sql = "SELECT COUNT(*) FROM $table WHERE time >= $since;";
    $recent_attempts = $wpdb->get_var($sql);

    // Check if the threshold has been hit.
    if ($recent_attempts >= static::LOGIN_DISABLE_THRESHOLD) {
      update_option('ww_auth_log__login_disabled', $now);
      $this->log(strtr('Login has been disabled for !time minutes', array(
        '!time' => static::LOGIN_DISABLE_TIME,
      )));
    }
  }

  /**
   * Kill the request if login has been disabled.
   */
  public function killIfLoginDisabled() {
    $login_disabled = get_option('ww_auth_log__login_disabled');
    if ($login_disabled) {
      // Check if the login has been disabled for long enough.
      if ($login_disabled < (time() - (60 * static::LOGIN_DISABLE_TIME))) {
        // Allow this function to quick return next time.
        update_option('ww_auth_log__login_disabled', FALSE);
      }
      else {
        // Kill the request.
        $this->log('Login attempted while disabled');
        ob_end_clean();
        http_response_code(403);
        die();
      }
    }
  }

  /**
   * Implements action: wp_login.
   *
   * @param string $user_login
   *  The username.
   * @param \WP_User $user
   *  The user object.
   */
  public function wp_login($user_login, $user) {
		$this->log("Accepted password for $user_login");
	}

  /**
   * Implements action: wp_login_failed.
   *
   * @param string $username
   *  The username.
   */
  public function wp_login_failed($username)	{
    // Log the failure.
    $msg = (wp_cache_get($username, 'userlogins'))
      ? "Authentication failure for $username"
      : "Authentication attempt for unknown user $username";
    $this->log($msg);
    $this->recordFailedLogin($username);
  }

  /**
   * Implements action: xmlrpc_call.
   *
   * @param string $call
   *  The xmlrpc method being called.
   */
  public function xmlrpc_call($call) {
    // Log 'pingback' requests. TODO: What does these actually do?
		if ($call === 'pingback.ping') {
			$this->log('Pingback requested');
		}
    $this->killIfLoginDisabled();
	}

  /**
   * Implements action: xmlrpc_login_error.
   *
   * @param string $error
   *  The XML-RPC error message.
   * @param \WP_User $user
   *  The user object.
   */
  public function xmlrpc_login_error($error, $user)
  {
    $this->log('XML-RPC authentication failure');
    $this->recordFailedLogin($user->user_login);

    // kill the request
    ob_end_clean();
    header('HTTP/1.0 403 Forbidden');
    header('Content-Type: text/plain');
    exit('Forbidden');
  }

  /**
   * Implements filter: xmlrpc_pingback_error.
   *
   * @param \IXR_Error $error
   *  An IXR_Error object containing the error code and message.
   */
  public function xmlrpc_pingback_error($error)
  {
    // TODO: Why only return and not log if 48?
    if (48 === $error->code) {
      return $error;
    }
    $this->log('Pingback error '.$error->code.' generated');
  }

  /**
   * Implements action: plugins_loaded.
   */
  public function plugins_loaded() {
    // Check if a database update is required.
    $db_version = get_site_option('ww_auth_log__db_version');
    if (!$db_version || version_compare(static::DB_VERSION, $db_version, '<')) {
      $this->install();
    }
  }

}
