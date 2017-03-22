<?php

namespace WWAuthLog;

/**
 * WordPress WW Auth Logger.
 */
class WWAuthLogger {

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
      '!message' => $log_entry,
  		'!ip' => $_SERVER['REMOTE_ADDR'],
  	));
    error_log($log_entry."\n", 3, $this->log_path);
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
}
