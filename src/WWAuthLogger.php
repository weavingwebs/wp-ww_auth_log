<?php /** @noinspection PhpInconsistentReturnPointsInspection */

namespace WW\AuthLog;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use \WP_Scripts;
use \WP_Styles;
use \Exception;
use \WWAuth_WP_REST_Users_Controller;
use \WP_Error;

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

  const WW_INTERNAL_IPS = [
    '172.25.162.216', // Boomer.
  ];

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
     * @var string $_disable_scripts_regex
     * Regex required for disabling code execution in uploads directory
     */
    private static $_disable_scripts_regex = '/# BEGIN Wordfence code execution protection.+?# END Wordfence code execution protection/s';

    /**
     * .htaccess file contents to disable all script execution in a given directory.
     * Regex required for disabling code execution in uploads directory
     */
    private static $_disable_scripts_htaccess = '# BEGIN Wordfence code execution protection
    <IfModule mod_php5.c>
    php_flag engine 0
    </IfModule>
    <IfModule mod_php7.c>
    php_flag engine 0
    </IfModule>
    <IfModule mod_php.c>
    php_flag engine 0
    </IfModule>
    
    AddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .htm .shtml .sh .cgi
    Options -ExecCGI
    # END Wordfence code execution protection
    ';


	/**
	 * Public constructor.
	 */
	public function __construct() {
		$this->log_path = ABSPATH . '../logs/wordpress_auth.log';
		$this->hostname = gethostname();

		// Wordpress always forces the timezone to UTC, if fail2ban's clock is not
		// UTC then it will ignore all entries. Just hope php.ini is set to the
		// same timezone as the host.
		$this->timezone = new \DateTimeZone( ini_get( 'date.timezone' ) );
	}

	/**
	 * Initialise the Wordpress Hooks.
     *
     * @throws Exception
	 */
	public function wpInit() {
		add_action( 'wp_login', [ $this, 'wp_login' ], 10, 2 );
		add_action( 'wp_login_failed', [ $this, 'wp_login_failed' ] );
		add_action( 'xmlrpc_call', [ $this, 'xmlrpc_call' ] );
		add_action( 'xmlrpc_login_error', [ $this, 'xmlrpc_login_error' ], 10, 2 );
		add_filter( 'xmlrpc_pingback_error', [ $this, 'xmlrpc_pingback_error' ], 5 );
		add_action( 'plugins_loaded', [ $this, 'plugins_loaded' ] );
		add_action( 'login_init', [ $this, 'killIfLoginDisabled' ] );
		add_filter( 'authenticate', [ $this, 'killIfLoginDisabled' ] );
    add_filter( 'http_request_args', [ $this, 'http_request_args' ], 10, 2 );

    // Auth cookie expiration.
    add_filter( 'auth_cookie_expiration', [ $this, 'auth_cookie_expiration' ] );

    // Settings hooks.
    // NOTE: We need to be fully bootstrapped to use get_option so we have to
    // always register the hooks.
    add_filter( 'wp_new_user_notification_email_admin', $this->return_false_if_option_true_callback('ww_auth_log_disable_new_user_notification_to_admin'));
    add_filter( 'wp_password_change_notification_email', $this->return_false_if_option_true_callback('ww_auth_log_disable_password_change_notification_to_admin'));
    add_filter( 'admin_email_check_interval', $this->return_false_if_option_true_callback('ww_auth_log_disable_admin_email_check_interval'));
    add_filter( 'auto_core_update_send_email', $this->return_false_if_option_true_callback('ww_auth_log_disable_auto_core_update_send_email'));
    add_filter( 'auto_plugin_update_send_email', $this->return_false_if_option_true_callback('ww_auth_log_disable_auto_plugin_update_send_email'));
    add_filter( 'auto_theme_update_send_email', $this->return_false_if_option_true_callback('ww_auth_log_disable_auto_theme_update_send_email'));

    if(get_option('ww_auth_log_other_hideWPVersion')){
        add_filter('style_loader_src', static::class.'::replaceVersion');
        add_filter('script_loader_src', static::class.'::replaceVersion');
    }

    if(get_option('ww_auth_log_disableCodeExecutionUploads')){
        self::disableCodeExecutionForUploads();
    }else{
        self::removeCodeExecutionProtectionForUploads();
    }

    if (get_option('ww_auth_log_loginSec_disableAuthorScan')) {
        add_filter('oembed_response_data', static::class.'::oembedAuthorFilter', 99, 4);
        add_filter('rest_request_before_callbacks', static::class.'::jsonAPIAuthorFilter', 99, 3);
        add_filter('rest_post_dispatch', static::class.'::jsonAPIAdjustHeaders', 99, 3);
        add_filter('wp_sitemaps_users_pre_url_list', '__return_false', 99, 0);
        add_filter('wp_sitemaps_add_provider', static::class.'::wpSitemapUserProviderFilter', 99, 2);
    }

    add_action('request', static::class.'::preventAuthorNScans');
    add_action('init', static::class.'::initAction');

    add_filter('get_the_generator_html', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_xhtml', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_atom', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_rss2', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_rdf', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_comment', static::class.'::genFilter', 99, 2);
    add_filter('get_the_generator_export', static::class.'::genFilter', 99, 2);


    // Register the installer. NOTE: this function must be passed the filepath
		// to the main plugin file (The one with 'Plugin Name:').
		register_activation_hook( __DIR__ . '/wp-ww_auth_log.php', [ $this, 'install' ] );
	}

	/**
	 * Write to the log file.
	 *
	 * @param string $message
	 *  The message to write to the log. The date, hostname and IP will be added
	 *  automatically.
	 *
	 * @throws \Exception
	 */
	public function log( $message ) {
		$date = new \DateTime( 'now', $this->timezone );

		$log_entry = strtr( '!date !host !message from !ip',
			[
				'!date'    => $date->format( 'M j H:i:s.u Y' ),
				'!host'    => gethostname(),
				'!message' => $message,
				'!ip'      => $_SERVER['REMOTE_ADDR'],
			] );
		error_log( $log_entry . "\n", 3, $this->log_path );
	}

	/**
	 * Create/update the database tables required by the logger.
	 */
	public function install() {
		// Include the db functions.
		global $wpdb;
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		$charset_collate = $wpdb->get_charset_collate();

		// Create the login attempts table.
		$table_name = $wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE;
		$sql        = "CREATE TABLE $table_name (
  		time int NOT NULL,
  		username varchar(255) NOT NULL,
  		ip varchar(45) NOT NULL,
  		KEY time (time)
  	) $charset_collate;";
		dbDelta( $sql );

		// Update version.
		update_option( 'ww_auth_log__db_version', static::DB_VERSION );
	}

	/**
	 * Record a failed login.
	 *
	 * @param string $username
	 *
	 * @throws \Exception
	 */
	public function recordFailedLogin( $username ) {
		// Write the failure to login attempts.
		global $wpdb;
		$now    = time();
		$result = $wpdb->insert(
			$wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE,
			[
				'time'     => $now,
				'username' => $username,
				'ip'       => $_SERVER['REMOTE_ADDR'],
			]
		);

		// Check the insert worked.
		if ( ! $result ) {
			error_log( 'Warning: wp-ww_auth_log failed to write the login failure' );
		}

		// Check our table for the number of failed logins in the last X minutes.
		$since           = $now - ( 60 * static::LOGIN_DISABLE_WINDOW );
		$table           = $wpdb->prefix . static::LOGIN_ATTEMPTS_TABLE;
		$sql             = "SELECT COUNT(*) FROM $table WHERE time >= $since;";
		$recent_attempts = $wpdb->get_var( $sql );

		// Check if the threshold has been hit.
		if ( $recent_attempts >= static::LOGIN_DISABLE_THRESHOLD ) {
			update_option( 'ww_auth_log__login_disabled', $now );
			$this->log( strtr( 'Login has been disabled for !time minutes',
				[
					'!time' => static::LOGIN_DISABLE_TIME,
				] ) );
		}
	}

	protected function optionStrToArray($option_name) {
		$str = trim(get_option($option_name));
		if ($str) {
			$value = explode( ',', $str );
			$value = array_map( 'trim', $value );
			$value = array_filter( $value );
			return $value;
		}
		return [];
	}

	/**
	 * Kill the request if login is disabled or the country is not whitelisted.
	 *
	 * @throws \Exception
	 */
	public function killIfLoginDisabled() {
		// Check IP Whitelist (bypasses disabled login).
		$ip_whitelist = $this->optionStrToArray('ww_auth_log_ip_whitelist');
		if ( $ip_whitelist && in_array( $_SERVER['REMOTE_ADDR'], $ip_whitelist, TRUE ) ) {
			return;
		}

		$login_disabled = get_option( 'ww_auth_log__login_disabled' );
		$kill_login     = FALSE;
		if ( $login_disabled ) {
			// Check if the login has been disabled for long enough.
			if ( $login_disabled < ( time() - ( 60 * static::LOGIN_DISABLE_TIME ) ) ) {
				// Allow this function to quick return next time.
				update_option( 'ww_auth_log__login_disabled', FALSE );
			} else {
				$kill_login = TRUE;
				$this->log( 'Login attempted while disabled' );
			}
		}

		// Check Country Whitelist.
		if ( ! $kill_login ) {
			$country_whitelist = $this->optionStrToArray('ww_auth_log_country_whitelist');
			if ( $country_whitelist ) {
				$country    = $this->getIpCountry( '[Unknown]' );
        if ( $country !== '[WW]' ) {
          $kill_login = ! in_array( $country, $country_whitelist, TRUE );
          if ( $kill_login ) {
            $this->log( 'Login attempted from country not in whitelist: ' . $country );
          }
        }
			}
		}

		// Check Country Blacklist.
		if ( ! $kill_login ) {
			$country_blacklist = $this->optionStrToArray('ww_auth_log_country_blacklist');
			if ( $country_blacklist ) {
				$country    = $this->getIpCountry( '[Unknown]' );
        if ( $country !== '[WW]' ) {
          $kill_login = in_array( $country, $country_blacklist, TRUE );
          if ( $kill_login ) {
            $this->log( 'Login attempted from country in blacklist: ' . $country );
          }
        }
			}
		}

		// Kill the request.
		if ( $kill_login ) {
			if ( ob_get_length() !== FALSE ) {
				ob_end_clean();
			}
			http_response_code( 403 );
			die();
		}
	}

	/**
	 * Implements action: wp_login.
	 *
	 * @param string $user_login
	 *  The username.
	 * @param \WP_User $user
	 *  The user object.
	 *
	 * @throws \Exception
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function wp_login( $user_login, $user ) {
		$this->log( "Accepted password for $user_login" );
	}

	/**
	 * Implements action: wp_login_failed.
	 *
	 * @param string $username
	 *  The username.
	 *
	 * @throws \Exception
	 */
	public function wp_login_failed( $username ) {
		// Log the failure.
    $action_label = ( wp_cache_get( $username, 'userlogins' ) ) ? "failure for $username" : "attempt for unknown user $username";

    // Check IP Whitelist.
    $ip_whitelist = $this->optionStrToArray('ww_auth_log_ip_whitelist');
    if ( $ip_whitelist && in_array( $_SERVER['REMOTE_ADDR'], $ip_whitelist, TRUE ) ) {
      // NOTE: It's important to avoid the word 'authentication' here as it
      // would be picked up by fail2ban/nf2b.
      $this->log('Whitelisted IP auth ' . $action_label);
    } else {
      $this->log('Authentication ' . $action_label);
      $this->recordFailedLogin($username);
    }
	}

	/**
	 * Implements action: xmlrpc_call.
	 *
	 * @param string $call
	 *  The xmlrpc method being called.
	 *
	 * @throws \Exception
	 */
	public function xmlrpc_call( $call ) {
		// Log 'pingback' requests. TODO: What does these actually do?
		if ( $call === 'pingback.ping' ) {
			$this->log( 'Pingback requested' );
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
	 *
	 * @throws \Exception
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function xmlrpc_login_error( $error, $user ) {
		$this->log( 'XML-RPC authentication failure' );
		$this->recordFailedLogin( $user->user_login );

		// kill the request
		ob_end_clean();
		header( 'HTTP/1.0 403 Forbidden' );
		header( 'Content-Type: text/plain' );
		exit( 'Forbidden' );
	}

	/**
	 * Implements filter: xmlrpc_pingback_error.
	 *
	 * @param \IXR_Error $error
	 *  An IXR_Error object containing the error code and message.
	 *
	 * @return \IXR_Error
	 *
	 * @throws \Exception
	 */
	public function xmlrpc_pingback_error( $error ) {
		// TODO: Why only return and not log if 48?
		if ( 48 === $error->code ) {
			return $error;
		}
		$this->log( 'Pingback error ' . $error->code . ' generated' );
	}

	/**
	 * Implements action: plugins_loaded.
	 */
	public function plugins_loaded() {
		// Check if a database update is required.
		$db_version = get_site_option( 'ww_auth_log__db_version' );
		if ( ! $db_version || version_compare( static::DB_VERSION, $db_version, '<' ) ) {
			$this->install();
		}
	}

  /**
   * Implements filter: http_request_args.
   */
  public function http_request_args(array $args, string $url): array {
    // We need to allow plugin downloads that are local to our server.
    if (strpos($url, 'https://www.weavingwebs.co.uk/') === 0) {
      $args['reject_unsafe_urls'] = false;
    }
    return $args;
  }

  public function auth_cookie_expiration($expire) {
    $expiry_hours = get_option('ww_auth_log_auth_cookie_expiration');
    return $expiry_hours ? ($expiry_hours * 3600) : $expire;
  }

  public function return_false_if_option_true_callback($option_name) {
    return static function($value) use ($option_name) {
      return get_option($option_name) ? FALSE : $value;
    };
  }

	/**
	 * @param string $default
	 *
	 * @return string|null
	 * @throws \MaxMind\Db\Reader\InvalidDatabaseException
	 */
	protected function getIpCountry( $default = NULL ) {
    $ip = $_SERVER['REMOTE_ADDR'];
    if (in_array($ip, static::WW_INTERNAL_IPS, TRUE)) {
      return '[WW]';
    }

		$reader = new Reader(
			__DIR__ . '/../GeoLite2-Country.mmdb',
			// List of locale codes to use in name property in order of preference
			[ 'en' ]
		);
		try {
			$record  = $reader->country( $ip );
			$country = $record->country->isoCode;
		}
		catch ( AddressNotFoundException $e ) {
			$country = $default;
		}
		finally {
			$reader->close();
		}

		return $country;
	}

    /**
     * Part of function to hide WP version number from being found easily
     *
     * @param $url
     * @return array|mixed|string|string[]|null
     */
    public static function replaceVersion($url) {
        if (is_string($url))
            return preg_replace_callback("/([&;\?]ver)=(.+?)(&|$)/", static::class."::replaceVersionCallback", $url);
        return $url;
    }

    /**
     * Part of function to hide WP version number from being found easily
     *
     * @param $matches
     * @return string
     */
    public static function replaceVersionCallback($matches) {
        global $wp_version;
        return $matches[1] . '=' . ($wp_version === $matches[2] ? wp_hash($matches[2]) : $matches[2]) . $matches[3];
    }

    /**
     * Part of function to hide WP version number from being found easily
     * @return void
     */
    public static function initAction()
    {
		if (get_option('ww_auth_log_other_hideWPVersion')) {

            global $wp_version;
            global $wp_styles;

            if (!($wp_styles instanceof WP_Styles)) {
                $wp_styles = new WP_Styles();
            }
            if ($wp_styles->default_version === $wp_version) {
                $wp_styles->default_version = wp_hash($wp_styles->default_version);
            }

            foreach ($wp_styles->registered as $key => $val) {
                if ($wp_styles->registered[$key]->ver === $wp_version) {
                    $wp_styles->registered[$key]->ver = wp_hash($wp_styles->registered[$key]->ver);
                }
            }

            global $wp_scripts;
            if (!($wp_scripts instanceof WP_Scripts)) {
                $wp_scripts = new WP_Scripts();
            }
            if ($wp_scripts->default_version === $wp_version) {
                $wp_scripts->default_version = wp_hash($wp_scripts->default_version);
            }

            foreach ($wp_scripts->registered as $key => $val) {
                if ($wp_scripts->registered[$key]->ver === $wp_version) {
                    $wp_scripts->registered[$key]->ver = wp_hash($wp_scripts->registered[$key]->ver);
                }
            }
        }
    }

    /**
     * Part of function to hide WP version number from being found easily
     *
     * @param $gen
     * @param $type
     * @return mixed|string
     */
    public static function genFilter($gen, $type){
        if(get_option('ww_auth_log_other_hideWPVersion')){
            return '';
        } else {
            return $gen;
        }
    }

    /**
     * Add/Merge .htaccess file in the uploads directory to prevent code execution.
     *
     * Part of function to disable code execution from the uploads directory
     *
     * @return bool
     * @throws Exception
     */
    public static function disableCodeExecutionForUploads() {
        $uploads_htaccess_file_path = self::_uploadsHtaccessFilePath();
        $uploads_htaccess_has_content = false;
        if (file_exists($uploads_htaccess_file_path)) {
            $htaccess_contents = file_get_contents($uploads_htaccess_file_path);

            // htaccess exists and contains our htaccess code to disable script execution, nothing more to do
            if (strpos($htaccess_contents, self::$_disable_scripts_htaccess) !== false) {
                return true;
            }
            $uploads_htaccess_has_content = strlen(trim($htaccess_contents)) > 0;
        }
        if (@file_put_contents($uploads_htaccess_file_path, ($uploads_htaccess_has_content ? "\n\n" : "") . self::$_disable_scripts_htaccess, FILE_APPEND | LOCK_EX) === false) {
            throw new Exception(__("Unable to save the .htaccess file needed to disable script execution in the uploads directory. Please check your permissions on that directory.", 'wordfence'));
        }
        update_option( 'ww_auth_log_disableCodeExecutionUploadsPHP7Migrated', true );
        return true;
    }

    /**
     * Part of function to disable code execution from the uploads directory

     * @return void
     */
    public static function migrateCodeExecutionForUploadsPHP7() {
        if (get_option('disableCodeExecutionUploads')) {
            if (!get_option('disableCodeExecutionUploadsPHP7Migrated')) {
                $uploads_htaccess_file_path = self::_uploadsHtaccessFilePath();
                if (file_exists($uploads_htaccess_file_path)) {
                    $htaccess_contents = file_get_contents($uploads_htaccess_file_path);
                    if (preg_match(self::$_disable_scripts_regex, $htaccess_contents)) {
                        $htaccess_contents = preg_replace(self::$_disable_scripts_regex, self::$_disable_scripts_htaccess, $htaccess_contents);
                        @file_put_contents($uploads_htaccess_file_path, $htaccess_contents);
                        set_option('disableCodeExecutionUploadsPHP7Migrated', true);
                    }
                }
            }
        }
    }

    /**
     * Remove script execution protections for our the .htaccess file in the uploads directory.
     *
     * Part of function to disable code execution from the uploads directory

     * @return bool
     * @throws Exception
     */
    public static function removeCodeExecutionProtectionForUploads() {
        $uploads_htaccess_file_path = self::_uploadsHtaccessFilePath();
        if (file_exists($uploads_htaccess_file_path)) {
            $htaccess_contents = file_get_contents($uploads_htaccess_file_path);

            // Check that it is in the file
            if (preg_match(self::$_disable_scripts_regex, $htaccess_contents)) {
                $htaccess_contents = preg_replace(self::$_disable_scripts_regex, '', $htaccess_contents);

                $error_message = __("Unable to remove code execution protections applied to the .htaccess file in the uploads directory. Please check your permissions on that file.", 'wordfence');
                if (strlen(trim($htaccess_contents)) === 0) {
                    // empty file, remove it
                    if (!@unlink($uploads_htaccess_file_path)) {
                        throw new Exception($error_message);
                    }

                } elseif (@file_put_contents($uploads_htaccess_file_path, $htaccess_contents, LOCK_EX) === false) {
                    throw new Exception($error_message);
                }
            }
        }
        return true;
    }

    /**
     * Part of function to disable code execution from the uploads directory
     *
     * @return string
     */
    private static function _uploadsHtaccessFilePath() {
        $upload_dir = wp_upload_dir();
        return $upload_dir['basedir'] . '/.htaccess';
    }

    /**
     * Part of function to prevent discovery of usernames
     *
     * @param $data
     * @param $post
     * @param $width
     * @param $height
     * @return mixed
     */
	public static function oembedAuthorFilter($data, $post, $width, $height) {
		unset($data['author_name']);
		unset($data['author_url']);
		return $data;
	}

    /**
     * Part of function to prevent discovery of usernames
     *
     * @param $response
     * @param $handler
     * @param $request
     * @return mixed|\WP_Error|\WP_HTTP_Response|\WP_REST_Response
     */
	public static function jsonAPIAuthorFilter($response, $handler, $request) {
		$route = $request->get_route();
		if (!current_user_can('edit_others_posts')) {
			$urlBase = WWAuth_WP_REST_Users_Controller::wfGetURLBase();
			if (preg_match('~' . preg_quote($urlBase, '~') . '/*$~i', $route)) {
				$error = new WP_Error('rest_user_cannot_view', __('Sorry, you are not allowed to list users.', 'ww_auth_log'), array('status' => rest_authorization_required_code()));
				$response = rest_ensure_response($error);
				if (!defined('WWAUTH_REST_API_SUPPRESSED')) { define('WWAUTH_REST_API_SUPPRESSED', true); }
			}
			else if (preg_match('~' . preg_quote($urlBase, '~') . '/+(\d+)/*$~i', $route, $matches)) {
				$id = (int) $matches[1];
				if (get_current_user_id() !== $id) {
					$error = new WP_Error('rest_user_invalid_id', __('Invalid user ID.', 'ww_auth_log'), array('status' => 404));
					$response = rest_ensure_response($error);
					if (!defined('WWAUTH_REST_API_SUPPRESSED')) { define('WWAUTH_REST_API_SUPPRESSED', true); }
				}
			}
		}
		return $response;
	}

    /**
     * Part of function to prevent discovery of usernames
     *
     * @param $response
     * @param $server
     * @param $request
     * @return mixed
     */
	public static function jsonAPIAdjustHeaders($response, $server, $request) {
		if (defined('WWAUTH_REST_API_SUPPRESSED')) {
			$response->header('Allow', 'GET');
		}

		return $response;
	}

    /**
     * Part of function to prevent discovery of usernames
     *
     * @param $provider
     * @param $name
     * @return false|mixed
     */
	public static function wpSitemapUserProviderFilter($provider, $name) {
		if ($name === 'users') {
			return false;
		}
		return $provider;
	}

	/**
	 * Modify the query to prevent username enumeration.
	 *
	 * @param array $query_vars
	 * @return array
	 */
	public static function preventAuthorNScans($query_vars) {
		if (get_option('ww_auth_log_loginSec_disableAuthorScan') && !is_admin() &&
			!empty($query_vars['author']) && (is_array($query_vars['author']) || is_numeric(preg_replace('/[^0-9]/', '', $query_vars['author']))) &&
			(
				(isset($_GET['author']) && (is_array($_GET['author']) || is_numeric(preg_replace('/[^0-9]/', '', $_GET['author'])))) ||
				(isset($_POST['author']) && (is_array($_POST['author']) || is_numeric(preg_replace('/[^0-9]/', '', $_POST['author']))))
			)
		) {
			global $wp_query;
			$wp_query->set_404();
			status_header(404);
			nocache_headers();

			$template = get_404_template();
			if ($template && file_exists($template)) {
				include($template);
			}

			exit;
		}
		return $query_vars;
	}

}
