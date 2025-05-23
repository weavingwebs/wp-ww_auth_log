<?php

namespace WW\AuthLog;

class WWAuthLogSettings {

	/**
	 * Initialise the Wordpress Hooks.
	 */
	public function wpInit() {
		add_action( 'admin_init', [$this, 'admin_init'] );
		add_action( 'admin_menu', [$this, 'admin_menu'] );
	}

	public function admin_init() {
		add_option( 'ww_auth_log_country_whitelist', 'GB');
		register_setting( 'ww_auth_log_options', 'ww_auth_log_country_whitelist' );

    add_option( 'ww_auth_log_country_blacklist', 'RU,KP,CN,BY,UA');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_country_blacklist' );

    add_option( 'ww_auth_log_auth_cookie_expiration', '10');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_auth_cookie_expiration' );

	  add_option( 'ww_auth_log_ip_whitelist', '');
		register_setting( 'ww_auth_log_options', 'ww_auth_log_ip_whitelist' );

	  add_option( 'ww_auth_log_disable_new_user_notification_to_admin', '');
		register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_new_user_notification_to_admin' );

	  add_option( 'ww_auth_log_disable_password_change_notification_to_admin', '');
		register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_password_change_notification_to_admin' );

    add_option( 'ww_auth_log_disable_admin_email_check_interval', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_admin_email_check_interval' );

    add_option( 'ww_auth_log_disable_auto_core_update_send_email', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_auto_core_update_send_email' );

    add_option( 'ww_auth_log_disable_auto_plugin_update_send_email', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_auto_plugin_update_send_email' );

    add_option( 'ww_auth_log_disable_auto_theme_update_send_email', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disable_auto_theme_update_send_email' );

    add_option( 'ww_auth_log_other_hideWPVersion', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_other_hideWPVersion' );

    add_option( 'ww_auth_log_disableCodeExecutionUploads', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disableCodeExecutionUploads' );

    add_option( 'ww_auth_log_disableCodeExecutionUploadsPHP7Migrated', '1');
    register_setting( 'ww_auth_log_options', 'ww_auth_log_disableCodeExecutionUploadsPHP7Migrated' );
	}

	public function admin_menu() {
		add_options_page('WW Auth Log', 'WW Auth Log', 'manage_options', 'ww_auth_log', [$this, 'adminHtml']);
	}

	public function adminHtml() {
		?>
		<div>
			<h2>WW Auth Log - Settings</h2>
			<form method="post" action="options.php">
				<?php settings_fields( 'ww_auth_log_options' ); ?>

        <div>
          <h3>IP Whitelist</h3>
          <label for="ww_auth_log_ip_whitelist">IPs:</label>
          <input
            type="text"
            id="ww_auth_log_ip_whitelist"
            name="ww_auth_log_ip_whitelist"
            value="<?php echo get_option('ww_auth_log_ip_whitelist'); ?>"
            size="60"
          />
          <ul class="ul-disc">
            <li>comma separate multiple values.</li>
            <li>Whitelisted IPs will bypass disabled login & Country Whitelist.</li>
          </ul>
        </div>

        <div>
          <h3>Country Whitelist</h3>
          <label for="ww_auth_log_country_whitelist">Countries:</label>
          <input
            type="text"
            id="ww_auth_log_country_whitelist"
            name="ww_auth_log_country_whitelist"
            value="<?php echo get_option('ww_auth_log_country_whitelist'); ?>"
            placeholder="i.e. GB,IE"
          />
          <ul class="ul-disc">
            <li>ISO country codes.</li>
            <li>comma separate multiple values.</li>
            <li>leave empty to allow anywhere.</li>
            <li>use [Unknown] to allow ips without a geoip entry (includes local subnets).</li>
          </ul>
        </div>

        <div>
          <h3>Country Blacklist</h3>
          <label for="ww_auth_log_country_blacklist">Countries:</label>
          <input
            type="text"
            id="ww_auth_log_country_blacklist"
            name="ww_auth_log_country_blacklist"
            value="<?php echo get_option('ww_auth_log_country_blacklist'); ?>"
            placeholder="i.e. GB,IE"
          />
          <ul class="ul-disc">
            <li>ISO country codes.</li>
            <li>comma separate multiple values.</li>
            <li>please note: whitelist takes precedence</li>
          </ul>
        </div>

        <div>
          <h3>Auth Cookie Expiration</h3>
          <label for="ww_auth_log_auth_cookie_expiration">Expiration in hours:</label>
          <input
            type="number"
            id="ww_auth_log_auth_cookie_expiration"
            name="ww_auth_log_auth_cookie_expiration"
            value="<?php echo get_option('ww_auth_log_auth_cookie_expiration'); ?>"
            min="0"
            placeholder=""
          />
          Must be a number of hours, leave blank for WordPress default.
        </div>

        <div>
          <h3>Admin Email Notifications</h3>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_new_user_notification_to_admin"
                name="ww_auth_log_disable_new_user_notification_to_admin"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_new_user_notification_to_admin'), 1 ); ?>
              />
              Disable New User Notifications to Admin
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_password_change_notification_to_admin"
                name="ww_auth_log_disable_password_change_notification_to_admin"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_password_change_notification_to_admin'), 1 ); ?>
              />
              Disable Password Change Notifications to Admin
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_admin_email_check_interval"
                name="ww_auth_log_disable_admin_email_check_interval"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_admin_email_check_interval'), 1 ); ?>
              />
              Disable periodic admin email verification page on login
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_auto_core_update_send_email"
                name="ww_auth_log_disable_auto_core_update_send_email"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_auto_core_update_send_email'), 1 ); ?>
              />
              Disable core update emails
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_auto_plugin_update_send_email"
                name="ww_auth_log_disable_auto_plugin_update_send_email"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_auto_plugin_update_send_email'), 1 ); ?>
              />
              Disable plugin update emails
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disable_auto_theme_update_send_email"
                name="ww_auth_log_disable_auto_theme_update_send_email"
                value="1"
                <?php checked( get_option('ww_auth_log_disable_auto_theme_update_send_email'), 1 ); ?>
              />
              Disable theme update emails
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_other_hideWPVersion"
                name="ww_auth_log_other_hideWPVersion"
                value="1"
                <?php checked( get_option('ww_auth_log_other_hideWPVersion'), 1 ); ?>
              />
              Hide Wordpress version
            </label>
          </div>
          <div>
            <label>
              <input
                type="checkbox"
                id="ww_auth_log_disableCodeExecutionUploads"
                name="ww_auth_log_disableCodeExecutionUploads"
                value="1"
                <?php checked( get_option('ww_auth_log_disableCodeExecutionUploads'), 1 ); ?>
              />
              Disable Code Execution for Uploads directory
            </label>
          </div>
        </div>

				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}

}
