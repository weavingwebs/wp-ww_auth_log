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

	  add_option( 'ww_auth_log_ip_whitelist', '');
		register_setting( 'ww_auth_log_options', 'ww_auth_log_ip_whitelist' );
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
            <li>enter <code>!</code> to disallow any country (if the IP is not explicitly whitelisted).</li>
            <li>use [Unknown] to allow ips without a geoip entry (includes local subnets).</li>
          </ul>
        </div>

				<?php  submit_button(); ?>
			</form>
		</div>
		<?php
	}

}
