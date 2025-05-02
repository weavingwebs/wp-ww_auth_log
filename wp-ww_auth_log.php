<?php
/**
* Plugin Name: WW Auth Log
* Description: Weaving Webs Additional Security.
* Text Domain: wp-ww_auth_log
* Version: 1.2.16
* Author: Weaving Webs Ltd
* License: GPL2
* SPDX-License-Identifier: GPL-2.0
*/

// Init the logger.
use WW\AuthLog\WWAuthLogger;
use WW\AuthLog\WWAuthLogSettings;

require __DIR__ . '/vendor/autoload.php';

$ww_auth_logger = new WWAuthLogger();
$ww_auth_logger->wpInit();
$ww_auth_logger_settings = new WWAuthLogSettings();
$ww_auth_logger_settings->wpInit();

$update_checker = Puc_v4_Factory::buildUpdateChecker(
  'https://weavingwebs.co.uk/wordpress-plugins/ww_auth_log/details.json',
  __FILE__, //Full path to the main plugin file or functions.php.
  'ww_auth_log'
);
