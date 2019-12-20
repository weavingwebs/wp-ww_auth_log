<?php
/**
* Plugin Name: WP WW Auth Log
* Description: Write all login attempts to a file (Based on wp-fail2ban)
* Text Domain: wp-ww_auth_log
* Version: 0.2.1
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
