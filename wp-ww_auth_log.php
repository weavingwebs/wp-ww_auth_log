<?php
/**
* Plugin Name: WP WW Auth Log
* Description: Write all login attempts to a file (Based on wp-fail2ban)
* Text Domain: wp-ww_auth_log
* Version: 0.1.0
* Author: Weaving Webs Ltd
* License: GPL2
* SPDX-License-Identifier: GPL-2.0
*/

// Init the logger.
require_once __DIR__ . '/WWAuthLogger.php';
$ww_auth_logger = new \WWAuthLog\WWAuthLogger();
$ww_auth_logger->wpInit();
