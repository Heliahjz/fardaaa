<?php
if (!defined('ONIVAL_ENTRY')) {
    define('ONIVAL_ENTRY', true);
}

/**
 * ==============================================================================
 * Dedicated Bale Bot Webhook Entry Point
 * URL: https://yourdomain.com/api/bale-webhook.php
 * ==============================================================================
 */

$_GET['platform'] = 'bale';
if (!isset($_GET['bot'])) {
    $_GET['bot'] = 'customer';
}
require __DIR__ . '/webhook.php';
