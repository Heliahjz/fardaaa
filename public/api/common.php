<?php
if (!defined('ONIVAL_ENTRY')) {
    http_response_code(404);
    exit;
}

/**
 * ==============================================================================
 * ONIVAL Core Engine & Security Bootstrap for PHP Shared Hosting (ParsPack/cPanel)
 * ==============================================================================
 * Provides unified transactional storage, structured logging, authentication,
 * inventory management, and hardened Bale bot integration.
 * ==============================================================================
 */

error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');

// ------------------------------------------------------------------------------
// ------------------------------------------------------------------------------
// 1. Canonical Paths & Environment Resolution (Derived strictly from code location)
// ------------------------------------------------------------------------------
$apiDir = __DIR__;
$publicDir = dirname(__DIR__);
$homeDir = dirname(__DIR__, 2);
define('ONIVAL_PRIVATE_DIR', $homeDir . '/onival-private');

// Subdirectories inside private directory
$logDir = ONIVAL_PRIVATE_DIR . '/logs';
$receiptsDir = ONIVAL_PRIVATE_DIR . '/receipts';
$backupsDir = ONIVAL_PRIVATE_DIR . '/backups';
$tmpDir = ONIVAL_PRIVATE_DIR . '/tmp';

$dataFile = ONIVAL_PRIVATE_DIR . '/onival-persistent-data.json';
$lockFile = ONIVAL_PRIVATE_DIR . '/.onival.lock';
$logFile = $logDir . '/app.log';
$secretFile = ONIVAL_PRIVATE_DIR . '/session_secret';
$rateLimitsFile = ONIVAL_PRIVATE_DIR . '/rate_limits.json';
$revokedTokensFile = ONIVAL_PRIVATE_DIR . '/revoked_tokens.json';
$webhookUpdatesFile = ONIVAL_PRIVATE_DIR . '/webhook_updates.json';
$committedWritesCount = 0;
define('ONIVAL_BUILD_ID', 'ONIVAL-2026.04-HOTFIX');
define('ONIVAL_MIN_PHP_VERSION', '8.0.0');
define('ONIVAL_MIN_PHP_VERSION_ID', 80000);

// PHP Version Compatibility Polyfills
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return (string)$needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

if (!function_exists('array_is_list')) {
    function array_is_list(array $array): bool {
        $i = 0;
        foreach ($array as $k => $v) {
            if ($k !== $i++) {
                return false;
            }
        }
        return true;
    }
}

function isValidAdminUsername($username, $isPending = false, $initialUsername = 'onival_setup') {
    if (!is_string($username)) {
        return ['ok' => false, 'code' => 'INVALID_USERNAME', 'error' => 'نام کاربری نامعتبر است.'];
    }
    $u = trim($username);
    if (!preg_match('/^[a-zA-Z0-9._-]{3,32}$/', $u)) {
        return ['ok' => false, 'code' => 'INVALID_USERNAME', 'error' => 'نام کاربری جدید باید بین ۳ تا ۳۲ کاراکتر و فقط شامل حروف انگلیسی، اعداد، نقطه، خط فاصله یا زیرخط باشد.'];
    }
    if (strpos($u, '@') !== false) {
        return ['ok' => false, 'code' => 'INVALID_USERNAME', 'error' => 'نام کاربری نمی‌تواند ساختار ایمیل داشته باشد.'];
    }
    $norm = strtolower($u);
    if ($isPending && strtolower(trim((string)$initialUsername)) === $norm) {
        return ['ok' => false, 'code' => 'USERNAME_SAME_AS_INITIAL', 'error' => 'نام کاربری جدید باید با شناسه کاربری موقت اولیه متفاوت باشد.'];
    }
    if ($norm === 'admin') {
        return ['ok' => false, 'code' => 'USERNAME_RESERVED', 'error' => 'استفاده از نام کاربری عمومی admin مجاز نمی‌باشد.'];
    }
    return ['ok' => true, 'username' => $u];
}

function isUsablePasswordHash($hash) {
    if (!is_string($hash) || trim($hash) === '') {
        return false;
    }
    $trimmed = trim($hash);
    if (!str_starts_with($trimmed, '$')) {
        return false;
    }
    $info = password_get_info($trimmed);
    return isset($info['algo']) && $info['algo'] !== null && $info['algo'] !== 0;
}

function checkOpenBasedirCompatibilityPhp() {
    $ob = ini_get('open_basedir');
    if (empty($ob)) return ['ok' => true, 'open_basedir' => 'none'];
    $allowed = explode(PATH_SEPARATOR, $ob);
    foreach ($allowed as $path) {
        $clean = rtrim($path, '/\\');
        if (str_starts_with(ONIVAL_PRIVATE_DIR, $clean)) {
            return ['ok' => true, 'open_basedir' => $ob];
        }
    }
    return ['ok' => false, 'open_basedir' => $ob];
}

function ensurePrivateStorageAvailableOrExit() {
    if (!is_dir(ONIVAL_PRIVATE_DIR) || !is_writable(ONIVAL_PRIVATE_DIR)) {
        onival_log('storage', 'LOGIN_FAIL', 'LOGIN_FAIL reason=storage_unavailable', [
            'reason' => 'storage_unavailable',
            'privateDir' => ONIVAL_PRIVATE_DIR,
            'open_basedir' => ini_get('open_basedir') ?: 'none'
        ]);
        http_response_code(503);
        echo json_encode([
            'ok' => false,
            'code' => 'STORAGE_UNAVAILABLE',
            'error' => 'فضای ذخیره‌سازی خصوصی سیستم در دسترس نمی‌باشد (storage_unavailable).'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * Authoritative single bootstrap & readiness function for ONIVAL runtime
 */
function ensureRuntimeReady() {
    global $dataFile, $lockFile, $logDir, $receiptsDir, $backupsDir, $tmpDir;

    // 0. Minimum supported PHP version check
    if (PHP_VERSION_ID < ONIVAL_MIN_PHP_VERSION_ID) {
        return [
            'ok' => false,
            'code' => 'PHP_UNSUPPORTED',
            'status' => 'php_unsupported',
            'detail' => ONIVAL_MIN_PHP_VERSION,
            'error' => 'نسخه PHP سرور باید حداقل ' . ONIVAL_MIN_PHP_VERSION . ' باشد (php_unsupported).'
        ];
    }

    // 1. Ensure private runtime directory exists (0700 where supported)
    if (!is_dir(ONIVAL_PRIVATE_DIR)) {
        @mkdir(ONIVAL_PRIVATE_DIR, 0700, true);
        @chmod(ONIVAL_PRIVATE_DIR, 0700);
    }
    if (!is_dir(ONIVAL_PRIVATE_DIR)) {
        return [
            'ok' => false,
            'code' => 'STORAGE_UNAVAILABLE',
            'status' => 'storage_unavailable',
            'detail' => 'dir_missing',
            'error' => 'پوشه خصوصی داده‌های سرور قابل ایجاد نیست (storage_unavailable).'
        ];
    }

    // 2. Storage write/delete probe with status marker cache (avoids per-request churn)
    $markerFile = ONIVAL_PRIVATE_DIR . '/.runtime_probe_ok';
    $shouldProbe = true;
    if (file_exists($markerFile)) {
        $mtime = @filemtime($markerFile);
        if ($mtime && (time() - $mtime < 300) && is_writable(ONIVAL_PRIVATE_DIR)) {
            $shouldProbe = false;
        }
    }

    if ($shouldProbe) {
        $probe = ONIVAL_PRIVATE_DIR . '/.storage_probe_' . bin2hex(random_bytes(8));
        if (@file_put_contents($probe, 'ok', LOCK_EX) === false) {
            return [
                'ok' => false,
                'code' => 'STORAGE_UNAVAILABLE',
                'status' => 'storage_unavailable',
                'detail' => 'probe_failed',
                'error' => 'پوشه خصوصی داده‌ها قابل نوشتن نیست (storage_unavailable).'
            ];
        }
        @unlink($probe);
        @touch($markerFile);
    }

    // 3. Ensure subdirectories
    foreach ([$logDir, $receiptsDir, $backupsDir, $tmpDir] as $sd) {
        if (!is_dir($sd)) {
            @mkdir($sd, 0700, true);
            @chmod($sd, 0700);
        }
    }

    // 4. Database initialization under exclusive lock
    $lockFp = @fopen($lockFile, 'c+');
    if (!$lockFp || !@flock($lockFp, LOCK_EX)) {
        if ($lockFp) @fclose($lockFp);
        return [
            'ok' => false,
            'code' => 'STORAGE_LOCK_FAILED',
            'status' => 'storage_unavailable',
            'detail' => 'lock_failed',
            'error' => 'قفل پایگاه داده برقرار نشد.'
        ];
    }

    $db = null;
    $dbLoaded = false;
    if (file_exists($dataFile)) {
        $raw = @file_get_contents($dataFile);
        if ($raw === false || trim($raw) === '') {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return [
                'ok' => false,
                'code' => 'DB_INVALID',
                'status' => 'db_invalid',
                'detail' => 'empty_or_unreadable',
                'error' => 'پایگاه داده موجود است اما خالی یا غیرقابل خواندن است (db_invalid).'
            ];
        }

        $parsed = @json_decode($raw, true);
        if (!is_array($parsed)) {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return [
                'ok' => false,
                'code' => 'DB_INVALID',
                'status' => 'db_invalid',
                'detail' => 'invalid_json',
                'error' => 'فرمت پایگاه داده موجود نامعتبر است (db_invalid).'
            ];
        }

        // List-type core keys must be non-associative lists
        $listKeys = ['products', 'productCategories', 'orders'];
        foreach ($listKeys as $lk) {
            if (!array_key_exists($lk, $parsed) || !is_array($parsed[$lk]) || !array_is_list($parsed[$lk])) {
                @flock($lockFp, LOCK_UN);
                @fclose($lockFp);
                return [
                    'ok' => false,
                    'code' => 'DB_INVALID',
                    'status' => 'db_invalid',
                    'detail' => 'core_key_invalid',
                    'error' => "ساختار پایگاه داده ناقص است؛ کلید لیستی {$lk} باید یک لیست متوالی باشد (db_invalid)."
                ];
            }
        }

        // Object-type core keys must be associative arrays or empty array {}
        $mapKeys = ['siteContent', 'adminCredentials'];
        foreach ($mapKeys as $mk) {
            if (!array_key_exists($mk, $parsed) || !is_array($parsed[$mk])) {
                @flock($lockFp, LOCK_UN);
                @fclose($lockFp);
                return [
                    'ok' => false,
                    'code' => 'DB_INVALID',
                    'status' => 'db_invalid',
                    'detail' => 'core_key_invalid',
                    'error' => "ساختار پایگاه داده ناقص است؛ کلید {$mk} باید یک شیء باشد (db_invalid)."
                ];
            }
            if (!empty($parsed[$mk]) && array_is_list($parsed[$mk])) {
                @flock($lockFp, LOCK_UN);
                @fclose($lockFp);
                return [
                    'ok' => false,
                    'code' => 'DB_INVALID',
                    'status' => 'db_invalid',
                    'detail' => 'core_key_invalid',
                    'error' => "ساختار پایگاه داده نامعتبر است؛ کلید شیئی {$mk} نباید به صورت لیست عددی ذخیره شود (db_invalid)."
                ];
            }
        }

        $db = $parsed;
        $dbLoaded = true;
    }

    $seed = null;
    $seedFile = __DIR__ . '/seed.php';
    if (file_exists($seedFile)) {
        $seed = require $seedFile;
    }

    $needsWrite = false;
    if (!$dbLoaded) {
        if (!is_array($seed) || empty($seed['products']) || !is_array($seed['products']) || !array_is_list($seed['products']) || count($seed['products']) === 0) {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return [
                'ok' => false,
                'code' => 'SEED_MISSING',
                'status' => 'seed_missing',
                'detail' => 'seed_missing',
                'error' => 'فایل سید اولیه سرور یافت نشد یا محصولات آن خالی/نامعتبر است (seed_missing).'
            ];
        }
        $db = $seed;
        $needsWrite = true;
    } else {
        // For an existing loaded database, ensure missing optional collections get neutral defaults (NEVER copy seed into existing DB)
        $optionalCols = ['posts', 'postCategories', 'contactMessages', 'slugRedirects'];
        foreach ($optionalCols as $col) {
            if (!isset($db[$col]) || !is_array($db[$col])) {
                $db[$col] = [];
                $needsWrite = true;
            }
        }
    }

    // State-based credential check & bootstrap
    $creds = $db['adminCredentials'] ?? [];
    $isCompleted = !empty($creds['initialSetupCompleted']);
    $hasUsablePass = !empty($creds['password']) && isUsablePasswordHash($creds['password']);
    $hasOtp = !empty($creds['oneTimePassword']) && is_string($creds['oneTimePassword']) && trim($creds['oneTimePassword']) !== '';

    if ($isCompleted) {
        if (!$hasUsablePass) {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            onival_log('auth', 'credential_unusable', 'initialSetupCompleted is true but no usable password hash exists');
            return [
                'ok' => false,
                'code' => 'CREDENTIAL_UNUSABLE',
                'status' => 'credential_unusable',
                'detail' => 'password_hash_unusable',
                'error' => 'رمز عبور مدیر معتبر نیست.'
            ];
        }
    } else {
        if (!$hasUsablePass && !$hasOtp) {
            $initAdmin = $seed['initialAdmin'] ?? null;
            if (!is_array($initAdmin) || empty($initAdmin['username']) || empty($initAdmin['tempPassword'])) {
                @flock($lockFp, LOCK_UN);
                @fclose($lockFp);
                return [
                    'ok' => false,
                    'code' => 'BOOTSTRAP_FAILED',
                    'status' => 'bootstrap_failed',
                    'detail' => 'seed_credential_missing',
                    'error' => 'اطلاعات احراز هویت اولیه در سید سرور موجود نیست.'
                ];
            }

            $initUser = trim((string)$initAdmin['username']);
            $initTempPass = trim((string)$initAdmin['tempPassword']);
            $hashedOtp = password_hash($initTempPass, PASSWORD_DEFAULT);

            if (!isset($db['adminCredentials']) || !is_array($db['adminCredentials'])) {
                $db['adminCredentials'] = [];
            }
            $db['adminCredentials']['username'] = $initUser;
            $db['adminCredentials']['password'] = '';
            $db['adminCredentials']['oneTimePassword'] = $hashedOtp;
            $db['adminCredentials']['oneTimePasswordExpired'] = false;
            $db['adminCredentials']['initialSetupCompleted'] = false;
            $db['adminCredentials']['email'] = $db['adminCredentials']['email'] ?? 'admin@onival.com';
            $db['adminCredentials']['name'] = $db['adminCredentials']['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)';
            $needsWrite = true;
        }
    }

    if ($needsWrite) {
        $tmp = $dataFile . '.tmp.' . uniqid('', true);
        $encoded = json_encode($db, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        $written = @file_put_contents($tmp, $encoded, LOCK_EX);
        if ($written === false || $written !== strlen($encoded)) {
            @unlink($tmp);
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return ['ok' => false, 'code' => 'DB_WRITE_FAILED', 'error' => 'خطا در ثبت پایگاه داده روی دیسک هاست.'];
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $dataFile)) {
            @unlink($tmp);
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return ['ok' => false, 'code' => 'DB_RENAME_FAILED', 'error' => 'خطا در نهایی‌سازی پایگاه داده روی سرور.'];
        }
        @chmod($dataFile, 0600);
    }

    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);

    return [
        'ok' => true,
        'code' => 'READY',
        'status' => 'ready',
        'detail' => 'ready',
        'initialSetupCompleted' => !empty($db['adminCredentials']['initialSetupCompleted'])
    ];
}

// ------------------------------------------------------------------------------
// 2. Structured Bounded Application Logger (Outside Public Web)
// ------------------------------------------------------------------------------
function onival_sanitize_log_data($data) {
    if (is_null($data) || is_scalar($data)) {
        if (is_string($data)) {
            // Mask bot tokens and credentials in query strings or text
            $data = preg_replace('/(?i)(token|secret|password|authorization|auth|provider_token|card|k)=([^\s&]+)/', '$1=[REDACTED]', $data);
            if (strlen($data) > 60 && preg_match('/^[a-f0-9]{32,}$/i', $data)) {
                return substr($data, 0, 6) . '...[REDACTED]';
            }
        }
        return $data;
    }
    if (is_array($data)) {
        $clean = [];
        $sensitiveKeys = [
            'password', 'newpassword', 'currentpassword', 'token', 'bottoken',
            'adminbottoken', 'customerbottoken', 'balebottoken', 'provider_token',
            'balepaymenttoken', 'balepaymenttokenlive', 'balepaymenttokentest',
            'webhooksecrettoken', 'customerwebhooksecrettoken', 'adminwebhooksecrettoken',
            'authorization', 'x-admin-token', 'k', 'secret'
        ];
        foreach ($data as $k => $v) {
            if (in_array(strtolower((string)$k), $sensitiveKeys, true)) {
                $clean[$k] = '[REDACTED]';
            } else {
                $clean[$k] = onival_sanitize_log_data($v);
            }
        }
        return $clean;
    }
    return '[object]';
}

function onival_log($stage, $category, $message, $context = [], $correlationId = null) {
    global $logFile;
    if (empty($correlationId)) {
        $correlationId = substr(bin2hex(random_bytes(8)), 0, 12);
    }

    $entry = [
        'timestamp' => date('c'),
        'correlationId' => $correlationId,
        'stage' => $stage,
        'category' => $category,
        'message' => mb_substr((string)$message, 0, 500, 'UTF-8'),
        'context' => onival_sanitize_log_data($context),
        'server' => [
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
            'uri' => onival_sanitize_log_data($_SERVER['REQUEST_URI'] ?? ''),
            'ip' => isset($_SERVER['REMOTE_ADDR']) ? hash('sha256', $_SERVER['REMOTE_ADDR']) : 'local'
        ]
    ];

    $line = json_encode($entry, JSON_UNESCAPED_UNICODE) . "\n";
    $written = false;

    try {
        $dir = dirname($logFile);
        if (is_dir($dir) && is_writable($dir)) {
            // Rotate log file if > 2MB, keep 1 rotated copy
            if (file_exists($logFile) && @filesize($logFile) > 2097152) {
                @rename($logFile, $logFile . '.1');
            }
            $res = @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
            if ($res !== false) {
                $written = true;
            }
        }
    } catch (\Throwable $e) {
        $written = false;
    }

    if (!$written) {
        // Fall back to single-line sanitized reason codes via error_log() (no paths, no secrets)
        $cleanCategory = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$category);
        $cleanStage = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$stage);
        $reason = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)($context['reason'] ?? $category));
        @error_log("[ONIVAL_FALLBACK] stage={$cleanStage} cat={$cleanCategory} reason={$reason} corr={$correlationId}");
    }

    return $correlationId;
}

// ------------------------------------------------------------------------------
// 3. HMAC Session Secret
// ------------------------------------------------------------------------------
function getAdminSessionSecret() {
    global $secretFile;
    $envSecret = getenv('ADMIN_TOKEN_SECRET');
    if (!empty($envSecret) && strlen($envSecret) >= 32) {
        return $envSecret;
    }
    if (file_exists($secretFile)) {
        $stored = trim((string)@file_get_contents($secretFile));
        if (strlen($stored) >= 32) {
            return $stored;
        }
    }
    $newSecret = bin2hex(random_bytes(32));
    @file_put_contents($secretFile, $newSecret, LOCK_EX);
    return $newSecret;
}

// ------------------------------------------------------------------------------
// 4. Atomic Transactional JSON Database Access (Sidecar Lock Pattern)
// ------------------------------------------------------------------------------
function withDatabaseTransaction(callable $callback) {
    global $dataFile, $lockFile, $committedWritesCount;

    $lockFp = @fopen($lockFile, 'c+');
    if (!$lockFp) {
        onival_log('database', 'lock_failure', 'Could not open sidecar lock file', ['lockFile' => $lockFile]);
        return ['ok' => false, 'code' => 'DATA_WRITE_FAILED', 'error' => 'خطای قفل پایگاه داده (Database Lock Error)'];
    }

    $locked = @flock($lockFp, LOCK_EX);
    if (!$locked) {
        @fclose($lockFp);
        onival_log('database', 'lock_failure', 'Could not acquire exclusive sidecar lock');
        return ['ok' => false, 'code' => 'DATA_WRITE_FAILED', 'error' => 'پایگاه داده در حال حاضر مشغول است'];
    }

    try {
        if (!file_exists($dataFile)) {
            ensureRuntimeReady();
        }
        if (!file_exists($dataFile)) {
            throw new \RuntimeException('Database file is missing and initialization failed');
        }

        $raw = @file_get_contents($dataFile);
        if ($raw === false || strlen($raw) < 5) {
            throw new \RuntimeException('Database file is unreadable (INVALID_JSON)');
        }
        $db = @json_decode($raw, true);
        if (!is_array($db) || !isset($db['products'])) {
            throw new \RuntimeException('Database file contains invalid JSON (INVALID_JSON)');
        }

        // State-based bootstrap check under existing lock
        $creds = $db['adminCredentials'] ?? [];
        if (empty($creds['initialSetupCompleted']) && empty($creds['oneTimePassword']) && empty($creds['password'])) {
            ensureRuntimeReady();
            $freshRaw = @file_get_contents($dataFile);
            $freshDb = @json_decode($freshRaw, true);
            if (is_array($freshDb) && isset($freshDb['products'])) {
                $db = $freshDb;
            }
        }

        // Execute mutation
        $result = $callback($db);

        // If callback returned boolean false or explicitly indicated cancel, do not write
        if ($result !== false && (!is_array($result) || !isset($result['_cancelWrite']))) {
            $db['updatedAt'] = date('c');
            $jsonOut = json_encode($db, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

            if (!empty($jsonOut) && strlen($jsonOut) > 10) {
                $tmpFile = $dataFile . '.tmp.' . uniqid('', true);
                $written = @file_put_contents($tmpFile, $jsonOut, LOCK_EX);
                if ($written !== false && $written === strlen($jsonOut)) {
                    if (file_exists($dataFile)) {
                        @copy($dataFile, $dataFile . '.bak');
                    }
                    if (!@rename($tmpFile, $dataFile)) {
                        @unlink($tmpFile);
                        throw new \RuntimeException('Failed to atomically rename database temporary file');
                    }
                    @chmod($dataFile, 0600);
                    // Read back verification
                    $verifyRaw = @file_get_contents($dataFile);
                    $verifyJson = @json_decode($verifyRaw, true);
                    if (!is_array($verifyJson) || !isset($verifyJson['products'])) {
                        throw new \RuntimeException('Database verification readback failed after write');
                    }
                    $committedWritesCount++;
                } else {
                    @unlink($tmpFile);
                    throw new \RuntimeException('Failed to write complete database JSON contents');
                }
            }
        }

        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
        return $result;
    } catch (\Throwable $e) {
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
        onival_log('database', 'transaction_exception', $e->getMessage(), [
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ]);
        return ['ok' => false, 'code' => 'DATA_WRITE_FAILED', 'error' => 'خطای سیستمی در ثبت تراکنش دیتابیس: ' . $e->getMessage()];
    }
}

function loadDatabaseReadonly() {
    global $dataFile, $lockFile;
    if (!file_exists($dataFile)) {
        ensureRuntimeReady();
    }
    if (!file_exists($dataFile)) {
        return null;
    }

    $lockFp = @fopen($lockFile, 'r');
    if ($lockFp) {
        @flock($lockFp, LOCK_SH);
    }
    $raw = @file_get_contents($dataFile);
    if ($lockFp) {
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
    }

    if (!$raw || strlen($raw) < 5) return null;
    $data = @json_decode($raw, true);
    if (!is_array($data) || !isset($data['products'])) {
        return null; // Never return empty template for corrupted/failed read
    }

    // State-based bootstrap check: if setup is pending and credentials are null/empty
    $creds = $data['adminCredentials'] ?? [];
    if (empty($creds['initialSetupCompleted']) && empty($creds['oneTimePassword']) && empty($creds['password'])) {
        ensureRuntimeReady();
        $freshRaw = @file_get_contents($dataFile);
        $freshData = @json_decode($freshRaw, true);
        if (is_array($freshData) && isset($freshData['products'])) {
            $data = $freshData;
        }
    }

    return $data;
}

// ------------------------------------------------------------------------------
// 5. Authentication & Passwords
// ------------------------------------------------------------------------------
function hashAdminPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function matchesOneTimeCredential($input, $stored) {
    if (!is_string($input) || !is_string($stored) || $input === '' || $stored === '') {
        return false;
    }
    $trimmedInput = trim($input);
    $trimmedStored = trim($stored);
    if ($trimmedInput === '' || $trimmedStored === '') {
        return false;
    }

    // Modern password_hash check
    if (str_starts_with($trimmedStored, '$')) {
        if (password_verify($trimmedInput, $trimmedStored) || password_verify($input, $trimmedStored)) {
            return true;
        }
    }

    // Legacy plain check via hash_equals
    if (hash_equals($trimmedStored, $trimmedInput) || hash_equals($stored, $input)) {
        return true;
    }

    return false;
}

function verifyAdminPassword($inputPass, $storedPassOrHash, $isInitialPending = false, $oneTimePassOrHash = null) {
    // Reject empty input immediately
    if (!is_string($inputPass) || trim($inputPass) === '') return false;
    $trimmedInput = trim($inputPass);

    // Initial setup pending (initialSetupCompleted === false): strictly verify against stored oneTimePassword
    if ($isInitialPending) {
        return matchesOneTimeCredential($inputPass, (string)$oneTimePassOrHash);
    }

    // Post-setup: strictly valid native password_hash ($2y$, $argon2id$, etc.)
    if (!is_string($storedPassOrHash) || trim($storedPassOrHash) === '') return false;
    $trimmedStored = trim($storedPassOrHash);

    // Never authenticate against a scrypt: or non-standard hash
    if (!str_starts_with($trimmedStored, '$')) {
        return false;
    }

    if (password_verify($trimmedInput, $trimmedStored) || password_verify($inputPass, $trimmedStored)) {
        return true;
    }

    return false;
}

// ------------------------------------------------------------------------------
// 5.1 Shared Authoritative Pricing Function
// ------------------------------------------------------------------------------
function calculateProductPricePhp($product, $selectedSize = null) {
    $basePrice = $selectedSize ? (int)($selectedSize['price'] ?? 0) : (int)($product['price'] ?? 0);
    $isAmazing = !empty($product['isAmazingOffer']) || !empty($product['isSpecialOffer']);

    // Quota resolution: a missing size-level quota inherits product-level quota; product-level zero means no promo.
    $productPromoQuota = isset($product['specialOfferStock']) && $product['specialOfferStock'] !== '' && $product['specialOfferStock'] !== null
        ? (int)$product['specialOfferStock']
        : null;

    if ($productPromoQuota === 0) {
        $quota = 0;
    } elseif ($selectedSize && isset($selectedSize['specialOfferStock']) && $selectedSize['specialOfferStock'] !== '' && $selectedSize['specialOfferStock'] !== null) {
        $quota = (int)$selectedSize['specialOfferStock'];
    } else {
        $quota = $productPromoQuota;
    }

    $promoDiscountPrice = $selectedSize && !empty($selectedSize['discountPrice'])
        ? (int)$selectedSize['discountPrice']
        : (!empty($product['discountPrice']) ? (int)$product['discountPrice'] : null);

    $ordinaryDiscount = max(0, min(99, (int)($product['discount'] ?? $product['discountPercent'] ?? 0)));

    // Rule: The promotional "amazing offer" discount applies only while active and quota > 0
    if ($isAmazing) {
        if ($quota !== null && $quota <= 0) {
            // When exhausted, the base price applies and the code must not fall through to the ordinary-discount branch
            return [
                'price' => $basePrice,
                'oldPrice' => null,
                'isPromo' => false,
                'quotaExhausted' => true
            ];
        }
        if ($promoDiscountPrice && $promoDiscountPrice > 0 && $promoDiscountPrice < $basePrice) {
            return [
                'price' => $promoDiscountPrice,
                'oldPrice' => $basePrice,
                'isPromo' => true,
                'quotaExhausted' => false
            ];
        }
        if ($ordinaryDiscount > 0) {
            $calc = (int)round($basePrice * (100 - $ordinaryDiscount) / 100);
            return [
                'price' => $calc,
                'oldPrice' => $basePrice,
                'isPromo' => true,
                'quotaExhausted' => false
            ];
        }
    }

    // Rule: Ordinary discount always applies for non-promo products
    if ($ordinaryDiscount > 0) {
        $calc = (int)round($basePrice * (100 - $ordinaryDiscount) / 100);
        return [
            'price' => $calc,
            'oldPrice' => $basePrice,
            'isPromo' => false,
            'quotaExhausted' => false
        ];
    }

    if ($promoDiscountPrice && $promoDiscountPrice > 0 && $promoDiscountPrice < $basePrice && ($quota === null || $quota > 0)) {
        return [
            'price' => $promoDiscountPrice,
            'oldPrice' => $basePrice,
            'isPromo' => false,
            'quotaExhausted' => false
        ];
    }

    return [
        'price' => $basePrice,
        'oldPrice' => null,
        'isPromo' => false,
        'quotaExhausted' => false
    ];
}

function getBearerToken() {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        return trim($matches[1]);
    }
    if (!empty($_SERVER['HTTP_X_ADMIN_TOKEN'])) {
        return trim($_SERVER['HTTP_X_ADMIN_TOKEN']);
    }
    return '';
}

$GLOBALS['__ONIVAL_CACHED_RAW_BODY'] = null;

function getRequestBodyCached($maxBytes = 10485760) {
    if ($GLOBALS['__ONIVAL_CACHED_RAW_BODY'] !== null) {
        if ($maxBytes !== null && strlen($GLOBALS['__ONIVAL_CACHED_RAW_BODY']) > $maxBytes) {
            http_response_code(413);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok' => false,
                'code' => 'PAYLOAD_TOO_LARGE',
                'error' => 'حجم بدنه درخواست بیش از حد مجاز است (413 Payload Too Large).'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        return $GLOBALS['__ONIVAL_CACHED_RAW_BODY'];
    }

    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($maxBytes !== null && $contentLength > $maxBytes) {
        http_response_code(413);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok' => false,
            'code' => 'PAYLOAD_TOO_LARGE',
            'error' => 'حجم بدنه درخواست بیش از حد مجاز است (413 Payload Too Large).'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $raw = @file_get_contents('php://input', false, null, 0, $maxBytes ? ($maxBytes + 1) : -1);
    if ($raw !== false && $maxBytes !== null && strlen($raw) > $maxBytes) {
        http_response_code(413);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok' => false,
            'code' => 'PAYLOAD_TOO_LARGE',
            'error' => 'حجم بدنه درخواست بیش از حد مجاز است (413 Payload Too Large).'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $GLOBALS['__ONIVAL_CACHED_RAW_BODY'] = ($raw !== false) ? $raw : '';
    return $GLOBALS['__ONIVAL_CACHED_RAW_BODY'];
}

function readBoundedRequestBodyPhp($maxBytes = 10485760) {
    return getRequestBodyCached($maxBytes);
}

function claimWebhookUpdatePhp($updateId, $ttlSeconds = 120) {
    global $webhookUpdatesFile;
    if ($updateId === null || $updateId === '' || empty($webhookUpdatesFile)) {
        return ['ok' => true, 'claimed' => true];
    }

    // Verify it strictly lives in ONIVAL_PRIVATE_DIR
    if (!str_starts_with($webhookUpdatesFile, ONIVAL_PRIVATE_DIR)) {
        return ['ok' => false, 'code' => 'INVALID_PATH'];
    }

    $lockFile = $webhookUpdatesFile . '.lock';
    $lockFp = @fopen($lockFile, 'c+');
    if (!$lockFp || !@flock($lockFp, LOCK_EX)) {
        if ($lockFp) @fclose($lockFp);
        return ['ok' => false, 'code' => 'LOCK_FAILED'];
    }

    $now = time();
    $data = [];
    if (file_exists($webhookUpdatesFile)) {
        $raw = @file_get_contents($webhookUpdatesFile);
        $data = @json_decode($raw, true) ?: [];
    }

    // Prune entries older than 24h
    $pruned = [];
    foreach ($data as $id => $entry) {
        $ts = is_array($entry) ? ($entry['timestamp'] ?? 0) : (int)$entry;
        if (($now - $ts) < 86400) {
            $pruned[$id] = is_array($entry) ? $entry : ['state' => 'done', 'timestamp' => $ts];
        }
    }
    // Bounded store: retain up to 3000 recent update claims
    if (count($pruned) > 3000) {
        $pruned = array_slice($pruned, -3000, null, true);
    }

    $updateKey = (string)$updateId;
    if (isset($pruned[$updateKey])) {
        $existing = $pruned[$updateKey];
        $state = $existing['state'] ?? 'done';
        $ts = (int)($existing['timestamp'] ?? 0);

        // Done entries are NEVER reclaimed
        if ($state === 'done') {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
            return ['ok' => true, 'claimed' => false, 'reason' => 'done'];
        }

        // In flight check: if claimed recently (< TTL), prevent double processing
        if ($state === 'claimed') {
            if (($now - $ts) < $ttlSeconds) {
                @flock($lockFp, LOCK_UN);
                @fclose($lockFp);
                return ['ok' => true, 'claimed' => false, 'reason' => 'in_flight'];
            }
            // Stale claim (> TTL) is reclaimed below!
        }
    }

    // Claim update with timestamp
    $pruned[$updateKey] = [
        'state' => 'claimed',
        'timestamp' => $now
    ];

    $tmp = $webhookUpdatesFile . '.tmp.' . uniqid('', true);
    @file_put_contents($tmp, json_encode($pruned), LOCK_EX);
    @rename($tmp, $webhookUpdatesFile);

    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);

    return ['ok' => true, 'claimed' => true];
}

function finalizeWebhookUpdatePhp($updateId, $outcome = 'done') {
    global $webhookUpdatesFile;
    if ($updateId === null || $updateId === '' || empty($webhookUpdatesFile)) {
        return;
    }

    $lockFile = $webhookUpdatesFile . '.lock';
    $lockFp = @fopen($lockFile, 'c+');
    if (!$lockFp || !@flock($lockFp, LOCK_EX)) {
        if ($lockFp) @fclose($lockFp);
        return;
    }

    $now = time();
    $data = [];
    if (file_exists($webhookUpdatesFile)) {
        $raw = @file_get_contents($webhookUpdatesFile);
        $data = @json_decode($raw, true) ?: [];
    }

    $updateKey = (string)$updateId;
    if ($outcome === 'released' || $outcome === false) {
        // Processing aborted before committed side effects: release claim so redelivery can retry
        unset($data[$updateKey]);
    } else {
        // Default is done
        $data[$updateKey] = [
            'state' => 'done',
            'timestamp' => $now
        ];
    }

    $tmp = $webhookUpdatesFile . '.tmp.' . uniqid('', true);
    @file_put_contents($tmp, json_encode($data), LOCK_EX);
    @rename($tmp, $webhookUpdatesFile);

    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);
}

function isRateLimitedPhp($bucketName, $maxRequests) {
    global $rateLimitsFile;
    $ip = getClientIpPhp();
    $now = time();
    $file = $rateLimitsFile;
    $bucketKey = substr(hash('sha256', "{$bucketName}:{$ip}"), 0, 24);

    $lockFp = @fopen($file . '.lock', 'c+');
    if (!$lockFp || !@flock($lockFp, LOCK_SH)) {
        if ($lockFp) @fclose($lockFp);
        return false;
    }

    $data = [];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        $data = @json_decode($raw, true) ?: [];
    }
    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);

    $current = $data[$bucketKey] ?? null;
    if ($current && isset($current['resetAt']) && $current['resetAt'] > $now && ($current['count'] ?? 0) >= $maxRequests) {
        return max(1, $current['resetAt'] - $now);
    }
    return false;
}

function recordRateLimitHitPhp($bucketName, $windowSeconds) {
    global $rateLimitsFile;
    $ip = getClientIpPhp();
    $now = time();
    $file = $rateLimitsFile;
    $bucketKey = substr(hash('sha256', "{$bucketName}:{$ip}"), 0, 24);

    $lockFp = @fopen($file . '.lock', 'c+');
    if ($lockFp && @flock($lockFp, LOCK_EX)) {
        $data = [];
        if (file_exists($file)) {
            $raw = @file_get_contents($file);
            $data = @json_decode($raw, true) ?: [];
        }
        $pruned = [];
        foreach ($data as $k => $rec) {
            if (isset($rec['resetAt']) && $rec['resetAt'] > $now) {
                $pruned[$k] = $rec;
            }
        }
        if (count($pruned) > 200) {
            $pruned = array_slice($pruned, -200, null, true);
        }
        $current = $pruned[$bucketKey] ?? null;
        if (!$current || $now >= $current['resetAt']) {
            $pruned[$bucketKey] = ['count' => 1, 'resetAt' => $now + $windowSeconds];
        } else {
            $pruned[$bucketKey]['count']++;
        }
        @file_put_contents($file, json_encode($pruned), LOCK_EX);
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
    }
}

function getRevokedTokensFilePath() {
    global $revokedTokensFile;
    return $revokedTokensFile;
}

function revokeAdminTokenPhp($token) {
    $file = getRevokedTokensFilePath();
    $tokenSig = substr(hash('sha256', (string)$token), 0, 32);
    $now = time();

    $lockFp = @fopen($file . '.lock', 'c+');
    if ($lockFp && @flock($lockFp, LOCK_EX)) {
        $data = [];
        if (file_exists($file)) {
            $raw = @file_get_contents($file);
            $data = @json_decode($raw, true) ?: [];
        }
        $pruned = [];
        foreach ($data as $sig => $ts) {
            if ($now - $ts < 86400) {
                $pruned[$sig] = $ts;
            }
        }
        $pruned[$tokenSig] = $now;
        if (count($pruned) > 200) {
            $pruned = array_slice($pruned, -200, null, true);
        }
        @file_put_contents($file, json_encode($pruned), LOCK_EX);
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
    }
}

function isTokenRevokedPhp($token) {
    $file = getRevokedTokensFilePath();
    if (!file_exists($file)) return false;
    $tokenSig = substr(hash('sha256', (string)$token), 0, 32);
    $raw = @file_get_contents($file);
    $data = @json_decode($raw, true);
    if (!is_array($data) || !isset($data[$tokenSig])) {
        return false;
    }
    return (time() - $data[$tokenSig]) < 86400;
}

function getClientIpPhp() {
    $trustProxy = getenv('TRUST_PROXY') === 'true';
    if ($trustProxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $candidate = trim($parts[0]);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

function checkRateLimitPhp($bucketName, $maxRequests, $windowSeconds) {
    global $rateLimitsFile;
    $ip = getClientIpPhp();
    $now = time();
    $file = $rateLimitsFile;
    $bucketKey = substr(hash('sha256', "{$bucketName}:{$ip}"), 0, 24);

    $lockFp = @fopen($file . '.lock', 'c+');
    if (!$lockFp || !@flock($lockFp, LOCK_EX)) {
        if ($lockFp) @fclose($lockFp);
        return ['allowed' => true, 'remaining' => $maxRequests, 'retryAfter' => 0];
    }

    $data = [];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        $data = @json_decode($raw, true) ?: [];
    }

    $active = [];
    foreach ($data as $k => $rec) {
        if (isset($rec['resetAt']) && $rec['resetAt'] > $now) {
            $active[$k] = $rec;
        }
    }
    if (count($active) > 200) {
        $active = array_slice($active, -200, null, true);
    }

    $current = $active[$bucketKey] ?? null;
    if (!$current || $now >= $current['resetAt']) {
        $active[$bucketKey] = [
            'count' => 1,
            'resetAt' => $now + $windowSeconds
        ];
        @file_put_contents($file, json_encode($active), LOCK_EX);
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
        return ['allowed' => true, 'remaining' => $maxRequests - 1, 'retryAfter' => 0];
    }

    if ($current['count'] >= $maxRequests) {
        $retryAfter = max(1, $current['resetAt'] - $now);
        @flock($lockFp, LOCK_UN);
        @fclose($lockFp);
        return ['allowed' => false, 'remaining' => 0, 'retryAfter' => $retryAfter];
    }

    $active[$bucketKey]['count']++;
    @file_put_contents($file, json_encode($active), LOCK_EX);
    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);
    return ['allowed' => true, 'remaining' => max(0, $maxRequests - $active[$bucketKey]['count']), 'retryAfter' => 0];
}

function enforceRateLimitOrExitPhp($bucketName, $maxRequests, $windowSeconds, $customMsg = '') {
    $res = checkRateLimitPhp($bucketName, $maxRequests, $windowSeconds);
    if (!$res['allowed']) {
        header('Retry-After: ' . $res['retryAfter']);
        http_response_code(429);
        echo json_encode([
            'ok' => false,
            'code' => 'RATE_LIMIT_EXCEEDED',
            'error' => $customMsg ?: "تعداد درخواست‌های شما بیش از حد مجاز است. لطفاً {$res['retryAfter']} ثانیه دیگر امتحان نمایید.",
            'retryAfterSeconds' => $res['retryAfter']
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

function generateAdminSessionToken($username, $passOrHash, $time = null) {
    $secret = getAdminSessionSecret();
    $issuedAt = $time !== null ? (int)$time : time();
    $sig = hash_hmac('sha256', strtolower(trim($username)) . ':' . trim($passOrHash) . ':' . $issuedAt, $secret);
    return 'host_auth_' . $issuedAt . '_' . $sig;
}

function isRequestAdminAuthorized($db) {
    $token = getBearerToken();
    if (empty($token)) return false;

    // Check if token has been revoked via logout
    if (isTokenRevokedPhp($token)) {
        return false;
    }

    $now = time();
    if (preg_match('/^host_auth_(\d+)_([a-f0-9]{64})$/i', $token, $m)) {
        $issuedAt = (int)$m[1];
        $sig = $m[2];

        // 24-hour expiration check
        if ($now - $issuedAt > 86400 || $issuedAt > $now + 300) {
            return false;
        }

        $creds = $db['adminCredentials'] ?? [];
        $validUser = strtolower(trim($creds['username'] ?? 'admin'));
        $validEmail = strtolower(trim($creds['email'] ?? ''));
        $validPass = trim($creds['password'] ?? '');
        if (empty($validPass) && !empty($creds['oneTimePassword']) && empty($creds['initialSetupCompleted'])) {
            $validPass = trim($creds['oneTimePassword']);
        }
        if (empty($validPass)) {
            return false;
        }
        $secret = getAdminSessionSecret();

        $expectedSigUser = hash_hmac('sha256', $validUser . ':' . $validPass . ':' . $issuedAt, $secret);
        if (hash_equals($expectedSigUser, $sig)) {
            return true;
        }
        if (!empty($validEmail)) {
            $expectedSigEmail = hash_hmac('sha256', $validEmail . ':' . $validPass . ':' . $issuedAt, $secret);
            if (hash_equals($expectedSigEmail, $sig)) {
                return true;
            }
        }
    }

    return false;
}

// ------------------------------------------------------------------------------
// 6. Safe Inventory Management (Atomic, Per-Product & Per-Size Variants)
// ------------------------------------------------------------------------------
function deductOrderInventory(&$db, &$order) {
    if (!empty($order['inventoryDeducted'])) {
        return ['ok' => true, 'alreadyDeducted' => true];
    }
    if (empty($order['items']) || !is_array($order['items'])) {
        $order['inventoryDeducted'] = true;
        return ['ok' => true];
    }

    // Step 1: Aggregate duplicate product/variant lines to prevent overselling
    $aggregated = [];
    foreach ($order['items'] as $item) {
        $productId = (int)($item['productId'] ?? $item['id'] ?? 0);
        $qty = (int)($item['quantity'] ?? 1);
        if ($qty <= 0) {
            return ['ok' => false, 'code' => 'INVALID_QUANTITY', 'error' => 'تعداد محصول انتخابی نامعتبر است.'];
        }
        $size = trim((string)($item['size'] ?? ''));
        $key = "{$productId}::{$size}";
        if (!isset($aggregated[$key])) {
            $aggregated[$key] = [
                'productId' => $productId,
                'size' => $size,
                'quantity' => 0
            ];
        }
        $aggregated[$key]['quantity'] += $qty;
    }

    // Pre-check availability across aggregated items before any mutation
    foreach ($aggregated as $agg) {
        $productId = $agg['productId'];
        $qty = $agg['quantity'];
        $size = $agg['size'];

        $productFound = false;
        if (!empty($db['products']) && is_array($db['products'])) {
            foreach ($db['products'] as $prod) {
                if ((int)($prod['id'] ?? 0) === $productId && empty($prod['isDelete'])) {
                    $productFound = true;
                    // Check size variant stock
                    if ($size !== '' && !empty($prod['sizes']) && is_array($prod['sizes'])) {
                        $sizeFound = false;
                        foreach ($prod['sizes'] as $sObj) {
                            $sName = trim((string)($sObj['name'] ?? $sObj['size'] ?? ''));
                            if ($sName === $size) {
                                $sizeFound = true;
                                if (isset($sObj['stock'])) {
                                    $curSizeStock = (int)$sObj['stock'];
                                    if ($curSizeStock < $qty) {
                                        return [
                                            'ok' => false,
                                            'code' => 'STOCK_CONFLICT',
                                            'error' => "موجودی بسته «{$size}» برای محصول «{$prod['title']}» کافی نیست (موجودی فعلی: {$curSizeStock})."
                                        ];
                                    }
                                }
                                break;
                            }
                        }
                    }

                    // Check main product stock
                    if (isset($prod['stock'])) {
                        $curProdStock = (int)$prod['stock'];
                        if ($curProdStock < $qty) {
                            return [
                                'ok' => false,
                                'code' => 'STOCK_CONFLICT',
                                'error' => "موجودی کل محصول «{$prod['title']}» کافی نیست (موجودی فعلی: {$curProdStock})."
                            ];
                        }
                    }
                    break;
                }
            }
        }

        if (!$productFound && empty($order['isConsultation'])) {
            return [
                'ok' => false,
                'code' => 'PRODUCT_NOT_FOUND',
                'error' => "محصول با شناسه {$productId} در انبار یافت نشد."
            ];
        }
    }

    // Step 2: Perform atomic deduction and track exact deducted quantities
    $deductedDetails = [];
    foreach ($aggregated as $agg) {
        $productId = $agg['productId'];
        $qty = $agg['quantity'];
        $size = $agg['size'];
        $specialDeducted = 0;

        if (!empty($db['products']) && is_array($db['products'])) {
            foreach ($db['products'] as &$prod) {
                if ((int)($prod['id'] ?? 0) === $productId) {
                    if ($size !== '' && !empty($prod['sizes']) && is_array($prod['sizes'])) {
                        foreach ($prod['sizes'] as &$sObj) {
                            $sName = trim((string)($sObj['name'] ?? $sObj['size'] ?? ''));
                            if ($sName === $size) {
                                if (isset($sObj['stock'])) {
                                    $sObj['stock'] = max(0, (int)$sObj['stock'] - $qty);
                                    $sObj['isOutOfStock'] = ($sObj['stock'] <= 0);
                                }
                                if (isset($sObj['specialOfferStock']) && $sObj['specialOfferStock'] !== null && $sObj['specialOfferStock'] !== '') {
                                    $curSpecial = (int)$sObj['specialOfferStock'];
                                    $specialDeducted = min($curSpecial, $qty);
                                    $sObj['specialOfferStock'] = max(0, $curSpecial - $qty);
                                }
                                break;
                            }
                        }
                        unset($sObj);
                    }

                    if (isset($prod['stock'])) {
                        $prod['stock'] = max(0, (int)$prod['stock'] - $qty);
                        if ($prod['stock'] <= 0) {
                            $prod['isOutOfStock'] = true;
                            $prod['availability'] = 'OutOfStock';
                        }
                    }

                    if (isset($prod['specialOfferStock']) && $prod['specialOfferStock'] !== null && $prod['specialOfferStock'] !== '') {
                        $curSpecialProd = (int)$prod['specialOfferStock'];
                        if ($specialDeducted === 0) {
                            $specialDeducted = min($curSpecialProd, $qty);
                        }
                        $prod['specialOfferStock'] = max(0, $curSpecialProd - $qty);
                    }
                    break;
                }
            }
            unset($prod);
        }

        $deductedDetails[] = [
            'productId' => $productId,
            'size' => $size,
            'quantity' => $qty,
            'specialOfferDeducted' => $specialDeducted
        ];
    }

    $order['deductedStockDetails'] = $deductedDetails;
    $order['inventoryDeducted'] = true;
    return ['ok' => true];
}

function releaseOrderInventory(&$db, &$order) {
    if (empty($order['inventoryDeducted'])) {
        return ['ok' => true, 'alreadyReleased' => true];
    }
    // Shipped or Completed orders must NOT be restocked by status change
    $currentStatus = $order['status'] ?? '';
    if ($currentStatus === 'Shipped' || $currentStatus === 'Completed') {
        return ['ok' => true, 'skippedShipped' => true];
    }

    $itemsToRestore = !empty($order['deductedStockDetails']) && is_array($order['deductedStockDetails'])
        ? $order['deductedStockDetails']
        : [];

    if (empty($itemsToRestore) && !empty($order['items']) && is_array($order['items'])) {
        foreach ($order['items'] as $it) {
            $itemsToRestore[] = [
                'productId' => (int)($it['productId'] ?? $it['id'] ?? 0),
                'size' => trim((string)($it['size'] ?? '')),
                'quantity' => max(1, (int)($it['quantity'] ?? 1)),
                'specialOfferDeducted' => 0
            ];
        }
    }

    foreach ($itemsToRestore as $rItem) {
        $productId = (int)($rItem['productId'] ?? 0);
        $qty = max(1, (int)($rItem['quantity'] ?? 1));
        $size = trim((string)($rItem['size'] ?? ''));
        $specialDeducted = (int)($rItem['specialOfferDeducted'] ?? 0);

        if (!empty($db['products']) && is_array($db['products'])) {
            foreach ($db['products'] as &$prod) {
                if ((int)($prod['id'] ?? 0) === $productId) {
                    if ($size !== '' && !empty($prod['sizes']) && is_array($prod['sizes'])) {
                        foreach ($prod['sizes'] as &$sObj) {
                            $sName = trim((string)($sObj['name'] ?? $sObj['size'] ?? ''));
                            if ($sName === $size) {
                                if (isset($sObj['stock'])) {
                                    $sObj['stock'] = (int)$sObj['stock'] + $qty;
                                    $sObj['isOutOfStock'] = ($sObj['stock'] <= 0);
                                }
                                if ($specialDeducted > 0 && isset($sObj['specialOfferStock'])) {
                                    $sObj['specialOfferStock'] = (int)$sObj['specialOfferStock'] + $specialDeducted;
                                }
                                break;
                            }
                        }
                        unset($sObj);
                    }

                    if (isset($prod['stock'])) {
                        $prod['stock'] = (int)$prod['stock'] + $qty;
                        if ($prod['stock'] > 0) {
                            $prod['isOutOfStock'] = false;
                            $prod['availability'] = 'InStock';
                        }
                    }

                    if ($specialDeducted > 0 && isset($prod['specialOfferStock'])) {
                        $prod['specialOfferStock'] = (int)$prod['specialOfferStock'] + $specialDeducted;
                    }
                    break;
                }
            }
            unset($prod);
        }
    }

    $order['inventoryDeducted'] = false;
    unset($order['deductedStockDetails']);
    return ['ok' => true];
}

function validateReceiptImageBytesPhp($binData) {
    if (empty($binData) || strlen($binData) < 20 || strlen($binData) > 5242880) {
        return ['ok' => false, 'error' => 'حجم فایل رسید معتبر نیست (حداکثر ۵ مگابایت مجاز است).'];
    }

    // Check for script tags or PHP execution injection
    $startChunk = substr($binData, 0, 512);
    if (stripos($startChunk, '<?php') !== false || stripos($startChunk, '<?=') !== false || stripos($startChunk, '<script') !== false) {
        return ['ok' => false, 'error' => 'محتوای فایل ارسالی غیرمجاز است.'];
    }

    // Validate image magic bytes
    $isPng = (substr($binData, 0, 8) === "\x89PNG\x0d\x0a\x1a\x0a");
    $isJpeg = (substr($binData, 0, 3) === "\xff\xd8\xff");
    $isWebp = (substr($binData, 0, 4) === 'RIFF' && substr($binData, 8, 4) === 'WEBP');

    if (!$isPng && !$isJpeg && !$isWebp) {
        return ['ok' => false, 'error' => 'فایل ارسالی یک تصویر معتبر (PNG، JPG یا WEBP) نمی‌باشد.'];
    }

    $ext = 'jpg';
    $mime = 'image/jpeg';
    if ($isPng) { $ext = 'png'; $mime = 'image/png'; }
    elseif ($isWebp) { $ext = 'webp'; $mime = 'image/webp'; }

    // Hardened image dimension and pixel bounds validation
    if (function_exists('getimagesizefromstring')) {
        $imgInfo = @getimagesizefromstring($binData);
        if ($imgInfo === false) {
            return ['ok' => false, 'error' => 'فایل ارسالی تصویر معتبری نیست یا تخریب شده است.'];
        }
        $w = (int)($imgInfo[0] ?? 0);
        $h = (int)($imgInfo[1] ?? 0);
        $detectedMime = $imgInfo['mime'] ?? '';
        $allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!in_array($detectedMime, $allowedMimes, true)) {
            return ['ok' => false, 'error' => 'نوع فایل تصویری مجاز نیست (تنها JPG، PNG و WEBP مجاز هستند).'];
        }
        if ($w < 50 || $h < 50) {
            return ['ok' => false, 'error' => 'ابعاد تصویر ارسالی بسیار کوچک است.'];
        }
        if ($w > 8000 || $h > 8000 || ($w * $h) > 25000000) {
            return ['ok' => false, 'error' => 'ابعاد تصویر بیش از حد مجاز است (حداکثر ۲۵ مگاپیکسل).'];
        }
    }

    return ['ok' => true, 'ext' => $ext, 'mime' => $mime];
}

function processOrderPaymentApprovalPhp(&$db, $orderIdOrCode, $actor = 'admin') {
    $order = findOrderByCodePhp($db['orders'] ?? [], $orderIdOrCode, true);
    if (!$order) {
        foreach ($db['orders'] ?? [] as $ord) {
            if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                $order = $ord;
                break;
            }
        }
    }
    if (!$order) {
        return ['ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'سفارش مورد نظر یافت نشد.'];
    }

    if (($order['paymentStatus'] ?? '') === 'Paid') {
        return ['ok' => true, 'alreadyPaid' => true, 'order' => $order];
    }
    if (($order['status'] ?? '') === 'Cancelled') {
        return ['ok' => false, 'code' => 'ORDER_CANCELLED', 'error' => 'سفارش لغو شده است و امکان تایید آن وجود ندارد.'];
    }

    foreach ($db['orders'] as &$ord) {
        if (($ord['trackingCode'] ?? '') === $order['trackingCode']) {
            $invRes = deductOrderInventory($db, $ord);
            if (!$invRes['ok']) {
                return $invRes; // Abort without persisting Paid
            }
            $ord['paymentStatus'] = 'Paid';
            $ord['status'] = 'Processing';
            $ord['approvedAt'] = date('c');
            $ord['approvedBy'] = $actor;
            if (!empty($ord['consultationDetails'])) {
                $ord['consultationDetails']['consultationStatus'] = 'Scheduled';
            }
            if (!empty($db['contactMessages']) && is_array($db['contactMessages'])) {
                foreach ($db['contactMessages'] as &$msg) {
                    $isMatch = (
                        (!empty($msg['orderId']) && (string)$msg['orderId'] === (string)($ord['id'] ?? '')) ||
                        (!empty($msg['trackingCode']) && $msg['trackingCode'] === $ord['trackingCode']) ||
                        (!empty($ord['isConsultation']) && !empty($msg['isConsultation']) && !empty($ord['phoneNumber']) && ($msg['phoneNumber'] ?? '') === $ord['phoneNumber'])
                    );
                    if ($isMatch) {
                        $msg['paymentStatus'] = 'Paid';
                        if (!empty($msg['consultationDetails'])) {
                            $msg['consultationDetails']['consultationStatus'] = 'Scheduled';
                        }
                    }
                }
                unset($msg);
            }
            return ['ok' => true, 'order' => $ord];
        }
    }
    return ['ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'خطا در ثبت سفارش.'];
}

function processOrderRejectionPhp(&$db, $orderIdOrCode, $reason = '', $actor = 'admin') {
    $order = findOrderByCodePhp($db['orders'] ?? [], $orderIdOrCode, true);
    if (!$order) {
        foreach ($db['orders'] ?? [] as $ord) {
            if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                $order = $ord;
                break;
            }
        }
    }
    if (!$order) {
        return ['ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'سفارش مورد نظر یافت نشد.'];
    }

    if (($order['status'] ?? '') === 'Cancelled') {
        return ['ok' => true, 'alreadyCancelled' => true, 'order' => $order];
    }

    $curStatus = $order['status'] ?? '';
    if ($curStatus === 'Shipped' || $curStatus === 'Completed') {
        return ['ok' => false, 'code' => 'TRANSITION_NOT_ALLOWED', 'error' => 'امکان لغو سفارشات ارسال‌شده یا تکمیل‌شده وجود ندارد.'];
    }

    foreach ($db['orders'] as &$ord) {
        if (($ord['trackingCode'] ?? '') === $order['trackingCode']) {
            if (!empty($ord['inventoryDeducted'])) {
                releaseOrderInventory($db, $ord);
            }
            $prevPay = $ord['paymentStatus'] ?? 'Unpaid';
            $ord['status'] = 'Cancelled';
            $ord['paymentStatus'] = ($prevPay === 'Paid') ? 'Paid_Cancelled' : 'Rejected';
            $ord['rejectedAt'] = date('c');
            $ord['rejectedBy'] = $actor;
            if (!empty($reason)) {
                $ord['cancellationReason'] = mb_substr($reason, 0, 500, 'UTF-8');
            }
            if (!empty($ord['consultationDetails'])) {
                $ord['consultationDetails']['consultationStatus'] = 'Cancelled';
            }
            if (!empty($db['contactMessages']) && is_array($db['contactMessages'])) {
                foreach ($db['contactMessages'] as &$msg) {
                    $isMatch = (
                        (!empty($msg['orderId']) && (string)$msg['orderId'] === (string)($ord['id'] ?? '')) ||
                        (!empty($msg['trackingCode']) && $msg['trackingCode'] === $ord['trackingCode']) ||
                        (!empty($ord['isConsultation']) && !empty($msg['isConsultation']) && !empty($ord['phoneNumber']) && ($msg['phoneNumber'] ?? '') === $ord['phoneNumber'])
                    );
                    if ($isMatch) {
                        $msg['paymentStatus'] = ($prevPay === 'Paid') ? 'Paid_Cancelled' : 'Rejected';
                        if (!empty($msg['consultationDetails'])) {
                            $msg['consultationDetails']['consultationStatus'] = 'Cancelled';
                        }
                        if (!empty($reason)) {
                            $msg['adminResponse'] = mb_substr($reason, 0, 500, 'UTF-8');
                        }
                    }
                }
                unset($msg);
            }
            return ['ok' => true, 'order' => $ord];
        }
    }
    return ['ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'خطا در ثبت لغو سفارش.'];
}

// ------------------------------------------------------------------------------
// 7. Hardened Bale Bot API Client
// ------------------------------------------------------------------------------
function callBaleApi($token, $method, $parameters = []) {
    $token = trim((string)$token);
    if (empty($token)) {
        return ['ok' => false, 'error' => 'Missing bot token'];
    }

    $baseUrl = 'https://tapi.bale.ai';
    $url = $baseUrl . "/bot{$token}/{$method}";

    $jsonPayload = json_encode($parameters, JSON_UNESCAPED_UNICODE);
    if ($jsonPayload === false || json_last_error() !== JSON_ERROR_NONE) {
        onival_log('bot_api', 'json_encode_failed', "JSON encoding failed for {$method}", [
            'method' => $method,
            'code' => 'JSON_ENCODE_FAILED'
        ]);
        return ['ok' => false, 'code' => 'JSON_ENCODE_FAILED', 'error' => 'JSON encoding failed'];
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json; charset=utf-8']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonPayload);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        onival_log('bot_api', 'curl_error', "cURL error on {$method}", [
            'httpCode' => $httpCode,
            'curlError' => $error,
            'method' => $method
        ]);
        return ['ok' => false, 'code' => 'BOT_API_FAILED', 'error' => $error, 'http_code' => $httpCode];
    }

    $decoded = @json_decode($response, true);
    if (!is_array($decoded)) {
        onival_log('bot_api', 'invalid_json', "Invalid JSON response on {$method}", [
            'httpCode' => $httpCode
        ]);
        return ['ok' => false, 'code' => 'BOT_API_FAILED', 'error' => 'Invalid JSON from Bale API', 'http_code' => $httpCode];
    }

    return $decoded;
}

function sendBaleMessage($token, $chatId, $text, $replyMarkup = null) {
    $payload = [
        'chat_id' => is_numeric($chatId) ? (int)$chatId : $chatId,
        'text' => $text
    ];
    if ($replyMarkup) {
        $payload['reply_markup'] = $replyMarkup;
    }
    return callBaleApi($token, 'sendMessage', $payload);
}

function downloadBaleFileToDisk($token, $fileId, $targetPath) {
    $token = trim((string)$token);
    if (empty($token) || empty($fileId)) return false;

    $info = callBaleApi($token, 'getFile', ['file_id' => $fileId]);
    if (empty($info['ok']) || empty($info['result']['file_path'])) {
        return false;
    }
    $filePath = $info['result']['file_path'];
    $fileUrl = "https://tapi.bale.ai/file/bot{$token}/{$filePath}";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $fileUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    $data = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200 && $data && strlen($data) > 100) {
        @file_put_contents($targetPath, $data, LOCK_EX);
        return true;
    }
    return false;
}

function sendBalePhoto($token, $chatId, $photo, $caption = '', $replyMarkup = null) {
    $token = trim((string)$token);
    if (empty($token)) {
        return ['ok' => false, 'error' => 'Missing bot token'];
    }
    $baseUrl = 'https://tapi.bale.ai';
    $url = $baseUrl . "/bot{$token}/sendPhoto";

    $hasLocalFile = is_string($photo) && file_exists($photo) && is_file($photo);

    if ($hasLocalFile) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        $mime = mime_content_type($photo) ?: 'image/jpeg';
        $postData = [
            'chat_id' => is_numeric($chatId) ? (int)$chatId : $chatId,
            'photo' => new CURLFile($photo, $mime, basename($photo))
        ];
        if (!empty($caption)) {
            $postData['caption'] = mb_substr($caption, 0, 1024, 'UTF-8');
        }
        if ($replyMarkup) {
            $encodedMarkup = is_array($replyMarkup) ? json_encode($replyMarkup, JSON_UNESCAPED_UNICODE) : $replyMarkup;
            if ($encodedMarkup === false || json_last_error() !== JSON_ERROR_NONE) {
                onival_log('bot_api', 'json_encode_failed', "JSON encoding failed for sendPhoto reply_markup", [
                    'code' => 'JSON_ENCODE_FAILED'
                ]);
                return ['ok' => false, 'code' => 'JSON_ENCODE_FAILED', 'error' => 'JSON encoding failed'];
            }
            $postData['reply_markup'] = $encodedMarkup;
        }

        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['ok' => false, 'code' => 'BOT_API_FAILED', 'error' => $error, 'http_code' => $httpCode];
        }
        $decoded = @json_decode($response, true);
        return is_array($decoded) ? $decoded : ['ok' => false, 'code' => 'BOT_API_FAILED', 'error' => 'Invalid JSON'];
    }

    $payload = [
        'chat_id' => is_numeric($chatId) ? (int)$chatId : $chatId,
        'photo' => $photo
    ];
    if (!empty($caption)) {
        $payload['caption'] = mb_substr($caption, 0, 1024, 'UTF-8');
    }
    if ($replyMarkup) {
        $payload['reply_markup'] = $replyMarkup;
    }
    return callBaleApi($token, 'sendPhoto', $payload);
}

function sendBaleInvoiceSafe($token, $chatId, $title, $description, $payloadStr, $providerToken, $currency, $prices, $paymentMode = 'live') {
    // Security Guard: Never allow WALLET-TEST token in live mode
    if ($paymentMode === 'live' && strpos((string)$providerToken, 'WALLET-TEST') !== false) {
        return [
            'ok' => false,
            'code' => 'INVALID_WALLET_MODE',
            'error' => 'امکان استفاده از توکن تستی در حالت پرداخت لایو وجود ندارد.'
        ];
    }

    $body = [
        'chat_id' => is_numeric($chatId) ? (int)$chatId : $chatId,
        'title' => mb_substr((string)$title, 0, 32, 'UTF-8'),
        'description' => mb_substr((string)$description, 0, 255, 'UTF-8'),
        'payload' => substr((string)$payloadStr, 0, 128),
        'provider_token' => (string)$providerToken,
        'start_parameter' => substr((string)$payloadStr, 0, 64),
        'currency' => $currency ?: 'IRR',
        'prices' => $prices
    ];
    return callBaleApi($token, 'sendInvoice', $body);
}

// ------------------------------------------------------------------------------
// 8. Digit Normalization & Order Code Lookup
function checkOrderStockAvailablePhp($db, $order) {
    if (empty($order['items']) || !is_array($order['items'])) {
        return ['ok' => true];
    }
    foreach ($order['items'] as $item) {
        $productId = (int)($item['productId'] ?? $item['id'] ?? 0);
        $qty = max(1, (int)($item['quantity'] ?? 1));
        $size = trim((string)($item['size'] ?? ''));

        $productFound = false;
        if (!empty($db['products']) && is_array($db['products'])) {
            foreach ($db['products'] as $prod) {
                if ((int)($prod['id'] ?? 0) === $productId && empty($prod['isDelete'])) {
                    $productFound = true;
                    if ($size !== '' && !empty($prod['sizes']) && is_array($prod['sizes'])) {
                        foreach ($prod['sizes'] as $sObj) {
                            $sName = trim((string)($sObj['name'] ?? $sObj['size'] ?? ''));
                            if ($sName === $size) {
                                if (isset($sObj['stock']) && (int)$sObj['stock'] < $qty) {
                                    return ['ok' => false, 'code' => 'STOCK_CONFLICT', 'error' => "موجودی بسته «{$size}» برای «{$prod['title']}» کافی نیست."];
                                }
                                break;
                            }
                        }
                    }
                    if (isset($prod['stock']) && (int)$prod['stock'] < $qty) {
                        return ['ok' => false, 'code' => 'STOCK_CONFLICT', 'error' => "موجودی کل «{$prod['title']}» کافی نیست."];
                    }
                    break;
                }
            }
        }
        if (!$productFound && empty($order['isConsultation'])) {
            return ['ok' => false, 'code' => 'PRODUCT_NOT_FOUND', 'error' => "محصول با شناسه {$productId} یافت نشد."];
        }
    }
    return ['ok' => true];
}

function getOrCreateWebhookSecrets(&$telegramConfig) {
    $updated = false;
    $cSec = trim((string)($telegramConfig['customerWebhookSecretToken'] ?? ''));
    if (empty($cSec) || strpos($cSec, 'csec_') !== 0 || strlen($cSec) < 20) {
        $telegramConfig['customerWebhookSecretToken'] = 'csec_' . bin2hex(random_bytes(16));
        $updated = true;
    }
    $aSec = trim((string)($telegramConfig['adminWebhookSecretToken'] ?? ''));
    if (empty($aSec) || strpos($aSec, 'asec_') !== 0 || strlen($aSec) < 20 || $aSec === $telegramConfig['customerWebhookSecretToken']) {
        $telegramConfig['adminWebhookSecretToken'] = 'asec_' . bin2hex(random_bytes(16));
        $updated = true;
    }
    if (($telegramConfig['webhookSecretToken'] ?? '') !== $telegramConfig['customerWebhookSecretToken']) {
        $telegramConfig['webhookSecretToken'] = $telegramConfig['customerWebhookSecretToken'];
        $updated = true;
    }
    return [
        'customer' => $telegramConfig['customerWebhookSecretToken'],
        'admin' => $telegramConfig['adminWebhookSecretToken'],
        'updated' => $updated
    ];
}

function generateUniqueTrackingCodePhp($existingOrders, $prefix = 'ONV-ORD') {
    $existingCodes = [];
    if (is_array($existingOrders)) {
        foreach ($existingOrders as $ord) {
            if (!empty($ord['trackingCode'])) {
                $existingCodes[strtoupper(trim($ord['trackingCode']))] = true;
            }
        }
    }

    for ($i = 0; $i < 30; $i++) {
        $hex = strtoupper(bin2hex(random_bytes(4)));
        $cand = "{$prefix}-{$hex}";
        if (!isset($existingCodes[$cand])) {
            return $cand;
        }
    }
    return "{$prefix}-" . strtoupper(bin2hex(random_bytes(6)));
}

function generateContactTrackingCodePhp() {
    return 'ONV-MSG-' . strtoupper(bin2hex(random_bytes(4)));
}

function maskPublicPhonePhp($p) {
    if (!$p) return '';
    $clean = trim((string)$p);
    if (strlen($clean) >= 10) return substr($clean, 0, 4) . '***' . substr($clean, -3);
    if (strlen($clean) >= 4) return substr($clean, 0, 2) . '***' . substr($clean, -2);
    return '***';
}

function maskPublicAddressPhp($a) {
    if (!$a) return '';
    $clean = trim((string)$a);
    $parts = preg_split('/[،,-]/u', $clean);
    if (count($parts) > 1) return trim($parts[0]) . '، *** (تحویل پستی)';
    return mb_substr($clean, 0, 14, 'UTF-8') . '... (تحویل پستی)';
}

function buildPublicSafeOrderPhp($order, $isAdmin = false) {
    if (!$order || !is_array($order)) return null;
    if ($isAdmin) return $order;

    return [
        'id' => $order['id'] ?? 0,
        'trackingCode' => $order['trackingCode'] ?? '',
        'orderNumber' => $order['orderNumber'] ?? '',
        'userFullName' => $order['userFullName'] ?? ($order['customerName'] ?? 'مشتری گرامی'),
        'customerName' => $order['customerName'] ?? ($order['userFullName'] ?? 'مشتری گرامی'),
        'phoneNumber' => maskPublicPhonePhp($order['phoneNumber'] ?? ''),
        'userAddress' => maskPublicAddressPhp($order['userAddress'] ?? ''),
        'totalPrice' => (int)($order['totalPrice'] ?? $order['finalTotal'] ?? 0),
        'finalTotal' => (int)($order['finalTotal'] ?? $order['totalPrice'] ?? 0),
        'status' => $order['status'] ?? 'Pending',
        'paymentStatus' => $order['paymentStatus'] ?? 'Unpaid',
        'paymentMethod' => $order['paymentMethod'] ?? '',
        'creationTime' => $order['creationTime'] ?? ($order['createdAt'] ?? ''),
        'balePaymentUrl' => $order['balePaymentUrl'] ?? '',
        'items' => array_map(function($it) {
            return [
                'productId' => $it['productId'] ?? ($it['id'] ?? 0),
                'productName' => $it['productName'] ?? ($it['name'] ?? ''),
                'name' => $it['name'] ?? ($it['productName'] ?? ''),
                'size' => $it['size'] ?? 'استاندارد',
                'quantity' => (int)($it['quantity'] ?? ($it['qty'] ?? 1)),
                'unitPrice' => (int)($it['unitPrice'] ?? ($it['price'] ?? 0)),
                'totalPrice' => (int)($it['totalPrice'] ?? 0)
            ];
        }, $order['items'] ?? []),
        'hasReceipt' => !empty($order['receiptFileId']) || !empty($order['receiptImageUrl']) || !empty($order['receiptImage']),
        'receiptSubmittedAt' => $order['receiptSubmittedAt'] ?? ($order['receiptUploadedAt'] ?? null),
        'isConsultation' => !empty($order['isConsultation']),
        'consultationDetails' => !empty($order['consultationDetails']) ? [
            'topicTitle' => $order['consultationDetails']['topicTitle'] ?? 'مشاوره سلامت',
            'preferredDate' => $order['consultationDetails']['preferredDate'] ?? '',
            'preferredTimeSlot' => $order['consultationDetails']['preferredTimeSlot'] ?? '',
            'socialPlatform' => $order['consultationDetails']['socialPlatform'] ?? '',
            'consultationStatus' => $order['consultationDetails']['consultationStatus'] ?? 'PendingPayment',
            'adminResponse' => $order['consultationDetails']['adminResponse'] ?? null,
            'respondedAt' => $order['consultationDetails']['respondedAt'] ?? null
        ] : null
    ];
}

// ------------------------------------------------------------------------------
// 8. Digit Normalization & Order Code Lookup
// ------------------------------------------------------------------------------
function normalizeDigitsPhp($str) {
    if (!$str) return '';
    $farsi = ['۰','۱','۲','۳','۴','۵','۶','۷','۸','۹'];
    $arabic = ['٠','١','٢','٣','٤','٥','٦','٧','٨','٩'];
    $english = ['0','1','2','3','4','5','6','7','8','9'];
    $str = str_replace($farsi, $english, $str);
    return str_replace($arabic, $english, $str);
}

function extractOrderCodePhp($text) {
    if (empty($text) || !is_string($text)) return null;
    $norm = normalizeDigitsPhp(trim($text));

    // 1. Explicitly ignore standard menu commands, greetings and conversational text
    if (preg_match('/^[\/!#]?(start|help|admin|orders|شروع|راهنما|سفارشات|فروشگاه|محصولات|تماس|پشتیبانی|پیگیری|پرداخت|hello|hi|salam|test|سلام|درود|تست)$/iu', $norm)) {
        return null;
    }
    // Ignore multiword reply-keyboard text labels
    if (preg_match('/^(?:🧾\s*استعلام|🛍️\s*فروشگاه|📦\s*پیگیری|💳\s*راهنما|📞\s*تماس|استعلام و پرداخت فاکتور|فروشگاه اونیوال|پیگیری سفارش|راهنمای روش‌های پرداخت|تماس با ما)/iu', $norm)) {
        return null;
    }

    // Ignore Iranian mobile numbers
    if (preg_match('/^09\d{9}$/', $norm)) {
        return null;
    }

    // Ignore messages containing weight or units or currency without code
    if (preg_match('/(گرمی?|کیلو|تومان|ریال|بسته|عدد)/iu', $norm) && !preg_match('/(?:ONV|ORD)[-_]/iu', $norm)) {
        return null;
    }

    // 2. Handle /start pay_<code|reference> or /start order_<code|reference>
    if (preg_match('/^\/start[\s_]+(?:pay_|order_|پرداخت_)?([A-Za-z0-9_-]{4,32})/iu', $norm, $m)) {
        $cand = trim(preg_replace('/^(?:pay_|order_|پرداخت_)/iu', '', $m[1]));
        if (!empty($cand) && !preg_match('/^(admin|help|orders|start)$/iu', $cand)) {
            return $cand;
        }
    }

    // 3. Handle /confirm_<code|reference> or /approve_<code|reference>
    if (preg_match('/^\/(?:confirm_|approve_|تایید_)([A-Za-z0-9_-]{4,32})/iu', $norm, $m)) {
        return trim($m[1]);
    }

    // 4. Strict ONV- or ORD- prefixed tracking codes delimited by boundary or whitespace
    if (preg_match('/(?:^|[\s:#-])((?:ONV|ORD)[-_][A-Za-z0-9_-]{4,24})(?:$|[\s:#-])/iu', $norm, $m)) {
        return trim($m[1]);
    }

    // 5. Explicit label prefix like "فاکتور: XXXXX" or "کد رهگیری: XXXXX"
    if (preg_match('/(?:فاکتور|سفارش|کد\s*رهگیری|کد\s*پیگیری|شماره\s*سفارش|شماره\s*فاکتور|invoice|order)\s*[:#-]?\s*([A-Za-z0-9_-]{4,32})/iu', $norm, $m)) {
        $cand = trim($m[1]);
        if (!preg_match('/(گرمی?|کیلو|تومان|ریال)/iu', $cand) && !preg_match('/^09\d{9}$/', $cand)) {
            // Reject short pure numeric strings (under 7 digits) to prevent 5-digit order number takeover
            if (!preg_match('/^\d{1,6}$/', $cand)) {
                return $cand;
            }
        }
    }

    // 6. If the entire trimmed message is strictly an uppercase tracking reference format
    if (preg_match('/^(?:ONV|ORD)[-_][A-Za-z0-9_-]{4,24}$/i', $norm)) {
        return $norm;
    }

    return null;
}

function findOrderByCodePhp($orders, $searchQuery, $allowOrderNumber = false) {
    if (empty($orders) || !is_array($orders) || empty($searchQuery)) return null;
    $raw = trim((string)$searchQuery);
    $norm = normalizeDigitsPhp($raw);
    $cleanQuery = strtoupper(preg_replace('/[^A-Z0-9_-]/i', '', $norm));
    $cleanQueryWithoutPrefix = preg_replace('/^(?:PAY_|ORDER_|PAY-|ORDER-)/i', '', $cleanQuery);

    foreach ($orders as $ord) {
        $track = trim($ord['trackingCode'] ?? '');
        $ordNum = trim($ord['orderNumber'] ?? '');

        // 1. Strict match on trackingCode
        if (strcasecmp($track, $raw) === 0) {
            return $ord;
        }

        // 2. Only allow matching short 5-digit orderNumber if explicitly authorized by admin context
        if ($allowOrderNumber && !empty($ordNum) && strcasecmp($ordNum, $raw) === 0) {
            return $ord;
        }

        $cleanTrack = strtoupper(preg_replace('/[^A-Z0-9_-]/i', '', $track));
        $cleanOrdNum = strtoupper(preg_replace('/[^A-Z0-9_-]/i', '', $ordNum));

        if (!empty($cleanQuery)) {
            if ($cleanTrack === $cleanQuery) {
                return $ord;
            }
            if ($allowOrderNumber && !empty($cleanOrdNum) && $cleanOrdNum === $cleanQuery) {
                return $ord;
            }
            if ($cleanQueryWithoutPrefix !== '' && $cleanTrack === $cleanQueryWithoutPrefix) {
                return $ord;
            }
            if ($allowOrderNumber && $cleanQueryWithoutPrefix !== '' && !empty($cleanOrdNum) && $cleanOrdNum === $cleanQueryWithoutPrefix) {
                return $ord;
            }
        }
    }
    return null;
}

function getOrderAmountTomanPhp($order) {
    if (empty($order) || !is_array($order)) return 150000;
    if (!empty($order['finalTotal']) && is_numeric($order['finalTotal']) && (int)$order['finalTotal'] > 0) {
        return (int)$order['finalTotal'];
    }
    if (!empty($order['totalPrice']) && is_numeric($order['totalPrice']) && (int)$order['totalPrice'] > 0) {
        return (int)$order['totalPrice'];
    }
    if (!empty($order['total']) && is_numeric($order['total']) && (int)$order['total'] > 0) {
        return (int)$order['total'];
    }
    if (!empty($order['amount']) && is_numeric($order['amount']) && (int)$order['amount'] > 0) {
        return (int)$order['amount'];
    }
    return 150000;
}

// ------------------------------------------------------------------------------
// 9. Slug Generation & Sanitization
// ------------------------------------------------------------------------------
function sanitizeSlugPhp($input, $fallbackPrefix = 'item', $fallbackId = null) {
    $raw = trim((string)$input);
    $raw = mb_strtolower($raw, 'UTF-8');
    // Replace zero-width non-joiner and spaces with hyphen
    $raw = preg_replace('/[\x{200B}-\x{200D}\x{FEFF}]/u', '-', $raw);
    $raw = preg_replace('/[_\s\/\\\]+/u', '-', $raw);
    // Allow Unicode letters, numbers and hyphens
    $raw = preg_replace('/[^\p{L}\p{N}-]+/u', '', $raw);
    $raw = preg_replace('/-+/u', '-', $raw);
    $raw = trim($raw, '-');

    if (mb_strlen($raw, 'UTF-8') >= 2) {
        return mb_substr($raw, 0, 120, 'UTF-8');
    }
    return $fallbackPrefix . '-' . ($fallbackId ?? time());
}

function isSlugDuplicatePhp($items, $candidateSlug, $excludeId = null) {
    $norm = sanitizeSlugPhp($candidateSlug);
    foreach ($items as $it) {
        if (!empty($it['isDelete'])) continue;
        if ($excludeId !== null && (int)($it['id'] ?? 0) === (int)$excludeId) continue;
        if (sanitizeSlugPhp($it['slug'] ?? '') === $norm) {
            return true;
        }
    }
    return false;
}

// ------------------------------------------------------------------------------
// 10. Structured Diagnostic Suite
// ------------------------------------------------------------------------------
function runDiagnosticsSuite($db, $options = []) {
    global $dataFile, $lockFile, $logFile;
    $stages = [];
    $correlationId = substr(bin2hex(random_bytes(8)), 0, 12);
    $tgCfg = $db['telegramConfig'] ?? [];
    $adminChatId = trim((string)($tgCfg['adminChatId'] ?? $tgCfg['baleAdminChatId'] ?? ''));

    $customerToken = trim((string)($tgCfg['customerBotToken'] ?? $tgCfg['baleBotToken'] ?? $tgCfg['botToken'] ?? ''));
    $adminToken = trim((string)($tgCfg['adminBotToken'] ?? $tgCfg['baleAdminBotToken'] ?? ''));
    $paymentMode = strtolower(trim((string)($tgCfg['balePaymentMode'] ?? 'live')));
    $walletToken = ($paymentMode === 'test')
        ? trim((string)($tgCfg['balePaymentTokenTest'] ?? 'WALLET-TEST-1111111111111111'))
        : trim((string)($tgCfg['balePaymentTokenLive'] ?? $tgCfg['balePaymentToken'] ?? ''));

    // STAGE A: Server connection and response format
    $stages[] = [
        'stage' => 'A',
        'name' => 'ارتباط با سرور و قالب پاسخ (Server Connection & Format)',
        'method' => 'GET',
        'endpoint' => '/api/health',
        'httpStatus' => 200,
        'ok' => true,
        'category' => 'server_liveness',
        'correlationId' => $correlationId,
        'details' => [
            'backendVersion' => 'Onival-PHP-1.2.0',
            'phpVersion' => PHP_VERSION,
            'serverSoftware' => $_SERVER['SERVER_SOFTWARE'] ?? 'LiteSpeed/Apache',
            'responseFormat' => 'application/json; charset=utf-8'
        ]
    ];

    // STAGE B: Administrator authentication
    $isAuthed = isRequestAdminAuthorized($db);
    $creds = $db['adminCredentials'] ?? [];
    $stages[] = [
        'stage' => 'B',
        'name' => 'احراز هویت مدیر سیستم (Admin Authentication)',
        'method' => 'GET',
        'endpoint' => '/api/admin/verify-session',
        'httpStatus' => $isAuthed ? 200 : 401,
        'ok' => $isAuthed,
        'category' => $isAuthed ? 'auth_verified' : 'AUTH_REQUIRED',
        'correlationId' => $correlationId,
        'details' => [
            'username' => $creds['username'] ?? 'admin',
            'initialSetupCompleted' => !empty($creds['initialSetupCompleted']),
            'sessionType' => 'HMAC-SHA256 (24-Hour Expiry)'
        ]
    ];

    // STAGE C: Reading bot configuration
    $hasCustToken = !empty($customerToken);
    $hasAdminToken = !empty($adminToken);
    $stages[] = [
        'stage' => 'C',
        'name' => 'خواندن پیکربندی ربات‌ها (Bot Configuration Readiness)',
        'method' => 'GET',
        'endpoint' => '/api/bot/config',
        'httpStatus' => 200,
        'ok' => ($hasCustToken || $hasAdminToken),
        'category' => ($hasCustToken && $hasAdminToken) ? 'config_complete' : 'config_partial',
        'correlationId' => $correlationId,
        'details' => [
            'customerBotUsername' => ltrim(trim((string)($tgCfg['customerBotUsername'] ?? 'Onivalbot')), '@'),
            'adminBotUsername' => ltrim(trim((string)($tgCfg['adminBotUsername'] ?? 'onivaladminbot')), '@'),
            'adminChatIdConfigured' => !empty($adminChatId),
            'targetAdminChatId' => $adminChatId,
            'customerBotTokenSet' => $hasCustToken,
            'adminBotTokenSet' => $hasAdminToken,
            'paymentMode' => $paymentMode,
            'walletTokenSet' => !empty($walletToken)
        ]
    ];

    // STAGE D: Database readiness and atomic sidecar locking
    $dbOk = false;
    $lockOk = false;
    $writeOk = false;
    if (file_exists($dataFile) && filesize($dataFile) > 10) {
        $dbOk = true;
    }
    $lockFp = @fopen($lockFile, 'c+');
    if ($lockFp) {
        if (@flock($lockFp, LOCK_EX)) {
            $lockOk = true;
            $testTmp = ONIVAL_PRIVATE_DIR . '/.diag_test_' . uniqid();
            if (@file_put_contents($testTmp, 'ok') !== false) {
                $writeOk = true;
                @unlink($testTmp);
            }
            @flock($lockFp, LOCK_UN);
        }
        @fclose($lockFp);
    }
    $stageDOk = ($dbOk && $lockOk && $writeOk);
    $stages[] = [
        'stage' => 'D',
        'name' => 'آمادگی پایگاه داده و قفل همزمانی (Database & Sidecar Lock Readiness)',
        'method' => 'INTERNAL',
        'endpoint' => 'database',
        'httpStatus' => $stageDOk ? 200 : 500,
        'ok' => $stageDOk,
        'category' => $stageDOk ? 'storage_ready' : 'DATA_WRITE_FAILED',
        'correlationId' => $correlationId,
        'details' => [
            'canonicalDbExists' => $dbOk,
            'exclusiveLockAcquired' => $lockOk,
            'atomicWriteVerified' => $writeOk,
            'totalProducts' => count($db['products'] ?? []),
            'totalOrders' => count($db['orders'] ?? [])
        ]
    ];

    // STAGE E: Customer bot getMe test
    if ($hasCustToken) {
        $custMe = callBaleApi($customerToken, 'getMe');
        $custMeOk = !empty($custMe['ok']);
        $stages[] = [
            'stage' => 'E',
            'name' => 'تست هویت ربات مشتری در بله (Customer Bot getMe)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/getMe',
            'httpStatus' => $custMe['http_code'] ?? ($custMeOk ? 200 : 400),
            'ok' => $custMeOk,
            'category' => $custMeOk ? 'bot_online' : 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => [
                'botUsername' => $custMe['result']['username'] ?? 'N/A',
                'botName' => $custMe['result']['first_name'] ?? 'N/A',
                'statusDescription' => $custMe['description'] ?? ($custMeOk ? 'OK' : 'Error')
            ]
        ];
    } else {
        $stages[] = [
            'stage' => 'E',
            'name' => 'تست هویت ربات مشتری در بله (Customer Bot getMe)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/getMe',
            'httpStatus' => 400,
            'ok' => false,
            'category' => 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => ['message' => 'توکن ربات مشتری تنظیم نشده است.']
        ];
    }

    // STAGE F: Admin bot getMe test
    if ($hasAdminToken) {
        $admMe = callBaleApi($adminToken, 'getMe');
        $admMeOk = !empty($admMe['ok']);
        $stages[] = [
            'stage' => 'F',
            'name' => 'تست هویت ربات ادمین در بله (Admin Bot getMe)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/getMe',
            'httpStatus' => $admMe['http_code'] ?? ($admMeOk ? 200 : 400),
            'ok' => $admMeOk,
            'category' => $admMeOk ? 'bot_online' : 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => [
                'botUsername' => $admMe['result']['username'] ?? 'N/A',
                'botName' => $admMe['result']['first_name'] ?? 'N/A',
                'statusDescription' => $admMe['description'] ?? ($admMeOk ? 'OK' : 'Error')
            ]
        ];
    } else {
        $stages[] = [
            'stage' => 'F',
            'name' => 'تست هویت ربات ادمین در بله (Admin Bot getMe)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/getMe',
            'httpStatus' => 400,
            'ok' => false,
            'category' => 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => ['message' => 'توکن ربات ادمین تنظیم نشده است.']
        ];
    }

    // STAGE G: Actual test-message delivery to configured administrator
    if ($hasAdminToken && !empty($adminChatId)) {
        $testText = "🔔 تست ارتباط سیستمی اونیوال با شناسه مدیریت ({$adminChatId})\nزمان: " . date('Y/m/d - H:i:s');
        $sendRes = sendBaleMessage($adminToken, $adminChatId, $testText);
        $sendOk = !empty($sendRes['ok']);
        $stages[] = [
            'stage' => 'G',
            'name' => 'ارسال پیام تست به شناسه چت مدیر (Admin Test Message Delivery)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/sendMessage',
            'httpStatus' => $sendRes['http_code'] ?? ($sendOk ? 200 : 400),
            'ok' => $sendOk,
            'category' => $sendOk ? 'delivered' : 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => [
                'recipientChatId' => $adminChatId,
                'messageId' => $sendRes['result']['message_id'] ?? null,
                'description' => $sendRes['description'] ?? ($sendOk ? 'پیام با موفقیت به بله ادمین تحویل شد.' : 'خطا در تحویل به چت مدیر')
            ]
        ];
    } else {
        $stages[] = [
            'stage' => 'G',
            'name' => 'ارسال پیام تست به شناسه چت مدیر (Admin Test Message Delivery)',
            'method' => 'POST',
            'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/sendMessage',
            'httpStatus' => 400,
            'ok' => false,
            'category' => 'BOT_API_FAILED',
            'correlationId' => $correlationId,
            'details' => ['message' => 'توکن ربات ادمین یا شناسه چت مدیر وارد نشده است.']
        ];
    }

    // STAGE H: Webhook registration and inspection for EACH bot
    $hookCust = $hasCustToken ? callBaleApi($customerToken, 'getWebhookInfo') : null;
    $hookAdmin = $hasAdminToken ? callBaleApi($adminToken, 'getWebhookInfo') : null;
    $stages[] = [
        'stage' => 'H',
        'name' => 'استعلام و وضعیت وب‌هوک ربات‌ها (Webhook Inspection for Each Bot)',
        'method' => 'POST',
        'endpoint' => 'https://tapi.bale.ai/bot[TOKEN]/getWebhookInfo',
        'httpStatus' => 200,
        'ok' => true,
        'category' => 'webhook_status',
        'correlationId' => $correlationId,
        'details' => [
            'customerBotWebhook' => [
                'url' => $hookCust['result']['url'] ?? 'ثبت نشده',
                'pendingUpdates' => $hookCust['result']['pending_update_count'] ?? 0,
                'lastErrorMessage' => $hookCust['result']['last_error_message'] ?? 'بدون خطا'
            ],
            'adminBotWebhook' => [
                'url' => $hookAdmin['result']['url'] ?? 'ثبت نشده',
                'pendingUpdates' => $hookAdmin['result']['pending_update_count'] ?? 0,
                'lastErrorMessage' => $hookAdmin['result']['last_error_message'] ?? 'بدون خطا'
            ]
        ]
    ];

    // STAGE I: Command/button handling test
    $testCmd1 = extractOrderCodePhp('/start pay_ONV-ORD-101');
    $testCmd2 = extractOrderCodePhp('/confirm_ONV-ORD-101');
    $cmdOk = ($testCmd1 === 'ONV-ORD-101' && $testCmd2 === 'ONV-ORD-101');
    $stages[] = [
        'stage' => 'I',
        'name' => 'پردازشگر دستورات و دکمه‌ها (Command & Button Parsing Test)',
        'method' => 'INTERNAL',
        'endpoint' => 'extractOrderCodePhp()',
        'httpStatus' => $cmdOk ? 200 : 500,
        'ok' => $cmdOk,
        'category' => $cmdOk ? 'parser_verified' : 'parser_failed',
        'correlationId' => $correlationId,
        'details' => [
            'payDeepLinkParsed' => $testCmd1,
            'adminConfirmCmdParsed' => $testCmd2
        ]
    ];

    // STAGE J: Matching a real order
    $sampleOrder = !empty($db['orders']) ? $db['orders'][0] : null;
    $orderMatchOk = false;
    if ($sampleOrder && !empty($sampleOrder['trackingCode'])) {
        $found = findOrderByCodePhp($db['orders'], $sampleOrder['trackingCode']);
        $orderMatchOk = ($found && ($found['trackingCode'] === $sampleOrder['trackingCode']));
    }
    $stages[] = [
        'stage' => 'J',
        'name' => 'تطبیق و جستجوی سفارش واقعی (Real Order Lookup Test)',
        'method' => 'INTERNAL',
        'endpoint' => 'findOrderByCodePhp()',
        'httpStatus' => $orderMatchOk ? 200 : 404,
        'ok' => $orderMatchOk,
        'category' => $orderMatchOk ? 'order_lookup_success' : 'PRODUCT_NOT_FOUND',
        'correlationId' => $correlationId,
        'details' => [
            'testedCode' => $sampleOrder['trackingCode'] ?? 'N/A',
            'matched' => $orderMatchOk
        ]
    ];

    // STAGE K: Invoice generation test
    $invoiceStructureValid = (!empty($walletToken) && ($paymentMode !== 'live' || strpos($walletToken, 'WALLET-TEST') === false));
    $stages[] = [
        'stage' => 'K',
        'name' => 'اعتبارسنجی صدور فاکتور کیف پول بله (Invoice Generation Validation)',
        'method' => 'INTERNAL',
        'endpoint' => 'sendBaleInvoiceSafe()',
        'httpStatus' => $invoiceStructureValid ? 200 : 400,
        'ok' => $invoiceStructureValid,
        'category' => $invoiceStructureValid ? 'invoice_ready' : 'INVALID_WALLET_MODE',
        'correlationId' => $correlationId,
        'details' => [
            'paymentMode' => $paymentMode,
            'walletTokenConfigured' => !empty($walletToken),
            'liveTestMismatchPrevented' => true
        ]
    ];

    return [
        'ok' => true,
        'correlationId' => $correlationId,
        'timestamp' => date('c'),
        'backendVersion' => 'Onival-PHP-1.2.0',
        'phpVersion' => PHP_VERSION,
        'totalStages' => count($stages),
        'passedStages' => count(array_filter($stages, fn($s) => !empty($s['ok']))),
        'stages' => $stages
    ];
}

// ------------------------------------------------------------------------------
// 11. Unified Panel Log Adapter (Bounded Tail-Read & Schema Translation)
// ------------------------------------------------------------------------------
/**
 * Reads recent structured events from app.log with bounded tail reading
 * and maps them to the unified frontend format:
 * { id, time, timestamp, type, platform, text, status, details }
 */
function getRecentBotActivityLogsPhp($maxItems = 50, $bytesToRead = 65536) {
    global $logFile;
    if (!file_exists($logFile)) {
        return [];
    }

    $fileSize = @filesize($logFile);
    if ($fileSize === 0 || $fileSize === false) {
        return [];
    }

    $fp = @fopen($logFile, 'rb');
    if (!$fp) {
        return [];
    }

    $readLength = min($fileSize, $bytesToRead);
    $offset = max(0, $fileSize - $readLength);
    fseek($fp, $offset);
    $chunk = fread($fp, $readLength);
    fclose($fp);

    if ($chunk === false || $chunk === '') {
        return [];
    }

    // If we didn't read from the start of the file, drop the leading partial line
    if ($offset > 0) {
        $firstNewline = strpos($chunk, "\n");
        if ($firstNewline !== false) {
            $chunk = substr($chunk, $firstNewline + 1);
        }
    }

    $lines = explode("\n", $chunk);
    $events = [];

    // Process lines in reverse order (newest first)
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        $line = trim($lines[$i]);
        if ($line === '') continue;

        $entry = @json_decode($line, true);
        if (!is_array($entry)) continue;

        $timestamp = (string)($entry['timestamp'] ?? '');
        $stage = (string)($entry['stage'] ?? '');
        $category = (string)($entry['category'] ?? '');
        $rawMessage = (string)($entry['message'] ?? '');
        $correlationId = (string)($entry['correlationId'] ?? '');
        $context = is_array($entry['context'] ?? null) ? $entry['context'] : [];

        // Redact any sensitive tokens, secrets, or raw keys in the message
        $cleanMessage = preg_replace('/(?::|token=|secret=)[a-zA-Z0-9_-]{16,}/i', ':***', $rawMessage);
        $cleanMessage = preg_replace('/[a-zA-Z0-9_-]{32,}/', '***', $cleanMessage);

        // Derive status explicitly without inventing false success
        $status = 'info';
        $lowCategory = strtolower($category);
        $lowStage = strtolower($stage);
        if (strpos($lowCategory, 'error') !== false || strpos($lowCategory, 'fail') !== false || strpos($lowCategory, 'critical') !== false || strpos($lowCategory, 'exception') !== false || strpos($lowCategory, 'rejected') !== false || strpos($lowCategory, 'conflict') !== false) {
            $status = 'error';
        } elseif (strpos($lowCategory, 'warn') !== false || strpos($lowCategory, 'review') !== false || strpos($lowCategory, 'pending') !== false || strpos($lowCategory, 'underpaid') !== false) {
            $status = 'warning';
        } elseif (strpos($lowCategory, 'success') !== false || strpos($lowCategory, 'approved') !== false || strpos($lowCategory, 'verified') !== false || strpos($lowCategory, 'saved') !== false || strpos($lowCategory, 'uploaded') !== false) {
            $status = 'success';
        }

        // Derive platform
        $platform = 'bale';
        if (strpos($lowStage, 'telegram') !== false || strpos($lowCategory, 'telegram') !== false) {
            $platform = 'telegram';
        } elseif (strpos($lowStage, 'database') !== false || strpos($lowStage, 'account') !== false) {
            $platform = 'system';
        }

        // Derive readable Persian/standard time
        $timeStr = date('H:i:s');
        if (!empty($timestamp)) {
            $ts = strtotime($timestamp);
            if ($ts !== false) {
                $timeStr = date('H:i:s', $ts);
            }
        }

        // Derive stable unique integer ID for React key and item selection
        $idSeed = $timestamp . '_' . $correlationId . '_' . $stage . '_' . $category . '_' . $i;
        $stableId = (int)sprintf('%u', crc32($idSeed));
        if ($stableId <= 0) $stableId = abs(crc32($idSeed)) ?: ($i + 1);

        $events[] = [
            'id' => $stableId,
            'time' => $timeStr,
            'timestamp' => $timestamp,
            'type' => !empty($category) ? $category : $stage,
            'platform' => $platform,
            'text' => $cleanMessage,
            'status' => $status,
            'details' => !empty($context) ? json_encode($context, JSON_UNESCAPED_UNICODE) : null
        ];

        if (count($events) >= $maxItems) {
            break;
        }
    }

    return $events;
}

/**
 * Escapes a CSV field and neutralizes spreadsheet formula injection (=, +, -, @, \t, \r)
 */
function escapeCsvFieldPhp($field): string {
    if ($field === null || $field === '') {
        return '""';
    }
    $str = str_replace('"', '""', (string)$field);
    if (preg_match('/^[=+\-@\t\r]/', $str)) {
        $str = "'" . $str;
    }
    return '"' . $str . '"';
}
