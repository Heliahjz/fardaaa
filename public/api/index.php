<?php
define('ONIVAL_ENTRY', true);
header('Content-Type: application/json; charset=utf-8');

/**
 * ==============================================================================
 * ONIVAL Production Server API Backend for Shared Hosting (ParsPack / cPanel)
 * ==============================================================================
 * Clean, transactional REST API router backed by canonical storage,
 * robust role-based access control, hardened image handling, and diagnostic tools.
 * ==============================================================================
 */

require_once __DIR__ . '/common.php';

// ------------------------------------------------------------------------------
// 1. Request URL & Method Parser
// ------------------------------------------------------------------------------
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);

if (!empty($_GET['path'])) {
    $path = '/api/' . ltrim($_GET['path'], '/');
} elseif (preg_match('#(/api(?:/.*)?)$#', $path, $matches)) {
    $path = $matches[1];
}
$path = preg_replace('#^/+#', '/', $path);
$path = rtrim($path, '/');
if ($path === '') {
    $path = '/api';
}

// Early Webhook delegation BEFORE reading request body in index.php
if (
    $path === '/api/webhook/bale' ||
    $path === '/api/bot/webhook/bale' ||
    $path === '/api/webhook/bale/customer' ||
    $path === '/api/webhook/bale/admin' ||
    $path === '/api/webhook/telegram' ||
    $path === '/api/bot/webhook/telegram' ||
    $path === '/api/webhook.php' ||
    $path === '/api/bale-webhook.php' ||
    $path === '/api/telegram-webhook.php' ||
    $path === '/api/webhook'
) {
    if (strpos($path, 'admin') !== false) {
        $_GET['bot'] = 'admin';
    }
    require __DIR__ . '/webhook.php';
    exit;
}

// Scoped CORS configuration: Exact origin matching only (no strpos substring match)
$rawOrigin = rtrim($_SERVER['HTTP_ORIGIN'] ?? '', '/');
$allowedOrigins = ['https://onival.ir', 'https://www.onival.ir', 'http://localhost:3000', 'http://localhost:5173'];
$isAllowedOrigin = in_array($rawOrigin, $allowedOrigins, true);

$isPrivateRoute = (strpos($path, '/api/admin') !== false || strpos($path, '/api/account') !== false || strpos($path, '/api/bot') !== false || strpos($path, 'export-state') !== false || strpos($path, 'import-state') !== false);

if ($isPrivateRoute) {
    if ($isAllowedOrigin && !empty($rawOrigin)) {
        header("Access-Control-Allow-Origin: {$rawOrigin}");
        header('Access-Control-Allow-Credentials: true');
    }
} else {
    // Public endpoints allow CORS for storefront & price engines
    if ($isAllowedOrigin && !empty($rawOrigin)) {
        header("Access-Control-Allow-Origin: {$rawOrigin}");
    } else {
        header('Access-Control-Allow-Origin: *');
    }
}
header('Vary: Origin');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Admin-Token');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Powered-By: Onival-Engine-PHP');

if ($method === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Verify runtime readiness
$runtimeReady = ensureRuntimeReady();

// Public Health endpoint: MUST be answered even when ensureRuntimeReady() fails
if (($path === '/api/health' || $path === '/api/ping') && $method === 'GET') {
    if (!$runtimeReady['ok']) {
        http_response_code(503);
        echo json_encode([
            'ok' => false,
            'build' => ONIVAL_BUILD_ID,
            'status' => $runtimeReady['status'] ?? 'storage_unavailable',
            'detail' => $runtimeReady['detail'] ?? 'dir_missing'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    http_response_code(200);
    echo json_encode([
        'ok' => true,
        'build' => ONIVAL_BUILD_ID,
        'status' => 'ready',
        'detail' => 'ready'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// For all other routes: if runtime readiness failed, exit with 503
if (!$runtimeReady['ok']) {
    http_response_code(503);
    echo json_encode([
        'ok' => false,
        'code' => $runtimeReady['code'] ?? 'STORAGE_UNAVAILABLE',
        'status' => $runtimeReady['status'] ?? 'storage_unavailable',
        'detail' => $runtimeReady['detail'] ?? 'dir_missing',
        'error' => $runtimeReady['error'] ?? 'زیرساخت سرور یا پایگاه داده در دسترس نمی‌باشد (503 Service Unavailable).'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Determine body limit per route: 10MB only for receipt upload, 1MB for all others
$maxBodyBytes = (strpos($path, '/upload-receipt') !== false || strpos($path, '/receipt') !== false)
    ? 10485760
    : 1048576;
$rawInput = readBoundedRequestBodyPhp($maxBodyBytes);
$body = @json_decode($rawInput, true) ?: [];

// Support HTTP Method Override (header or body)
$overrideMethod = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? ($_POST['_method'] ?? ($body['_method'] ?? null));
if ($overrideMethod) {
    $method = strtoupper(trim($overrideMethod));
}

// Read-only state for fast querying
$db = loadDatabaseReadonly();

function enforceAdminAuthOrExit($db, $targetPath = null) {
    global $path;
    $checkPath = $targetPath ?: $path;
    if (!isRequestAdminAuthorized($db)) {
        http_response_code(401);
        echo json_encode([
            'ok' => false,
            'code' => 'AUTH_REQUIRED',
            'error' => 'دسترسی غیرمجاز. لطفاً وارد حساب مدیریت شوید (401 Unauthorized).'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $creds = $db['adminCredentials'] ?? [];
    if (empty($creds['initialSetupCompleted'])) {
        $allowedSetupPaths = [
            '/api/admin/setup-credentials',
            '/api/account/change-credentials',
            '/api/admin/logout',
            '/api/admin/verify-session',
            '/api/account/profile',
            '/api/admin/setup-status'
        ];
        if (!in_array($checkPath, $allowedSetupPaths, true)) {
            http_response_code(403);
            echo json_encode([
                'ok' => false,
                'code' => 'SETUP_REQUIRED',
                'setupRequired' => true,
                'error' => 'تکمیل راه‌اندازی اولیه و تعیین نام کاربری و رمز عبور دائمی جدید الزامی است (403 Forbidden).'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }
}

// ------------------------------------------------------------------------------
// 2. Public Storefront & Health Endpoints
// ------------------------------------------------------------------------------

// Admin Setup Status (Authenticated session check only - never reveals setup state to unauthenticated visitors)
if ($path === '/api/admin/setup-status' && $method === 'GET') {
    if (!isRequestAdminAuthorized($db)) {
        http_response_code(401);
        echo json_encode([
            'ok' => false,
            'code' => 'AUTH_REQUIRED',
            'error' => 'دسترسی غیرمجاز. لطفاً وارد حساب مدیریت شوید.'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $creds = $db['adminCredentials'] ?? [];
    echo json_encode([
        'ok' => true,
        'initialSetupCompleted' => !empty($creds['initialSetupCompleted'])
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ------------------------------------------------------------------------------
// 3. Products Endpoints (Full CRUD & Stock Management)
// ------------------------------------------------------------------------------

// GET /api/products or /api/product
if (($path === '/api/products' || $path === '/api/product') && $method === 'GET') {
    $targetId = !empty($_GET['id']) ? (int)$_GET['id'] : null;
    if ($targetId) {
        foreach ($db['products'] ?? [] as $prod) {
            if ((int)($prod['id'] ?? 0) === $targetId && empty($prod['isDelete'])) {
                echo json_encode($prod);
                exit;
            }
        }
        http_response_code(404);
        echo json_encode(['ok' => false, 'code' => 'PRODUCT_NOT_FOUND', 'error' => 'محصول مورد نظر یافت نشد']);
        exit;
    }
    $isAdmin = isRequestAdminAuthorized($db);
    $all = $db['products'] ?? [];
    $filtered = array_values(array_filter($all, function($p) use ($isAdmin) {
        if (!empty($p['isDelete'])) return false;
        if (!$isAdmin && ($p['status'] ?? 'published') === 'draft') return false;
        return true;
    }));
    echo json_encode($filtered);
    exit;
}

// GET /api/products/{id} or /api/product/{id}
if (preg_match('#^/api/products?/(\d+)$#', $path, $m) && $method === 'GET') {
    $pId = (int)$m[1];
    foreach ($db['products'] ?? [] as $prod) {
        if ((int)($prod['id'] ?? 0) === $pId && empty($prod['isDelete'])) {
            echo json_encode($prod);
            exit;
        }
    }
    http_response_code(404);
    echo json_encode(['ok' => false, 'code' => 'PRODUCT_NOT_FOUND', 'error' => 'محصول مورد نظر یافت نشد']);
    exit;
}

// POST /api/products or /api/product (Create New Product)
if (($path === '/api/products' || $path === '/api/product') && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    $title = trim((string)($body['title'] ?? ''));
    if (empty($title)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'عنوان محصول الزامی است.']);
        exit;
    }

    $res = withDatabaseTransaction(function(&$dbRef) use ($body, $title) {
        if (!isset($dbRef['products']) || !is_array($dbRef['products'])) {
            $dbRef['products'] = [];
        }

        $nextId = 1;
        if (!empty($dbRef['products'])) {
            foreach ($dbRef['products'] as $p) {
                if ((int)($p['id'] ?? 0) >= $nextId) {
                    $nextId = (int)$p['id'] + 1;
                }
            }
        }

        $candidateSlug = sanitizeSlugPhp($body['slug'] ?? $title, 'product', $nextId);
        if (isSlugDuplicatePhp($dbRef['products'], $candidateSlug)) {
            return [
                'ok' => false,
                'code' => 'SLUG_DUPLICATE',
                'error' => "نامک (Slug) «{$candidateSlug}» تکراری است و قبلاً برای محصول دیگری استفاده شده است."
            ];
        }

        // Parse and validate sizes
        $sizesInput = $body['sizes'] ?? [];
        $parsedSizes = null;
        if (is_array($sizesInput) && count($sizesInput) > 0) {
            $parsedSizes = [];
            foreach ($sizesInput as $s) {
                $sName = trim((string)($s['name'] ?? $s['size'] ?? ''));
                if ($sName === '') continue;
                $sPrice = max(0, (int)($s['price'] ?? 0));
                // Zero stock is strictly preserved
                $sStock = (isset($s['stock']) && $s['stock'] !== '' && $s['stock'] !== null)
                    ? max(0, (int)$s['stock'])
                    : 10;
                $sOfferStock = (isset($s['specialOfferStock']) && $s['specialOfferStock'] !== '' && $s['specialOfferStock'] !== null)
                    ? max(0, (int)$s['specialOfferStock'])
                    : null;

                $parsedSizes[] = [
                    'name' => $sName,
                    'price' => $sPrice,
                    'stock' => $sStock,
                    'specialOfferStock' => $sOfferStock,
                    'isOutOfStock' => ($sStock <= 0),
                    'sku' => trim((string)($s['sku'] ?? '')) ?: null
                ];
            }
        }

        $computedStock = 0;
        if ($parsedSizes && count($parsedSizes) > 0) {
            foreach ($parsedSizes as $s) {
                $computedStock += $s['stock'];
            }
        } else {
            $computedStock = (isset($body['stock']) && $body['stock'] !== '' && $body['stock'] !== null)
                ? max(0, (int)$body['stock'])
                : 20;
        }

        $computedOfferStock = null;
        if ($parsedSizes && count($parsedSizes) > 0) {
            $hasOffer = false;
            $sumOffer = 0;
            foreach ($parsedSizes as $s) {
                if ($s['specialOfferStock'] !== null) {
                    $hasOffer = true;
                    $sumOffer += $s['specialOfferStock'];
                }
            }
            if ($hasOffer) $computedOfferStock = $sumOffer;
        } elseif (isset($body['specialOfferStock']) && $body['specialOfferStock'] !== '' && $body['specialOfferStock'] !== null) {
            $computedOfferStock = max(0, (int)$body['specialOfferStock']);
        }

        $resolvedPrice = ($parsedSizes && count($parsedSizes) > 0)
            ? $parsedSizes[0]['price']
            : max(0, (int)($body['price'] ?? 0));

        $catId = (int)($body['categoryId'] ?? 1);
        $catTitle = 'عمومی';
        $catSlug = 'honey';
        if (!empty($dbRef['productCategories']) && is_array($dbRef['productCategories'])) {
            foreach ($dbRef['productCategories'] as $c) {
                if ((int)($c['id'] ?? 0) === $catId) {
                    $catTitle = $c['title'] ?? 'عمومی';
                    $catSlug = $c['slug'] ?? 'honey';
                    break;
                }
            }
        }

        $nowIso = date('c');
        $newProd = [
            'id' => $nextId,
            'title' => $title,
            'slug' => $candidateSlug,
            'price' => $resolvedPrice,
            'hasSize' => !empty($body['hasSize']) || ($parsedSizes && count($parsedSizes) > 0),
            'sizes' => $parsedSizes,
            'priceSmall' => ($parsedSizes && count($parsedSizes) > 0) ? $parsedSizes[0]['price'] : (isset($body['priceSmall']) ? (int)$body['priceSmall'] : null),
            'priceLarge' => ($parsedSizes && count($parsedSizes) > 0) ? $parsedSizes[count($parsedSizes) - 1]['price'] : (isset($body['priceLarge']) ? (int)$body['priceLarge'] : null),
            'discount' => max(0, min(99, (int)($body['discount'] ?? 0))),
            'discountPercent' => max(0, min(99, (int)($body['discount'] ?? 0))),
            'type' => $body['type'] ?? $catSlug,
            'features' => is_array($body['features'] ?? null) ? $body['features'] : [],
            'categoryId' => $catId,
            'categoryTitle' => $catTitle,
            'imageName' => trim((string)($body['imageName'] ?? '')) ?: 'https://images.unsplash.com/photo-1587049359535-b64d3dd0d716?w=800&auto=format&fit=crop&q=80',
            'imageAlt' => trim((string)($body['imageAlt'] ?? '')) ?: $title,
            'images' => is_array($body['images'] ?? null) ? $body['images'] : (!empty($body['imageName']) ? [$body['imageName']] : []),
            'videoUrl' => trim((string)($body['videoUrl'] ?? '')),
            'videoType' => trim((string)($body['videoType'] ?? 'direct')),
            'imageAspectRatio' => $body['imageAspectRatio'] ?? 'square',
            'imageFitMode' => $body['imageFitMode'] ?? 'cover',
            'imageZoomLevel' => (float)($body['imageZoomLevel'] ?? 2),
            'description' => trim((string)($body['description'] ?? '')),
            'content' => trim((string)($body['content'] ?? '')),
            'isDelete' => false,
            'creationTime' => date('Y/m/d'),
            'publishedAt' => $body['publishedAt'] ?? $nowIso,
            'updatedAt' => $nowIso,
            'status' => ($body['status'] ?? 'published') === 'draft' ? 'draft' : 'published',
            'availability' => $computedStock <= 0 ? 'OutOfStock' : ($body['availability'] ?? 'InStock'),
            'stock' => $computedStock,
            'isOutOfStock' => ($computedStock <= 0),
            'specialOfferStock' => $computedOfferStock,
            'specialOfferInitialStock' => isset($body['specialOfferInitialStock']) ? (int)$body['specialOfferInitialStock'] : $computedOfferStock,
            'isAmazingOffer' => !empty($body['isAmazingOffer']) || !empty($body['isSpecialOffer']),
            'isSpecialOffer' => !empty($body['isAmazingOffer']) || !empty($body['isSpecialOffer']),
            'sku' => trim((string)($body['sku'] ?? '')) ?: "ONV-PRD-{$nextId}",
            'seoTitle' => trim((string)($body['seoTitle'] ?? '')),
            'seoDescription' => trim((string)($body['seoDescription'] ?? '')),
            'ogTitle' => trim((string)($body['ogTitle'] ?? '')),
            'ogDescription' => trim((string)($body['ogDescription'] ?? '')),
            'ogImage' => trim((string)($body['ogImage'] ?? '')),
            'canonicalUrl' => trim((string)($body['canonicalUrl'] ?? '')),
            'robotsNoIndex' => !empty($body['robotsNoIndex']),
            'robotsNoFollow' => !empty($body['robotsNoFollow'])
        ];

        $dbRef['products'][] = $newProd;
        return ['ok' => true, 'product' => $newProd];
    });

    if (empty($res['ok'])) {
        http_response_code($res['code'] === 'SLUG_DUPLICATE' ? 409 : 500);
        echo json_encode($res);
        exit;
    }

    onival_log('catalog', 'product_created', "Product created: {$res['product']['title']}", ['id' => $res['product']['id']]);
    http_response_code(201);
    echo json_encode($res['product']);
    exit;
}

// PUT / PATCH / POST /api/products/{id} or /api/product/{id} (Update Product)
if (preg_match('#^/api/products?/(\d+)$#', $path, $m) && ($method === 'PUT' || $method === 'PATCH' || $method === 'POST')) {
    enforceAdminAuthOrExit($db);
    $pId = (int)$m[1];

    $res = withDatabaseTransaction(function(&$dbRef) use ($pId, $body) {
        $idx = -1;
        if (!empty($dbRef['products']) && is_array($dbRef['products'])) {
            foreach ($dbRef['products'] as $i => $p) {
                if ((int)($p['id'] ?? 0) === $pId && empty($p['isDelete'])) {
                    $idx = $i;
                    break;
                }
            }
        }

        if ($idx === -1) {
            return ['ok' => false, 'code' => 'PRODUCT_NOT_FOUND', 'error' => 'محصول مورد نظر یافت نشد.'];
        }

        $existing = &$dbRef['products'][$idx];

        $title = isset($body['title']) ? trim((string)$body['title']) : $existing['title'];
        $nextSlug = isset($body['slug']) && trim((string)$body['slug']) !== ''
            ? sanitizeSlugPhp($body['slug'], 'product', $pId)
            : ($existing['slug'] ?? "product-{$pId}");

        if (isSlugDuplicatePhp($dbRef['products'], $nextSlug, $pId)) {
            return [
                'ok' => false,
                'code' => 'SLUG_DUPLICATE',
                'error' => "نامک (Slug) «{$nextSlug}» تکراری است و قبلاً برای محصول دیگری استفاده شده است."
            ];
        }

        // Record 301 redirect if published slug changed
        if (!empty($existing['slug']) && $existing['slug'] !== $nextSlug && ($existing['status'] ?? 'published') === 'published') {
            if (!isset($dbRef['slugRedirects'])) $dbRef['slugRedirects'] = [];
            $fromPath = "/products/{$existing['slug']}";
            $toPath = "/products/{$nextSlug}";
            $dbRef['slugRedirects'] = array_values(array_filter($dbRef['slugRedirects'], fn($r) => ($r['fromPath'] ?? '') !== $fromPath));
            $dbRef['slugRedirects'][] = [
                'id' => time() * 1000 + rand(10, 99),
                'fromPath' => $fromPath,
                'toPath' => $toPath,
                'entityType' => 'product',
                'entityId' => $pId,
                'createdAt' => date('c')
            ];
        }

        // Parse and validate sizes
        $parsedSizes = $existing['sizes'] ?? null;
        if (isset($body['sizes']) && is_array($body['sizes'])) {
            $parsedSizes = [];
            foreach ($body['sizes'] as $s) {
                $sName = trim((string)($s['name'] ?? $s['size'] ?? ''));
                if ($sName === '') continue;
                $sPrice = max(0, (int)($s['price'] ?? 0));
                // Preserve exact 0
                $sStock = (isset($s['stock']) && $s['stock'] !== '' && $s['stock'] !== null)
                    ? max(0, (int)$s['stock'])
                    : 10;
                $sOfferStock = (isset($s['specialOfferStock']) && $s['specialOfferStock'] !== '' && $s['specialOfferStock'] !== null)
                    ? max(0, (int)$s['specialOfferStock'])
                    : null;

                $parsedSizes[] = [
                    'name' => $sName,
                    'price' => $sPrice,
                    'stock' => $sStock,
                    'specialOfferStock' => $sOfferStock,
                    'isOutOfStock' => ($sStock <= 0),
                    'sku' => trim((string)($s['sku'] ?? '')) ?: null
                ];
            }
        }

        $computedStock = 0;
        if ($parsedSizes && count($parsedSizes) > 0) {
            foreach ($parsedSizes as $s) {
                $computedStock += $s['stock'];
            }
        } else {
            $computedStock = (isset($body['stock']) && $body['stock'] !== '' && $body['stock'] !== null)
                ? max(0, (int)$body['stock'])
                : ($existing['stock'] ?? 0);
        }

        $computedOfferStock = $existing['specialOfferStock'] ?? null;
        if ($parsedSizes && count($parsedSizes) > 0) {
            $hasOffer = false;
            $sumOffer = 0;
            foreach ($parsedSizes as $s) {
                if ($s['specialOfferStock'] !== null) {
                    $hasOffer = true;
                    $sumOffer += $s['specialOfferStock'];
                }
            }
            if ($hasOffer) $computedOfferStock = $sumOffer;
        } elseif (isset($body['specialOfferStock']) && $body['specialOfferStock'] !== '' && $body['specialOfferStock'] !== null) {
            $computedOfferStock = max(0, (int)$body['specialOfferStock']);
        }

        $resolvedPrice = ($parsedSizes && count($parsedSizes) > 0)
            ? $parsedSizes[0]['price']
            : (isset($body['price']) ? max(0, (int)$body['price']) : ($existing['price'] ?? 0));

        $catId = isset($body['categoryId']) ? (int)$body['categoryId'] : ($existing['categoryId'] ?? 1);
        $catTitle = $existing['categoryTitle'] ?? 'عمومی';
        $catSlug = $existing['type'] ?? 'honey';
        if (!empty($dbRef['productCategories']) && is_array($dbRef['productCategories'])) {
            foreach ($dbRef['productCategories'] as $c) {
                if ((int)($c['id'] ?? 0) === $catId) {
                    $catTitle = $c['title'] ?? 'عمومی';
                    $catSlug = $c['slug'] ?? 'honey';
                    break;
                }
            }
        }

        $nowIso = date('c');

        $existing['title'] = $title;
        $existing['slug'] = $nextSlug;
        $existing['price'] = $resolvedPrice;
        $existing['hasSize'] = isset($body['hasSize']) ? !empty($body['hasSize']) : (!empty($existing['hasSize']) || ($parsedSizes && count($parsedSizes) > 0));
        $existing['sizes'] = $parsedSizes;
        $existing['priceSmall'] = ($parsedSizes && count($parsedSizes) > 0) ? $parsedSizes[0]['price'] : (isset($body['priceSmall']) ? (int)$body['priceSmall'] : ($existing['priceSmall'] ?? null));
        $existing['priceLarge'] = ($parsedSizes && count($parsedSizes) > 0) ? $parsedSizes[count($parsedSizes) - 1]['price'] : (isset($body['priceLarge']) ? (int)$body['priceLarge'] : ($existing['priceLarge'] ?? null));
        if (isset($body['discount'])) {
            $existing['discount'] = max(0, min(99, (int)$body['discount']));
            $existing['discountPercent'] = $existing['discount'];
        }
        $existing['type'] = $body['type'] ?? $catSlug;
        if (isset($body['features']) && is_array($body['features'])) {
            $existing['features'] = $body['features'];
        }
        $existing['categoryId'] = $catId;
        $existing['categoryTitle'] = $catTitle;
        if (isset($body['imageName'])) $existing['imageName'] = trim((string)$body['imageName']);
        if (isset($body['imageAlt'])) $existing['imageAlt'] = trim((string)$body['imageAlt']);
        if (isset($body['images']) && is_array($body['images'])) $existing['images'] = $body['images'];
        if (isset($body['videoUrl'])) $existing['videoUrl'] = trim((string)$body['videoUrl']);
        if (isset($body['videoType'])) $existing['videoType'] = trim((string)$body['videoType']);
        if (isset($body['imageAspectRatio'])) $existing['imageAspectRatio'] = $body['imageAspectRatio'];
        if (isset($body['imageFitMode'])) $existing['imageFitMode'] = $body['imageFitMode'];
        if (isset($body['imageZoomLevel'])) $existing['imageZoomLevel'] = (float)$body['imageZoomLevel'];
        if (isset($body['description'])) $existing['description'] = trim((string)$body['description']);
        if (isset($body['content'])) $existing['content'] = trim((string)$body['content']);
        $existing['updatedAt'] = $nowIso;
        if (isset($body['status'])) $existing['status'] = $body['status'] === 'draft' ? 'draft' : 'published';
        $existing['stock'] = $computedStock;
        $existing['isOutOfStock'] = ($computedStock <= 0);
        $existing['availability'] = $computedStock <= 0 ? 'OutOfStock' : ($body['availability'] ?? ($existing['availability'] ?? 'InStock'));
        $existing['specialOfferStock'] = $computedOfferStock;
        if (isset($body['specialOfferInitialStock'])) $existing['specialOfferInitialStock'] = (int)$body['specialOfferInitialStock'];
        if (isset($body['isAmazingOffer'])) {
            $existing['isAmazingOffer'] = !empty($body['isAmazingOffer']);
            $existing['isSpecialOffer'] = !empty($body['isAmazingOffer']);
        }
        if (isset($body['sku'])) $existing['sku'] = trim((string)$body['sku']);
        if (isset($body['seoTitle'])) $existing['seoTitle'] = trim((string)$body['seoTitle']);
        if (isset($body['seoDescription'])) $existing['seoDescription'] = trim((string)$body['seoDescription']);
        if (isset($body['ogTitle'])) $existing['ogTitle'] = trim((string)$body['ogTitle']);
        if (isset($body['ogDescription'])) $existing['ogDescription'] = trim((string)$body['ogDescription']);
        if (isset($body['ogImage'])) $existing['ogImage'] = trim((string)$body['ogImage']);
        if (isset($body['canonicalUrl'])) $existing['canonicalUrl'] = trim((string)$body['canonicalUrl']);
        if (isset($body['robotsNoIndex'])) $existing['robotsNoIndex'] = !empty($body['robotsNoIndex']);
        if (isset($body['robotsNoFollow'])) $existing['robotsNoFollow'] = !empty($body['robotsNoFollow']);

        return ['ok' => true, 'product' => $existing];
    });

    if (empty($res['ok'])) {
        $code = $res['code'] ?? '';
        http_response_code($code === 'PRODUCT_NOT_FOUND' ? 404 : ($code === 'SLUG_DUPLICATE' ? 409 : 500));
        echo json_encode($res);
        exit;
    }

    onival_log('catalog', 'product_updated', "Product updated: {$res['product']['title']}", ['id' => $pId]);
    echo json_encode($res['product']);
    exit;
}

// DELETE /api/products/{id} or /api/product/{id} (Soft Delete Product)
if (preg_match('#^/api/products?/(\d+)$#', $path, $m) && ($method === 'DELETE' || ($method === 'POST' && !empty($body['isDelete'])))) {
    enforceAdminAuthOrExit($db);
    $pId = (int)$m[1];

    $res = withDatabaseTransaction(function(&$dbRef) use ($pId) {
        if (!empty($dbRef['products']) && is_array($dbRef['products'])) {
            foreach ($dbRef['products'] as &$p) {
                if ((int)($p['id'] ?? 0) === $pId && empty($p['isDelete'])) {
                    $p['isDelete'] = true;
                    $p['updatedAt'] = date('c');
                    return ['ok' => true, 'product' => $p];
                }
            }
        }
        return ['ok' => false, 'code' => 'PRODUCT_NOT_FOUND', 'error' => 'محصول مورد نظر یافت نشد.'];
    });

    if (empty($res['ok'])) {
        http_response_code(404);
        echo json_encode($res);
        exit;
    }

    onival_log('catalog', 'product_deleted', "Product deleted: ID {$pId}");
    echo json_encode(['ok' => true, 'message' => 'محصول با موفقیت حذف شد']);
    exit;
}

// ------------------------------------------------------------------------------
// 4. Product Categories CRUD
// ------------------------------------------------------------------------------
if (($path === '/api/product-categories' || $path === '/api/product-category') && $method === 'GET') {
    echo json_encode($db['productCategories'] ?? []);
    exit;
}

if (($path === '/api/product-categories' || $path === '/api/product-category') && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $title = trim((string)($body['title'] ?? ''));
    if (empty($title)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'عنوان دسته‌بندی الزامی است']);
        exit;
    }

    $res = withDatabaseTransaction(function(&$dbRef) use ($body, $title) {
        if (!isset($dbRef['productCategories'])) $dbRef['productCategories'] = [];
        $nextId = 1;
        foreach ($dbRef['productCategories'] as $c) {
            if ((int)($c['id'] ?? 0) >= $nextId) $nextId = (int)$c['id'] + 1;
        }
        $slug = sanitizeSlugPhp($body['slug'] ?? $title, 'cat', $nextId);
        $newCat = [
            'id' => $nextId,
            'title' => $title,
            'slug' => $slug,
            'parentId' => !empty($body['parentId']) ? (int)$body['parentId'] : null,
            'sortOrder' => (int)($body['sortOrder'] ?? count($dbRef['productCategories']) + 1)
        ];
        $dbRef['productCategories'][] = $newCat;
        return $newCat;
    });

    echo json_encode($res);
    exit;
}

if (preg_match('#^/api/product-categor(?:y|ies)/(\d+)$#', $path, $m) && ($method === 'PUT' || $method === 'PATCH' || $method === 'POST')) {
    enforceAdminAuthOrExit($db);
    $cId = (int)$m[1];
    $res = withDatabaseTransaction(function(&$dbRef) use ($cId, $body) {
        if (!empty($dbRef['productCategories'])) {
            foreach ($dbRef['productCategories'] as &$c) {
                if ((int)($c['id'] ?? 0) === $cId) {
                    if (isset($body['title'])) $c['title'] = trim((string)$body['title']);
                    if (isset($body['slug'])) $c['slug'] = sanitizeSlugPhp($body['slug'], 'cat', $cId);
                    if (isset($body['parentId'])) $c['parentId'] = !empty($body['parentId']) ? (int)$body['parentId'] : null;
                    return $c;
                }
            }
        }
        return null;
    });
    if ($res) {
        echo json_encode($res);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'code' => 'NOT_FOUND', 'error' => 'دسته‌بندی یافت نشد']);
    }
    exit;
}

if (preg_match('#^/api/product-categor(?:y|ies)/(\d+)$#', $path, $m) && ($method === 'DELETE' || ($method === 'POST' && !empty($body['isDelete'])))) {
    enforceAdminAuthOrExit($db);
    $cId = (int)$m[1];
    withDatabaseTransaction(function(&$dbRef) use ($cId) {
        if (!empty($dbRef['productCategories'])) {
            $dbRef['productCategories'] = array_values(array_filter($dbRef['productCategories'], fn($c) => (int)($c['id'] ?? 0) !== $cId));
        }
    });
    echo json_encode(['ok' => true, 'message' => 'دسته‌بندی حذف شد']);
    exit;
}

// ------------------------------------------------------------------------------
// 5. Blog Posts & Categories CRUD
// ------------------------------------------------------------------------------
if ($path === '/api/posts' && $method === 'GET') {
    $posts = array_values(array_filter($db['posts'] ?? [], fn($p) => empty($p['isDelete'])));
    echo json_encode($posts);
    exit;
}

if (preg_match('#^/api/posts/(\d+)$#', $path, $m) && $method === 'GET') {
    $pId = (int)$m[1];
    foreach ($db['posts'] ?? [] as $post) {
        if ((int)($post['id'] ?? 0) === $pId && empty($post['isDelete'])) {
            echo json_encode($post);
            exit;
        }
    }
    http_response_code(404);
    echo json_encode(['ok' => false, 'code' => 'POST_NOT_FOUND', 'error' => 'مقاله یافت نشد']);
    exit;
}

if ($path === '/api/posts' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $title = trim((string)($body['title'] ?? ''));
    if (empty($title)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'عنوان مقاله الزامی است']);
        exit;
    }

    $res = withDatabaseTransaction(function(&$dbRef) use ($body, $title) {
        if (!isset($dbRef['posts'])) $dbRef['posts'] = [];
        $nextId = 1;
        foreach ($dbRef['posts'] as $p) {
            if ((int)($p['id'] ?? 0) >= $nextId) $nextId = (int)$p['id'] + 1;
        }
        $slug = sanitizeSlugPhp($body['slug'] ?? $title, 'post', $nextId);
        $newPost = [
            'id' => $nextId,
            'title' => $title,
            'slug' => $slug,
            'categoryId' => (int)($body['categoryId'] ?? 1),
            'categoryTitle' => $body['categoryTitle'] ?? 'وبلاگ',
            'description' => trim((string)($body['description'] ?? '')),
            'content' => trim((string)($body['content'] ?? '')),
            'imageName' => trim((string)($body['imageName'] ?? '')),
            'imageAlt' => trim((string)($body['imageAlt'] ?? $title)),
            'authorName' => trim((string)($body['authorName'] ?? 'مدیریت اونیوال')),
            'creationTime' => date('Y/m/d'),
            'viewCount' => 0,
            'isDelete' => false,
            'status' => ($body['status'] ?? 'published') === 'draft' ? 'draft' : 'published',
            'publishedAt' => $body['publishedAt'] ?? date('c'),
            'updatedAt' => date('c'),
            'seoTitle' => trim((string)($body['seoTitle'] ?? '')),
            'seoDescription' => trim((string)($body['seoDescription'] ?? ''))
        ];
        $dbRef['posts'][] = $newPost;
        return $newPost;
    });

    http_response_code(201);
    echo json_encode($res);
    exit;
}

if (preg_match('#^/api/posts/(\d+)$#', $path, $m) && $method === 'PUT') {
    enforceAdminAuthOrExit($db);
    $pId = (int)$m[1];
    $res = withDatabaseTransaction(function(&$dbRef) use ($pId, $body) {
        if (!empty($dbRef['posts'])) {
            foreach ($dbRef['posts'] as &$p) {
                if ((int)($p['id'] ?? 0) === $pId && empty($p['isDelete'])) {
                    if (isset($body['title'])) $p['title'] = trim((string)$body['title']);
                    if (isset($body['slug'])) $p['slug'] = sanitizeSlugPhp($body['slug'], 'post', $pId);
                    if (isset($body['description'])) $p['description'] = trim((string)$body['description']);
                    if (isset($body['content'])) $p['content'] = trim((string)$body['content']);
                    if (isset($body['imageName'])) $p['imageName'] = trim((string)$body['imageName']);
                    if (isset($body['imageAlt'])) $p['imageAlt'] = trim((string)$body['imageAlt']);
                    if (isset($body['authorName'])) $p['authorName'] = trim((string)$body['authorName']);
                    if (isset($body['categoryId'])) $p['categoryId'] = (int)$body['categoryId'];
                    if (isset($body['categoryTitle'])) $p['categoryTitle'] = $body['categoryTitle'];
                    if (isset($body['status'])) $p['status'] = $body['status'] === 'draft' ? 'draft' : 'published';
                    if (isset($body['seoTitle'])) $p['seoTitle'] = trim((string)$body['seoTitle']);
                    if (isset($body['seoDescription'])) $p['seoDescription'] = trim((string)$body['seoDescription']);
                    $p['updatedAt'] = date('c');
                    return $p;
                }
            }
        }
        return null;
    });

    if ($res) {
        echo json_encode($res);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'code' => 'POST_NOT_FOUND', 'error' => 'مقاله یافت نشد']);
    }
    exit;
}

if (preg_match('#^/api/posts/(\d+)$#', $path, $m) && $method === 'DELETE') {
    enforceAdminAuthOrExit($db);
    $pId = (int)$m[1];
    withDatabaseTransaction(function(&$dbRef) use ($pId) {
        if (!empty($dbRef['posts'])) {
            foreach ($dbRef['posts'] as &$p) {
                if ((int)($p['id'] ?? 0) === $pId) {
                    $p['isDelete'] = true;
                    $p['updatedAt'] = date('c');
                    break;
                }
            }
        }
    });
    echo json_encode(['ok' => true, 'message' => 'مقاله حذف شد']);
    exit;
}

if ($path === '/api/post-categories' && $method === 'GET') {
    echo json_encode($db['postCategories'] ?? []);
    exit;
}

if ($path === '/api/post-categories' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $title = trim((string)($body['title'] ?? ''));
    if (empty($title)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'عنوان الزامی است']);
        exit;
    }
    $res = withDatabaseTransaction(function(&$dbRef) use ($title) {
        if (!isset($dbRef['postCategories'])) $dbRef['postCategories'] = [];
        $nextId = 1;
        foreach ($dbRef['postCategories'] as $c) {
            if ((int)($c['id'] ?? 0) >= $nextId) $nextId = (int)$c['id'] + 1;
        }
        $newCat = ['id' => $nextId, 'title' => $title, 'slug' => sanitizeSlugPhp($title, 'post-cat', $nextId)];
        $dbRef['postCategories'][] = $newCat;
        return $newCat;
    });
    echo json_encode($res);
    exit;
}

if (preg_match('#^/api/post-categor(?:y|ies)/(\d+)$#', $path, $m) && ($method === 'PUT' || $method === 'PATCH')) {
    enforceAdminAuthOrExit($db);
    $cId = (int)$m[1];
    $res = withDatabaseTransaction(function(&$dbRef) use ($cId, $body) {
        if (!empty($dbRef['postCategories'])) {
            foreach ($dbRef['postCategories'] as &$c) {
                if ((int)($c['id'] ?? 0) === $cId) {
                    if (isset($body['title'])) $c['title'] = trim((string)$body['title']);
                    if (isset($body['slug'])) $c['slug'] = sanitizeSlugPhp($body['slug'], 'post-cat', $cId);
                    return $c;
                }
            }
        }
        return null;
    });
    if ($res) {
        echo json_encode($res);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'code' => 'NOT_FOUND', 'error' => 'دسته‌بندی مقاله یافت نشد']);
    }
    exit;
}

if (preg_match('#^/api/post-categories/(\d+)$#', $path, $m) && $method === 'DELETE') {
    enforceAdminAuthOrExit($db);
    $cId = (int)$m[1];
    withDatabaseTransaction(function(&$dbRef) use ($cId) {
        if (!empty($dbRef['postCategories'])) {
            $dbRef['postCategories'] = array_values(array_filter($dbRef['postCategories'], fn($c) => (int)($c['id'] ?? 0) !== $cId));
        }
    });
    echo json_encode(['ok' => true, 'message' => 'دسته‌بندی حذف شد']);
    exit;
}

// ------------------------------------------------------------------------------
// 6. Site Content Management
// ------------------------------------------------------------------------------
if ($path === '/api/site-content' && $method === 'GET') {
    echo json_encode($db['siteContent'] ?? []);
    exit;
}

if ($path === '/api/site-content' && ($method === 'PUT' || $method === 'POST')) {
    enforceAdminAuthOrExit($db);
    $res = withDatabaseTransaction(function(&$dbRef) use ($body) {
        if (!isset($dbRef['siteContent'])) $dbRef['siteContent'] = [];
        $dbRef['siteContent'] = array_merge($dbRef['siteContent'], $body);
        return $dbRef['siteContent'];
    });
    echo json_encode(['ok' => true, 'siteContent' => $res]);
    exit;
}

if ($path === '/api/site-content/reset' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $res = withDatabaseTransaction(function(&$dbRef) {
        $existingPay = $dbRef['siteContent']['paymentConfig'] ?? [];
        $dbRef['siteContent'] = [
            'brandName' => 'اونیوال',
            'brandEnglishName' => 'ONIVAL',
            'brandDescription' => 'عرضه مستقیم عسل طبیعی، ژل رویال، گرده گل و فرآورده‌های ارگانیک کوهستان',
            'tagline' => 'فروشگاه تخصصی محصولات ارگانیک و کندوی اونیوال',
            'phone' => '۰۲۱-۱۲۳۴۵۶۷۸',
            'email' => 'info@onival.ir',
            'address' => 'تهران، خیابان ولیعصر، مجموعه فرآورده‌های طبیعی اونیوال',
            'paymentConfig' => array_merge([
                'defaultMethod' => 'card_to_card',
                'cardToCardEnabled' => true,
                'baleBotEnabled' => true,
                'gatewayEnabled' => false,
                'cardNumber' => '۶۰۳۷-۹۹۷۵-۹۹۱۲-۳۴۵۶',
                'cardHolderName' => 'مجموعه تخصصی فرآورده‌های ارگانیک اونیوال',
                'bankName' => 'بانک ملی ایران'
            ], $existingPay),
            'updatedAt' => date('c')
        ];
        return $dbRef['siteContent'];
    });

    onival_log('site_content', 'reset', 'Site content reset to default by admin');
    echo json_encode(['ok' => true, 'message' => 'محتوای پیش‌فرض سایت بازگردانی شد.', 'siteContent' => $res]);
    exit;
}

// ------------------------------------------------------------------------------
// 7. Orders Placement & Management
// ------------------------------------------------------------------------------

// GET /api/orders
if ($path === '/api/orders' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    echo json_encode($db['orders'] ?? []);
    exit;
}

// GET /api/orders/track/{code}
if (preg_match('#^/api/orders/track/([^/]+)$#', $path, $m) && $method === 'GET') {
    enforceRateLimitOrExitPhp('order_track', 30, 300);
    $trackCode = trim(urldecode($m[1]));
    $matched = findOrderByCodePhp($db['orders'] ?? [], $trackCode);
    $isAdmin = isRequestAdminAuthorized($db);
    if ($matched) {
        echo json_encode([
            'found' => true,
            'type' => 'order',
            'data' => buildPublicSafeOrderPhp($matched, $isAdmin)
        ]);
        exit;
    }

    if (!empty($db['contactMessages'])) {
        foreach ($db['contactMessages'] as $msg) {
            if (strcasecmp(trim((string)($msg['trackingCode'] ?? '')), $trackCode) === 0) {
                $rawName = trim((string)($msg['fullName'] ?? ''));
                $safeName = $isAdmin ? $rawName : (mb_strlen($rawName, 'UTF-8') > 2 ? mb_substr($rawName, 0, 2, 'UTF-8') . '***' : '***');
                $safeMsg = [
                    'id' => $msg['id'] ?? 0,
                    'trackingCode' => $msg['trackingCode'] ?? '',
                    'fullName' => $safeName,
                    'message' => $msg['message'] ?? '',
                    'adminResponse' => $msg['adminResponse'] ?? null,
                    'creationTime' => $msg['creationTime'] ?? '',
                    'respondedAt' => $msg['respondedAt'] ?? null,
                    'isRead' => !empty($msg['isRead'])
                ];
                echo json_encode([
                    'found' => true,
                    'type' => 'message',
                    'data' => $safeMsg
                ]);
                exit;
            }
        }
    }

    http_response_code(404);
    echo json_encode([
        'found' => false,
        'ok' => false,
        'code' => 'NOT_FOUND',
        'error' => 'سفارشی یا پیامی با این کد رهگیری یافت نشد'
    ]);
    exit;
}

// POST /api/orders (Public Order Placement with Strict Server-Side Pricing & Stock Validation)
if ($path === '/api/orders' && $method === 'POST') {
    enforceRateLimitOrExitPhp('create_order', 15, 600, 'تعداد سفارش‌های ثبت شده شما در این بازه زمانی بیش از حد مجاز است. لطفاً ۱۰ دقیقه دیگر مجدداً تلاش فرمایید.');

    $userFullName = trim((string)($body['userFullName'] ?? $body['customerName'] ?? ''));
    $phoneNumber = trim((string)($body['phoneNumber'] ?? ''));
    $userAddress = trim((string)($body['userAddress'] ?? ''));
    $rawItems = $body['items'] ?? [];

    if (empty($userFullName) || empty($phoneNumber) || empty($userAddress)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'نام خریدار، شماره تماس و آدرس گیرنده الزامی است.']);
        exit;
    }

    if (!is_array($rawItems) || count($rawItems) === 0) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'سبد خرید خالی است.']);
        exit;
    }

    // Strict validation of items & quantities before transaction
    $aggregated = [];
    foreach ($rawItems as $it) {
        $pId = (int)($it['productId'] ?? $it['id'] ?? 0);
        if ($pId <= 0) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'شناسه کالای نامعتبر در سبد خرید.']);
            exit;
        }

        if (!isset($it['quantity']) && !isset($it['qty'])) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'تعداد کالای انتخابی مشخص نشده است.']);
            exit;
        }

        $qtyRaw = $it['quantity'] ?? $it['qty'];
        if (!is_numeric($qtyRaw) || (int)$qtyRaw <= 0 || (int)$qtyRaw > 100 || (int)$qtyRaw != $qtyRaw) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'تعداد کالا نامعتبر است (باید عدد صحیح بین ۱ تا ۱۰۰ باشد).']);
            exit;
        }
        $qty = (int)$qtyRaw;
        $sName = trim((string)($it['size'] ?? ''));
        $key = "{$pId}___{$sName}";
        if (!isset($aggregated[$key])) {
            $aggregated[$key] = [
                'productId' => $pId,
                'size' => $sName,
                'quantity' => 0
            ];
        }
        $aggregated[$key]['quantity'] += $qty;
    }

    // Execute atomic lookup, pricing, validation and creation using fresh dbRef
    $txRes = withDatabaseTransaction(function(&$dbRef) use ($userFullName, $phoneNumber, $userAddress, $aggregated, $body) {
        $allProducts = $dbRef['products'] ?? [];
        $verifiedItems = [];
        $serverCalculatedTotal = 0;

        foreach ($aggregated as $agg) {
            $pId = $agg['productId'];
            $size = $agg['size'];
            $qty = $agg['quantity'];

            $prod = null;
            foreach ($allProducts as $p) {
                if ((int)($p['id'] ?? 0) === $pId && empty($p['isDelete'])) {
                    $prod = $p;
                    break;
                }
            }

            if (!$prod) {
                return ['_cancelWrite' => true, 'ok' => false, 'httpCode' => 404, 'code' => 'PRODUCT_NOT_FOUND', 'error' => "محصول با شناسه {$pId} در فروشگاه یافت نشد."];
            }

            $basePrice = 0;
            $availStock = 0;
            $specialOfferStock = 0;
            $sizeMatched = false;

            if ($size !== '' && !empty($prod['sizes']) && is_array($prod['sizes'])) {
                foreach ($prod['sizes'] as $sObj) {
                    $sName = trim((string)($sObj['name'] ?? $sObj['size'] ?? ''));
                    if ($sName === $size) {
                        $sizeMatched = true;
                        $basePrice = max(0, (int)($sObj['price'] ?? 0));
                        $availStock = isset($sObj['stock']) ? (int)$sObj['stock'] : 999;
                        $specialOfferStock = isset($sObj['specialOfferStock']) ? (int)$sObj['specialOfferStock'] : 0;
                        break;
                    }
                }
                if (!$sizeMatched) {
                    return ['_cancelWrite' => true, 'ok' => false, 'httpCode' => 400, 'code' => 'VALIDATION_ERROR', 'error' => "سایز «{$size}» برای محصول «{$prod['title']}» نامعتبر است."];
                }
            } else {
                $basePrice = max(0, (int)($prod['price'] ?? 0));
                $availStock = isset($prod['stock']) ? (int)$prod['stock'] : 999;
                $specialOfferStock = isset($prod['specialOfferStock']) ? (int)$prod['specialOfferStock'] : 0;
            }

            if ($availStock < $qty) {
                return ['_cancelWrite' => true, 'ok' => false, 'httpCode' => 409, 'code' => 'STOCK_CONFLICT', 'error' => "موجودی «{$prod['title']}» (" . ($size ? "سایز {$size}" : "کامل") . ") کافی نیست. موجودی انبار: {$availStock} عدد."];
            }

            $discount = max(0, min(99, (int)($prod['discount'] ?? $prod['discountPercent'] ?? 0)));
            $isDiscountActive = ($discount > 0 && ($prod['isAmazingOffer'] ?? false || $prod['isSpecialOffer'] ?? false || $discount > 0));

            $itemTotal = 0;
            if ($isDiscountActive && $specialOfferStock > 0) {
                $discountedPrice = (int)round($basePrice * (100 - $discount) / 100);
                if ($qty <= $specialOfferStock) {
                    $itemTotal = $discountedPrice * $qty;
                    $effectiveUnitPrice = $discountedPrice;
                } else {
                    $discountedQty = $specialOfferStock;
                    $regularQty = $qty - $specialOfferStock;
                    $itemTotal = ($discountedPrice * $discountedQty) + ($basePrice * $regularQty);
                    $effectiveUnitPrice = (int)round($itemTotal / $qty);
                }
            } elseif ($discount > 0) {
                $discountedPrice = (int)round($basePrice * (100 - $discount) / 100);
                $itemTotal = $discountedPrice * $qty;
                $effectiveUnitPrice = $discountedPrice;
            } else {
                $itemTotal = $basePrice * $qty;
                $effectiveUnitPrice = $basePrice;
            }

            $serverCalculatedTotal += $itemTotal;

            $verifiedItems[] = [
                'productId' => $pId,
                'id' => $pId,
                'productName' => $prod['title'],
                'name' => $prod['title'],
                'size' => $size ?: 'استاندارد',
                'quantity' => $qty,
                'unitPrice' => $effectiveUnitPrice,
                'basePrice' => $basePrice,
                'totalPrice' => $itemTotal
            ];
        }

        $generatedCode = generateUniqueTrackingCodePhp($dbRef['orders'] ?? [], 'ONV-ORD');
        $botUsername = ltrim(trim((string)($dbRef['telegramConfig']['customerBotUsername'] ?? $dbRef['telegramConfig']['baleBotUsername'] ?? 'Onivalbot')), '@');
        $balePaymentUrl = "https://ble.ir/{$botUsername}?start=pay_{$generatedCode}";

        $newOrder = [
            'id' => time() * 1000 + rand(10, 99),
            'orderNumber' => (string)rand(10000, 99999),
            'trackingCode' => $generatedCode,
            'userFullName' => mb_substr($userFullName, 0, 100, 'UTF-8'),
            'customerName' => mb_substr($userFullName, 0, 100, 'UTF-8'),
            'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
            'userAddress' => mb_substr($userAddress, 0, 500, 'UTF-8'),
            'postalCode' => trim((string)($body['postalCode'] ?? '')),
            'items' => $verifiedItems,
            'totalPrice' => $serverCalculatedTotal,
            'finalTotal' => $serverCalculatedTotal,
            'status' => 'Pending',
            'paymentStatus' => 'Unpaid',
            'paymentMethod' => $body['paymentMethod'] ?? 'card_to_card',
            'balePaymentUrl' => $balePaymentUrl,
            'creationTime' => date('Y/m/d'),
            'reservedAt' => date('c'),
            'inventoryDeducted' => false
        ];

        if (!isset($dbRef['orders']) || !is_array($dbRef['orders'])) {
            $dbRef['orders'] = [];
        }
        array_unshift($dbRef['orders'], $newOrder);
        return [
            'ok' => true,
            'order' => $newOrder,
            'trackingCode' => $generatedCode,
            'totalPrice' => $serverCalculatedTotal
        ];
    });

    if (empty($txRes['ok'])) {
        http_response_code($txRes['httpCode'] ?? 400);
        echo json_encode([
            'ok' => false,
            'code' => $txRes['code'] ?? 'ORDER_FAILED',
            'error' => $txRes['error'] ?? 'خطا در ثبت سفارش'
        ]);
        exit;
    }

    onival_log('order', 'order_placed', "Order placed: {$txRes['trackingCode']}", [
        'amount' => $txRes['totalPrice']
    ]);

    http_response_code(201);
    echo json_encode([
        'ok' => true,
        'order' => $txRes['order'],
        'trackingCode' => $txRes['trackingCode'],
        'totalPrice' => $txRes['totalPrice']
    ]);
    exit;
}

// POST /api/consultations/book
if ($path === '/api/consultations/book' && $method === 'POST') {
    enforceRateLimitOrExitPhp('consultation_book', 5, 300, 'تعداد درخواست‌های رزرو مشاوره شما بیش از حد مجاز است. لطفاً ۵ دقیقه دیگر مجدداً تلاش فرمایید.');
    $fullName = trim((string)($body['fullName'] ?? ''));
    $phoneNumber = trim((string)($body['phoneNumber'] ?? ''));
    $topicId = $body['topicId'] ?? null;
    $topicTitle = trim((string)($body['topicTitle'] ?? 'مشاوره تخصصی سلامت'));
    $preferredDate = trim((string)($body['preferredDate'] ?? 'فردا'));
    $preferredTimeSlot = trim((string)($body['preferredTimeSlot'] ?? '۱۰:۰۰ الی ۱۱:۰۰'));
    $socialPlatform = trim((string)($body['socialPlatform'] ?? 'پیام‌رسان بله'));
    $socialContactId = trim((string)($body['socialContactId'] ?? ''));
    $durationMinutes = (int)($body['durationMinutes'] ?? 30);
    $question = trim((string)($body['question'] ?? ''));

    if (empty($fullName) || empty($phoneNumber)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'نام و شماره تماس برای رزرو مشاوره الزامی است.']);
        exit;
    }

    // Authoritative topic price resolution strictly from server database (ignore client price)
    $consultPrice = 0;
    $configuredTopics = $db['siteContent']['consultationConfig']['topics'] ?? [];
    if (!empty($configuredTopics) && is_array($configuredTopics)) {
        foreach ($configuredTopics as $tp) {
            if ((string)($tp['id'] ?? '') === (string)$topicId || (string)($tp['title'] ?? '') === $topicTitle) {
                $consultPrice = max(0, (int)($tp['price'] ?? 0));
                $topicTitle = $tp['title'] ?? $topicTitle;
                if (!empty($tp['durationMinutes'])) $durationMinutes = (int)$tp['durationMinutes'];
                break;
            }
        }
    }
    // If not matched in specific topics, use authoritative configured base price (never untrusted client price)
    if ($consultPrice === 0) {
        $consultPrice = max(0, (int)($db['siteContent']['consultationConfig']['basePrice'] ?? 120000));
    }

    // Idempotency check: prevent rapid duplicate bookings within 60 seconds
    $recentDuplicate = null;
    $nowSec = time();
    foreach ($db['orders'] ?? [] as $existingOrd) {
        if (!empty($existingOrd['isConsultation']) && ($existingOrd['phoneNumber'] ?? '') === $phoneNumber) {
            $createdTime = strtotime($existingOrd['createdAt'] ?? '');
            if ($createdTime && ($nowSec - $createdTime) < 60) {
                if (($existingOrd['consultationDetails']['topicTitle'] ?? '') === $topicTitle) {
                    $recentDuplicate = $existingOrd;
                    break;
                }
            }
        }
    }

    if ($recentDuplicate) {
        http_response_code(200);
        echo json_encode([
            'ok' => true,
            'trackingCode' => $recentDuplicate['trackingCode'],
            'order' => $recentDuplicate,
            'message' => 'درخواست مشاوره شما قبلاً با موفقیت ثبت شده است.'
        ]);
        exit;
    }

    $trackingCode = generateUniqueTrackingCodePhp($db['orders'] ?? [], 'ONV-CNS');
    $botUsername = ltrim(trim((string)($db['telegramConfig']['customerBotUsername'] ?? $db['telegramConfig']['baleBotUsername'] ?? 'Onivalbot')), '@');
    $balePaymentUrl = "https://ble.ir/{$botUsername}?start=pay_{$trackingCode}";
    $newOrderId = time() * 1000 + rand(10, 99);

    $consultationOrder = [
        'id' => $newOrderId,
        'orderNumber' => (string)rand(10000, 99999),
        'trackingCode' => $trackingCode,
        'userFullName' => mb_substr($fullName, 0, 100, 'UTF-8'),
        'customerName' => mb_substr($fullName, 0, 100, 'UTF-8'),
        'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
        'userAddress' => "مشاوره آنلاین در {$socialPlatform} ({$socialContactId}) | تاریخ: {$preferredDate} - زمان: {$preferredTimeSlot}" . ($question ? " | توضیحات: {$question}" : ""),
        'totalPrice' => $consultPrice,
        'finalTotal' => $consultPrice,
        'status' => 'Pending',
        'paymentStatus' => 'Unpaid',
        'paymentMethod' => 'card_to_card',
        'creationTime' => date('Y/m/d H:i'),
        'createdAt' => date('c'),
        'balePaymentUrl' => $balePaymentUrl,
        'isConsultation' => true,
        'consultationDetails' => [
            'topicId' => $topicId,
            'topicTitle' => $topicTitle,
            'preferredDate' => $preferredDate,
            'preferredTimeSlot' => $preferredTimeSlot,
            'socialPlatform' => $socialPlatform,
            'socialContactId' => $socialContactId,
            'durationMinutes' => $durationMinutes,
            'question' => $question,
            'consultationStatus' => 'PendingPayment'
        ],
        'items' => [
            [
                'productId' => 9999,
                'productName' => "رزرو مشاوره: {$topicTitle}",
                'size' => "{$preferredDate} | {$preferredTimeSlot} ({$socialPlatform})",
                'quantity' => 1,
                'unitPrice' => $consultPrice,
                'totalPrice' => $consultPrice
            ]
        ]
    ];

    $contactMsg = [
        'id' => time() * 1000 + rand(10, 99),
        'fullName' => mb_substr($fullName, 0, 100, 'UTF-8'),
        'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
        'trackingCode' => $trackingCode,
        'message' => "[رزرو مشاوره: {$topicTitle}] - زمان: {$preferredDate} ({$preferredTimeSlot}) - پیام‌رسان: {$socialPlatform} ({$socialContactId})" . ($question ? " - شرح: {$question}" : ""),
        'creationTime' => date('Y/m/d H:i'),
        'isRead' => false,
        'isResponded' => false,
        'isConsultation' => true,
        'orderId' => $newOrderId,
        'consultationDetails' => $consultationOrder['consultationDetails']
    ];

    // Atomically create both order and contact message in one transaction
    withDatabaseTransaction(function(&$dbRef) use ($consultationOrder, $contactMsg) {
        if (!isset($dbRef['orders'])) $dbRef['orders'] = [];
        array_unshift($dbRef['orders'], $consultationOrder);

        if (!isset($dbRef['contactMessages'])) $dbRef['contactMessages'] = [];
        array_unshift($dbRef['contactMessages'], $contactMsg);
    });

    onival_log('consultation', 'booking_created', "Consultation booked: {$trackingCode} (Amount: {$consultPrice})");

    http_response_code(201);
    echo json_encode([
        'ok' => true,
        'trackingCode' => $trackingCode,
        'order' => $consultationOrder,
        'contact' => $contactMsg,
        'message' => 'درخواست مشاوره با موفقیت ثبت شد.'
    ]);
    exit;
}

// PUT /api/orders/{id}
if (preg_match('#^/api/orders/(\d+)$#', $path, $m) && $method === 'PUT') {
    enforceAdminAuthOrExit($db);
    $orderId = (int)$m[1];
    $updated = withDatabaseTransaction(function(&$dbRef) use ($orderId, $body) {
        foreach ($dbRef['orders'] as &$ord) {
            if ((int)($ord['id'] ?? 0) === $orderId) {
                $ord = array_merge($ord, $body);
                return $ord;
            }
        }
        return null;
    });
    if ($updated) {
        echo json_encode(['ok' => true, 'order' => $updated]);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'code' => 'NOT_FOUND', 'error' => 'سفارش یافت نشد']);
    }
    exit;
}

// PUT /api/orders/{id}/status
if (preg_match('#^/api/orders/(\d+)/status$#', $path, $m) && $method === 'PUT') {
    enforceAdminAuthOrExit($db);
    $orderId = (int)$m[1];
    $newStatus = $body['status'] ?? null;
    $newPayStatus = $body['paymentStatus'] ?? null;

    $updated = withDatabaseTransaction(function(&$dbRef) use ($orderId, $newStatus, $newPayStatus) {
        if ($newPayStatus === 'Paid') {
            $appRes = processOrderPaymentApprovalPhp($dbRef, $orderId, 'admin');
            if (empty($appRes['ok'])) {
                return ['_cancelWrite' => true, 'ok' => false, 'code' => $appRes['code'] ?? 'STOCK_CONFLICT', 'error' => $appRes['error']];
            }
            if ($newStatus) {
                foreach ($dbRef['orders'] as &$o) {
                    if ((int)($o['id'] ?? 0) === $orderId) {
                        $o['status'] = $newStatus;
                        return $o;
                    }
                }
            }
            return $appRes['order'];
        }

        if ($newStatus === 'Cancelled') {
            $rejRes = processOrderRejectionPhp($dbRef, $orderId, 'تغییر وضعیت به لغو توسط مدیر', 'admin');
            if (empty($rejRes['ok'])) {
                return ['_cancelWrite' => true, 'ok' => false, 'code' => $rejRes['code'] ?? 'ERROR', 'error' => $rejRes['error']];
            }
            return $rejRes['order'];
        }

        foreach ($dbRef['orders'] as &$ord) {
            if ((int)($ord['id'] ?? 0) === $orderId) {
                if ($newStatus) $ord['status'] = $newStatus;
                if ($newPayStatus) $ord['paymentStatus'] = $newPayStatus;
                return $ord;
            }
        }
        return ['_cancelWrite' => true, 'ok' => false, 'code' => 'NOT_FOUND', 'error' => 'سفارش یافت نشد'];
    });

    if (!empty($updated['ok']) || (is_array($updated) && !isset($updated['ok']))) {
        echo json_encode(['ok' => true, 'order' => $updated]);
    } else {
        $conflictCodes = ['STOCK_CONFLICT', 'TRANSITION_NOT_ALLOWED'];
        http_response_code(in_array($updated['code'] ?? '', $conflictCodes, true) ? 409 : 404);
        echo json_encode(['ok' => false, 'code' => $updated['code'] ?? 'NOT_FOUND', 'error' => $updated['error'] ?? 'سفارش یافت نشد']);
    }
    exit;
}

// POST /api/orders/{id}/approve-payment & verify-receipt
if ((preg_match('#^/api/orders/([^/]+)/approve-payment$#', $path, $m) || preg_match('#^/api/orders/([^/]+)/verify-receipt$#', $path, $m)) && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $orderIdOrCode = $m[1];
    $approved = isset($body['approved']) ? !empty($body['approved']) : true;

    $res = withDatabaseTransaction(function(&$dbRef) use ($orderIdOrCode, $approved) {
        if ($approved) {
            $r = processOrderPaymentApprovalPhp($dbRef, $orderIdOrCode, 'admin');
        } else {
            $r = processOrderRejectionPhp($dbRef, $orderIdOrCode, 'رد توسط مدیر', 'admin');
        }
        if (empty($r['ok'])) {
            return ['_cancelWrite' => true, 'ok' => false, 'code' => $r['code'] ?? 'ERROR', 'error' => $r['error']];
        }
        return $r;
    });

    if (!empty($res['ok'])) {
        $approvedOrder = $res['order'];
        $customerToken = trim((string)($db['telegramConfig']['customerBotToken'] ?? $db['telegramConfig']['baleBotToken'] ?? ''));
        $custChat = $approvedOrder['baleChatId'] ?? $approvedOrder['chatId'] ?? null;
        if ($custChat && !empty($customerToken)) {
            $msg = $approved
                ? "🎉 خریدار گرامی، فیش واریزی سفارش {$approvedOrder['trackingCode']} توسط مدیریت تایید گردید و مرسوله شما وارد مرحله بسته‌بندی شد. 📦"
                : "⚠️ خریدار گرامی، فیش واریزی ارسال شده برای سفارش {$approvedOrder['trackingCode']} مورد تایید قرار نگرفت و رد شد. لطفاً جهت راهنمایی با پشتیبانی تماس بگیرید.";
            sendBaleMessage($customerToken, $custChat, $msg);
        }
        echo json_encode(['ok' => true, 'order' => $approvedOrder]);
    } else {
        http_response_code(($res['code'] ?? '') === 'STOCK_CONFLICT' ? 409 : 400);
        echo json_encode(['ok' => false, 'code' => $res['code'] ?? 'ERROR', 'error' => $res['error'] ?? 'خطا در تایید']);
    }
    exit;
}

// POST /api/orders/{code}/upload-receipt (Public Card-to-Card Receipt Upload)
if (preg_match('#^/api/orders/([^/]+)/(?:upload-receipt|receipt)$#', $path, $m) && $method === 'POST') {
    enforceRateLimitOrExitPhp('upload_receipt', 6, 900, 'تعداد درخواست‌های بارگذاری فیش بیش از حد مجاز است. لطفاً پس از ۱۵ دقیقه مجدداً تلاش فرمایید.');

    $orderIdOrCode = trim($m[1]);
    $isAdmin = isRequestAdminAuthorized($db);

    // 1. Security guard: disallow sequential numeric IDs for non-admin visitors
    if ((is_numeric($orderIdOrCode) || strlen($orderIdOrCode) < 6) && !$isAdmin) {
        http_response_code(403);
        echo json_encode([
            'ok' => false,
            'code' => 'FORBIDDEN',
            'error' => 'بارگذاری فیش نیازمند کد رهگیری معتبر سفارش (مانند ONV-ORD-XXX) می‌باشد.'
        ]);
        exit;
    }

    // 2. Pre-verify order existence and status BEFORE touching any file system storage
    $preOrder = findOrderByCodePhp($db['orders'] ?? [], $orderIdOrCode, $isAdmin);
    if (!$preOrder && $isAdmin) {
        foreach ($db['orders'] ?? [] as $ord) {
            if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                $preOrder = $ord;
                break;
            }
        }
    }
    if (!$preOrder) {
        http_response_code(404);
        echo json_encode([
            'ok' => false,
            'code' => 'ORDER_NOT_FOUND',
            'error' => 'فاکتور با کد رهگیری ارائه شده یافت نشد.'
        ]);
        exit;
    }

    if (($preOrder['paymentStatus'] ?? '') === 'Paid' || ($preOrder['status'] ?? '') === 'Completed') {
        http_response_code(400);
        echo json_encode([
            'ok' => false,
            'code' => 'ORDER_ALREADY_PAID',
            'error' => 'این سفارش قبلاً تسویه شده و امکان تغییر فیش آن وجود ندارد.'
        ]);
        exit;
    }

    if (($preOrder['status'] ?? '') === 'Cancelled') {
        http_response_code(400);
        echo json_encode([
            'ok' => false,
            'code' => 'ORDER_CANCELLED',
            'error' => 'این سفارش لغو گردیده است و امکان ارسال فیش برای آن وجود ندارد.'
        ]);
        exit;
    }

    $receiptImage = $body['receiptImage'] ?? $body['receiptImageUrl'] ?? '';
    if (empty($receiptImage) || !is_string($receiptImage)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_PAYLOAD', 'error' => 'لطفاً تصویر فیش واریزی را انتخاب نمایید.']);
        exit;
    }

    if (!preg_match('#^data:image\/(png|jpe?g|webp);base64,(.+)$#i', $receiptImage, $imgMatch)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_MIME', 'error' => 'تنها فرمت‌های تصویری PNG، JPG و WEBP مجاز هستند.']);
        exit;
    }

    // 3. Strict Base64 decoding & byte validation
    $binData = base64_decode($imgMatch[2], true);
    if ($binData === false) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_BASE64', 'error' => 'کدگذاری تصویر نامعتبر است.']);
        exit;
    }

    $imgCheck = validateReceiptImageBytesPhp($binData);
    if (!$imgCheck['ok']) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_IMAGE', 'error' => $imgCheck['error']]);
        exit;
    }

    // 4. Generate unique random filename in private server storage
    $receiptFileName = 'receipt_' . bin2hex(random_bytes(10)) . '.' . $imgCheck['ext'];
    $receiptFilePath = $receiptsDir . '/' . $receiptFileName;

    if (@file_put_contents($receiptFilePath, $binData, LOCK_EX) === false) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'خطا در ذخیره‌سازی فایل رسید روی سرور']);
        exit;
    }

    $savedUrl = '/api/admin/receipts/' . $receiptFileName;

    // 5. Final transactional state commit with re-verification and cleanup on failure
    $txRes = withDatabaseTransaction(function(&$dbRef) use ($orderIdOrCode, $savedUrl, $isAdmin, $receiptFilePath, $body) {
        $matched = findOrderByCodePhp($dbRef['orders'] ?? [], $orderIdOrCode, $isAdmin);
        if (!$matched && $isAdmin) {
            foreach ($dbRef['orders'] ?? [] as $ord) {
                if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                    $matched = $ord;
                    break;
                }
            }
        }
        if (!$matched) {
            @unlink($receiptFilePath);
            return ['_cancelWrite' => true, 'ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'سفارش مورد نظر یافت نشد.'];
        }

        if (($matched['paymentStatus'] ?? '') === 'Paid' || ($matched['status'] ?? '') === 'Completed') {
            @unlink($receiptFilePath);
            return ['_cancelWrite' => true, 'ok' => false, 'code' => 'ORDER_ALREADY_PAID', 'error' => 'این سفارش قبلاً تسویه شده است.'];
        }
        if (($matched['status'] ?? '') === 'Cancelled') {
            @unlink($receiptFilePath);
            return ['_cancelWrite' => true, 'ok' => false, 'code' => 'ORDER_CANCELLED', 'error' => 'این سفارش لغو گردیده است.'];
        }

        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $matched['trackingCode']) {
                $ord['receiptImage'] = $savedUrl;
                $ord['receiptImageUrl'] = $savedUrl;
                $ord['paymentMethod'] = 'card_to_card';
                $ord['paymentStatus'] = 'PendingVerification';
                $ord['receiptUploadedAt'] = date('c');
                $ord['receiptSubmittedAt'] = date('Y/m/d - H:i');
                if (!empty($body['receiptNote'])) {
                    $ord['receiptNote'] = mb_substr((string)$body['receiptNote'], 0, 500, 'UTF-8');
                }
                return ['ok' => true, 'order' => $ord];
            }
        }
        @unlink($receiptFilePath);
        return ['_cancelWrite' => true, 'ok' => false, 'code' => 'ORDER_NOT_FOUND', 'error' => 'خطا در بروزرسانی فیش'];
    });

    if (empty($txRes['ok'])) {
        @unlink($receiptFilePath);
        http_response_code($txRes['code'] === 'ORDER_NOT_FOUND' ? 404 : 400);
        echo json_encode($txRes);
        exit;
    }

    $updatedOrder = $txRes['order'];

    // Dispatch admin notification via Bale bot
    $adminNotified = false;
    $tg = $db['telegramConfig'] ?? [];
    $adminToken = trim((string)($tg['adminBotToken'] ?? $tg['baleAdminBotToken'] ?? ''));
    $adminChat = trim((string)($tg['adminChatId'] ?? $tg['baleAdminChatId'] ?? ''));
    if (!empty($adminToken) && !empty($adminChat)) {
        $track = $updatedOrder['trackingCode'];
        $amountToman = getOrderAmountTomanPhp($updatedOrder);
        $caption = "🔔 فیش واریز کارت‌به‌کارت جدید از وب‌سایت دریافت شد!\n\n" .
            "📦 شماره سفارش: {$track}\n" .
            "💰 مبلغ: " . number_format($amountToman) . " تومان\n" .
            "⏰ زمان: " . date('Y/m/d - H:i') . "\n\n" .
            "⚡ جهت تایید یا رد فیش کلیک فرمایید:\n" .
            "تایید: /confirm_{$track}\n" .
            "رد: /reject_{$track}";
        $btns = [
            'inline_keyboard' => [
                [
                    ['text' => '✅ تایید فیش واریزی', 'callback_data' => "confirm_{$track}"],
                    ['text' => '❌ رد فیش', 'callback_data' => "reject_{$track}"]
                ]
            ]
        ];

        $photoSend = sendBalePhoto($adminToken, $adminChat, $receiptFilePath, $caption, $btns);
        $adminNotified = !empty($photoSend['ok']);
        if (!$adminNotified) {
            $msgSend = sendBaleMessage($adminToken, $adminChat, $caption, $btns);
            $adminNotified = !empty($msgSend['ok']);
        }
    }

    echo json_encode([
        'ok' => true,
        'message' => 'تصویر فیش واریزی با موفقیت بارگذاری شد و در انتظار تایید مدیریت است.',
        'trackingCode' => $updatedOrder['trackingCode'] ?? $orderIdOrCode,
        'paymentStatus' => 'PendingVerification',
        'receiptUrl' => $savedUrl,
        'adminNotified' => $adminNotified,
        'order' => buildPublicSafeOrderPhp($updatedOrder, $isAdmin)
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 8. Contact Messages
// ------------------------------------------------------------------------------
if ($path === '/api/contact' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    echo json_encode($db['contactMessages'] ?? []);
    exit;
}

if ($path === '/api/contact' && $method === 'POST') {
    enforceRateLimitOrExitPhp('contact_submit', 5, 300, 'تعداد پیام‌های ارسالی شما بیش از حد مجاز است. لطفاً ۵ دقیقه دیگر مجدداً تلاش فرمایید.');
    $fullName = trim((string)($body['fullName'] ?? ''));
    $phoneNumber = trim((string)($body['phoneNumber'] ?? ''));
    $messageText = trim((string)($body['message'] ?? ''));

    if (empty($fullName) || empty($messageText)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'نام و متن پیام الزامی است']);
        exit;
    }

    $newMsg = [
        'id' => time() * 1000 + rand(10, 99),
        'fullName' => mb_substr($fullName, 0, 100, 'UTF-8'),
        'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
        'message' => mb_substr($messageText, 0, 2000, 'UTF-8'),
        'trackingCode' => generateContactTrackingCodePhp(),
        'creationTime' => date('Y/m/d H:i'),
        'isRead' => false
    ];

    withDatabaseTransaction(function(&$dbRef) use ($newMsg) {
        if (!isset($dbRef['contactMessages'])) $dbRef['contactMessages'] = [];
        array_unshift($dbRef['contactMessages'], $newMsg);
    });

    echo json_encode(['ok' => true, 'message' => 'پیام شما با موفقیت ثبت شد', 'contact' => $newMsg]);
    exit;
}

if (preg_match('#^/api/contact/(\d+)/respond$#', $path, $m) && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $msgId = (int)$m[1];
    $reply = trim((string)($body['response'] ?? $body['reply'] ?? ''));

    withDatabaseTransaction(function(&$dbRef) use ($msgId, $reply) {
        if (!empty($dbRef['contactMessages'])) {
            foreach ($dbRef['contactMessages'] as &$msg) {
                if ((int)($msg['id'] ?? 0) === $msgId) {
                    $msg['isRead'] = true;
                    $msg['isResponded'] = true;
                    $msg['adminResponse'] = $reply;
                    $msg['respondedAt'] = date('Y/m/d - H:i');
                    break;
                }
            }
        }
    });

    echo json_encode(['ok' => true, 'message' => 'پاسخ ذخیره شد']);
    exit;
}

if (preg_match('#^/api/contact/(\d+)$#', $path, $m) && $method === 'DELETE') {
    enforceAdminAuthOrExit($db);
    $msgId = (int)$m[1];
    withDatabaseTransaction(function(&$dbRef) use ($msgId) {
        if (!empty($dbRef['contactMessages'])) {
            $dbRef['contactMessages'] = array_values(array_filter($dbRef['contactMessages'], fn($m) => (int)($m['id'] ?? 0) !== $msgId));
        }
    });
    echo json_encode(['ok' => true]);
    exit;
}

// ------------------------------------------------------------------------------
// 9. Admin Authentication & Session Management
// ------------------------------------------------------------------------------
if ($path === '/api/admin/login' && $method === 'POST') {
    $retryAfter = isRateLimitedPhp('admin_login_fail', 10);
    if ($retryAfter !== false) {
        onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=rate_limited', ['reason' => 'rate_limited']);
        header('Retry-After: ' . $retryAfter);
        http_response_code(429);
        echo json_encode([
            'ok' => false,
            'code' => 'RATE_LIMIT_EXCEEDED',
            'error' => "تعداد تلاش‌های ناموفق ورود بیش از حد مجاز است. لطفاً {$retryAfter} ثانیه دیگر امتحان نمایید.",
            'retryAfterSeconds' => $retryAfter
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (!is_dir(ONIVAL_PRIVATE_DIR) || !is_writable(ONIVAL_PRIVATE_DIR)) {
        onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=storage_unavailable', ['reason' => 'storage_unavailable']);
        http_response_code(503);
        echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'فضای ذخیره‌سازی سرور در دسترس نیست.']);
        exit;
    }

    $u = trim((string)($body['username'] ?? $body['email'] ?? ''));
    $p = trim((string)($body['password'] ?? ''));

    if (empty($u) || empty($p)) {
        onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=bad_credentials', ['reason' => 'bad_credentials']);
        recordRateLimitHitPhp('admin_login_fail', 900);
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'نام کاربری و رمز عبور الزامی است.']);
        exit;
    }

    if (empty($db) || !isset($db['adminCredentials'])) {
        onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=data_file_unreadable', ['reason' => 'data_file_unreadable']);
        recordRateLimitHitPhp('admin_login_fail', 900);
        http_response_code(401);
        echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
        exit;
    }

    $creds = $db['adminCredentials'] ?? [];
    $isInitialPending = empty($creds['initialSetupCompleted']);
    $validPass = trim((string)($creds['password'] ?? ''));
    $storedOtp = isset($creds['oneTimePassword']) ? trim((string)$creds['oneTimePassword']) : '';
    $otpExpired = !empty($creds['oneTimePasswordExpired']);

    if ($isInitialPending) {
        // Pending-state login: accept strictly and exclusively the configured initial username (constant-time exact comparison)
        $configuredUser = trim((string)($creds['username'] ?? 'onival_setup'));
        if (!hash_equals($configuredUser, $u)) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=bad_credentials', ['reason' => 'bad_credentials', 'isInitialPending' => true]);
            recordRateLimitHitPhp('admin_login_fail', 900);
            http_response_code(401);
            echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
            exit;
        }

        if (empty($storedOtp) || $otpExpired) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=otp_invalid', ['reason' => 'otp_invalid']);
            recordRateLimitHitPhp('admin_login_fail', 900);
            http_response_code(401);
            echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
            exit;
        }
    } else {
        // Post-setup login: check username or email
        $validUser = strtolower(trim($creds['username'] ?? ''));
        $validEmail = strtolower(trim($creds['email'] ?? ''));
        $isUserMatch = (strtolower($u) === $validUser || (!empty($validEmail) && strtolower($u) === $validEmail));
        if (!$isUserMatch) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=bad_credentials', ['reason' => 'bad_credentials']);
            recordRateLimitHitPhp('admin_login_fail', 900);
            http_response_code(401);
            echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
            exit;
        }

        if (!empty($storedOtp) && matchesOneTimeCredential($p, $storedOtp)) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=otp_invalid', ['reason' => 'otp_invalid', 'context' => 'otp_attempted_after_setup']);
            recordRateLimitHitPhp('admin_login_fail', 900);
            http_response_code(401);
            echo json_encode(['ok' => false, 'code' => 'OTP_EXPIRED', 'error' => 'رمز عبور یکبار مصرف اولیه منقضی شده است. لطفاً با نام کاربری و رمز عبور دائمی جدید وارد شوید.']);
            exit;
        }

        if (empty($validPass) || !isUsablePasswordHash($validPass)) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=no_usable_credential', ['reason' => 'no_usable_credential']);
            recordRateLimitHitPhp('admin_login_fail', 900);
            http_response_code(401);
            echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
            exit;
        }
    }

    $validOtp = $isInitialPending ? $storedOtp : null;
    $isPassMatch = verifyAdminPassword($p, $validPass, $isInitialPending, $validOtp);

    if ($isPassMatch) {
        $sessionCred = $isInitialPending ? ($storedOtp ?: ($creds['oneTimePassword'] ?? '')) : ($creds['password'] ?? '');
        $token = generateAdminSessionToken($creds['username'] ?? 'admin', $sessionCred);
        if (empty($token)) {
            onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=session_secret_error', ['reason' => 'session_secret_error']);
            http_response_code(503);
            echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'خطا در ایجاد نشست مدیریت بر روی سرور.']);
            exit;
        }
        echo json_encode([
            'ok' => true,
            'success' => true,
            'token' => $token,
            'profile' => [
                'username' => $creds['username'] ?? 'admin',
                'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
                'email' => $creds['email'] ?? '',
                'initialSetupCompleted' => !empty($creds['initialSetupCompleted'])
            ],
            'isInitialPending' => $isInitialPending,
            'message' => $isInitialPending
                ? 'ورود اولیه با موفقیت انجام شد. لطفاً در پنل، نام کاربری و رمز عبور دائمی جدید خود را ثبت فرمایید.'
                : 'ورود به پنل مدیریت با موفقیت انجام شد.'
        ]);
        exit;
    }

    $failReason = $isInitialPending ? 'otp_invalid' : 'bad_credentials';
    onival_log('auth', 'LOGIN_FAIL', 'LOGIN_FAIL reason=' . $failReason, [
        'reason' => $failReason,
        'isInitialPending' => $isInitialPending
    ]);
    recordRateLimitHitPhp('admin_login_fail', 900);
    http_response_code(401);
    echo json_encode(['ok' => false, 'code' => 'AUTH_FAILED', 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
    exit;
}

if ($path === '/api/admin/logout' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $token = getBearerToken();
    if (!empty($token)) {
        revokeAdminTokenPhp($token);
    }
    // Expire cookie if set
    setcookie('admin_token', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    echo json_encode(['ok' => true, 'message' => 'خروج از حساب مدیریت با موفقیت انجام شد.']);
    exit;
}

if ($path === '/api/admin/verify-session' && $method === 'GET') {
    if (isRequestAdminAuthorized($db)) {
        $creds = $db['adminCredentials'] ?? [];
        echo json_encode([
            'ok' => true,
            'profile' => [
                'username' => $creds['username'] ?? 'admin',
                'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
                'email' => $creds['email'] ?? '',
                'initialSetupCompleted' => !empty($creds['initialSetupCompleted'])
            ]
        ]);
        exit;
    }
    http_response_code(401);
    echo json_encode(['ok' => false, 'code' => 'AUTH_REQUIRED', 'error' => 'نشست کاربری نامعتبر یا منقضی شده است.']);
    exit;
}

if ($path === '/api/account/profile' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $creds = $db['adminCredentials'] ?? [];
    echo json_encode([
        'username' => $creds['username'] ?? 'admin',
        'email' => $creds['email'] ?? 'admin@onival.com',
        'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
        'initialSetupCompleted' => !empty($creds['initialSetupCompleted']),
        'siteLogo' => $db['siteContent']['siteLogo'] ?? ''
    ]);
    exit;
}

if (($path === '/api/account/change-credentials' || $path === '/api/admin/setup-credentials') && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    $creds = $db['adminCredentials'] ?? [];
    $isInitialPending = empty($creds['initialSetupCompleted']);
    $validPass = trim((string)($creds['password'] ?? ''));

    $newUsername = trim((string)($body['newUsername'] ?? $body['username'] ?? ''));
    $newPassword = (string)($body['newPassword'] ?? $body['password'] ?? '');
    $curPass = trim((string)($body['currentPassword'] ?? ''));
    $email = trim((string)($body['email'] ?? ''));
    $name = trim((string)($body['name'] ?? ''));

    $hasLogoFields = isset($body['siteLogo']) || isset($body['siteLogoFit']) || isset($body['siteLogoShape']) || isset($body['siteLogoScale']);
    $hasProfileFields = isset($body['email']) || isset($body['name']);

    if ($isInitialPending) {
        // Pending state: require BOTH newUsername and newPassword. Any empty/logo-only/username-only/password-only request -> 400 MISSING_REQUIRED_FIELDS with no state change
        if ($newUsername === '' || $newPassword === '') {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => 'MISSING_REQUIRED_FIELDS',
                'error' => 'تعیین نام کاربری جدید و رمز عبور دائمی هر دو الزامی است.'
            ]);
            exit;
        }

        $validUserRes = isValidAdminUsername($newUsername, true, $creds['username'] ?? 'onival_setup');
        if (!$validUserRes['ok']) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => $validUserRes['code'],
                'error' => $validUserRes['error']
            ]);
            exit;
        }

        if (strlen($newPassword) < 12) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => 'PASSWORD_TOO_SHORT',
                'error' => 'رمز عبور جدید باید حداقل ۱۲ کاراکتر باشد.'
            ]);
            exit;
        }

        if (matchesOneTimeCredential($newPassword, (string)($creds['oneTimePassword'] ?? ''))) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => 'PASSWORD_SAME_AS_TEMP',
                'error' => 'رمز عبور جدید نمی‌تواند مشابه رمز عبور موقت اولیه باشد.'
            ]);
            exit;
        }

        if (strtolower($newPassword) === strtolower($newUsername)) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => 'PASSWORD_SAME_AS_USERNAME',
                'error' => 'رمز عبور جدید نمی‌تواند مشابه نام کاربری باشد.'
            ]);
            exit;
        }

        if (!empty($creds['password']) && (password_verify($newPassword, $creds['password']) || hash_equals($creds['password'], $newPassword))) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'code' => 'PASSWORD_SAME_AS_CURRENT',
                'error' => 'رمز عبور جدید نمی‌تواند مشابه رمز عبور فعلی باشد.'
            ]);
            exit;
        }

        $backupCreds = $creds;
        $newHash = hashAdminPassword($newPassword);

        $res = withDatabaseTransaction(function(&$dbRef) use ($newUsername, $newHash, $email, $name) {
            if (!isset($dbRef['adminCredentials'])) {
                $dbRef['adminCredentials'] = [];
            }
            $c = &$dbRef['adminCredentials'];
            $c['username'] = $newUsername;
            $c['password'] = $newHash;
            if (!empty($email)) $c['email'] = $email;
            if (!empty($name)) $c['name'] = $name;
            $c['initialSetupCompleted'] = true;
            $c['oneTimePassword'] = null;
            $c['oneTimePasswordExpired'] = true;
            return $c;
        });

        if (!$res || empty($res['username'])) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'خطا در ثبت اطلاعات در دیسک هاست.']);
            exit;
        }

        // Re-read persisted data and verify with password_verify and stored username
        $freshDb = loadDatabaseReadonly();
        $freshCreds = $freshDb['adminCredentials'] ?? [];
        $readUser = $freshCreds['username'] ?? '';
        $readHash = $freshCreds['password'] ?? '';

        if ($readUser !== $newUsername || !password_verify($newPassword, $readHash) || empty($freshCreds['initialSetupCompleted']) || !empty($freshCreds['oneTimePassword'])) {
            withDatabaseTransaction(function(&$rollbackDb) use ($backupCreds) {
                $rollbackDb['adminCredentials'] = $backupCreds;
            });
            http_response_code(503);
            echo json_encode([
                'ok' => false,
                'code' => 'STORAGE_UNAVAILABLE',
                'status' => 'storage_unavailable',
                'error' => 'تایید صحت ذخیره‌سازی داده‌ها بر روی دیسک با خطا مواجه شد.'
            ]);
            exit;
        }

        // ONLY THEN revoke all sessions
        $newSecret = bin2hex(random_bytes(32));
        @file_put_contents($secretFile, $newSecret, LOCK_EX);
        onival_log('account', 'setup_completed', 'Initial setup completed successfully and all previous sessions revoked');

        echo json_encode([
            'ok' => true,
            'setupCompleted' => true,
            'initialSetupCompleted' => true,
            'message' => 'راه‌اندازی با موفقیت انجام شد. تمامی نشست‌های قبلی باطل شدند. لطفاً با نام کاربری و رمز عبور دائمی جدید وارد شوید.'
        ]);
        exit;
    }

    // Completed state
    $isChangingPassword = !empty($newPassword);
    $isChangingUsername = (!empty($newUsername) && strcasecmp($newUsername, $creds['username'] ?? 'admin') !== 0);

    // Request with no recognized change field -> 400 NO_CHANGES
    if (!$hasLogoFields && !$hasProfileFields && !$isChangingPassword && !$isChangingUsername) {
        http_response_code(400);
        echo json_encode([
            'ok' => false,
            'code' => 'NO_CHANGES',
            'error' => 'هیچ تغییری در مشخصات یا تنظیمات درخواست نشده است.'
        ]);
        exit;
    }

    // Logo-only or profile-only allowed without current password
    if (!$isChangingPassword && !$isChangingUsername) {
        if ($hasLogoFields) {
            withDatabaseTransaction(function(&$dbRef) use ($body) {
                if (!isset($dbRef['siteContent'])) $dbRef['siteContent'] = [];
                if (isset($body['siteLogo'])) $dbRef['siteContent']['siteLogo'] = $body['siteLogo'];
                if (isset($body['siteLogoFit'])) $dbRef['siteContent']['siteLogoFit'] = $body['siteLogoFit'];
                if (isset($body['siteLogoShape'])) $dbRef['siteContent']['siteLogoShape'] = $body['siteLogoShape'];
                if (isset($body['siteLogoScale'])) $dbRef['siteContent']['siteLogoScale'] = (int)$body['siteLogoScale'];
            });
        }
        if ($hasProfileFields) {
            withDatabaseTransaction(function(&$dbRef) use ($email, $name) {
                if (!isset($dbRef['adminCredentials'])) $dbRef['adminCredentials'] = [];
                if (!empty($email)) $dbRef['adminCredentials']['email'] = $email;
                if (!empty($name)) $dbRef['adminCredentials']['name'] = $name;
            });
        }
        $freshDb = loadDatabaseReadonly();
        $currCreds = $freshDb['adminCredentials'] ?? [];
        echo json_encode([
            'ok' => true,
            'profile' => [
                'username' => $currCreds['username'] ?? 'admin',
                'email' => $currCreds['email'] ?? '',
                'name' => $currCreds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
                'initialSetupCompleted' => !empty($currCreds['initialSetupCompleted'])
            ],
            'siteContent' => $freshDb['siteContent'] ?? [],
            'message' => 'تنظیمات با موفقیت ذخیره گردید.'
        ]);
        exit;
    }

    // Credential change requires current password
    if (empty($curPass) || !verifyAdminPassword($curPass, $validPass, false)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_CREDENTIALS', 'error' => 'رمز عبور فعلی مدیریت اشتباه است.']);
        exit;
    }

    if ($isChangingUsername) {
        $uCheck = isValidAdminUsername($newUsername, false, $creds['username'] ?? 'admin');
        if (!$uCheck['ok']) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => $uCheck['code'], 'error' => $uCheck['error']]);
            exit;
        }
    }

    if ($isChangingPassword) {
        if (strlen($newPassword) < 12) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'PASSWORD_TOO_SHORT', 'error' => 'رمز عبور جدید باید حداقل ۱۲ کاراکتر باشد.']);
            exit;
        }

        $normNew = strtolower($newPassword);
        $targetUser = strtolower($newUsername ?: ($creds['username'] ?? 'admin'));
        if ($normNew === $targetUser) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'PASSWORD_SAME_AS_USERNAME', 'error' => 'رمز عبور جدید نمی‌تواند مشابه نام کاربری باشد.']);
            exit;
        }

        $existingOtp = trim((string)($creds['oneTimePassword'] ?? ''));
        if (!empty($existingOtp) && matchesOneTimeCredential($newPassword, $existingOtp)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'code' => 'PASSWORD_SAME_AS_TEMP', 'error' => 'رمز عبور جدید نمی‌تواند مشابه رمز عبور یکبار مصرف اولیه باشد.']);
            exit;
        }
    }

    $res = withDatabaseTransaction(function(&$dbRef) use ($newUsername, $newPassword, $email, $name, $secretFile, $isChangingPassword, $isChangingUsername) {
        if (!isset($dbRef['adminCredentials'])) {
            $dbRef['adminCredentials'] = [];
        }
        $c = &$dbRef['adminCredentials'];
        if (!empty($newUsername)) $c['username'] = $newUsername;
        if (!empty($email)) $c['email'] = $email;
        if (!empty($name)) $c['name'] = $name;

        if ($isChangingPassword) {
            $c['password'] = hashAdminPassword($newPassword);
            $newSecret = bin2hex(random_bytes(32));
            @file_put_contents($secretFile, $newSecret, LOCK_EX);
        } elseif ($isChangingUsername) {
            $newSecret = bin2hex(random_bytes(32));
            @file_put_contents($secretFile, $newSecret, LOCK_EX);
        }

        return $c;
    });

    if (!$res || empty($res['username'])) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'خطا در ثبت اطلاعات در دیسک هاست.']);
        exit;
    }

    if ($isChangingPassword) {
        $freshDb = loadDatabaseReadonly();
        $freshCreds = $freshDb['adminCredentials'] ?? [];
        if (empty($freshCreds['password']) || !verifyAdminPassword($newPassword, $freshCreds['password'], false)) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'تایید صحت ذخیره‌سازی رمز عبور جدید بر روی دیسک با خطا مواجه شد.']);
            exit;
        }
    }

    $freshToken = generateAdminSessionToken($res['username'] ?? 'admin', $res['password'] ?? '');
    onival_log('account', 'credentials_updated', 'Admin credentials updated and previous sessions invalidated');

    echo json_encode([
        'ok' => true,
        'token' => $freshToken,
        'profile' => [
            'username' => $res['username'],
            'email' => $res['email'] ?? '',
            'name' => $res['name'] ?? '',
            'initialSetupCompleted' => !empty($res['initialSetupCompleted'])
        ],
        'message' => 'مشخصات امنیتی مدیریت با موفقیت بروزرسانی شد.'
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 10. Dashboard Stats & Protected Receipts
// ------------------------------------------------------------------------------
if ($path === '/api/stats' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $activeProds = array_filter($db['products'] ?? [], fn($p) => empty($p['isDelete']));
    echo json_encode([
        'totalProducts' => count($activeProds),
        'totalPosts' => count(array_filter($db['posts'] ?? [], fn($p) => empty($p['isDelete']))),
        'pendingOrders' => count(array_filter($db['orders'] ?? [], fn($o) => ($o['status'] ?? '') === 'Pending')),
        'unreadMessages' => count(array_filter($db['contactMessages'] ?? [], fn($m) => empty($m['isRead']))),
        'totalRevenue' => array_reduce($db['orders'] ?? [], fn($carry, $o) => $carry + (int)($o['totalPrice'] ?? 0), 0),
        'serverEngine' => 'Host-PHP-LiteSpeed-Live'
    ]);
    exit;
}

if (preg_match('#^/api/(?:admin/)?receipts/([a-zA-Z0-9._-]+)$#', $path, $m) && $method === 'GET') {
    if (!isRequestAdminAuthorized($db)) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(['ok' => false, 'code' => 'AUTH_REQUIRED', 'error' => 'دسترسی غیرمجاز. ورود به پنل مدیریت الزامی است.']);
        exit;
    }

    $rawFileName = $m[1];
    $cleanFileName = basename($rawFileName);
    if ($cleanFileName !== $rawFileName || !preg_match('/^[a-zA-Z0-9._-]+\.(jpg|jpeg|png|webp)$/i', $cleanFileName)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(['ok' => false, 'code' => 'INVALID_FILENAME', 'error' => 'نام فایل نامعتبر است']);
        exit;
    }

    $resolvedReceiptsDir = realpath($receiptsDir);
    if (!$resolvedReceiptsDir || !is_dir($resolvedReceiptsDir)) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(['ok' => false, 'code' => 'NOT_FOUND', 'error' => 'پوشه فیش‌ها یافت نشد']);
        exit;
    }

    $filePath = $resolvedReceiptsDir . DIRECTORY_SEPARATOR . $cleanFileName;
    $realFilePath = realpath($filePath);

    if (!$realFilePath || strpos($realFilePath, $resolvedReceiptsDir) !== 0 || !file_exists($realFilePath)) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(['ok' => false, 'code' => 'NOT_FOUND', 'error' => 'فایل رسید یافت نشد']);
        exit;
    }

    $mime = mime_content_type($realFilePath) ?: 'image/jpeg';
    if (!in_array($mime, ['image/jpeg', 'image/png', 'image/webp'], true)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(['ok' => false, 'code' => 'FORBIDDEN_FILE_TYPE', 'error' => 'نوع فایل مجاز نمی‌باشد']);
        exit;
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($realFilePath));
    header('Cache-Control: no-store, private, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('Content-Security-Policy: default-src \'none\'');
    readfile($realFilePath);
    exit;
}

// ------------------------------------------------------------------------------
// 11. Bot Management, Webhook & Diagnostics Endpoints
// ------------------------------------------------------------------------------
if ($path === '/api/bot/config' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $cfg = $db['telegramConfig'] ?? [];
    $safe = $cfg;

    $safe['hasCustomerToken'] = !empty($cfg['customerBotToken'] || $cfg['baleBotToken'] || $cfg['botToken']);
    $safe['hasAdminToken'] = !empty($cfg['adminBotToken'] || $cfg['baleAdminBotToken']);
    $safe['hasWalletLiveToken'] = !empty($cfg['balePaymentTokenLive'] || $cfg['balePaymentToken']);
    $safe['hasWalletTestToken'] = !empty($cfg['balePaymentTokenTest']);
    $safe['hasWebhookSecret'] = !empty($cfg['webhookSecretToken']);

    unset($safe['botToken'], $safe['baleBotToken'], $safe['customerBotToken'], $safe['adminBotToken']);
    unset($safe['balePaymentTokenLive'], $safe['balePaymentTokenTest'], $safe['balePaymentToken'], $safe['webhookSecretToken']);

    echo json_encode([
        'ok' => true,
        'config' => $safe,
        'logs' => getRecentBotActivityLogsPhp()
    ]);
    exit;
}

if ($path === '/api/bot/config' && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    $curTg = $db['telegramConfig'] ?? [];
    $newCustomerToken = trim((string)($body['customerBotToken'] ?? $body['botToken'] ?? ''));
    $newAdminToken = trim((string)($body['adminBotToken'] ?? ''));
    $verifiedCustomerUsername = '';
    $verifiedAdminUsername = '';

    // Validate newly provided customer token with getMe outside the DB lock
    if (!empty($newCustomerToken) && !preg_match('/^\*+|\[REDACTED\]/i', $newCustomerToken)) {
        $curToken = trim((string)($curTg['customerBotToken'] ?? $curTg['botToken'] ?? ''));
        if ($newCustomerToken !== $curToken) {
            $testMe = callBaleApi($newCustomerToken, 'getMe');
            if (empty($testMe['ok'])) {
                http_response_code(400);
                echo json_encode([
                    'ok' => false,
                    'code' => 'INVALID_BOT_TOKEN',
                    'error' => 'توکن ربات مشتری نامعتبر است: ' . ($testMe['description'] ?? 'عدم پاسخگویی وب‌سرویس بله')
                ]);
                exit;
            }
            $verifiedCustomerUsername = trim((string)($testMe['result']['username'] ?? ''));
        }
    }

    // Validate newly provided admin token with getMe outside the DB lock
    if (!empty($newAdminToken) && !preg_match('/^\*+|\[REDACTED\]/i', $newAdminToken)) {
        $curAdminToken = trim((string)($curTg['adminBotToken'] ?? ''));
        if ($newAdminToken !== $curAdminToken) {
            $testMeAdmin = callBaleApi($newAdminToken, 'getMe');
            if (empty($testMeAdmin['ok'])) {
                http_response_code(400);
                echo json_encode([
                    'ok' => false,
                    'code' => 'INVALID_ADMIN_BOT_TOKEN',
                    'error' => 'توکن ربات ادمین نامعتبر است: ' . ($testMeAdmin['description'] ?? 'عدم پاسخگویی وب‌سرویس بله')
                ]);
                exit;
            }
            $verifiedAdminUsername = trim((string)($testMeAdmin['result']['username'] ?? ''));
        }
    }

    $saved = withDatabaseTransaction(function(&$dbRef) use ($body, $verifiedCustomerUsername, $verifiedAdminUsername) {
        if (!isset($dbRef['telegramConfig'])) $dbRef['telegramConfig'] = [];
        $cur = &$dbRef['telegramConfig'];

        // Sensitive secret fields: update only if non-empty and not masked/redacted
        $secretKeys = ['customerBotToken', 'adminBotToken', 'botToken', 'baleBotToken', 'balePaymentTokenLive', 'balePaymentTokenTest', 'balePaymentToken', 'webhookSecretToken'];
        foreach ($secretKeys as $sk) {
            if (isset($body[$sk])) {
                $val = trim((string)$body[$sk]);
                if ($val !== '' && !preg_match('/^\*+|\[REDACTED\]/i', $val)) {
                    $cur[$sk] = $val;
                }
            }
        }

        // Non-secret fields: update directly
        $normalKeys = [
            'customerBotUsername', 'customerBotEnabled', 'adminBotUsername', 'adminChatId', 'adminBotEnabled',
            'baleAdminChatId', 'baleAdminUsername', 'baleBotUsername', 'balePaymentMode', 'baseUrl',
            'baleAutoSendInvoice', 'baleAutoNotifyAdminAllTransactions', 'baleAdminDirectApproval', 'active',
            'supportPhone', 'supportEmail', 'workingHours'
        ];
        foreach ($normalKeys as $nk) {
            if (isset($body[$nk])) {
                $cur[$nk] = $body[$nk];
            }
        }

        // Commit verified usernames derived directly from getMe on the server (overriding stale client inputs)
        if (!empty($verifiedCustomerUsername)) {
            $cur['customerBotUsername'] = $verifiedCustomerUsername;
            $cur['baleBotUsername'] = $verifiedCustomerUsername;
            $cur['botUsername'] = $verifiedCustomerUsername;
        }
        if (!empty($verifiedAdminUsername)) {
            $cur['adminBotUsername'] = $verifiedAdminUsername;
            $cur['baleAdminUsername'] = $verifiedAdminUsername;
        }

        return $cur;
    });

    onival_log('bot_config', 'config_saved', 'Bot configuration saved durably on host');
    echo json_encode(['ok' => true, 'saved' => true, 'message' => 'تنظیمات ربات‌ها با موفقیت در دیسک هاست ذخیره شد.']);
    exit;
}

// POST /api/bot/send-test-message & /api/bot/send-real-message
if (($path === '/api/bot/send-test-message' || $path === '/api/bot/send-real-message') && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $targetBot = strtolower(trim((string)($body['target'] ?? $body['platform'] ?? 'bale')));
    $isAdminTarget = ($targetBot === 'admin' || !empty($body['isAdmin']));

    $token = $isAdminTarget
        ? trim((string)($body['token'] ?? $tg['adminBotToken'] ?? $tg['baleAdminBotToken'] ?? ''))
        : trim((string)($body['token'] ?? $tg['customerBotToken'] ?? $tg['baleBotToken'] ?? $tg['botToken'] ?? ''));

    $chatId = trim((string)($body['chatId'] ?? ($isAdminTarget ? ($tg['adminChatId'] ?? $tg['baleAdminChatId'] ?? '') : ($tg['adminChatId'] ?? ''))));
    $text = trim((string)($body['text'] ?? $body['message'] ?? 'پیام آزمایشی از پنل مدیریت فروشگاه اونیوال'));

    if (empty($token) || empty($chatId)) {
        http_response_code(400);
        echo json_encode([
            'ok' => false,
            'code' => 'VALIDATION_ERROR',
            'error' => 'توکن ربات یا شناسه چت مقصد مشخص نشده است.'
        ]);
        exit;
    }

    $sendRes = sendBaleMessage($token, $chatId, $text);
    $isOk = !empty($sendRes['ok']);

    http_response_code($isOk ? 200 : 502);
    echo json_encode([
        'ok' => $isOk,
        'success' => $isOk,
        'delivered' => $isOk,
        'messageId' => $sendRes['result']['message_id'] ?? null,
        'message' => $isOk ? 'پیام با موفقیت به بله تحویل داده شد.' : ('خطا در ارسال پیام: ' . ($sendRes['description'] ?? 'عدم دریافت پاسخ')),
        'description' => $sendRes['description'] ?? null,
        'rawResponse' => $sendRes
    ]);
    exit;
}

// POST /api/bot/test-connection & test-customer-bot
if (($path === '/api/bot/test-connection' || $path === '/api/bot/test-customer-bot') && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['customerBotToken'] ?? $tg['baleBotToken'] ?? $tg['botToken'] ?? ''));

    if (empty($token)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'توکن ربات مشتری وارد نشده است.']);
        exit;
    }

    $me = callBaleApi($token, 'getMe');
    if (!empty($me['ok'])) {
        echo json_encode([
            'ok' => true,
            'connected' => true,
            'botUser' => $me['result']['username'] ?? 'Onivalbot',
            'botInfo' => $me['result'],
            'message' => 'اتصال به ربات مشتری با موفقیت تایید شد.'
        ]);
    } else {
        http_response_code(502);
        echo json_encode([
            'ok' => false,
            'code' => 'BOT_API_FAILED',
            'status' => $me['http_code'] ?? 400,
            'description' => $me['description'] ?? 'خطا در ارتباط با وب‌سرویس بله',
            'error' => $me['description'] ?? 'توکن ربات مشتری نامعتبر است'
        ]);
    }
    exit;
}

// POST /api/bot/test-admin-bot
if ($path === '/api/bot/test-admin-bot' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['adminBotToken'] ?? $tg['baleAdminBotToken'] ?? ''));

    if (empty($token)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'توکن ربات ادمین وارد نشده است.']);
        exit;
    }

    $me = callBaleApi($token, 'getMe');
    if (!empty($me['ok'])) {
        echo json_encode([
            'ok' => true,
            'connected' => true,
            'botUser' => $me['result']['username'] ?? 'onivaladminbot',
            'botInfo' => $me['result'],
            'message' => 'اتصال به ربات اختصاصی ادمین با موفقیت تایید شد.'
        ]);
    } else {
        http_response_code(502);
        echo json_encode([
            'ok' => false,
            'code' => 'BOT_API_FAILED',
            'status' => $me['http_code'] ?? 400,
            'description' => $me['description'] ?? 'خطا در ارتباط با وب‌سرویس بله'
        ]);
    }
    exit;
}

// POST /api/bot/test-admin-welcome
if ($path === '/api/bot/test-admin-welcome' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['adminBotToken'] ?? ''));
    $chatId = trim((string)($body['chatId'] ?? $tg['adminChatId'] ?? $tg['baleAdminChatId'] ?? ''));

    if (empty($token) || empty($chatId)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'توکن ربات ادمین یا شناسه چت ادمین وارد نشده است.']);
        exit;
    }

    $text = "اتصال ربات به هاست با موفقیت انجام شد. شما به عنوان ادمین شناسایی شدید\nزمان: " . date('Y/m/d - H:i:s');
    $send = sendBaleMessage($token, $chatId, $text);

    if (!empty($send['ok'])) {
        echo json_encode([
            'ok' => true,
            'delivered' => true,
            'messageId' => $send['result']['message_id'] ?? null,
            'message' => 'پیام با موفقیت به بله ادمین ارسال گردید.'
        ]);
    } else {
        $desc = $send['description'] ?? 'خطا در ارسال';
        $isForbidden = (strpos($desc, 'Forbidden') !== false || ($send['http_code'] ?? 0) === 403);
        http_response_code(502);
        echo json_encode([
            'ok' => false,
            'code' => 'BOT_API_FAILED',
            'delivered' => false,
            'status' => $send['http_code'] ?? 400,
            'description' => $desc,
            'forbiddenStartRequired' => $isForbidden,
            'message' => $isForbidden
                ? 'خطای ۴۰۳ بله: ربات نمی‌تواند شروع‌کننده مکالمه باشد. لطفاً ابتدا در بله دکمه Start را به ربات ارسال فرمایید.'
                : "پاسخ بله: {$desc}"
        ]);
    }
    exit;
}

// POST /api/bot/webhook-action (Real Webhook Registration & Querying with Role Isolation)
if ($path === '/api/bot/webhook-action' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $action = strtolower(trim((string)($body['action'] ?? 'info')));
    $targetBot = strtolower(trim((string)($body['bot'] ?? 'all')));
    $tg = $db['telegramConfig'] ?? [];

    $secrets = getOrCreateWebhookSecrets($tg);
    if (!empty($secrets['updated'])) {
        withDatabaseTransaction(function(&$dbRef) use ($secrets) {
            if (!isset($dbRef['telegramConfig'])) $dbRef['telegramConfig'] = [];
            $dbRef['telegramConfig']['customerWebhookSecretToken'] = $secrets['customer'];
            $dbRef['telegramConfig']['adminWebhookSecretToken'] = $secrets['admin'];
            $dbRef['telegramConfig']['webhookSecretToken'] = $secrets['customer'];
        });
    }

    $cToken = trim((string)($tg['customerBotToken'] ?? $tg['baleBotToken'] ?? $tg['botToken'] ?? ''));
    $aToken = trim((string)($tg['adminBotToken'] ?? $tg['baleAdminBotToken'] ?? ''));
    $cSec = $tg['customerWebhookSecretToken'] ?? $secrets['customer'];
    $aSec = $tg['adminWebhookSecretToken'] ?? $secrets['admin'];

    $botsToProcess = [];
    if ($targetBot === 'customer') {
        $botsToProcess['customer'] = ['token' => $cToken, 'secret' => $cSec];
    } elseif ($targetBot === 'admin') {
        $botsToProcess['admin'] = ['token' => $aToken, 'secret' => $aSec];
    } else {
        if (!empty($cToken)) $botsToProcess['customer'] = ['token' => $cToken, 'secret' => $cSec];
        if (!empty($aToken)) $botsToProcess['admin'] = ['token' => $aToken, 'secret' => $aSec];
        if (empty($botsToProcess) && !empty($cToken)) {
            $botsToProcess['customer'] = ['token' => $cToken, 'secret' => $cSec];
        }
    }

    if (empty($botsToProcess)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'TOKEN_MISSING', 'message' => 'هیچ توکن فعالی برای ربات‌های بله در تنظیمات یافت نشد.']);
        exit;
    }

    $results = [];
    $allOk = true;

    foreach ($botsToProcess as $bRole => $bData) {
        $bToken = $bData['token'];
        $bSecret = $bData['secret'];
        if (empty($bToken)) {
            $results[$bRole] = ['ok' => false, 'error' => "توکن ربات {$bRole} تنظیم نشده است."];
            $allOk = false;
            continue;
        }

        $canonicalUrl = "https://onival.ir/api/webhook/bale?bot={$bRole}&k=" . urlencode($bSecret);
        if ($action === 'set') {
            $res = callBaleApi($bToken, 'setWebhook', [
                'url' => $canonicalUrl,
                'secret_token' => $bSecret
            ]);
            $isOk = !empty($res['ok']);
            if (!$isOk) $allOk = false;
            $results[$bRole] = [
                'ok' => $isOk,
                'registeredUrl' => "https://onival.ir/api/webhook/bale?bot={$bRole}&k=[PROTECTED]",
                'message' => $isOk ? "وب‌هوک ربات {$bRole} با موفقیت ثبت شد." : ($res['description'] ?? 'خطا در ثبت وب‌هوک'),
                'apiData' => $res
            ];
        } elseif ($action === 'delete') {
            $res = callBaleApi($bToken, 'deleteWebhook', []);
            $isOk = !empty($res['ok']);
            if (!$isOk) $allOk = false;
            $results[$bRole] = [
                'ok' => $isOk,
                'message' => $isOk ? "وب‌هوک ربات {$bRole} حذف شد." : ($res['description'] ?? 'خطا در حذف وب‌هوک'),
                'apiData' => $res
            ];
        } else {
            $res = callBaleApi($bToken, 'getWebhookInfo', []);
            $isOk = !empty($res['ok']);
            if (!$isOk) $allOk = false;
            if (isset($res['result']['url'])) {
                $res['result']['url'] = preg_replace('/k=[^&]+/', 'k=[PROTECTED]', $res['result']['url']);
            }
            if (isset($res['result']['last_error_message'])) {
                $res['result']['last_error_message'] = preg_replace('/k=[^&]+/', 'k=[PROTECTED]', $res['result']['last_error_message']);
            }
            $results[$bRole] = [
                'ok' => $isOk,
                'apiData' => $res,
                'message' => $isOk ? "وضعیت وب‌هوک ربات {$bRole} دریافت شد." : ($res['description'] ?? 'خطا در استعلام')
            ];
        }
    }

    echo json_encode([
        'ok' => $allOk,
        'action' => $action,
        'results' => $results,
        'message' => $allOk
            ? ($action === 'set' ? 'وب‌هوک ربات‌های بله با موفقیت در سرورهای بله ثبت شد.' : ($action === 'delete' ? 'وب‌هوک‌ها حذف شدند.' : 'استعلام وضعیت وب‌هوک‌ها انجام شد.'))
            : 'یک یا چند عملیات وب‌هوک با خطا مواجه شد.'
    ]);
    exit;
}

// GET & POST /api/admin/diagnostics
if ($path === '/api/admin/diagnostics' || $path === '/api/admin/diagnostics/run') {
    enforceAdminAuthOrExit($db);
    $suite = runDiagnosticsSuite($db);
    echo json_encode($suite);
    exit;
}

// GET /api/admin/logs & /api/bot/logs
if (($path === '/api/admin/logs' || $path === '/api/bot/logs') && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $logs = getRecentBotActivityLogsPhp(100);
    echo json_encode(['ok' => true, 'logs' => $logs]);
    exit;
}

if (($path === '/api/bot/logs' || $path === '/api/admin/logs') && $method === 'DELETE') {
    enforceAdminAuthOrExit($db);
    if (file_exists($logFile)) {
        @file_put_contents($logFile, '');
    }
    withDatabaseTransaction(function(&$dbRef) {
        $dbRef['botActivityLogs'] = [];
    });
    echo json_encode(['ok' => true, 'message' => 'تاریخچه لاگ‌ها پاکسازی شد']);
    exit;
}

// ------------------------------------------------------------------------------
// 12. Torob & Emalls Feeds
// ------------------------------------------------------------------------------
if (($path === '/api/torob/products' || $path === '/torob/products') && $method === 'GET') {
    $rawProducts = $db['products'] ?? [];
    $categories = $db['categories'] ?? $db['productCategories'] ?? [];
    $catMap = [];
    foreach ($categories as $c) {
        $catMap[$c['id'] ?? ''] = $c['name'] ?? $c['title'] ?? '';
    }

    $torobList = [];
    foreach ($rawProducts as $p) {
        if (!empty($p['isDelete'])) continue;
        $slug = trim((string)($p['slug'] ?? ''));
        if ($slug === '' || ($p['status'] ?? 'published') === 'draft') continue;

        $pid = (string)($p['id'] ?? '');
        $title = trim((string)($p['title'] ?? $p['name'] ?? ''));
        if ($title === '') continue;

        $sizes = $p['sizes'] ?? [];
        $selectedSize = null;
        $isAvailable = false;
        $pDisc = (int)($p['discount'] ?? 0);

        $calcEffectiveVariantPrice = function($s, $discountPercent) {
            $base = (int)($s['price'] ?? 0);
            $hasPromoQuota = !isset($s['specialOfferStock']) || (int)$s['specialOfferStock'] > 0;
            if (!empty($s['discountPrice']) && $hasPromoQuota) {
                return (int)$s['discountPrice'];
            }
            if ($discountPercent > 0 && $hasPromoQuota) {
                return (int)round($base * (100 - $discountPercent) / 100);
            }
            return $base;
        };

        if (!empty($sizes) && is_array($sizes)) {
            $inStockSizes = array_values(array_filter($sizes, function($s) {
                return !empty($s['inStock']) || (isset($s['stock']) && (int)$s['stock'] > 0);
            }));

            if (!empty($inStockSizes)) {
                $isAvailable = true;
                $selectedSize = $inStockSizes[0];
                $minCalc = calculateProductPricePhp($p, $selectedSize);
                $minPrice = $minCalc['price'];

                foreach ($inStockSizes as $s) {
                    $effCalc = calculateProductPricePhp($p, $s);
                    if ($effCalc['price'] < $minPrice) {
                        $minPrice = $effCalc['price'];
                        $selectedSize = $s;
                    }
                }
            } else {
                $selectedSize = $sizes[0];
                $isAvailable = false;
            }
        } else {
            $isAvailable = !empty($p['inStock']) || (isset($p['stock']) && (int)$p['stock'] > 0);
        }

        $calcFinal = calculateProductPricePhp($p, $selectedSize);
        $price = $calcFinal['price'];
        $oldPrice = $calcFinal['oldPrice'];

        // Sanitize image URLs: Never output raw base64 data URLs to feeds!
        $imgUrl = '';
        $rawImgs = !empty($p['images']) && is_array($p['images'])
            ? $p['images']
            : (!empty($p['imageName']) ? [$p['imageName']] : (!empty($p['image']) ? [$p['image']] : []));
        foreach ($rawImgs as $raw) {
            $rawStr = trim((string)$raw);
            if (!empty($rawStr) && strpos($rawStr, 'data:image') !== 0) {
                if (preg_match('#^https?://#i', $rawStr)) {
                    $imgUrl = preg_replace('#^http://#i', 'https://', $rawStr);
                } else {
                    $imgUrl = 'https://onival.ir/' . ltrim($rawStr, '/');
                }
                break;
            }
        }

        $sizeLabel = $selectedSize ? ($selectedSize['name'] ?? $selectedSize['size'] ?? '') : '';

        $torobList[] = [
            'page_unique' => $pid,
            'title' => $title,
            'subtitle' => $selectedSize && !empty($sizeLabel) ? ('وزن / سایز: ' . $sizeLabel) : '',
            'page_url' => "https://onival.ir/product/" . urlencode($slug),
            'price' => $price,
            'old_price' => $oldPrice > $price ? $oldPrice : null,
            'availability' => $isAvailable ? 'instock' : 'outofstock',
            'image_link' => $imgUrl,
            'category_name' => $catMap[$p['categoryId'] ?? $p['category'] ?? ''] ?? ($p['categoryTitle'] ?? $p['category'] ?? 'محصولات ارگانیک'),
            'spec' => [
                'guarantee' => 'ضمانت اصالت و برگه آزمایشگاه تخصصی اونیوال'
            ]
        ];
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'count' => count($torobList),
        'products' => $torobList
    ]);
    exit;
}

if (($path === '/api/emalls/products' || $path === '/emalls/products' || $path === '/api/emalls/p') && $method === 'GET') {
    $rawProducts = $db['products'] ?? [];
    $emallsList = [];

    foreach ($rawProducts as $p) {
        if (!empty($p['isDelete'])) continue;
        $slug = trim((string)($p['slug'] ?? ''));
        if ($slug === '' || ($p['status'] ?? 'published') === 'draft') continue;

        $pid = (string)($p['id'] ?? '');
        $title = trim((string)($p['title'] ?? $p['name'] ?? ''));
        if ($title === '') continue;

        $sizes = $p['sizes'] ?? [];
        $selectedSize = null;
        $isAvailable = false;

        if (!empty($sizes) && is_array($sizes)) {
            $inStockSizes = array_values(array_filter($sizes, function($s) {
                return !empty($s['inStock']) || (isset($s['stock']) && (int)$s['stock'] > 0);
            }));

            if (!empty($inStockSizes)) {
                $isAvailable = true;
                $selectedSize = $inStockSizes[0];
                $minCalc = calculateProductPricePhp($p, $selectedSize);
                $minPrice = $minCalc['price'];

                foreach ($inStockSizes as $s) {
                    $effCalc = calculateProductPricePhp($p, $s);
                    if ($effCalc['price'] < $minPrice) {
                        $minPrice = $effCalc['price'];
                        $selectedSize = $s;
                    }
                }
            } else {
                $selectedSize = $sizes[0];
                $isAvailable = false;
            }
        } else {
            $isAvailable = !empty($p['inStock']) || (isset($p['stock']) && (int)$p['stock'] > 0);
        }

        $calcFinal = calculateProductPricePhp($p, $selectedSize);
        $price = $calcFinal['price'];
        $oldPrice = $calcFinal['oldPrice'];

        $imgUrl = '';
        $rawImgs = !empty($p['images']) && is_array($p['images'])
            ? $p['images']
            : (!empty($p['imageName']) ? [$p['imageName']] : (!empty($p['image']) ? [$p['image']] : []));
        foreach ($rawImgs as $raw) {
            $rawStr = trim((string)$raw);
            if (!empty($rawStr) && strpos($rawStr, 'data:image') !== 0) {
                if (preg_match('#^https?://#i', $rawStr)) {
                    $imgUrl = preg_replace('#^http://#i', 'https://', $rawStr);
                } else {
                    $imgUrl = 'https://onival.ir/' . ltrim($rawStr, '/');
                }
                break;
            }
        }

        $emallsList[] = [
            'id' => $pid,
            'title' => $title,
            'url' => "https://onival.ir/product/" . urlencode($slug),
            'price' => $price,
            'old_price' => $oldPrice > $price ? $oldPrice : null,
            'is_available' => $isAvailable ? 1 : 0,
            'image' => $imgUrl,
            'guarantee' => 'ضمانت اصالت و برگه آزمایشگاه تخصصی اونیوال'
        ];
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'count' => count($emallsList),
        'products' => $emallsList
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 13. Technical SEO (Sitemap & Robots)
// ------------------------------------------------------------------------------
if ($path === '/sitemap.xml' && $method === 'GET') {
    header('Content-Type: application/xml; charset=utf-8');
    $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
    $xml .= '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";

    // Static pages
    $xml .= "  <url><loc>https://onival.ir/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>\n";
    $xml .= "  <url><loc>https://onival.ir/contact</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>\n";

    // Products (strictly exclude drafts and slug-less items)
    $products = array_filter($db['products'] ?? [], function($p) {
        if (!empty($p['isDelete'])) return false;
        if (empty($p['slug']) || trim((string)$p['slug']) === '') return false;
        if (($p['status'] ?? 'published') === 'draft') return false;
        return true;
    });
    foreach ($products as $p) {
        $slug = htmlspecialchars(trim((string)$p['slug']));
        $xml .= "  <url><loc>https://onival.ir/product/{$slug}</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n";
    }

    // Posts (strictly exclude drafts and slug-less items)
    $posts = array_filter($db['posts'] ?? [], function($p) {
        if (!empty($p['isDelete'])) return false;
        if (empty($p['slug']) || trim((string)$p['slug']) === '') return false;
        if (($p['status'] ?? 'published') === 'draft') return false;
        return true;
    });
    foreach ($posts as $p) {
        $slug = htmlspecialchars(trim((string)$p['slug']));
        $xml .= "  <url><loc>https://onival.ir/blog/{$slug}</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>\n";
    }

    $xml .= '</urlset>';
    echo $xml;
    exit;
}

if ($path === '/robots.txt' && $method === 'GET') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "User-agent: *\n";
    echo "Allow: /\n";
    echo "Disallow: /admin\n";
    echo "Disallow: /api/\n";
    echo "Sitemap: https://onival.ir/sitemap.xml\n";
    exit;
}

// ------------------------------------------------------------------------------
// 14. Authenticated Backup / Export & Validated Import
// ------------------------------------------------------------------------------
if (($path === '/api/admin/backup/download' || $path === '/api/host/export-state') && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');

    $exportData = $db;

    // Sanitize credentials and active secrets
    if (isset($exportData['adminCredentials'])) {
        unset($exportData['adminCredentials']['password']);
        unset($exportData['adminCredentials']['oneTimePassword']);
    }
    unset($exportData['adminTokenSecret']);

    if (isset($exportData['telegramConfig'])) {
        $secKeys = ['customerBotToken', 'adminBotToken', 'botToken', 'baleBotToken', 'balePaymentTokenLive', 'balePaymentTokenTest', 'balePaymentToken', 'webhookSecretToken', 'customerWebhookSecretToken', 'adminWebhookSecretToken'];
        foreach ($secKeys as $sk) {
            if (!empty($exportData['telegramConfig'][$sk])) {
                $exportData['telegramConfig'][$sk] = '[PROTECTED]';
            }
        }
    }

    if ($path === '/api/admin/backup/download') {
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="onival-backup-' . date('Y-m-d') . '.json"');
    } else {
        header('Content-Type: application/json; charset=utf-8');
    }

    echo json_encode($exportData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

if ($path === '/api/host/import-state' && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    if (empty($body['confirmed'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'CONFIRMATION_REQUIRED', 'error' => 'تایید صریح جهت بازگردانی اطلاعات الزامی است.']);
        exit;
    }

    $importPayload = $body['data'] ?? $body;
    if (!is_array($importPayload) || !isset($importPayload['products']) || !is_array($importPayload['products'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'INVALID_PAYLOAD', 'error' => 'ساختار فایل پشتیبان نامعتبر است (آرایه products الزامی است).']);
        exit;
    }

    global $backupsDir, $dataFile;
    if (!is_dir($backupsDir)) {
        @mkdir($backupsDir, 0700, true);
    }
    // Create durable backup file in backupsDir before modifying database state
    $backupPath = $backupsDir . '/pre_restore_' . date('Ymd_His') . '.json';
    if (!@copy($dataFile, $backupPath)) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'code' => 'STORAGE_UNAVAILABLE', 'status' => 'storage_unavailable', 'error' => 'تهیه نسخه پشتیبان قبل از بازیابی با خطا مواجه شد. عملیات متوقف گردید.']);
        exit;
    }

    $isFullRestore = !empty($body['fullRestore']) || !empty($importPayload['fullRestore']);

    withDatabaseTransaction(function(&$dbRef) use ($importPayload, $isFullRestore) {
        $allowedEntities = ['products', 'productCategories', 'categories', 'posts', 'postCategories', 'discounts', 'siteContent', 'consultations', 'slugRedirects'];
        if ($isFullRestore) {
            $allowedEntities[] = 'orders';
            $allowedEntities[] = 'contactMessages';
        }
        foreach ($allowedEntities as $ent) {
            if (isset($importPayload[$ent]) && is_array($importPayload[$ent])) {
                $dbRef[$ent] = $importPayload[$ent];
            }
        }

        // Never overwrite admin credentials or secrets with imported payload
    });

    onival_log('system', 'state_imported', 'Database state imported safely by admin', [
        'isFullRestore' => $isFullRestore,
        'backup' => basename($backupPath)
    ]);
    echo json_encode([
        'ok' => true,
        'isFullRestore' => $isFullRestore,
        'message' => $isFullRestore ? 'بازیابی کامل اطلاعات و تراکنش‌ها با موفقیت انجام شد.' : 'بازیابی کاتالوگ و محتوای سایت با موفقیت انجام شد (سفارشات و پیام‌های جاری بدون تغییر حفظ شدند).',
        'backupCreated' => basename($backupPath)
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// SEO Redirects Management (Admin Only)
// ------------------------------------------------------------------------------
if ($path === '/api/seo/redirects' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    echo json_encode($db['slugRedirects'] ?? []);
    exit;
}

if ($path === '/api/seo/redirects' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $from = trim((string)($body['fromPath'] ?? $body['fromSlug'] ?? ''));
    $to = trim((string)($body['toPath'] ?? $body['toSlug'] ?? ''));
    $type = trim((string)($body['entityType'] ?? 'custom'));
    $eId = !empty($body['entityId']) ? (int)$body['entityId'] : 0;
    if (empty($from) || empty($to)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'مسیر مبدا و مقصد الزامی است.']);
        exit;
    }
    $newRedir = [
        'id' => time() * 1000 + rand(10, 99),
        'fromPath' => '/' . ltrim($from, '/'),
        'toPath' => '/' . ltrim($to, '/'),
        'entityType' => $type,
        'entityId' => $eId,
        'createdAt' => date('c')
    ];
    withDatabaseTransaction(function(&$dbRef) use ($newRedir) {
        if (!isset($dbRef['slugRedirects'])) $dbRef['slugRedirects'] = [];
        $dbRef['slugRedirects'][] = $newRedir;
    });
    echo json_encode(['ok' => true, 'redirect' => $newRedir]);
    exit;
}

if (($path === '/api/seo/redirects' || preg_match('#^/api/seo/redirects/(\d+)$#', $path, $m)) && $method === 'DELETE') {
    enforceAdminAuthOrExit($db);
    $targetId = isset($m[1]) ? (int)$m[1] : (!empty($_GET['id']) ? (int)$_GET['id'] : (!empty($body['id']) ? (int)$body['id'] : null));
    $fromPath = !empty($_GET['fromPath']) ? trim((string)$_GET['fromPath']) : (!empty($body['fromPath']) ? trim((string)$body['fromPath']) : '');
    withDatabaseTransaction(function(&$dbRef) use ($targetId, $fromPath) {
        if (!empty($dbRef['slugRedirects']) && is_array($dbRef['slugRedirects'])) {
            $dbRef['slugRedirects'] = array_values(array_filter($dbRef['slugRedirects'], function($r) use ($targetId, $fromPath) {
                if ($targetId !== null && (int)($r['id'] ?? 0) === $targetId) return false;
                if (!empty($fromPath) && (trim((string)($r['fromPath'] ?? '')) === $fromPath || trim((string)($r['fromPath'] ?? ''), '/') === trim($fromPath, '/'))) return false;
                return true;
            }));
        }
    });
    echo json_encode(['ok' => true, 'message' => 'ریدایرکت با موفقیت حذف شد.']);
    exit;
}

// ------------------------------------------------------------------------------
// Data Exports (CSV & XML with Formula Injection Neutralization - Admin Only)
// ------------------------------------------------------------------------------
if ($path === '/api/admin/export/paid-orders.csv' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="paid-orders-' . date('Y-m-d') . '.csv"');

    $allOrders = $db['orders'] ?? [];
    $paidOrders = array_filter($allOrders, function($o) {
        $payStatus = $o['paymentStatus'] ?? '';
        $st = $o['status'] ?? '';
        return ($payStatus === 'Paid' || $st === 'Completed');
    });

    $headers = [
        'کد رهگیری',
        'نام مشتری',
        'شماره تماس',
        'آدرس تحویل',
        'مبلغ کل (تومان)',
        'روش پرداخت',
        'تاریخ ثبت',
        'وضعیت سفارش',
        'اقلام فاکتور'
    ];

    $lines = [];
    $lines[] = implode(',', array_map('escapeCsvFieldPhp', $headers));

    foreach ($paidOrders as $o) {
        $itemsStr = '';
        if (!empty($o['items']) && is_array($o['items'])) {
            $itemParts = [];
            foreach ($o['items'] as $it) {
                $pName = $it['productName'] ?? 'کالا';
                $sName = !empty($it['size']) ? " ({$it['size']})" : '';
                $qty = $it['quantity'] ?? 1;
                $tot = $it['totalPrice'] ?? ($it['unitPrice'] ?? 0);
                $itemParts[] = "{$pName}{$sName} × {$qty} ({$tot} تومان)";
            }
            $itemsStr = implode(' | ', $itemParts);
        }

        $payMethod = $o['paymentMethod'] ?? '';
        $payMethodFa = ($payMethod === 'card_to_card') ? 'کارت به کارت' : (($payMethod === 'online_gateway') ? 'درگاه پرداخت اینترنتی' : 'کیف پول بله');

        $statusFa = match ($o['status'] ?? '') {
            'Completed' => 'تکمیل شده',
            'Shipped' => 'ارسال شده',
            'Processing' => 'در حال آماده‌سازی',
            'Cancelled' => 'لغو شده',
            default => 'در انتظار'
        };

        $row = [
            $o['trackingCode'] ?? ('ONV-' . ($o['id'] ?? '')),
            $o['userFullName'] ?? ($o['customerName'] ?? 'مشتری بدون نام'),
            $o['phoneNumber'] ?? '',
            $o['userAddress'] ?? '',
            (int)($o['totalPrice'] ?? 0),
            $payMethodFa,
            $o['creationTime'] ?? ($o['createdAt'] ?? ''),
            $statusFa,
            $itemsStr
        ];
        $lines[] = implode(',', array_map('escapeCsvFieldPhp', $row));
    }

    echo "\xEF\xBB\xBF" . implode("\r\n", $lines);
    exit;
}

if ($path === '/api/admin/export/woocommerce-products.csv' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="woocommerce-products-' . date('Y-m-d') . '.csv"');

    $activeProducts = array_filter($db['products'] ?? [], fn($p) => empty($p['isDelete']));
    $columns = [
        'ID', 'Type', 'SKU', 'Name', 'Published', 'Is featured?', 'Visibility in catalog',
        'Short description', 'Description', 'Date sale price starts', 'Date sale price ends',
        'Tax status', 'Tax class', 'In stock?', 'Stock', 'Low stock amount', 'Backorders allowed?',
        'Sold individually?', 'Weight (kg)', 'Length (cm)', 'Width (cm)', 'Height (cm)',
        'Allow customer reviews?', 'Purchase note', 'Sale price', 'Regular price', 'Categories',
        'Tags', 'Shipping class', 'Images', 'Download limit', 'Download expiry days', 'Parent',
        'Grouped products', 'Upsells', 'Cross-sells', 'External URL', 'Button text', 'Position',
        'Attribute 1 name', 'Attribute 1 value(s)', 'Attribute 1 visible', 'Attribute 1 global'
    ];

    $lines = [];
    $lines[] = implode(',', array_map('escapeCsvFieldPhp', $columns));

    foreach ($activeProducts as $p) {
        $isVar = !empty($p['hasSize']) && !empty($p['sizes']) && is_array($p['sizes']);
        $cat = $p['categoryTitle'] ?? ($p['category'] ?? 'عمومی');
        $shortDesc = $p['description'] ?? '';
        $longDesc = $p['content'] ?? ($p['description'] ?? '');
        $sku = $p['slug'] ?? ('ONV-PRD-' . ($p['id'] ?? ''));

        $imgUrl = '';
        if (!empty($p['images']) && is_array($p['images'])) {
            $imgUrl = implode(', ', array_filter($p['images'], fn($i) => !empty($i) && strpos($i, 'data:') !== 0));
        } elseif (!empty($p['imageName'])) {
            $imgUrl = $p['imageName'];
        }

        if (!$isVar) {
            $calc = calculateProductPricePhp($p);
            $regPrice = (int)($p['price'] ?? 0);
            $salePrice = ($calc['oldPrice'] > $calc['price']) ? $calc['price'] : '';
            $inStock = (!empty($p['isOutOfStock']) || (isset($p['stock']) && (int)$p['stock'] <= 0)) ? 0 : 1;
            $stockQty = (int)($p['stock'] ?? 10);

            $row = [
                $p['id'] ?? '', 'simple', $sku, $p['title'] ?? '', 1, 0, 'visible',
                $shortDesc, $longDesc, '', '', 'taxable', '', $inStock, $stockQty, '', 0,
                0, '', '', '', '', 1, '', $salePrice, $regPrice, $cat,
                '', '', $imgUrl, '', '', '', '', '', '', '', '', 0,
                '', '', '', ''
            ];
            $lines[] = implode(',', array_map('escapeCsvFieldPhp', $row));
        } else {
            $baseSize = $p['sizes'][0] ?? [];
            $calc = calculateProductPricePhp($p, $baseSize);
            $regPrice = (int)($baseSize['price'] ?? ($p['price'] ?? 0));
            $salePrice = ($calc['oldPrice'] > $calc['price']) ? $calc['price'] : '';
            $inStock = (!empty($p['isOutOfStock']) || (isset($p['stock']) && (int)$p['stock'] <= 0)) ? 0 : 1;
            $stockQty = (int)($p['stock'] ?? 10);
            $sizeNames = implode(', ', array_map(fn($s) => $s['name'] ?? ($s['size'] ?? ''), $p['sizes']));

            $parentRow = [
                $p['id'] ?? '', 'variable', $sku, $p['title'] ?? '', 1, 0, 'visible',
                $shortDesc, $longDesc, '', '', 'taxable', '', $inStock, $stockQty, '', 0,
                0, '', '', '', '', 1, '', $salePrice, $regPrice, $cat,
                '', '', $imgUrl, '', '', '', '', '', '', '', '', 0,
                'وزن / سایز', $sizeNames, 1, 1
            ];
            $lines[] = implode(',', array_map('escapeCsvFieldPhp', $parentRow));

            foreach ($p['sizes'] as $vIdx => $s) {
                $vCalc = calculateProductPricePhp($p, $s);
                $vReg = (int)($s['price'] ?? 0);
                $vSale = ($vCalc['oldPrice'] > $vCalc['price']) ? $vCalc['price'] : '';
                $vStock = (isset($s['stock']) && (int)$s['stock'] <= 0) ? 0 : 1;
                $vQty = (int)($s['stock'] ?? 5);
                $vSku = $sku . '-' . ($vIdx + 1);

                $varRow = [
                    ($p['id'] ?? '') . '0' . ($vIdx + 1), 'variation', $vSku, ($p['title'] ?? '') . ' - ' . ($s['name'] ?? ''), 1, 0, 'visible',
                    '', '', '', '', 'taxable', '', $vStock, $vQty, '', 0,
                    0, '', '', '', '', 1, '', $vSale, $vReg, '',
                    '', '', '', '', '', $p['id'] ?? '', '', '', '', '', '', 0,
                    'وزن / سایز', $s['name'] ?? ($s['size'] ?? ''), 1, 1
                ];
                $lines[] = implode(',', array_map('escapeCsvFieldPhp', $varRow));
            }
        }
    }

    echo "\xEF\xBB\xBF" . implode("\r\n", $lines);
    exit;
}

if ($path === '/api/admin/export/wordpress-wxr.xml' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    header('Content-Type: application/xml; charset=utf-8');
    header('Content-Disposition: attachment; filename="wordpress-wxr-' . date('Y-m-d') . '.xml"');

    $siteBrand = htmlspecialchars($db['siteContent']['brandName'] ?? 'فروشگاه اونیوال | ONIVAL');
    $siteDesc = htmlspecialchars($db['siteContent']['metaDescription'] ?? 'تولید و عرضه مستقیم عسل ارگانیک، ژل رویال و محصولات زنبورعسل');
    $exportDate = date('r');

    $xml = '<?xml version="1.0" encoding="UTF-8" ?>' . "\n";
    $xml .= '<rss version="2.0"' . "\n";
    $xml .= '  xmlns:excerpt="http://wordpress.org/export/1.2/excerpt/"' . "\n";
    $xml .= '  xmlns:content="http://purl.org/rss/1.0/modules/content/"' . "\n";
    $xml .= '  xmlns:wfw="http://wellformedweb.org/CommentAPI/"' . "\n";
    $xml .= '  xmlns:dc="http://purl.org/dc/elements/1.1/"' . "\n";
    $xml .= '  xmlns:wp="http://wordpress.org/export/1.2/"' . "\n";
    $xml .= '>' . "\n";
    $xml .= '<channel>' . "\n";
    $xml .= "  <title>{$siteBrand}</title>\n";
    $xml .= "  <link>https://onival.ir</link>\n";
    $xml .= "  <description>{$siteDesc}</description>\n";
    $xml .= "  <pubDate>{$exportDate}</pubDate>\n";
    $xml .= "  <language>fa-IR</language>\n";
    $xml .= "  <wp:wxr_version>1.2</wp:wxr_version>\n";
    $xml .= "  <wp:base_site_url>https://onival.ir</wp:base_site_url>\n";
    $xml .= "  <wp:base_blog_url>https://onival.ir</wp:base_blog_url>\n";

    // Product Categories
    foreach ($db['productCategories'] ?? [] as $cat) {
        $cTitle = htmlspecialchars($cat['title'] ?? '');
        $cSlug = htmlspecialchars($cat['slug'] ?? ('cat-' . ($cat['id'] ?? '')));
        $xml .= "  <wp:category>\n";
        $xml .= "    <wp:term_id>" . (int)($cat['id'] ?? 0) . "</wp:term_id>\n";
        $xml .= "    <wp:category_nicename>{$cSlug}</wp:category_nicename>\n";
        $xml .= "    <wp:cat_name><![CDATA[{$cTitle}]]></wp:cat_name>\n";
        $xml .= "  </wp:category>\n";
    }

    // Products
    foreach ($db['products'] ?? [] as $p) {
        if (!empty($p['isDelete'])) continue;
        $pId = (int)($p['id'] ?? 0);
        $pTitle = str_replace(']]>', ']]]]><![CDATA[>', $p['title'] ?? '');
        $pDesc = str_replace(']]>', ']]]]><![CDATA[>', $p['description'] ?? '');
        $pContent = str_replace(']]>', ']]]]><![CDATA[>', $p['content'] ?? ($p['description'] ?? ''));
        $pSlug = htmlspecialchars($p['slug'] ?? ('product-' . $pId));
        $postDate = date('Y-m-d H:i:s');

        $xml .= "  <item>\n";
        $xml .= "    <title><![CDATA[{$pTitle}]]></title>\n";
        $xml .= "    <link>https://onival.ir/product/{$pSlug}</link>\n";
        $xml .= "    <pubDate>{$exportDate}</pubDate>\n";
        $xml .= "    <dc:creator><![CDATA[admin]]></dc:creator>\n";
        $xml .= "    <guid isPermaLink=\"false\">https://onival.ir/?post_type=product&#038;p={$pId}</guid>\n";
        $xml .= "    <description><![CDATA[{$pDesc}]]></description>\n";
        $xml .= "    <content:encoded><![CDATA[{$pContent}]]></content:encoded>\n";
        $xml .= "    <excerpt:encoded><![CDATA[{$pDesc}]]></excerpt:encoded>\n";
        $xml .= "    <wp:post_id>{$pId}</wp:post_id>\n";
        $xml .= "    <wp:post_date>{$postDate}</wp:post_date>\n";
        $xml .= "    <wp:post_type>product</wp:post_type>\n";
        $xml .= "    <wp:status>publish</wp:status>\n";
        $xml .= "  </item>\n";
    }

    $xml .= '</channel>' . "\n";
    $xml .= '</rss>';

    echo $xml;
    exit;
}

// ------------------------------------------------------------------------------
// 15. Isolated Bot Test Routes
// ------------------------------------------------------------------------------
if ($path === '/api/bot/test-send-invoice' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $tg['customerBotToken'] ?? $tg['baleBotToken'] ?? ''));
    $walletToken = trim((string)($body['walletToken'] ?? $tg['balePaymentTokenTest'] ?? ''));
    $chatId = trim((string)($body['chatId'] ?? $tg['adminChatId'] ?? ''));

    if (empty($token) || empty($chatId)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'code' => 'VALIDATION_ERROR', 'error' => 'توکن ربات و شناسه چت الزامی است.']);
        exit;
    }

    $title = 'فاکتور تست آزمایشی';
    $desc = 'تست ارتباط با وب‌سرویس صدور فاکتور کیف‌پول بله';
    $payload = 'test_inv_' . time();
    $prices = [['label' => 'مبلغ تست', 'amount' => 10000]];

    $invRes = sendBaleInvoiceSafe($token, $chatId, $title, $desc, $payload, $walletToken, 'IRR', $prices, 'test');
    echo json_encode([
        'ok' => !empty($invRes['ok']),
        'invoiceResult' => $invRes,
        'message' => !empty($invRes['ok']) ? 'فاکتور آزمایشی با موفقیت صادر شد.' : 'خطا در صدور فاکتور آزمایشی'
    ]);
    exit;
}

if ($path === '/api/bot/test-command' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $cmd = strtolower(trim((string)($body['command'] ?? '/start')));

    $responseMap = [
        '/start' => "🌿 به فروشگاه تخصصی عسل و محصولات ارگانیک اونیوال خوش آمدید!\nجهت مشاهده محصولات یا استعلام سفارش از منوی زیر استفاده فرمایید.",
        '/help' => "راهنمای استفاده از ربات اونیوال:\n▫️ پیگیری سفارش: ارسال کد رهگیری (مثلاً ONV-1234)\n▫️ کارت به کارت: راهنمای انتقال وجه و ثبت فیش",
        '/status' => "وضعیت سیستم: آنلاین\nسرویس‌دهنده: وب‌سرور لایت‌اسپید / هاست اشتراکی"
    ];

    echo json_encode([
        'ok' => true,
        'command' => $cmd,
        'simulatedResponse' => $responseMap[$cmd] ?? "دستور '{$cmd}' شناسایی نشد. لطفاً /help را امتحان کنید."
    ]);
    exit;
}

if ($path === '/api/bot/simulate-bale-payment-cycle' && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    // Completely isolated simulation without touching live orders array or stock
    $simTrackingCode = 'SIM-ONV-' . rand(1000, 9999);
    $simAttemptId = bin2hex(random_bytes(6));
    $simPayload = "pay_{$simTrackingCode}_{$simAttemptId}";
    $simAmountToman = 250000;
    $simAmountRials = 2500000;

    echo json_encode([
        'ok' => true,
        'isolated' => true,
        'message' => 'شبیه‌سازی چرخه پرداخت بله در محیط ایزوله تست با موفقیت اجرا شد (بدون تغییر در سفارشات واقعی).',
        'steps' => [
            '1_invoice_issued' => [
                'trackingCode' => $simTrackingCode,
                'attemptId' => $simAttemptId,
                'payload' => $simPayload,
                'amountRials' => $simAmountRials,
                'status' => 'invoice_issued'
            ],
            '2_pre_checkout_verified' => [
                'status' => 'approved',
                'matchedPayload' => $simPayload,
                'stockAvailable' => true
            ],
            '3_successful_payment_reconciliation' => [
                'chargeId' => 'SIM-BALE-' . time(),
                'status' => 'verified_test',
                'liveOrdersMutated' => false,
                'inventoryDeducted' => false
            ]
        ]
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 16. Fallback 404
// ------------------------------------------------------------------------------
http_response_code(404);
echo json_encode([
    'ok' => false,
    'code' => 'ROUTE_NOT_FOUND',
    'error' => "مسیر وب‌سرویس '{$path}' یافت نشد."
]);
