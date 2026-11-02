import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const distDir = path.join(process.cwd(), 'dist');
const publicDir = path.join(process.cwd(), 'public');
const scriptsDir = path.join(process.cwd(), 'scripts');
const serverDataDir = path.join(process.cwd(), 'server-data');

// Load and validate initial admin credentials configuration
const initialAdminConfigPath = path.join(scriptsDir, 'initial-admin.config.json');
if (!fs.existsSync(initialAdminConfigPath)) {
  throw new Error(`[BUILD ERROR] scripts/initial-admin.config.json missing!`);
}
const initialAdminConfig = JSON.parse(fs.readFileSync(initialAdminConfigPath, 'utf-8'));
if (!initialAdminConfig.username || !/^[a-zA-Z0-9_]{3,32}$/.test(initialAdminConfig.username)) {
  throw new Error(`[BUILD ERROR] Invalid username in scripts/initial-admin.config.json`);
}
if (!initialAdminConfig.tempPassword || initialAdminConfig.tempPassword.length < 12) {
  throw new Error(`[BUILD ERROR] tempPassword in scripts/initial-admin.config.json must be >= 12 chars`);
}

// Load canonical seed catalog data
const canonicalSeedPath = path.join(serverDataDir, 'onival-canonical-seed.json');
if (!fs.existsSync(canonicalSeedPath)) {
  throw new Error(`[BUILD ERROR] server-data/onival-canonical-seed.json missing!`);
}
const canonicalSeed = JSON.parse(fs.readFileSync(canonicalSeedPath, 'utf-8'));

// Build combined authoritative seed structure
const authoritativeSeed = {
  initialAdmin: {
    username: initialAdminConfig.username,
    tempPassword: initialAdminConfig.tempPassword
  },
  products: canonicalSeed.products || [],
  productCategories: canonicalSeed.productCategories || [],
  posts: canonicalSeed.posts || [],
  postCategories: canonicalSeed.postCategories || [],
  orders: canonicalSeed.orders || [],
  contactMessages: canonicalSeed.contactMessages || [],
  telegramConfig: canonicalSeed.telegramConfig || {},
  siteContent: canonicalSeed.siteContent || {},
  slugRedirects: canonicalSeed.slugRedirects || []
};

// Generate PHP seed file with strict entrypoint guard
const seedPhpContent = `<?php
if (!defined('ONIVAL_ENTRY')) {
    http_response_code(404);
    exit;
}

return json_decode(<<<'JSON_SEED'
${JSON.stringify(authoritativeSeed, null, 2)}
JSON_SEED
, true);
`;

// Write seed.php to public/api/seed.php
const publicApiDir = path.join(publicDir, 'api');
if (!fs.existsSync(publicApiDir)) {
  fs.mkdirSync(publicApiDir, { recursive: true });
}
fs.writeFileSync(path.join(publicApiDir, 'seed.php'), seedPhpContent, 'utf-8');
console.log('✓ Generated authoritative public/api/seed.php');

const htaccessContent = `# ==============================================================================
# ONIVAL Security & Routing Configuration for Apache / LiteSpeed / cPanel
# Generated automatically during build
# ==============================================================================

# 1. Prevent Directory Browsing
Options -Indexes

# 2. Block direct HTTP access to dotfiles
<FilesMatch "^\\.">
    Order allow,deny
    Deny from all
</FilesMatch>

# 3. Block direct HTTP access to sensitive extensions: .log, .bak, .sql, .zip, .env, .ini, .lock, etc.
<FilesMatch "\\.(log|bak|sql|zip|env.*|ini|conf|dist|sh|lock|yml|yaml|ts|tsx|map)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block all .json files except allowed web manifest
<FilesMatch "\\.json$">
    Order allow,deny
    Deny from all
</FilesMatch>

<Files "manifest.json">
    Order allow,deny
    Allow from all
</Files>

<Files "site.webmanifest">
    Order allow,deny
    Allow from all
</Files>

# Block direct HTTP access to internal seed.php
<Files "seed.php">
    Order allow,deny
    Deny from all
</Files>

# 4. Security Headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set X-XSS-Protection "1; mode=block"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# 5. API Backend & SPA URL Rewriting
<IfModule mod_rewrite.c>
    RewriteEngine On

    # Deny direct access to private server-data directory if present
    RewriteRule ^server-data/ - [F,L]

    # Technical SEO & feed routes
    RewriteRule ^sitemap\\.xml$ api/index.php?path=/sitemap.xml [QSA,L]
    RewriteRule ^robots\\.txt$ api/index.php?path=/robots.txt [QSA,L]
    RewriteRule ^torob/products$ api/index.php?path=/api/torob/products [QSA,L]
    RewriteRule ^emalls/products$ api/index.php?path=/api/emalls/products [QSA,L]

    # Route all /api and /api/* requests to PHP backend
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^api(?:/(.*))?$ api/index.php?path=$1 [QSA,L]

    # SPA Fallback for all other frontend routes
    RewriteRule ^index\\.html$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . index.html [L]
</IfModule>
`;

if (fs.existsSync(distDir)) {
  fs.writeFileSync(path.join(distDir, '.htaccess'), htaccessContent, 'utf-8');
  console.log('✓ Successfully generated secure .htaccess in dist/');

  // Put a verbatim copy of the generated .htaccess outside dist as HTACCESS-BACKUP.txt
  const backupHtaccessPath = path.join(process.cwd(), 'HTACCESS-BACKUP.txt');
  fs.writeFileSync(backupHtaccessPath, htaccessContent, 'utf-8');
  console.log('✓ Successfully generated HTACCESS-BACKUP.txt in project root');

  // Ensure api/ directory exists in dist/
  const distApiDir = path.join(distDir, 'api');
  if (!fs.existsSync(distApiDir)) {
    fs.mkdirSync(distApiDir, { recursive: true });
  }

  // Strictly copy authorized production PHP entrypoints
  const allowedApiFiles = ['index.php', 'common.php', 'webhook.php', 'bale-webhook.php', 'seed.php'];
  for (const phpFile of allowedApiFiles) {
    const src = path.join(publicDir, 'api', phpFile);
    const dest = path.join(distApiDir, phpFile);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      console.log(`✓ Copied ${phpFile} to dist/api/${phpFile}`);
    }
  }

  // Remove any legacy / unauthorized items from dist
  const forbiddenDistItems = [
    path.join(distDir, 'server-data'),
    path.join(distDir, 'tests'),
    path.join(distDir, 'scripts'),
    path.join(distDir, 'bale-bot.php'),
    path.join(distDir, 'telegram-bot.php'),
    path.join(distDir, 'bot-config.php'),
    path.join(distApiDir, 'telegram-webhook.php'),
    path.join(distApiDir, 'onival-canonical-seed.json'),
    path.join(distApiDir, 'onival-persistent-data.json'),
    path.join(distDir, 'onival-persistent-data.json'),
    path.join(distDir, 'FIRST-RUN-ADMIN-PASSWORD.txt'),
    path.join(distApiDir, 'FIRST-RUN-ADMIN-PASSWORD.txt')
  ];

  for (const item of forbiddenDistItems) {
    if (fs.existsSync(item)) {
      fs.rmSync(item, { recursive: true, force: true });
      console.log(`✓ Removed forbidden item from dist: ${path.basename(item)}`);
    }
  }

  // ==============================================================================
  // Automated Dist-Tree Assertions & Security Scanner
  // ==============================================================================
  const allowedJsonFiles = new Set(['manifest.json', 'site.webmanifest']);
  const forbiddenExts = ['.map', '.bak', '.zip', '.sql', '.log'];
  const denylistStrings = [
    '09123456789',
    '09351112233',
    '09124455667',
    '@maryam_sh',
    '923387796',
    'ONV-9421'
  ];

  // 1. Verify dist/api/seed.php exists and contains entrypoint guard
  const distSeedFile = path.join(distApiDir, 'seed.php');
  if (!fs.existsSync(distSeedFile)) {
    throw new Error(`[DIST ASSERTION FAILED] dist/api/seed.php missing!`);
  }
  const distSeedRaw = fs.readFileSync(distSeedFile, 'utf-8');
  if (!distSeedRaw.includes("!defined('ONIVAL_ENTRY')")) {
    throw new Error(`[DIST ASSERTION FAILED] dist/api/seed.php missing ONIVAL_ENTRY guard!`);
  }

  // 2. Static GATE: verify NO PHP file in dist/api contains literal 'server-data' or relative path traversal
  for (const phpFile of fs.readdirSync(distApiDir)) {
    if (phpFile.endsWith('.php') && phpFile !== 'seed.php') {
      const phpContent = fs.readFileSync(path.join(distApiDir, phpFile), 'utf-8');
      if (phpContent.includes('server-data')) {
        throw new Error(`[DIST ASSERTION FAILED] GATE: ${phpFile} contains forbidden literal 'server-data'!`);
      }
      if (/__DIR__\s*\.\s*['"]\/\.\.\//.test(phpContent)) {
        throw new Error(`[DIST ASSERTION FAILED] GATE: ${phpFile} contains forbidden relative traversal '__DIR__ . /../'!`);
      }
    }
  }

  // 3. Scan dist directory
  function scanDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else if (entry.isFile()) {
        const base = entry.name;

        // File name assertions
        if (base === 'onival-persistent-data.json' || base === 'FIRST-RUN-ADMIN-PASSWORD.txt') {
          throw new Error(`[DIST ASSERTION FAILED] Found forbidden file in dist: ${fullPath}`);
        }

        // Sensitive extension assertion (.map, .bak, .zip, .sql, .log)
        for (const ext of forbiddenExts) {
          if (base.endsWith(ext)) {
            throw new Error(`[DIST ASSERTION FAILED] Found sensitive extension ${ext} in dist: ${fullPath}`);
          }
        }

        // JSON files outside explicit allowlist
        if (base.endsWith('.json') && !allowedJsonFiles.has(base)) {
          throw new Error(`[DIST ASSERTION FAILED] Found unauthorized .json file in dist: ${fullPath}`);
        }

        // Secret leakage scanner: temp password MUST NOT appear in client assets or dist HTML
        if (fullPath.includes(path.join(distDir, 'assets')) || base === 'index.html') {
          const clientContent = fs.readFileSync(fullPath, 'utf-8');
          if (clientContent.includes(initialAdminConfig.tempPassword)) {
            throw new Error(`[DIST ASSERTION FAILED] Initial temp password leaked into client asset: ${fullPath}`);
          }
        }

        // Denylist string scan on text files
        if (/\.(js|css|html|php|txt|xml|webmanifest)$/i.test(base)) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          for (const needle of denylistStrings) {
            if (content.includes(needle)) {
              throw new Error(`[DIST ASSERTION FAILED] Found denylist string "${needle}" in dist file: ${fullPath}`);
            }
          }
        }
      }
    }
  }

  scanDir(distDir);
  console.log('✓ All dist-tree assertions and security scans passed successfully!');

  // ==============================================================================
  // J0: Populate public_html_ready/ as byte-identical deployment folder
  // ==============================================================================
  const publicHtmlReadyDir = path.join(process.cwd(), 'public_html_ready');
  if (fs.existsSync(publicHtmlReadyDir)) {
    fs.rmSync(publicHtmlReadyDir, { recursive: true, force: true });
    console.log('✓ Cleaned existing public_html_ready/');
  }
  fs.mkdirSync(publicHtmlReadyDir, { recursive: true });

  function copyRecursiveSync(src, dest) {
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);
      if (entry.isDirectory()) {
        fs.mkdirSync(destPath, { recursive: true });
        copyRecursiveSync(srcPath, destPath);
      } else if (entry.isFile()) {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }
  copyRecursiveSync(distDir, publicHtmlReadyDir);
  console.log('✓ Populated public_html_ready/ as byte-identical deployment copy');

  // ==============================================================================
  // Generate authoritative DEPLOY-MANIFEST.txt OUTSIDE dist in project root
  // ==============================================================================
  const BUILD_ID = 'ONIVAL-2026.04-HOTFIX';
  const fileEntries = [];
  let totalFiles = 0;
  let totalBytes = 0;

  function collectFiles(dir, baseDir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        collectFiles(fullPath, baseDir);
      } else if (entry.isFile()) {
        const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
        const size = fs.statSync(fullPath).size;
        const hash = crypto.createHash('sha256').update(fs.readFileSync(fullPath)).digest('hex');
        totalFiles++;
        totalBytes += size;
        fileEntries.push({ relPath, size, hash });
      }
    }
  }
  collectFiles(publicHtmlReadyDir, publicHtmlReadyDir);

  const fileLines = fileEntries
    .map(f => `  ${f.relPath} | ${f.size} bytes | SHA256: ${f.hash}`)
    .join('\n');

  const manifestContent = `if .htaccess is missing after extraction, rename a copy of this file to .htaccess
BUILD_ID: ${BUILD_ID}
BUILD_TIMESTAMP: ${new Date().toISOString()}
FILE_COUNT: ${totalFiles}
TOTAL_SIZE_BYTES: ${totalBytes}
FILES:
${fileLines}
`;

  const manifestPath = path.join(process.cwd(), 'DEPLOY-MANIFEST.txt');
  fs.writeFileSync(manifestPath, manifestContent, 'utf-8');
  console.log('✓ Generated authoritative DEPLOY-MANIFEST.txt in project root');
}
