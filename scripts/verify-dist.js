import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

export const EXPECTED_BUILD_ID = 'ONIVAL-2026.04-HOTFIX';

function getFileSha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function getDirFileMap(dir) {
  const fileMap = new Map();
  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const rel = path.relative(dir, fullPath).replace(/\\/g, '/');
        const hash = getFileSha256(fullPath);
        fileMap.set(rel, hash);
      }
    }
  }
  if (fs.existsSync(dir)) {
    walk(dir);
  }
  return fileMap;
}

export function verifyDist(distDir, manifestPath, commonPhpPath, publicHtmlReadyDir) {
  const projectRoot = path.dirname(manifestPath);
  const readyDir = publicHtmlReadyDir || path.join(projectRoot, 'public_html_ready');

  // 1. Verify dist directory exists and is a directory
  if (!fs.existsSync(distDir) || !fs.statSync(distDir).isDirectory()) {
    throw new Error(`[VERIFY-DIST FAILED] dist directory does not exist or is not a directory: ${distDir}`);
  }

  // 2. Verify dist/.htaccess exists
  const htaccessPath = path.join(distDir, '.htaccess');
  if (!fs.existsSync(htaccessPath) || fs.statSync(htaccessPath).size === 0) {
    throw new Error(`[VERIFY-DIST FAILED] dist/.htaccess is missing or empty!`);
  }

  // 3. Verify dist/api/seed.php exists and has entry guard
  const seedPhpPath = path.join(distDir, 'api', 'seed.php');
  if (!fs.existsSync(seedPhpPath)) {
    throw new Error(`[VERIFY-DIST FAILED] dist/api/seed.php is missing!`);
  }
  const seedContent = fs.readFileSync(seedPhpPath, 'utf-8');
  if (!seedContent.includes("!defined('ONIVAL_ENTRY')")) {
    throw new Error(`[VERIFY-DIST FAILED] dist/api/seed.php is missing ONIVAL_ENTRY guard!`);
  }

  // 4. Verify DEPLOY-MANIFEST.txt exists and matches BUILD_ID and header
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`[VERIFY-DIST FAILED] Manifest missing: ${manifestPath}`);
  }
  const manifestContent = fs.readFileSync(manifestPath, 'utf-8');
  if (!manifestContent.includes(`BUILD_ID: ${EXPECTED_BUILD_ID}`)) {
    throw new Error(`[VERIFY-DIST FAILED] Manifest BUILD_ID does not match expected: ${EXPECTED_BUILD_ID}`);
  }
  if (!manifestContent.includes('if .htaccess is missing after extraction, rename a copy of this file to .htaccess')) {
    throw new Error(`[VERIFY-DIST FAILED] Manifest missing recovery instructions for .htaccess!`);
  }

  // 5. Verify common.php build id matches
  if (!fs.existsSync(commonPhpPath)) {
    throw new Error(`[VERIFY-DIST FAILED] common.php missing at: ${commonPhpPath}`);
  }
  const commonPhpContent = fs.readFileSync(commonPhpPath, 'utf-8');
  const hasBuildId =
    commonPhpContent.includes(`define('ONIVAL_BUILD_ID', '${EXPECTED_BUILD_ID}')`) ||
    commonPhpContent.includes(`const ONIVAL_BUILD_ID = '${EXPECTED_BUILD_ID}'`);
  if (!hasBuildId) {
    throw new Error(`[VERIFY-DIST FAILED] common.php does not define expected ONIVAL_BUILD_ID: ${EXPECTED_BUILD_ID}`);
  }

  // 6. Verify HTACCESS-BACKUP.txt exists in project root outside public_html_ready
  const backupHtaccess = path.join(projectRoot, 'HTACCESS-BACKUP.txt');
  if (!fs.existsSync(backupHtaccess) || fs.statSync(backupHtaccess).size === 0) {
    throw new Error(`[VERIFY-DIST FAILED] HTACCESS-BACKUP.txt is missing or empty outside deployment directory!`);
  }

  // 7. Recursively scan dist and public_html_ready for forbidden files
  const allowedJsonFiles = new Set(['manifest.json', 'site.webmanifest']);
  const forbiddenExts = ['.map', '.bak', '.zip', '.sql', '.log'];

  function scanForbidden(dir, label) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanForbidden(fullPath, label);
      } else if (entry.isFile()) {
        const name = entry.name;
        if (
          name === 'onival-persistent-data.json' ||
          name === 'initial-admin.config.json' ||
          name.startsWith('FIRST-RUN')
        ) {
          throw new Error(`[VERIFY-DIST FAILED] Forbidden file found in ${label}: ${fullPath}`);
        }
        for (const ext of forbiddenExts) {
          if (name.endsWith(ext)) {
            throw new Error(`[VERIFY-DIST FAILED] Sensitive extension found in ${label}: ${fullPath}`);
          }
        }
        if (name.endsWith('.json') && !allowedJsonFiles.has(name)) {
          throw new Error(`[VERIFY-DIST FAILED] Unauthorized JSON file found in ${label}: ${fullPath}`);
        }
      }
    }
  }

  scanForbidden(distDir, 'dist');

  // 8. Verify public_html_ready exists and is a directory
  if (!fs.existsSync(readyDir) || !fs.statSync(readyDir).isDirectory()) {
    throw new Error(`[VERIFY-DIST FAILED] public_html_ready directory does not exist or is not a directory: ${readyDir}`);
  }

  scanForbidden(readyDir, 'public_html_ready');

  // 9. Bidirectional byte-identical comparison between dist and public_html_ready
  const distMap = getDirFileMap(distDir);
  const readyMap = getDirFileMap(readyDir);

  for (const [relPath, distHash] of distMap.entries()) {
    if (!readyMap.has(relPath)) {
      throw new Error(`[VERIFY-DIST FAILED] File in dist missing from public_html_ready: ${relPath}`);
    }
    const readyHash = readyMap.get(relPath);
    if (distHash !== readyHash) {
      throw new Error(`[VERIFY-DIST FAILED] SHA-256 mismatch for ${relPath}: dist=${distHash} vs ready=${readyHash}`);
    }
  }

  for (const [relPath] of readyMap.entries()) {
    if (!distMap.has(relPath)) {
      throw new Error(`[VERIFY-DIST FAILED] File in public_html_ready missing from dist: ${relPath}`);
    }
  }

  // 10. Required files present in public_html_ready
  const requiredReadyFiles = [
    '.htaccess',
    'api/seed.php',
    'api/index.php',
    'api/common.php',
    'api/webhook.php',
    'index.html'
  ];
  for (const req of requiredReadyFiles) {
    const fullReq = path.join(readyDir, req);
    if (!fs.existsSync(fullReq) || fs.statSync(fullReq).size === 0) {
      throw new Error(`[VERIFY-DIST FAILED] Required file missing or empty in public_html_ready: ${req}`);
    }
  }

  // 11. Build ID in public_html_ready/api/common.php matches
  const readyCommonPath = path.join(readyDir, 'api', 'common.php');
  const readyCommonContent = fs.readFileSync(readyCommonPath, 'utf-8');
  const readyHasBuildId =
    readyCommonContent.includes(`define('ONIVAL_BUILD_ID', '${EXPECTED_BUILD_ID}')`) ||
    readyCommonContent.includes(`const ONIVAL_BUILD_ID = '${EXPECTED_BUILD_ID}'`);
  if (!readyHasBuildId) {
    throw new Error(`[VERIFY-DIST FAILED] public_html_ready/api/common.php does not define expected ONIVAL_BUILD_ID!`);
  }

  return true;
}

// Auto-run when executed directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const distDir = path.join(process.cwd(), 'dist');
  const manifestPath = path.join(process.cwd(), 'DEPLOY-MANIFEST.txt');
  const commonPhpPath = path.join(distDir, 'api', 'common.php');
  const publicHtmlReadyDir = path.join(process.cwd(), 'public_html_ready');

  try {
    verifyDist(distDir, manifestPath, commonPhpPath, publicHtmlReadyDir);
    console.log('✓ verify-dist: Production distribution and public_html_ready are valid, complete, and byte-identical!');
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
