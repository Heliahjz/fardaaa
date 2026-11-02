import fs from 'fs';
import path from 'path';

/**
 * Gate G3: Static Receipt Display Enforcer
 * Scans frontend JSX/TSX/CSS files and ensures NO direct <img>, <a>, <source>, <video>,
 * window.open, or CSS url() uses receiptImage / receiptImageUrl / '/api/admin/receipts'
 * outside the shared AuthenticatedReceiptImage component.
 */

export function validateReceiptDisplayCode(content, filePath = 'snippet.tsx') {
  const errors = [];
  const lines = content.split('\n');

  // Match JSX tags or inline calls with receipt attributes
  const directImgPattern = /<img\b[^>]*\bsrc\s*=\s*\{[^}]*\b(?:receiptImage|receiptImageUrl)\b/i;
  const directPathPattern = /<img\b[^>]*\bsrc\s*=\s*["'{][^"'}]*(?:\/api\/admin\/receipts|\/api\/receipts)/i;
  const directAnchorPattern = /<a\b[^>]*\bhref\s*=\s*\{[^}]*\b(?:receiptImage|receiptImageUrl)\b/i;
  const directSourcePattern = /<source\b[^>]*\bsrc\s*=\s*\{[^}]*\b(?:receiptImage|receiptImageUrl)\b/i;
  const windowOpenPattern = /window\.open\s*\([^)]*\b(?:receiptImage|receiptImageUrl|\/api\/admin\/receipts)\b/i;
  const cssUrlPattern = /url\s*\([^)]*(?:receiptImage|receiptImageUrl|\/api\/admin\/receipts)/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (directImgPattern.test(line)) {
      errors.push(`[Line ${lineNum}] Direct <img> tag uses receiptImage/receiptImageUrl without AuthenticatedReceiptImage: ${line.trim()}`);
    }
    if (directPathPattern.test(line)) {
      errors.push(`[Line ${lineNum}] Direct <img> tag references protected receipt path: ${line.trim()}`);
    }
    if (directAnchorPattern.test(line)) {
      errors.push(`[Line ${lineNum}] Direct <a> tag links receipt URL directly: ${line.trim()}`);
    }
    if (directSourcePattern.test(line)) {
      errors.push(`[Line ${lineNum}] Direct <source> tag references receipt image: ${line.trim()}`);
    }
    if (windowOpenPattern.test(line)) {
      errors.push(`[Line ${lineNum}] window.open called directly with receipt URL: ${line.trim()}`);
    }
    if (cssUrlPattern.test(line)) {
      errors.push(`[Line ${lineNum}] CSS url() references receipt image: ${line.trim()}`);
    }
  }

  return {
    ok: errors.length === 0,
    errors
  };
}

export function runReceiptSecurityScan() {
  const srcDir = path.join(process.cwd(), 'src');
  if (!fs.existsSync(srcDir)) {
    return { ok: true, scannedFiles: 0, violations: [] };
  }

  const allViolations = [];
  let scannedFiles = 0;

  function scanDirectory(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDirectory(fullPath);
      } else if (entry.isFile() && /\.(tsx|jsx|ts|js|css)$/.test(entry.name)) {
        // Skip the shared component itself
        if (entry.name === 'AuthenticatedReceiptImage.tsx') {
          continue;
        }
        scannedFiles++;
        const content = fs.readFileSync(fullPath, 'utf-8');
        const res = validateReceiptDisplayCode(content, fullPath);
        if (!res.ok) {
          allViolations.push({
            file: path.relative(process.cwd(), fullPath),
            errors: res.errors
          });
        }
      }
    }
  }

  scanDirectory(srcDir);
  return {
    ok: allViolations.length === 0,
    scannedFiles,
    violations: allViolations
  };
}

// Execute CLI check when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const result = runReceiptSecurityScan();
  if (!result.ok) {
    console.error(`❌ [GATE G3 FAILED] Receipt display security violations detected in ${result.violations.length} file(s):`);
    for (const v of result.violations) {
      console.error(`\nFile: ${v.file}`);
      for (const err of v.errors) {
        console.error(`  - ${err}`);
      }
    }
    process.exit(1);
  } else {
    console.log(`✓ [GATE G3 PASSED] Scanned ${result.scannedFiles} frontend files. All receipt images use AuthenticatedReceiptImage.`);
  }
}
