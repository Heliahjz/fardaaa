import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export function validateTextBuffer(buf, filename = 'test.php') {
  // 1. Check PHP specific rules: BOM and leading output before <?php
  if (filename.endsWith('.php')) {
    // UTF-8 BOM: EF BB BF
    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
      throw new Error(`[CHECK-UTF8 FAILED] UTF-8 BOM detected at the start of PHP file: ${filename}`);
    }

    // Must start with <?php (no output or whitespace before opening tag)
    const startStr = buf.slice(0, 5).toString('ascii');
    if (startStr !== '<?php') {
      throw new Error(`[CHECK-UTF8 FAILED] Output or whitespace detected before opening <?php tag in: ${filename}`);
    }
  }

  // 2. Check CESU-8 / surrogate sequences (ED A0..BF followed by 80..BF)
  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] === 0xed && (buf[i + 1] >= 0xa0 && buf[i + 1] <= 0xbf) && (buf[i + 2] >= 0x80 && buf[i + 2] <= 0xbf)) {
      throw new Error(
        `[CHECK-UTF8 FAILED] CESU-8 / surrogate sequence detected at offset ${i} in: ${filename}`
      );
    }
  }

  // 3. Check UTF-8 validity
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch (err) {
    throw new Error(`[CHECK-UTF8 FAILED] Invalid UTF-8 byte sequence in: ${filename} (${err.message})`);
  }

  return true;
}

export function scanUtf8(rootDir = process.cwd()) {
  const ignoredDirs = new Set(['node_modules', '.git', 'dist', 'public_html_ready', '.aistudio']);
  const textExts = /\.(php|ts|tsx|js|jsx|json|html|css|txt|md|yml|yaml|webmanifest)$/i;

  let scannedCount = 0;

  function scan(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (ignoredDirs.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scan(fullPath);
      } else if (entry.isFile() && textExts.test(entry.name)) {
        scannedCount++;
        const buf = fs.readFileSync(fullPath);
        validateTextBuffer(buf, fullPath);
      }
    }
  }

  scan(rootDir);
  return { ok: true, scannedCount };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const res = scanUtf8();
    console.log(`✓ [GATE CHECK-UTF8 PASSED] Scanned ${res.scannedCount} text files. All UTF-8 and PHP rules valid.`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
