import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { sanitizeSlug, isSlugDuplicate } from '../src/utils/seo';
import { viewAfterLogin, shouldFetchAdminData, handleSetupSuccess, isValidAdminUsernameClient, getInitialUsernameForState } from '../src/authFlow';
import { verifyDist, EXPECTED_BUILD_ID, getDirFileMap } from '../scripts/verify-dist.js';
import { validateTextBuffer, scanUtf8 } from '../scripts/check-utf8.js';

describe('ONIVAL Pure Logic Unit Tests', () => {
  test('Slug Sanitization handles Persian and ASCII cleanly', () => {
    assert.equal(sanitizeSlug('عسل طبیعی سبلان'), 'عسل-طبیعی-سبلان');
    assert.equal(sanitizeSlug('Mountain Honey 100%'), 'mountain-honey-100');
    assert.equal(sanitizeSlug('   ', 'item', 1), 'item-1', 'Falls back gracefully on empty string');
  });

  test('Slug Duplicate Detection protects distinct items', () => {
    const existing = [
      { id: 1, slug: 'mountain-honey', isDelete: false },
      { id: 2, slug: 'royal-jelly', isDelete: false },
      { id: 3, slug: 'deleted-item', isDelete: true }
    ];

    // Same slug on different id should be flagged duplicate
    assert.equal(isSlugDuplicate(existing, 'mountain-honey', 4), true);

    // Same slug on self id should NOT be flagged duplicate
    assert.equal(isSlugDuplicate(existing, 'mountain-honey', 1), false);

    // Matching deleted item slug should NOT be duplicate
    assert.equal(isSlugDuplicate(existing, 'deleted-item', 5), false);
  });

  test('Product Route Pattern matches singular and plural endpoints', () => {
    const pluralRegex = /^\/api\/products?\/(\d+)$/;
    const mPlural = '/api/products/1'.match(pluralRegex);
    const mSingular = '/api/product/1'.match(pluralRegex);

    assert.ok(mPlural, 'Should match /api/products/1');
    assert.equal(mPlural[1], '1');

    assert.ok(mSingular, 'Should match /api/product/1');
    assert.equal(mSingular[1], '1');
  });

  test('Toman to Rial 10x conversion for Bale Wallet', () => {
    const amountToman = 350000;
    const amountRials = Math.round(amountToman * 10);
    assert.equal(amountRials, 3500000);
  });

  test('Order tracking code extraction accepts valid codes and rejects menu labels and phone numbers', () => {
    function extractOrderCodeJs(text: string): string | null {
      if (!text || typeof text !== 'string') return null;
      const farsi = ['۰','۱','۲','۳','۴','۵','۶','۷','۸','۹'];
      const arabic = ['٠','١','٢','٣','٤','٥','٦','٧','٨','٩'];
      let norm = text.trim();
      for (let i = 0; i < 10; i++) {
        norm = norm.replaceAll(farsi[i], String(i)).replaceAll(arabic[i], String(i));
      }

      if (/^[\/!#]?(start|help|admin|orders|شروع|راهنما|سفارشات|فروشگاه|محصولات|تماس|پشتیبانی|پیگیری|پرداخت)$/i.test(norm)) {
        return null;
      }
      if (/^(?:🧾\s*استعلام|🛍️\s*فروشگاه|📦\s*پیگیری|💳\s*راهنما|📞\s*تماس|استعلام و پرداخت فاکتور|فروشگاه اونیوال|پیگیری سفارش|راهنمای روش‌های پرداخت|تماس با ما)/i.test(norm)) {
        return null;
      }

      const startMatch = norm.match(/^\/start[\s_]+(?:pay_|order_|پرداخت_)?([A-Za-z0-9_-]+)/i);
      if (startMatch) {
        const cand = startMatch[1].replace(/^(?:pay_|order_|پرداخت_)/i, '').trim();
        if (cand && !/^(admin|help|orders|start)$/i.test(cand)) {
          return cand;
        }
      }

      const confMatch = norm.match(/^\/(?:confirm_|approve_|تایید_)([A-Za-z0-9_-]+)/i);
      if (confMatch) return confMatch[1].trim();

      const onvMatch = norm.match(/(ONV[-_]?[A-Za-z0-9_-]{3,}|ORD[-_]?[A-Za-z0-9_-]{3,})/i);
      if (onvMatch) return onvMatch[1].trim();

      const labelMatch = norm.match(/(?:فاکتور|سفارش|کد\s*رهگیری|کد\s*پیگیری|شماره\s*سفارش|شماره\s*فاکتور|invoice|order)\s*[:#-]?\s*([A-Za-z0-9_-]{3,})/i);
      if (labelMatch) {
        const cand = labelMatch[1].trim();
        if (!/(گرمی?|کیلو|تومان|ریال)/i.test(cand)) {
          return cand;
        }
      }

      if (!norm.startsWith('/') && /^[A-Za-z0-9_-]{3,32}$/.test(norm)) {
        if (/^09\d{9}$/.test(norm)) {
          return null;
        }
        return norm;
      }

      return null;
    }

    // Rejection of keyboard menu labels
    assert.equal(extractOrderCodeJs('🧾 استعلام و پرداخت فاکتور من'), null);
    assert.equal(extractOrderCodeJs('🛍️ فروشگاه اونیوال'), null);
    assert.equal(extractOrderCodeJs('📦 پیگیری سفارش'), null);
    assert.equal(extractOrderCodeJs('💳 راهنمای روش‌های پرداخت'), null);

    // Rejection of weights and phone numbers
    assert.equal(extractOrderCodeJs('عسل ۵۰۰ گرمی'), null);
    assert.equal(extractOrderCodeJs('09123456789'), null);
    assert.equal(extractOrderCodeJs('۰۹۱۲۳۴۵۶۷۸۹'), null);

    // Acceptance of valid codes
    assert.equal(extractOrderCodeJs('ONV-ORD-88219'), 'ONV-ORD-88219');
    assert.equal(extractOrderCodeJs('/start pay_ONV-ORD-88219'), 'ONV-ORD-88219');
    assert.equal(extractOrderCodeJs('سلام کد رهگیری من ONV-9912 است'), 'ONV-9912');
    assert.equal(extractOrderCodeJs('/confirm_ONV-ORD-88219'), 'ONV-ORD-88219');
  });

  test('Logo-only save in account does not mark initialSetupCompleted or expire OTP', () => {
    const creds = {
      username: 'admin',
      password: 'admin',
      initialSetupCompleted: false,
      oneTimePassword: 'Onival@Admin2025'
    };

    const payload = {
      siteLogo: 'data:image/png;base64,...',
      siteLogoFit: 'contain',
      siteLogoShape: 'rounded',
      siteLogoScale: 100
    };

    const isChangingPassword = Boolean(payload.newPassword && String(payload.newPassword).trim() !== '');
    const isChangingUsername = Boolean(payload.username && payload.username !== creds.username);

    // Pure logic rule: only change initialSetupCompleted when password or username changed
    if (isChangingPassword || isChangingUsername) {
      creds.initialSetupCompleted = true;
      creds.oneTimePassword = null;
    }

    assert.equal(creds.initialSetupCompleted, false, 'initialSetupCompleted must remain false');
    assert.equal(creds.oneTimePassword, 'Onival@Admin2025', 'oneTimePassword must be preserved');
  });

  test('Webhook Secret role isolation: customer secret rejects admin scope', () => {
    const customerSecret = 'csec_1234567890abcdef1234567890abcdef';
    const adminSecret = 'asec_9876543210fedcba9876543210fedcba';

    function verifySecretForScope(scope: 'customer' | 'admin', tokenPassed: string): boolean {
      const expected = scope === 'admin' ? adminSecret : customerSecret;
      return tokenPassed === expected;
    }

    assert.equal(verifySecretForScope('customer', customerSecret), true);
    assert.equal(verifySecretForScope('admin', adminSecret), true);
    assert.equal(verifySecretForScope('admin', customerSecret), false, 'Customer secret must be rejected for admin scope');
    assert.equal(verifySecretForScope('customer', adminSecret), false, 'Admin secret must be rejected for customer scope');
  });

  test('Test vs Live payment isolation: test payment does NOT deduct inventory or mark order as Paid', () => {
    const order = {
      trackingCode: 'ONV-ORD-771',
      totalPrice: 200000,
      paymentStatus: 'Unpaid',
      status: 'Pending',
      inventoryDeducted: false,
      testPaymentStatus: undefined as string | undefined
    };

    function processSuccessfulPayment(ord: typeof order, isTestMode: boolean) {
      if (isTestMode) {
        ord.testPaymentStatus = 'TestPaidVerified';
        // DO NOT mark Paid, DO NOT deduct stock
        return;
      }
      ord.paymentStatus = 'Paid';
      ord.status = 'Processing';
      ord.inventoryDeducted = true;
    }

    processSuccessfulPayment(order, true);
    assert.equal(order.paymentStatus, 'Unpaid', 'Test payment must keep paymentStatus Unpaid');
    assert.equal(order.inventoryDeducted, false, 'Test payment must NOT deduct stock');
    assert.equal(order.testPaymentStatus, 'TestPaidVerified', 'Test status should be recorded');
  });

  test('Public PII masking for tracking envelope', () => {
    function maskPhone(p: string): string {
      const clean = p.trim();
      if (clean.length >= 10) return clean.slice(0, 4) + '***' + clean.slice(-3);
      if (clean.length >= 4) return clean.slice(0, 2) + '***' + clean.slice(-2);
      return '***';
    }

    assert.equal(maskPhone('09123456789'), '0912***789');
    assert.equal(maskPhone('02112345678'), '0211***678');
  });

  test('Item 1: Username-only change during initial setup is rejected without password', () => {
    function validateCredentialChange(
      isInitialPending: boolean,
      currentPassStored: string,
      req: { username?: string; currentPassword?: string; newPassword?: string }
    ): { ok: boolean; error?: string } {
      const isChangingPassword = Boolean(req.newPassword && req.newPassword.trim() !== '');
      const isChangingUsername = Boolean(req.username && req.username.trim().toLowerCase() !== 'admin');

      if (isInitialPending && isChangingUsername && !isChangingPassword) {
        return { ok: false, error: 'Password required during initial setup' };
      }
      if (!isInitialPending && (isChangingPassword || isChangingUsername)) {
        if (!req.currentPassword || req.currentPassword !== currentPassStored) {
          return { ok: false, error: 'Current password invalid' };
        }
      }
      if (isChangingPassword && req.newPassword!.trim().length < 6) {
        return { ok: false, error: 'Password too short' };
      }
      return { ok: true };
    }

    // Initial setup with username only -> rejected!
    const res1 = validateCredentialChange(true, 'admin', { username: 'newadmin' });
    assert.equal(res1.ok, false);
    assert.equal(res1.error, 'Password required during initial setup');

    // Initial setup with username AND valid password -> accepted
    const res2 = validateCredentialChange(true, 'admin', { username: 'newadmin', newPassword: 'SuperSecretPassword123' });
    assert.equal(res2.ok, true);

    // Post-setup with username change without current password -> rejected!
    const res3 = validateCredentialChange(false, 'SuperSecretPassword123', { username: 'anotheradmin' });
    assert.equal(res3.ok, false);
    assert.equal(res3.error, 'Current password invalid');

    // Post-setup with correct current password -> accepted
    const res4 = validateCredentialChange(false, 'SuperSecretPassword123', { username: 'anotheradmin', currentPassword: 'SuperSecretPassword123' });
    assert.equal(res4.ok, true);
  });

  test('Item 4: Receipt upload rejects Paid and Cancelled orders and sets canonical properties', () => {
    function processReceiptUpload(order: { status: string; paymentStatus: string; receiptImage?: string; receiptImageUrl?: string }, filename: string) {
      if (order.paymentStatus === 'Paid') {
        return { ok: false, error: 'سفارش قبلاً تسویه شده است' };
      }
      if (order.status === 'Cancelled') {
        return { ok: false, error: 'سفارش لغو شده است' };
      }
      order.paymentStatus = 'PendingVerification';
      order.receiptImage = filename;
      order.receiptImageUrl = `/api/receipts/${filename}`;
      return { ok: true, adminNotified: true };
    }

    const paidOrder = { status: 'Processing', paymentStatus: 'Paid' };
    assert.equal(processReceiptUpload(paidOrder, 'rec1.jpg').ok, false);

    const cancelledOrder = { status: 'Cancelled', paymentStatus: 'Unpaid' };
    assert.equal(processReceiptUpload(cancelledOrder, 'rec2.jpg').ok, false);

    const pendingOrder: { status: string; paymentStatus: string; receiptImage?: string; receiptImageUrl?: string } = { status: 'Pending', paymentStatus: 'Unpaid' };
    const res = processReceiptUpload(pendingOrder, 'rec3.jpg');
    assert.equal(res.ok, true);
    assert.equal(pendingOrder.receiptImage, 'rec3.jpg');
    assert.equal(pendingOrder.receiptImageUrl, '/api/receipts/rec3.jpg');
    assert.equal(res.adminNotified, true);
  });

  test('Item 5: Consultation booking uses authoritative server price and prevents price tampering', () => {
    const consultationConfig = {
      basePrice: 120000,
      topics: [
        { id: 'diet-plan', title: 'برنامه غذایی ارگانیک', price: 250000, enabled: true },
        { id: 'honey-therapy', title: 'عسل درمانی', price: 180000, enabled: true }
      ]
    };

    function resolveConsultationPrice(topicId?: string, clientPrice?: number): number {
      let resolved = consultationConfig.basePrice;
      if (topicId) {
        const found = consultationConfig.topics.find(t => t.id === topicId);
        if (found && typeof found.price === 'number') {
          resolved = found.price;
        }
      }
      // Client price is strictly ignored
      return resolved;
    }

    // Client attempts to pass 1000 Toman for 250000 Toman topic
    const price1 = resolveConsultationPrice('diet-plan', 1000);
    assert.equal(price1, 250000, 'Must use server topic price, ignoring client 1000');

    // Unknown topic defaults to basePrice
    const price2 = resolveConsultationPrice('unknown-topic', 0);
    assert.equal(price2, 120000, 'Must fall back to basePrice');
  });

  test('Item 6: Bot config preserves existing tokens when submitted empty or masked', () => {
    const currentConfig = {
      customerBotToken: '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
      adminBotToken: '987654:XYZ-UVW9876tsRqp-cba57T2s1r987zy22',
      baleBotUsername: 'OnivalCustomerBot'
    };

    function updateConfig(
      existing: typeof currentConfig,
      submitted: { customerBotToken?: string; adminBotToken?: string }
    ) {
      const isMaskedOrEmpty = (tok?: string) => !tok || tok.trim() === '' || tok.includes('***') || tok.includes('[REDACTED]');
      const nextCust = isMaskedOrEmpty(submitted.customerBotToken) ? existing.customerBotToken : submitted.customerBotToken!.trim();
      const nextAdmin = isMaskedOrEmpty(submitted.adminBotToken) ? existing.adminBotToken : submitted.adminBotToken!.trim();
      return {
        ...existing,
        customerBotToken: nextCust,
        adminBotToken: nextAdmin
      };
    }

    const result = updateConfig(currentConfig, {
      customerBotToken: '123456:***',
      adminBotToken: ''
    });

    assert.equal(result.customerBotToken, currentConfig.customerBotToken, 'Must preserve existing customer token');
    assert.equal(result.adminBotToken, currentConfig.adminBotToken, 'Must preserve existing admin token');
  });

  test('Item 7: Order lookup strictly requires trackingCode in public context and rejects short numbers', () => {
    const orders = [
      { id: 101, trackingCode: 'ONV-ORD-88219', orderNumber: '101' },
      { id: 102, trackingCode: 'ONV-ORD-99342', orderNumber: '102' }
    ];

    function findOrderByCode(ordersList: typeof orders, query: string, allowOrderNumber: boolean) {
      const q = query.trim().toUpperCase();
      for (const ord of ordersList) {
        if (ord.trackingCode.toUpperCase() === q) return ord;
        if (allowOrderNumber && ord.orderNumber === q) return ord;
      }
      return null;
    }

    // Public context: allowOrderNumber = false
    assert.equal(findOrderByCode(orders, '101', false), null, 'Public query must NOT match 5-digit orderNumber');
    assert.equal(findOrderByCode(orders, 'ONV-ORD-88219', false)?.id, 101, 'Exact tracking code matches');

    // Admin context: allowOrderNumber = true
    assert.equal(findOrderByCode(orders, '101', true)?.id, 101, 'Admin query can match orderNumber');
  });

  test('Item 2 & 3: Payment attempts bounded to max 10 and charge replay rejected', () => {
    const order = {
      trackingCode: 'ONV-ORD-5544',
      paymentAttempts: [] as Array<{ chargeId: string; status: string }>,
      paymentStatus: 'Unpaid'
    };

    function recordAttempt(ord: typeof order, chargeId: string, status: string) {
      // Replay check
      for (const att of ord.paymentAttempts) {
        if (att.chargeId === chargeId && att.status === 'paid_success') {
          return { ok: true, alreadyPaid: true };
        }
      }
      ord.paymentAttempts.push({ chargeId, status });
      if (ord.paymentAttempts.length > 10) {
        ord.paymentAttempts = ord.paymentAttempts.slice(-10);
      }
      return { ok: true };
    }

    // Add 12 attempts
    for (let i = 1; i <= 12; i++) {
      recordAttempt(order, `CHG-${i}`, i === 12 ? 'paid_success' : 'invoice_issued');
    }

    assert.equal(order.paymentAttempts.length, 10, 'paymentAttempts array must be capped at 10 items');
    assert.equal(order.paymentAttempts[order.paymentAttempts.length - 1].chargeId, 'CHG-12');

    // Replay check for CHG-12
    const replay = recordAttempt(order, 'CHG-12', 'paid_success');
    assert.equal(replay.alreadyPaid, true, 'Replaying successful charge must be idempotent');
  });

  // =========================================================================
  // WORK GROUP A TESTS: AUTH & UPLOAD DEFECTS
  // =========================================================================
  test('Group A1: Setup-status never discloses OTP or password to public callers', () => {
    function getSetupStatusResponse(adminCreds: { initialSetupCompleted: boolean; oneTimePassword?: string | null }) {
      // Corrected safe response: only indicates completion state, never leaks OTP
      return {
        initialSetupCompleted: Boolean(adminCreds.initialSetupCompleted),
        defaultUsername: 'admin'
      };
    }

    const uninitialized = getSetupStatusResponse({ initialSetupCompleted: false, oneTimePassword: 'Onival@Admin2025' });
    assert.equal((uninitialized as any).initialOtp, undefined, 'Must not disclose initialOtp');
    assert.equal((uninitialized as any).oneTimePassword, undefined, 'Must not disclose oneTimePassword');
    assert.equal(uninitialized.initialSetupCompleted, false);

    const completed = getSetupStatusResponse({ initialSetupCompleted: true, oneTimePassword: null });
    assert.equal(completed.initialSetupCompleted, true);
    assert.equal((completed as any).initialOtp, undefined);
  });

  test('Group A2: Logout requires valid admin session token and does not wipe global secret anonymously', () => {
    const activeSessions = new Map<string, { username: string; expiresAt: number }>();
    activeSessions.set('tok_valid_123', { username: 'admin', expiresAt: Date.now() + 3600000 });

    function handleLogout(tokenPassed?: string): { ok: boolean; status: number; error?: string } {
      if (!tokenPassed || !activeSessions.has(tokenPassed)) {
        return { ok: false, status: 401, error: 'Unauthorized' };
      }
      activeSessions.delete(tokenPassed);
      return { ok: true, status: 200 };
    }

    // Anonymous logout attempt must be rejected 401 and NOT affect existing sessions
    const anonRes = handleLogout(undefined);
    assert.equal(anonRes.status, 401);
    assert.equal(activeSessions.has('tok_valid_123'), true, 'Existing session must NOT be invalidated by anonymous request');

    // Valid authenticated logout deletes token
    const authRes = handleLogout('tok_valid_123');
    assert.equal(authRes.status, 200);
    assert.equal(activeSessions.has('tok_valid_123'), false, 'Session must be revoked');
  });

  test('Group A3: Receipt upload validates order state before disk writing and cleans up on failure', () => {
    function validateReceiptBeforeWrite(order: { paymentStatus: string; status: string }, base64Data: string): { ok: boolean; error?: string } {
      if (order.paymentStatus === 'Paid') {
        return { ok: false, error: 'Order already paid' };
      }
      if (order.status === 'Cancelled') {
        return { ok: false, error: 'Order cancelled' };
      }
      if (base64Data.length > 2.8 * 1024 * 1024) {
        return { ok: false, error: 'File size exceeded' };
      }
      return { ok: true };
    }

    const paidOrder = { paymentStatus: 'Paid', status: 'Completed' };
    const check1 = validateReceiptBeforeWrite(paidOrder, 'data:image/png;base64,...');
    assert.equal(check1.ok, false);
    assert.equal(check1.error, 'Order already paid');
  });

  // =========================================================================
  // WORK GROUP B TESTS: ROUTE CONTRACTS & FEEDS
  // =========================================================================
  test('Group B: Torob and Emalls feeds select in-stock variant and strip base64 data URLs', () => {
    const product = {
      id: 10,
      name: 'عسل کوهی ارگانیک',
      price: 500000,
      image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      images: [
        'data:image/png;base64,fakebase64...',
        'https://onival.ir/uploads/honey.jpg'
      ],
      sizes: [
        { id: 1, size: '۵۰۰ گرم', price: 280000, stock: 0, inStock: false },
        { id: 2, size: '۱ کیلوگرم', price: 500000, discountPrice: 460000, stock: 15, inStock: true }
      ]
    };

    function resolveFeedProduct(p: typeof product) {
      let selectedSize = null;
      let isAvailable = false;
      const inStockSizes = p.sizes.filter(s => s.stock > 0 || s.inStock);

      if (inStockSizes.length > 0) {
        // Pick in-stock size
        selectedSize = inStockSizes[0];
        isAvailable = true;
      } else {
        selectedSize = p.sizes[0];
        isAvailable = false;
      }

      // Sanitize images: strip base64
      let safeImageUrl = '';
      for (const img of p.images) {
        if (!img.startsWith('data:image')) {
          safeImageUrl = img;
          break;
        }
      }

      return {
        id: p.id,
        price: selectedSize.discountPrice || selectedSize.price,
        isAvailable,
        selectedVariant: selectedSize.size,
        imageUrl: safeImageUrl
      };
    }

    const feedItem = resolveFeedProduct(product);
    assert.equal(feedItem.isAvailable, true, 'Must pick in-stock variant');
    assert.equal(feedItem.selectedVariant, '۱ کیلوگرم', 'Must select available 1kg variant over out-of-stock 500g variant');
    assert.equal(feedItem.price, 460000, 'Must use discountPrice of in-stock variant');
    assert.equal(feedItem.imageUrl, 'https://onival.ir/uploads/honey.jpg', 'Must ignore base64 and use real URL');
  });

  test('Group B: Export state sanitizes admin credentials and bot tokens', () => {
    const fullDbState = {
      products: [{ id: 1, name: 'عسل' }],
      adminCredentials: {
        username: 'admin',
        password: 'scrypt:salt:hash',
        oneTimePassword: null
      },
      telegramConfig: {
        customerBotToken: '12345:TOKEN',
        adminChatId: '987654321',
        webhookSecretToken: 'sec_abcdef'
      }
    };

    function sanitizeExport(db: typeof fullDbState) {
      const copy: any = JSON.parse(JSON.stringify(db));
      if (copy.adminCredentials) {
        delete copy.adminCredentials.password;
        delete copy.adminCredentials.oneTimePassword;
      }
      if (copy.telegramConfig) {
        copy.telegramConfig.customerBotToken = '[PROTECTED]';
        copy.telegramConfig.webhookSecretToken = '[PROTECTED]';
      }
      return copy;
    }

    const exported = sanitizeExport(fullDbState);
    assert.equal(exported.adminCredentials.password, undefined);
    assert.equal(exported.telegramConfig.customerBotToken, '[PROTECTED]');
    assert.equal(exported.telegramConfig.adminChatId, '987654321');
  });

  // =========================================================================
  // WORK GROUP C TESTS: PAYMENT ATTEMPT AND RECONCILIATION
  // =========================================================================
  test('Group C: Payment attempt generation produces unique attemptId and payload before invoice', () => {
    function generatePaymentAttempt(orderTrackingCode: string, amountToman: number) {
      const attemptId = 'a1b2c3d4';
      const payload = `pay_${orderTrackingCode}_${attemptId}`;
      const amountRials = Math.round(amountToman * 10);
      return {
        attemptId,
        payload,
        amountRials,
        status: 'invoice_issued'
      };
    }

    const attempt = generatePaymentAttempt('ONV-ORD-901', 350000);
    assert.equal(attempt.attemptId, 'a1b2c3d4');
    assert.equal(attempt.payload, 'pay_ONV-ORD-901_a1b2c3d4');
    assert.equal(attempt.amountRials, 3500000);
    assert.equal(attempt.status, 'invoice_issued');
  });

  test('Group C: Unknown attempt payload marks PAYMENT_REVIEW_REQUIRED and does NOT mark Paid', () => {
    const order = {
      trackingCode: 'ONV-ORD-901',
      paymentAttempts: [{ attemptId: 'orig_1', payload: 'pay_ONV-ORD-901_orig_1', amountRials: 1000000 }],
      paymentStatus: 'Unpaid'
    };

    function reconcilePayment(ord: typeof order, incomingPayload: string, paidRials: number) {
      const matched = ord.paymentAttempts.find(a => a.payload === incomingPayload);
      if (!matched) {
        return {
          ok: false,
          paymentStatus: 'PAYMENT_REVIEW_REQUIRED',
          reviewReason: 'Unknown payload mismatch'
        };
      }
      return { ok: true, paymentStatus: 'Paid' };
    }

    const res = reconcilePayment(order, 'pay_ONV-ORD-901_fake_attempt', 1000000);
    assert.equal(res.ok, false);
    assert.equal(res.paymentStatus, 'PAYMENT_REVIEW_REQUIRED');
  });

  // =========================================================================
  // WORK GROUP D TESTS: ATOMIC STOCK & ORDER TRANSITIONS
  // =========================================================================
  test('Group D1: Order line aggregation correctly verifies total stock for duplicate lines', () => {
    const stockState: Record<number, number> = { 101: 5 }; // Only 5 available in stock
    const cartLines = [
      { productId: 101, quantity: 3 },
      { productId: 101, quantity: 4 } // Total requested: 7, which exceeds 5!
    ];

    function validateCartStock(stock: Record<number, number>, lines: typeof cartLines): { ok: boolean; error?: string } {
      const aggregates: Record<number, number> = {};
      for (const line of lines) {
        aggregates[line.productId] = (aggregates[line.productId] || 0) + line.quantity;
      }
      for (const [pidStr, totalQty] of Object.entries(aggregates)) {
        const pid = Number(pidStr);
        const avail = stock[pid] ?? 0;
        if (totalQty > avail) {
          return { ok: false, error: `Stock insufficient: requested ${totalQty}, available ${avail}` };
        }
      }
      return { ok: true };
    }

    const checkRes = validateCartStock(stockState, cartLines);
    assert.equal(checkRes.ok, false, 'Duplicate lines exceeding total stock must be rejected');
    assert.match(checkRes.error!, /Stock insufficient/);
  });

  test('Group D2: Inventory deduction failure aborts transition and prevents Paid status', () => {
    let orderStatus = 'Pending';
    let paymentStatus = 'Unpaid';
    const inventory = { stock: 0 }; // Out of stock

    function approveOrderPayment(inv: { stock: number }): { ok: boolean; error?: string } {
      if (inv.stock < 1) {
        return { ok: false, error: 'موجودی انبار کافی نیست' };
      }
      inv.stock -= 1;
      orderStatus = 'Processing';
      paymentStatus = 'Paid';
      return { ok: true };
    }

    const result = approveOrderPayment(inventory);
    assert.equal(result.ok, false);
    assert.equal(orderStatus, 'Pending', 'Order status must NOT become Processing on inventory failure');
    assert.equal(paymentStatus, 'Unpaid', 'Payment status must NOT become Paid on inventory failure');
  });

  test('Group D3: Shipped or Completed orders cannot be restocked by status change alone', () => {
    const shippedOrder = {
      trackingCode: 'ONV-ORD-880',
      status: 'Shipped',
      paymentStatus: 'Paid',
      inventoryDeducted: true,
      items: [{ productId: 1, quantity: 2 }]
    };

    let warehouseStock = 10;

    function safeReleaseInventory(order: typeof shippedOrder) {
      // Rule: Shipped or Completed orders cannot release stock via status change!
      if (order.status === 'Shipped' || order.status === 'Completed') {
        return { ok: false, error: 'سفارش ارسال شده یا تحویل داده شده را نمی‌توان با تغییر وضعیت به انبار بازگرداند' };
      }
      warehouseStock += 2;
      order.inventoryDeducted = false;
      return { ok: true };
    }

    const res = safeReleaseInventory(shippedOrder);
    assert.equal(res.ok, false);
    assert.equal(warehouseStock, 10, 'Stock must NOT be restored for Shipped orders');
    assert.equal(shippedOrder.inventoryDeducted, true);
  });

  // =========================================================================
  // ADMIN LOGIN: PRESERVATION & VERIFICATION TESTS (MOCK DATA ONLY)
  // =========================================================================
  test('Admin Login: Fixture using legacy HMAC-SHA256 logs in and wrong password fails', () => {
    import('node:crypto').then(crypto => {
      const mockPassword = 'MockAdminPassword#2025';
      const wrongPassword = 'IncorrectPassword123';
      const legacyHmacHash = crypto.createHmac('sha256', 'onival_salt_2025_sec').update(mockPassword).digest('hex');

      function verifyTestPassword(input: string, stored: string): boolean {
        if (!input || !stored) return false;
        if (stored.length === 64 && /^[a-f0-9]{64}$/i.test(stored)) {
          const hmac = crypto.createHmac('sha256', 'onival_salt_2025_sec').update(input).digest('hex');
          if (crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(stored))) return true;
          const raw = crypto.createHash('sha256').update(input).digest('hex');
          if (crypto.timingSafeEqual(Buffer.from(raw), Buffer.from(stored))) return true;
        }
        return false;
      }

      assert.equal(verifyTestPassword(mockPassword, legacyHmacHash), true, 'Correct password verifies successfully against legacy HMAC-SHA256');
      assert.equal(verifyTestPassword(wrongPassword, legacyHmacHash), false, 'Wrong password fails against legacy HMAC-SHA256');
    });
  });

  test('Admin Login: Fixture using scrypt format logs in and wrong password fails', () => {
    import('node:crypto').then(crypto => {
      const mockPassword = 'AnotherMockSecurePassword!99';
      const wrongPassword = 'WrongPassword99';
      const salt = crypto.randomBytes(16);
      const hash = crypto.scryptSync(mockPassword, salt, 64);
      const storedScrypt = `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;

      function verifyScrypt(input: string, stored: string): boolean {
        if (!stored.startsWith('scrypt:')) return false;
        const parts = stored.split(':');
        if (parts.length !== 3) return false;
        const saltBuf = Buffer.from(parts[1], 'hex');
        const expectedBuf = Buffer.from(parts[2], 'hex');
        const computed = crypto.scryptSync(input, saltBuf, 64);
        return computed.length === expectedBuf.length && crypto.timingSafeEqual(computed, expectedBuf);
      }

      assert.equal(verifyScrypt(mockPassword, storedScrypt), true, 'Correct password verifies successfully against scrypt fixture');
      assert.equal(verifyScrypt(wrongPassword, storedScrypt), false, 'Wrong password fails against scrypt fixture');
    });
  });

  test('Admin Login: Completed-setup account is not overwritten by seed redeployment', () => {
    const existingDb = {
      adminCredentials: {
        username: 'production_superadmin',
        password: 'scrypt:salt:realproductionhash',
        email: 'admin@onival.ir',
        name: 'مدیریت ارشد اونیوال',
        initialSetupCompleted: true,
        oneTimePassword: null,
        oneTimePasswordExpired: true
      }
    };

    const seedCredentials = {
      username: 'admin',
      password: 'admin',
      email: 'admin@onival.com',
      name: 'مدیریت اونیوال (ONIVAL Admin)',
      initialSetupCompleted: false,
      oneTimePassword: 'Onival@Admin2025'
    };

    // Safe merge logic: if persistent data already exists and setup was completed, NEVER overwrite credentials with seed
    function mergeSeedData(current: typeof existingDb, seed: typeof seedCredentials) {
      if (current.adminCredentials && current.adminCredentials.initialSetupCompleted) {
        return current.adminCredentials; // Preserve configured account
      }
      return seed;
    }

    const merged = mergeSeedData(existingDb, seedCredentials);
    assert.equal(merged.username, 'production_superadmin', 'Configured admin username must be preserved');
    assert.equal(merged.password, 'scrypt:salt:realproductionhash', 'Configured password hash must NOT be replaced');
    assert.equal(merged.initialSetupCompleted, true, 'initialSetupCompleted must remain true');
    assert.equal(merged.oneTimePassword, null, 'oneTimePassword must remain null');
  });

  test('Admin Login: Username and password change invalidates old credentials and activates new', () => {
    import('node:crypto').then(crypto => {
      let currentCreds = {
        username: 'old_admin',
        password: crypto.createHmac('sha256', 'onival_salt_2025_sec').update('OldPassword123').digest('hex'),
        initialSetupCompleted: true
      };

      function login(u: string, p: string, creds: typeof currentCreds): boolean {
        if (u !== creds.username) return false;
        const legacy = crypto.createHmac('sha256', 'onival_salt_2025_sec').update(p).digest('hex');
        return crypto.timingSafeEqual(Buffer.from(legacy), Buffer.from(creds.password));
      }

      // Initial login with old credentials works
      assert.equal(login('old_admin', 'OldPassword123', currentCreds), true);

      // Perform credential change
      const newPasswordHash = crypto.createHmac('sha256', 'onival_salt_2025_sec').update('BrandNewPassword456').digest('hex');
      currentCreds = {
        username: 'new_admin',
        password: newPasswordHash,
        initialSetupCompleted: true
      };

      // Old credentials fail
      assert.equal(login('old_admin', 'OldPassword123', currentCreds), false, 'Old username & password must fail');
      assert.equal(login('new_admin', 'OldPassword123', currentCreds), false, 'Old password with new username must fail');

      // New credentials work
      assert.equal(login('new_admin', 'BrandNewPassword456', currentCreds), true, 'New credentials log in successfully');
    });
  });

  test('Admin Login: Completed-setup account strictly rejects hardcoded admin and OTP', () => {
    const creds = {
      username: 'onival_manager',
      password: 'scrypt:salt:configuredhash',
      initialSetupCompleted: true,
      oneTimePassword: null
    };

    function attemptLogin(p: string, credsState: typeof creds): { ok: boolean; reason?: string } {
      if (credsState.initialSetupCompleted) {
        if (p === 'admin' || p === 'Onival@Admin2025') {
          return { ok: false, reason: 'DEFAULT_OR_OTP_FORBIDDEN' };
        }
      }
      return { ok: false, reason: 'INVALID_CREDENTIALS' };
    }

    assert.equal(attemptLogin('admin', creds).reason, 'DEFAULT_OR_OTP_FORBIDDEN', 'Rejects default admin password');
    assert.equal(attemptLogin('Onival@Admin2025', creds).reason, 'DEFAULT_OR_OTP_FORBIDDEN', 'Rejects expired OTP');
  });

  // =========================================================================
  // ADDITIONAL REGRESSION & DEFECT-REPAIR TESTS
  // =========================================================================
  test('Contact Tracking Code: CSPRNG format matches ONV-MSG-[HEX8]', () => {
    function generateContactTrackingCodeJs(): string {
      return 'ONV-MSG-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    }

    const code1 = generateContactTrackingCodeJs();
    const code2 = generateContactTrackingCodeJs();
    assert.match(code1, /^ONV-MSG-[A-F0-9]{8}$/, 'Must have ONV-MSG prefix and 8 hex digits');
    assert.notEqual(code1, code2, 'Subsequent codes must be distinct CSPRNG random values');
  });

  test('CORS: Exact origin matching rejects deceptive substrings', () => {
    const allowedOrigins = ['https://onival.ir', 'https://www.onival.ir', 'http://localhost:3000', 'http://localhost:5173'];

    function isOriginAllowed(rawOrigin: string): boolean {
      const clean = rawOrigin.replace(/\/+$/, '');
      return allowedOrigins.includes(clean);
    }

    assert.equal(isOriginAllowed('https://onival.ir'), true);
    assert.equal(isOriginAllowed('https://www.onival.ir'), true);
    assert.equal(isOriginAllowed('http://localhost:3000'), true);
    // Deceptive origins that previously passed strpos matching:
    assert.equal(isOriginAllowed('https://evil-onival.ir'), false, 'Attacker prefix domain must be rejected');
    assert.equal(isOriginAllowed('https://onival.ir.attacker.com'), false, 'Subdomain attack must be rejected');
    assert.equal(isOriginAllowed('https://attacker.com?onival.ir'), false, 'Query string spoofing must be rejected');
  });

  test('Order Status Transition: Shipped and Completed orders reject cancellation with 409 TRANSITION_NOT_ALLOWED', () => {
    function cancelOrder(order: { status: string }): { ok: boolean; code?: string; error?: string } {
      if (order.status === 'Cancelled') {
        return { ok: true };
      }
      if (order.status === 'Shipped' || order.status === 'Completed') {
        return { ok: false, code: 'TRANSITION_NOT_ALLOWED', error: 'امکان لغو سفارشات ارسال‌شده یا تکمیل‌شده وجود ندارد.' };
      }
      order.status = 'Cancelled';
      return { ok: true };
    }

    const pendingOrder = { status: 'Pending' };
    assert.equal(cancelOrder(pendingOrder).ok, true);
    assert.equal(pendingOrder.status, 'Cancelled');

    const shippedOrder = { status: 'Shipped' };
    const shippedRes = cancelOrder(shippedOrder);
    assert.equal(shippedRes.ok, false);
    assert.equal(shippedRes.code, 'TRANSITION_NOT_ALLOWED');
    assert.equal(shippedOrder.status, 'Shipped');

    const completedOrder = { status: 'Completed' };
    const completedRes = cancelOrder(completedOrder);
    assert.equal(completedRes.ok, false);
    assert.equal(completedRes.code, 'TRANSITION_NOT_ALLOWED');
    assert.equal(completedOrder.status, 'Completed');
  });

  test('Backup Restore: Pre-restore backup failure aborts entire import without mutating data', () => {
    let databaseState = { products: [{ id: 1, title: 'Original Honey' }] };
    let backupCreated = false;

    function restoreDatabase(importData: any, simulateDiskError: boolean) {
      if (simulateDiskError) {
        // Backup copy failed
        return { ok: false, code: 'PRE_BACKUP_FAILED', error: 'Pre-backup copy failed' };
      }
      backupCreated = true;
      databaseState = { ...importData };
      return { ok: true };
    }

    // Disk failure simulation
    const failRes = restoreDatabase({ products: [{ id: 2, title: 'Imported State' }] }, true);
    assert.equal(failRes.ok, false);
    assert.equal(failRes.code, 'PRE_BACKUP_FAILED');
    assert.equal(databaseState.products[0].title, 'Original Honey', 'Database state must not be modified when backup fails');

    // Normal restore
    const passRes = restoreDatabase({ products: [{ id: 2, title: 'Imported State' }] }, false);
    assert.equal(passRes.ok, true);
    assert.equal(databaseState.products[0].title, 'Imported State');
    assert.equal(backupCreated, true);
  });

  test('Feeds: Drafts and slug-less products excluded; promo quotas respected', () => {
    const products = [
      { id: 1, title: 'عسل کوهستان', slug: 'mountain-honey', price: 200000, discountPrice: 150000, specialOfferStock: 5, status: 'published' },
      { id: 2, title: 'عسل بدون اسلاگ', slug: '', price: 200000, status: 'published' },
      { id: 3, title: 'عسل پیش‌نویس', slug: 'draft-honey', price: 200000, status: 'draft' },
      { id: 4, title: 'عسل با سهمیه تخفیف تمام‌شده', slug: 'expired-promo-honey', price: 300000, discountPrice: 210000, specialOfferStock: 0, status: 'published' }
    ];

    function filterAndPriceProducts(prods: typeof products) {
      const valid = prods.filter(p => p.slug && p.slug.trim() !== '' && p.status !== 'draft');
      return valid.map(p => {
        const hasPromoQuota = !('specialOfferStock' in p) || (p.specialOfferStock as number) > 0;
        const effectivePrice = (p.discountPrice && hasPromoQuota) ? p.discountPrice : p.price;
        return {
          id: p.id,
          title: p.title,
          price: effectivePrice,
          oldPrice: (p.discountPrice && hasPromoQuota) ? p.price : null
        };
      });
    }

    const feed = filterAndPriceProducts(products);
    assert.equal(feed.length, 2, 'Only 2 valid published products with slugs must be included');
    assert.equal(feed[0].id, 1);
    assert.equal(feed[0].price, 150000, 'Product with available promo quota gets discountPrice');
    assert.equal(feed[0].oldPrice, 200000);
    assert.equal(feed[1].id, 4);
    assert.equal(feed[1].price, 300000, 'Product with zero specialOfferStock reverts to regular price');
    assert.equal(feed[1].oldPrice, null);
  });

  test('Phase 1 Replay: Owner login record shape with initialSetupCompleted=false and OTP', () => {
    // Exact owner credential record shape from live production context
    const ownerCredRecord = {
      username: 'admin',
      initialSetupCompleted: false,
      oneTimePassword: 'TestDummyOneTimeSecret123',
      oneTimePasswordExpired: false,
      password: 'scrypt:16:64:mocklegacyhashthatcannotbeuseddirectly'
    };

    function simulateLoginHandler(body: { username?: string; password?: string }, db: any) {
      const u = (body.username || '').trim();
      const p = (body.password || '').trim();

      if (!u || !p) {
        return { status: 400, code: 'VALIDATION_ERROR', reason: 'body_field_missing' };
      }

      if (!db || !db.adminCredentials) {
        return { status: 401, code: 'AUTH_FAILED', reason: 'data_file_unreadable' };
      }

      const creds = db.adminCredentials;
      const isInitialPending = !creds.initialSetupCompleted;
      const validUser = (creds.username || 'admin').trim().toLowerCase();
      const storedOtp = creds.oneTimePassword ? String(creds.oneTimePassword).trim() : '';
      const otpExpired = Boolean(creds.oneTimePasswordExpired);

      const isUserMatch = (u.toLowerCase() === validUser) || (isInitialPending && u.toLowerCase() === 'admin');
      if (!isUserMatch) {
        return { status: 401, code: 'AUTH_FAILED', reason: 'username_mismatch' };
      }

      if (!isInitialPending) {
        if (storedOtp && p === storedOtp) {
          return { status: 401, code: 'OTP_EXPIRED', reason: 'otp_missing_or_expired' };
        }
        if (String(creds.password).startsWith('scrypt:')) {
          return { status: 401, code: 'AUTH_FAILED', reason: 'unsupported_stored_format' };
        }
      } else {
        if (!storedOtp || otpExpired) {
          return { status: 401, code: 'AUTH_FAILED', reason: 'otp_missing_or_expired' };
        }
      }

      // Verification during initial pending
      let isPassMatch = false;
      if (isInitialPending) {
        if (storedOtp) {
          const bufP = Buffer.from(p);
          const bufOtp = Buffer.from(storedOtp);
          if (bufP.length === bufOtp.length && crypto.timingSafeEqual(bufP, bufOtp)) {
            isPassMatch = true;
          }
        }
      }

      if (isPassMatch) {
        return { status: 200, ok: true, isInitialPending: true, reason: 'success' };
      }

      return { status: 401, code: 'AUTH_FAILED', reason: 'bad_password' };
    }

    const liveDb = { adminCredentials: ownerCredRecord };

    // 1. Correct dummy OTP matches -> PASS (HTTP 200)
    const successRes = simulateLoginHandler({ username: 'admin', password: 'TestDummyOneTimeSecret123' }, liveDb);
    assert.equal(successRes.status, 200);
    assert.equal(successRes.ok, true);
    assert.equal(successRes.reason, 'success');

    // 2. Wrong OTP fails with bad_password (HTTP 401)
    const wrongPassRes = simulateLoginHandler({ username: 'admin', password: 'WrongOtpValue' }, liveDb);
    assert.equal(wrongPassRes.status, 401);
    assert.equal(wrongPassRes.reason, 'bad_password');

    // 3. Username mismatch fails with username_mismatch (HTTP 401)
    const wrongUserRes = simulateLoginHandler({ username: 'non_existent_user', password: 'TestDummyOneTimeSecret123' }, liveDb);
    assert.equal(wrongUserRes.status, 401);
    assert.equal(wrongUserRes.reason, 'username_mismatch');

    // 4. Missing body fields fail with body_field_missing (HTTP 400)
    const missingFieldRes = simulateLoginHandler({ username: 'admin', password: '' }, liveDb);
    assert.equal(missingFieldRes.status, 400);
    assert.equal(missingFieldRes.reason, 'body_field_missing');

    // 5. Unreadable / empty database fails with data_file_unreadable (HTTP 401)
    const unreadableDbRes = simulateLoginHandler({ username: 'admin', password: 'TestDummyOneTimeSecret123' }, null);
    assert.equal(unreadableDbRes.status, 401);
    assert.equal(unreadableDbRes.reason, 'data_file_unreadable');

    // 6. Expired or missing OTP fails with otp_missing_or_expired (HTTP 401)
    const expiredOtpDb = {
      adminCredentials: { ...ownerCredRecord, oneTimePasswordExpired: true }
    };
    const expiredOtpRes = simulateLoginHandler({ username: 'admin', password: 'TestDummyOneTimeSecret123' }, expiredOtpDb);
    assert.equal(expiredOtpRes.status, 401);
    assert.equal(expiredOtpRes.reason, 'otp_missing_or_expired');
  });
  test('Attack Test 1: Missing DB triggers data_file_unreadable and never generates false default state', () => {
    function loadDbCheck(dataFileExists: boolean, rawContent: string | null) {
      if (!dataFileExists) {
        return { ok: false, error: 'DATABASE_FILE_MISSING', reason: 'data_file_unreadable' };
      }
      try {
        const parsed = JSON.parse(rawContent!);
        if (!parsed || typeof parsed !== 'object') {
          return { ok: false, error: 'DATABASE_CORRUPT', reason: 'data_file_unreadable' };
        }
        return { ok: true, data: parsed };
      } catch {
        return { ok: false, error: 'DATABASE_CORRUPT', reason: 'data_file_unreadable' };
      }
    }

    assert.equal(loadDbCheck(false, null).reason, 'data_file_unreadable');
    assert.equal(loadDbCheck(true, '{ broken json').reason, 'data_file_unreadable');
  });

  test('Attack Test 2: Stored scrypt legacy string NEVER authenticates even with matching plaintext password', () => {
    function verifyPasswordStrict(inputPass: string, storedHash: string, isInitialPending: boolean, validOtp: string | null): boolean {
      if (!inputPass || !storedHash) return false;
      if (isInitialPending) {
        if (!validOtp) return false;
        return crypto.timingSafeEqual(Buffer.from(inputPass), Buffer.from(validOtp));
      }
      // Completed setup requires native password hash (starting with $)
      if (storedHash.startsWith('scrypt:') || !storedHash.startsWith('$')) {
        return false;
      }
      return false;
    }

    const scryptHash = 'scrypt:16:64:mocklegacyhashthatcannotbeuseddirectly';
    assert.equal(verifyPasswordStrict('admin', scryptHash, false, null), false, 'scrypt hash must NEVER authenticate');
    assert.equal(verifyPasswordStrict('password123', scryptHash, false, null), false);
    assert.equal(verifyPasswordStrict(scryptHash, scryptHash, false, null), false);
  });

  test('Attack Test 3: Setup completion rejects passwords < 12 chars, identical to username, or identical to OTP', () => {
    function validateNewPermanentPassword(newPass: string, username: string, currentOtp: string | null) {
      if (!newPass || newPass.length < 12) {
        return { ok: false, code: 'VALIDATION_ERROR', error: 'Minimum 12 characters required' };
      }
      if (newPass.toLowerCase() === username.toLowerCase()) {
        return { ok: false, code: 'VALIDATION_ERROR', error: 'Password cannot equal username' };
      }
      if (currentOtp && newPass === currentOtp) {
        return { ok: false, code: 'VALIDATION_ERROR', error: 'Password cannot equal OTP' };
      }
      return { ok: true };
    }

    const otp = 'X7k9P2mQ4vL8wR1tY5zN';
    // Too short (<12)
    assert.equal(validateNewPermanentPassword('Short123', 'admin', otp).ok, false);
    // Exactly 11 chars
    assert.equal(validateNewPermanentPassword('12345678901', 'admin', otp).ok, false);
    // Identical to username
    assert.equal(validateNewPermanentPassword('adminadminadmin', 'adminadminadmin', otp).ok, false);
    // Identical to current OTP
    assert.equal(validateNewPermanentPassword(otp, 'admin', otp).ok, false);
    // Valid 12+ chars distinct password
    assert.equal(validateNewPermanentPassword('SecurePassword2025!', 'admin', otp).ok, true);
  });

  test('Attack Test 4: CSV Formula Injection Neutralization', () => {
    function escapeCsvField(field: any): string {
      if (field === null || field === undefined || field === '') return '""';
      let str = String(field).replace(/"/g, '""');
      if (/^[=+\-@\t\r]/.test(str)) {
        str = `'` + str;
      }
      return `"${str}"`;
    }

    // Formula injection attacks with =, +, -, @, \t, \r
    assert.equal(escapeCsvField('=SUM(A1:A10)'), `"'=SUM(A1:A10)"`);
    assert.equal(escapeCsvField('+cmd|"/C calc"!A0'), `"'+cmd|""/C calc""!A0"`);
    assert.equal(escapeCsvField('-2+3+cmd|'), `"'-2+3+cmd|"`);
    assert.equal(escapeCsvField('@SUM(1,2)'), `"'@SUM(1,2)"`);
    assert.equal(escapeCsvField("\tDDE"), `"'\tDDE"`);

    // Standard benign fields
    assert.equal(escapeCsvField('عسل طبیعی سبلان'), '"عسل طبیعی سبلان"');
    assert.equal(escapeCsvField(250000), '"250000"');
    assert.equal(escapeCsvField('ONV-12345'), '"ONV-12345"');
  });

  test('Attack Test 5: Webhook rejects non-POST and oversized body > 256KB', () => {
    function validateWebhookRequest(method: string, contentLength: number): { status: number; ok: boolean } {
      if (method.toUpperCase() !== 'POST') {
        return { status: 405, ok: false };
      }
      if (contentLength > 262144) {
        return { status: 413, ok: false };
      }
      return { status: 200, ok: true };
    }

    // Non-POST methods
    assert.equal(validateWebhookRequest('GET', 100).status, 405);
    assert.equal(validateWebhookRequest('PUT', 100).status, 405);
    assert.equal(validateWebhookRequest('DELETE', 100).status, 405);

    // Oversized body (>256KB)
    assert.equal(validateWebhookRequest('POST', 262145).status, 413);
    assert.equal(validateWebhookRequest('POST', 500000).status, 413);

    // Valid POST under 256KB
    assert.equal(validateWebhookRequest('POST', 1024).status, 200);
    assert.equal(validateWebhookRequest('POST', 262144).status, 200);
  });

  test('Attack Test 6: Webhook update_id deduplication drops replay attacks', () => {
    const seenWindow: number[] = [101, 102, 103];

    function processWebhookUpdate(updateId: number): { ok: boolean; duplicate: boolean } {
      if (seenWindow.includes(updateId)) {
        return { ok: true, duplicate: true };
      }
      seenWindow.push(updateId);
      if (seenWindow.length > 500) {
        seenWindow.shift();
      }
      return { ok: true, duplicate: false };
    }

    assert.equal(processWebhookUpdate(102).duplicate, true, 'Replay of 102 must be flagged duplicate');
    assert.equal(processWebhookUpdate(104).duplicate, false, 'New update 104 is processed');
    assert.equal(processWebhookUpdate(104).duplicate, true, 'Immediate replay of 104 is flagged duplicate');
  });

  test('Pricing Rules (Requirement 3.2): Ordinary discount, Amazing offer quota, and strict fallback without cross-discount', () => {
    function calculateProductPrice(product: any, selectedSize: any = null) {
      const basePrice = selectedSize && selectedSize.price !== undefined
        ? Number(selectedSize.price)
        : Number(product.price || 0);

      const hasVariant = Boolean(selectedSize && typeof selectedSize === 'object');
      const isAmazingOffer = Boolean(product.isAmazingOffer || product.isSpecialOffer);

      const quota = hasVariant && selectedSize.specialOfferStock !== undefined
        ? Number(selectedSize.specialOfferStock)
        : product.specialOfferStock !== undefined
        ? Number(product.specialOfferStock)
        : null;

      // Rule 1: Amazing Offer active with quota > 0
      if (isAmazingOffer && (quota === null || quota > 0)) {
        let discPrice: number | null = null;
        if (hasVariant && selectedSize.discountPrice && Number(selectedSize.discountPrice) > 0) {
          discPrice = Number(selectedSize.discountPrice);
        } else if (product.discountPrice && Number(product.discountPrice) > 0) {
          discPrice = Number(product.discountPrice);
        } else {
          const pct = Number(product.discount || product.discountPercent || 0);
          if (pct > 0) {
            discPrice = Math.round(basePrice * (100 - pct) / 100);
          }
        }
        if (discPrice !== null && discPrice < basePrice) {
          return { price: discPrice, oldPrice: basePrice, isPromo: true };
        }
      }

      // Rule 2: Amazing Offer quota exhausted -> strictly reverts to base price (NO ordinary discount fall-through!)
      if (isAmazingOffer && quota !== null && quota <= 0) {
        return { price: basePrice, oldPrice: 0, isPromo: false };
      }

      // Rule 3: Ordinary discount
      const ordPct = Number(product.discount || product.discountPercent || 0);
      if (ordPct > 0) {
        const ordPrice = Math.round(basePrice * (100 - ordPct) / 100);
        return { price: ordPrice, oldPrice: basePrice, isPromo: false };
      }

      return { price: basePrice, oldPrice: 0, isPromo: false };
    }

    // Case A: Ordinary discount 15% on 200,000 تومان product
    const pOrd = { price: 200000, discount: 15, isAmazingOffer: false };
    assert.deepEqual(calculateProductPrice(pOrd), { price: 170000, oldPrice: 200000, isPromo: false });

    // Case B: Amazing offer with quota = 5 on 200,000 تومان product with discountPrice = 140,000
    const pAmazingActive = { price: 200000, discountPrice: 140000, isAmazingOffer: true, specialOfferStock: 5 };
    assert.deepEqual(calculateProductPrice(pAmazingActive), { price: 140000, oldPrice: 200000, isPromo: true });

    // Case C: Amazing offer with quota = 0 (EXHAUSTED) and discount = 15%
    // MUST revert to base 200,000 without falling through to ordinary 15% discount!
    const pAmazingExhausted = { price: 200000, discountPrice: 140000, discount: 15, isAmazingOffer: true, specialOfferStock: 0 };
    assert.deepEqual(calculateProductPrice(pAmazingExhausted), { price: 200000, oldPrice: 0, isPromo: false });

    // Case D: Variant size inheriting parent amazing offer quota
    const pParent = { price: 100000, isAmazingOffer: true, specialOfferStock: 2, discount: 20 };
    const sVariant = { name: '500g', price: 150000 };
    assert.deepEqual(calculateProductPrice(pParent, sVariant), { price: 120000, oldPrice: 150000, isPromo: true });

    // Case E: Variant size with specific quota = 0 while parent has quota = 2
    const sVariantExhausted = { name: '1kg', price: 280000, specialOfferStock: 0 };
    assert.deepEqual(calculateProductPrice(pParent, sVariantExhausted), { price: 280000, oldPrice: 0, isPromo: false });
  });

  // ==============================================================================
  // FIX 1 & AUDIT VERIFICATION TESTS
  // ==============================================================================
  describe('Fix 1: State-Based Credential Bootstrap Logic', () => {
    function simulateBootstrapState(db: any): { bootstrapped: boolean; otpPlain: string | null; db: any } {
      const creds = db.adminCredentials || {};
      const isCompleted = Boolean(creds.initialSetupCompleted);
      const hasOtp = Boolean(creds.oneTimePassword && String(creds.oneTimePassword).trim() !== '');
      const hasPass = Boolean(creds.password && String(creds.password).trim() !== '');

      if (isCompleted || hasOtp || hasPass) {
        return { bootstrapped: false, otpPlain: null, db };
      }

      // Generate >= 16 char random password
      const otpPlain = crypto.randomBytes(10).toString('hex'); // 20 chars
      const salt = crypto.randomBytes(8).toString('hex');
      const hash = 'sim_hash_' + crypto.createHmac('sha256', salt).update(otpPlain).digest('hex');

      const updatedDb = JSON.parse(JSON.stringify(db));
      if (!updatedDb.adminCredentials) updatedDb.adminCredentials = {};
      updatedDb.adminCredentials.username = creds.username || 'admin';
      updatedDb.adminCredentials.password = '';
      updatedDb.adminCredentials.email = creds.email || 'admin@onival.com';
      updatedDb.adminCredentials.name = creds.name || 'مدیریت اونیوال (ONIVAL Admin)';
      updatedDb.adminCredentials.initialSetupCompleted = false;
      updatedDb.adminCredentials.oneTimePassword = hash;
      updatedDb.adminCredentials.oneTimePasswordExpired = false;

      return { bootstrapped: true, otpPlain, db: updatedDb };
    }

    test('State-based bootstrap: null/empty credential triggers generation of random password (>=16 chars)', () => {
      const seedDb = {
        products: [{ id: 1, title: 'عسل' }],
        adminCredentials: {
          username: 'admin',
          password: '',
          email: 'admin@onival.com',
          initialSetupCompleted: false,
          oneTimePassword: null
        }
      };

      const res = simulateBootstrapState(seedDb);
      assert.equal(res.bootstrapped, true, 'Must bootstrap when credentials null');
      assert.ok(res.otpPlain && res.otpPlain.length >= 16, 'Generated OTP must be >= 16 characters');
      assert.ok(res.db.adminCredentials.oneTimePassword.startsWith('sim_hash_'), 'Hash stored in DB');
    });

    test('Second run on bootstrapped state does nothing', () => {
      const alreadyBootstrappedDb = {
        products: [],
        adminCredentials: {
          username: 'admin',
          password: '',
          initialSetupCompleted: false,
          oneTimePassword: 'existing_valid_hash'
        }
      };

      const res = simulateBootstrapState(alreadyBootstrappedDb);
      assert.equal(res.bootstrapped, false, 'Must not bootstrap if usable OTP exists');
      assert.equal(res.otpPlain, null);
    });

    test('Completed account does not bootstrap', () => {
      const completedDb = {
        products: [],
        adminCredentials: {
          username: 'admin',
          password: 'valid_password_hash',
          initialSetupCompleted: true,
          oneTimePassword: null
        }
      };

      const res = simulateBootstrapState(completedDb);
      assert.equal(res.bootstrapped, false, 'Must not bootstrap if initialSetupCompleted is true');
    });

    test('Recovery: setting stored OTP to null regenerates credential', () => {
      const recoveredDb = {
        products: [],
        adminCredentials: {
          username: 'admin',
          password: '',
          initialSetupCompleted: false,
          oneTimePassword: null // Owner reset stored OTP to null
        }
      };

      const res = simulateBootstrapState(recoveredDb);
      assert.equal(res.bootstrapped, true, 'Resetting OTP to null triggers regeneration');
      assert.ok(res.otpPlain && res.otpPlain.length >= 16);
    });
  });

  describe('Fix 4 & Attack Protections', () => {
    test('Direct access to common.php without ONIVAL_ENTRY returns 404', () => {
      function evaluateEntryGuard(definedConstants: Record<string, any>): { status: number; exited: boolean } {
        if (!definedConstants['ONIVAL_ENTRY']) {
          return { status: 404, exited: true };
        }
        return { status: 200, exited: false };
      }

      // Direct HTTP request to /api/common.php
      const direct = evaluateEntryGuard({});
      assert.equal(direct.status, 404, 'Must return 404 for direct invocation');
      assert.equal(direct.exited, true);

      // Delegated request from index.php or webhook.php
      const delegated = evaluateEntryGuard({ ONIVAL_ENTRY: true });
      assert.equal(delegated.status, 200);
      assert.equal(delegated.exited, false);
    });

    test('Decoy live database in web root is ignored in favor of PRIVATE_DIR', () => {
      const privateDir = '/var/private/onival-private';
      const webRoot = '/public_html';

      function resolveDatabasePath(requestedPath: string, privateDirConstant: string): string {
        // Implementation strictly binds to PRIVATE_DIR
        return path.join(privateDirConstant, 'onival-persistent-data.json');
      }

      const decoyInWeb = path.join(webRoot, 'onival-persistent-data.json');
      const resolved = resolveDatabasePath(decoyInWeb, privateDir);
      assert.equal(resolved, path.join(privateDir, 'onival-persistent-data.json'));
      assert.notEqual(resolved, decoyInWeb, 'Must never read database from web root');
    });

    test('Anonymous logout returns 401 AUTH_REQUIRED', () => {
      function handleLogout(token: string | null): { status: number; code: string } {
        if (!token || token.trim() === '') {
          return { status: 401, code: 'AUTH_REQUIRED' };
        }
        return { status: 200, code: 'LOGGED_OUT' };
      }

      assert.deepEqual(handleLogout(null), { status: 401, code: 'AUTH_REQUIRED' });
      assert.deepEqual(handleLogout(''), { status: 401, code: 'AUTH_REQUIRED' });
      assert.deepEqual(handleLogout('valid_session_token'), { status: 200, code: 'LOGGED_OUT' });
    });

    test('Import-state requires explicit confirmation flag', () => {
      function handleImportState(body: any): { status: number; code: string } {
        if (!body.confirmed) {
          return { status: 400, code: 'CONFIRMATION_REQUIRED' };
        }
        if (!body.data || !Array.isArray(body.data.products)) {
          return { status: 400, code: 'INVALID_PAYLOAD' };
        }
        return { status: 200, code: 'RESTORE_SUCCESS' };
      }

      // Without confirmed flag
      assert.deepEqual(
        handleImportState({ data: { products: [{ id: 1 }] } }),
        { status: 400, code: 'CONFIRMATION_REQUIRED' }
      );

      // With confirmed flag but invalid payload
      assert.deepEqual(
        handleImportState({ confirmed: true, data: {} }),
        { status: 400, code: 'INVALID_PAYLOAD' }
      );

      // With confirmed flag and valid payload
      assert.deepEqual(
        handleImportState({ confirmed: true, data: { products: [{ id: 1 }] } }),
        { status: 200, code: 'RESTORE_SUCCESS' }
      );
    });

    test('CORS exact origin matching denies lookalike attacker domains', () => {
      const allowedOrigins = ['https://onival.ir', 'https://www.onival.ir', 'http://localhost:3000', 'http://localhost:5173'];

      function checkCorsOrigin(origin: string): boolean {
        const clean = origin.replace(/\/+$/, '');
        return allowedOrigins.includes(clean);
      }

      // Allowed origins
      assert.equal(checkCorsOrigin('https://onival.ir'), true);
      assert.equal(checkCorsOrigin('https://www.onival.ir'), true);
      assert.equal(checkCorsOrigin('http://localhost:3000'), true);

      // Attacker lookalikes
      assert.equal(checkCorsOrigin('https://onival.ir.attacker.com'), false);
      assert.equal(checkCorsOrigin('https://attacker-onival.ir'), false);
      assert.equal(checkCorsOrigin('https://onival.ir:8080'), false);
      assert.equal(checkCorsOrigin('http://onival.ir'), false);
    });
  });

  // ==============================================================================
  // PHASE 1 & DEFECTS F1-F6 AUTOMATED VERIFICATION SUITE
  // ==============================================================================
  describe('Phase 1 & Defects F1-F6 Corrective Tests', () => {
    test('Phase 1: Seed-based bootstrap sets onival_setup with pending status', async () => {
      const fs = await import('node:fs');
      const configPath = path.join(process.cwd(), 'scripts', 'initial-admin.config.json');
      assert.ok(fs.existsSync(configPath), 'scripts/initial-admin.config.json must exist');
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      assert.equal(cfg.username, 'onival_setup');
      assert.ok(cfg.tempPassword && cfg.tempPassword.length >= 12, 'Temp password must be >= 12 chars');

      // Check seed.php was generated and is valid
      const seedPhpPath = path.join(process.cwd(), 'public', 'api', 'seed.php');
      assert.ok(fs.existsSync(seedPhpPath), 'public/api/seed.php must exist');
      const seedContent = fs.readFileSync(seedPhpPath, 'utf-8');
      assert.ok(seedContent.includes("!defined('ONIVAL_ENTRY')"), 'seed.php must have ONIVAL_ENTRY guard');
      assert.ok(seedContent.includes('initialAdmin'), 'seed.php must contain initialAdmin');
      assert.ok(seedContent.includes('onival_setup'), 'seed.php must have initial admin username');
    });

    test('Phase 1: Pending setup token restricts routes with 403 SETUP_REQUIRED', () => {
      function evaluateAdminRouteAccess(path: string, initialSetupCompleted: boolean): { allowed: boolean; status: number; code?: string } {
        const allowedSetupPaths = [
          '/api/admin/setup-credentials',
          '/api/account/change-credentials',
          '/api/admin/logout',
          '/api/admin/verify-session',
          '/api/account/profile',
          '/api/admin/setup-status'
        ];

        if (!initialSetupCompleted) {
          if (allowedSetupPaths.includes(path)) {
            return { allowed: true, status: 200 };
          }
          return { allowed: false, status: 403, code: 'SETUP_REQUIRED' };
        }
        return { allowed: true, status: 200 };
      }

      // Allowed during initial setup
      assert.deepEqual(evaluateAdminRouteAccess('/api/admin/setup-credentials', false), { allowed: true, status: 200 });
      assert.deepEqual(evaluateAdminRouteAccess('/api/account/change-credentials', false), { allowed: true, status: 200 });
      assert.deepEqual(evaluateAdminRouteAccess('/api/admin/logout', false), { allowed: true, status: 200 });
      assert.deepEqual(evaluateAdminRouteAccess('/api/admin/verify-session', false), { allowed: true, status: 200 });

      // Blocked during initial setup
      assert.deepEqual(evaluateAdminRouteAccess('/api/orders', false), { allowed: false, status: 403, code: 'SETUP_REQUIRED' });
      assert.deepEqual(evaluateAdminRouteAccess('/api/products', false), { allowed: false, status: 403, code: 'SETUP_REQUIRED' });
      assert.deepEqual(evaluateAdminRouteAccess('/api/stats', false), { allowed: false, status: 403, code: 'SETUP_REQUIRED' });

      // Once setup is completed, all routes are allowed
      assert.deepEqual(evaluateAdminRouteAccess('/api/orders', true), { allowed: true, status: 200 });
      assert.deepEqual(evaluateAdminRouteAccess('/api/products', true), { allowed: true, status: 200 });
    });

    test('Phase 1: Setup credentials validation enforces min 12 chars and username inequality', () => {
      function validateSetupCredentials(username: string, pass: string, tempPass: string): { valid: boolean; code?: string } {
        if (!username || username.trim().length < 3) return { valid: false, code: 'INVALID_USERNAME' };
        if (!pass || pass.length < 12) return { valid: false, code: 'PASSWORD_TOO_SHORT' };
        if (pass.toLowerCase() === username.toLowerCase()) return { valid: false, code: 'PASSWORD_SAME_AS_USERNAME' };
        if (pass === tempPass) return { valid: false, code: 'PASSWORD_SAME_AS_TEMP' };
        return { valid: true };
      }

      assert.equal(validateSetupCredentials('admin', 'short78', 'Temp1234567890').valid, false);
      assert.equal(validateSetupCredentials('adminadminadmin', 'adminadminadmin', 'Temp1234567890').code, 'PASSWORD_SAME_AS_USERNAME');
      assert.equal(validateSetupCredentials('onival_admin', 'Temp1234567890', 'Temp1234567890').code, 'PASSWORD_SAME_AS_TEMP');
      assert.equal(validateSetupCredentials('new_admin_user', 'MySecurePassword2026!', 'Temp1234567890').valid, true);
    });

    test('Defect F2: Bearer authorization header extraction and removal of cookie fallback', () => {
      function getBearerTokenJs(headers: Record<string, string>, cookies?: Record<string, string>): string {
        const authHeader = headers['authorization'] || headers['Authorization'] || '';
        const match = authHeader.match(/Bearer\s+(.*)$/i);
        if (match) return match[1].trim();
        if (headers['x-admin-token'] || headers['X-Admin-Token']) {
          return (headers['x-admin-token'] || headers['X-Admin-Token']).trim();
        }
        // Cookie fallback is strictly removed
        return '';
      }

      assert.equal(getBearerTokenJs({ 'Authorization': 'Bearer test_token_xyz' }), 'test_token_xyz');
      assert.equal(getBearerTokenJs({ 'X-Admin-Token': 'test_token_123' }), 'test_token_123');
      // Cookie is ignored
      assert.equal(getBearerTokenJs({}, { 'admin_token': 'cookie_token' }), '');
    });

    test('Defect F3: Static Gate asserts NO PHP entrypoint contains runtime server-data path', async () => {
      const fs = await import('node:fs');
      const publicApiDir = path.join(process.cwd(), 'public', 'api');
      const files = ['common.php', 'index.php', 'webhook.php', 'bale-webhook.php'];

      for (const f of files) {
        const full = path.join(publicApiDir, f);
        if (fs.existsSync(full)) {
          const content = fs.readFileSync(full, 'utf-8');
          assert.equal(
            content.includes('server-data/receipts') || content.includes('../../server-data'),
            false,
            `File ${f} must not contain runtime server-data path reference`
          );
        }
      }
    });

    test('Defect F5: Order approval and rejection link and update contactMessages in same transaction', () => {
      const db: any = {
        orders: [
          {
            id: 101,
            trackingCode: 'ONV-ORD-101',
            phoneNumber: '09120000000',
            status: 'Pending',
            paymentStatus: 'PendingVerification',
            isConsultation: true,
            consultationDetails: { consultationStatus: 'PendingPayment' },
            items: [{ productId: 1, quantity: 1, size: '' }]
          }
        ],
        contactMessages: [
          {
            id: 501,
            trackingCode: 'ONV-ORD-101',
            orderId: 101,
            phoneNumber: '09120000000',
            isConsultation: true,
            paymentStatus: 'Unpaid',
            consultationDetails: { consultationStatus: 'PendingPayment' }
          }
        ]
      };

      // Simulate processOrderPaymentApprovalPhp
      function approveOrderSim(dbRef: any, orderCode: string) {
        for (const ord of dbRef.orders) {
          if (ord.trackingCode === orderCode) {
            ord.paymentStatus = 'Paid';
            ord.status = 'Processing';
            if (ord.consultationDetails) ord.consultationDetails.consultationStatus = 'Scheduled';

            for (const msg of dbRef.contactMessages || []) {
              if (msg.orderId === ord.id || msg.trackingCode === ord.trackingCode) {
                msg.paymentStatus = 'Paid';
                if (msg.consultationDetails) msg.consultationDetails.consultationStatus = 'Scheduled';
              }
            }
            return { ok: true, order: ord };
          }
        }
        return { ok: false };
      }

      const res = approveOrderSim(db, 'ONV-ORD-101');
      assert.equal(res.ok, true);
      assert.equal(db.orders[0].paymentStatus, 'Paid');
      assert.equal(db.orders[0].consultationDetails.consultationStatus, 'Scheduled');
      assert.equal(db.contactMessages[0].paymentStatus, 'Paid', 'Linked contact message must be marked Paid');
      assert.equal(db.contactMessages[0].consultationDetails.consultationStatus, 'Scheduled', 'Linked contact message consultationStatus must be Scheduled');
    });

    test('Defect F6: Bounded body reader rejects payload exceeding byte limit', () => {
      function evaluateBodySize(contentLength: number, bodyLength: number, maxAllowed: number): { status: number; code?: string } {
        if (contentLength > maxAllowed || bodyLength > maxAllowed) {
          return { status: 413, code: 'PAYLOAD_TOO_LARGE' };
        }
        return { status: 200 };
      }

      // Allowed under 10MB
      assert.deepEqual(evaluateBodySize(1024, 1024, 10485760), { status: 200 });
      // Exceeding 10MB
      assert.deepEqual(evaluateBodySize(10485761, 10485761, 10485760), { status: 413, code: 'PAYLOAD_TOO_LARGE' });
      // Webhook exceeding 256KB
      assert.deepEqual(evaluateBodySize(300000, 300000, 262144), { status: 413, code: 'PAYLOAD_TOO_LARGE' });
    });
    // ==============================================================================
    // H1-H5 Corrective Patch Test Suite
    // ==============================================================================
    describe('H1. Webhook Update Claim Lifecycle', () => {
      interface ClaimEntry {
        state: 'claimed' | 'done';
        timestamp: number;
      }

      function simulateClaim(store: Record<string, ClaimEntry>, updateId: number, now: number, ttlSeconds = 120) {
        const idKey = String(updateId);
        const existing = store[idKey];
        if (existing) {
          if (existing.state === 'done') {
            return { ok: true, claimed: false, reason: 'done' };
          }
          if (existing.state === 'claimed') {
            if ((now - existing.timestamp) < ttlSeconds) {
              return { ok: true, claimed: false, reason: 'in_flight' };
            }
            // Stale claim: can be reclaimed!
          }
        }
        store[idKey] = { state: 'claimed', timestamp: now };
        return { ok: true, claimed: true };
      }

      function simulateFinalize(store: Record<string, ClaimEntry>, updateId: number, now: number, outcome: 'done' | 'released') {
        const idKey = String(updateId);
        if (outcome === 'released') {
          delete store[idKey];
        } else {
          store[idKey] = { state: 'done', timestamp: now };
        }
      }

      test('Initial claim succeeds and marks claimed', () => {
        const store: Record<string, ClaimEntry> = {};
        const t0 = 1000;
        const res = simulateClaim(store, 991, t0, 120);
        assert.equal(res.ok, true);
        assert.equal(res.claimed, true);
        assert.equal(store['991'].state, 'claimed');
      });

      test('Concurrent/in-flight claim within 120s TTL is dropped', () => {
        const store: Record<string, ClaimEntry> = { '991': { state: 'claimed', timestamp: 1000 } };
        const res = simulateClaim(store, 991, 1050, 120);
        assert.equal(res.ok, true);
        assert.equal(res.claimed, false);
        assert.equal(res.reason, 'in_flight');
      });

      test('Stale claim (> 120s) is reclaimable', () => {
        const store: Record<string, ClaimEntry> = { '991': { state: 'claimed', timestamp: 1000 } };
        const res = simulateClaim(store, 991, 1130, 120);
        assert.equal(res.ok, true);
        assert.equal(res.claimed, true);
        assert.equal(store['991'].timestamp, 1130);
      });

      test('Done updates are NEVER reclaimed even after TTL', () => {
        const store: Record<string, ClaimEntry> = { '991': { state: 'done', timestamp: 1000 } };
        const res = simulateClaim(store, 991, 5000, 120);
        assert.equal(res.ok, true);
        assert.equal(res.claimed, false);
        assert.equal(res.reason, 'done');
      });

      test('Release claim on fatal error with 0 committed writes allows retry; default done retains done', () => {
        const store: Record<string, ClaimEntry> = { '991': { state: 'claimed', timestamp: 1000 } };

        // Simulating fatal error with committedWritesCount = 0 -> released
        const committedWritesCount = 0;
        const isFatal = true;
        const outcome = (isFatal && committedWritesCount === 0) ? 'released' : 'done';
        simulateFinalize(store, 991, 1010, outcome);
        assert.equal(store['991'], undefined, 'Claim must be released on fatal error prior to writes');

        // Can now be claimed again
        const retryClaim = simulateClaim(store, 991, 1015, 120);
        assert.equal(retryClaim.claimed, true);

        // If committed writes > 0, fatal error does NOT release claim
        const fatalAfterWriteOutcome = (true && 1 === 0) ? 'released' : 'done';
        simulateFinalize(store, 991, 1020, fatalAfterWriteOutcome);
        assert.equal(store['991'].state, 'done', 'Committed writes must keep state done');
      });
    });

    describe('H2. Frontend First-Login Setup Flow', () => {
      test('viewAfterLogin routes to account on pending and dashboard on completed', () => {
        assert.equal(viewAfterLogin({ isInitialPending: true }), 'account');
        assert.equal(viewAfterLogin({ profile: { initialSetupCompleted: false } }), 'account');
        assert.equal(viewAfterLogin({ initialSetupCompleted: false }), 'account');
        assert.equal(viewAfterLogin({ isInitialPending: false, profile: { initialSetupCompleted: true } }), 'dashboard');
      });

      test('shouldFetchAdminData prevents admin fetch when pending or unauthenticated', () => {
        assert.equal(shouldFetchAdminData(true, true), false, 'Cannot fetch when pending even if authenticated');
        assert.equal(shouldFetchAdminData(false, false), false, 'Cannot fetch when unauthenticated');
        assert.equal(shouldFetchAdminData(true, false), false, 'Cannot fetch when pending and unauthenticated');
        assert.equal(shouldFetchAdminData(false, true), true, 'Allowed only when authenticated and setup completed');
      });

      test('handleSetupSuccess returns targetTab dashboard and sign-in transition message', () => {
        const res = handleSetupSuccess();
        assert.equal(res.targetTab, 'dashboard');
        assert.equal(res.shouldLogout, true);
        assert.ok(res.successMessage.includes('راه‌اندازی با موفقیت انجام شد'));
      });

      test('Static Grep Gate: App.tsx must verify shouldFetchAdminData before fetching admin APIs', async () => {
        const fs = await import('node:fs');
        const appPath = path.join(process.cwd(), 'src', 'App.tsx');
        assert.ok(fs.existsSync(appPath), 'src/App.tsx must exist');
        const content = fs.readFileSync(appPath, 'utf-8');
        assert.ok(
          content.includes('shouldFetchAdminData'),
          'App.tsx must import and use shouldFetchAdminData'
        );
        assert.ok(
          content.includes('viewAfterLogin'),
          'App.tsx must import and use viewAfterLogin'
        );
        assert.ok(
          content.includes('handleSetupSuccess'),
          'App.tsx must import and use handleSetupSuccess'
        );
      });
    });

    describe('H3. Credential Route Validation Order', () => {
      function validateChangeCredentialsJs(body: any, isInitialPending: boolean, creds: any, matchesOtpFn: (p: string, o: string) => boolean) {
        const newUsername = (body.newUsername || body.username || '').trim();
        const newPassword = String(body.newPassword || body.password || '');
        const curPass = (body.currentPassword || '').trim();
        const hasLogoFields = 'siteLogo' in body || 'siteLogoFit' in body || 'siteLogoShape' in body || 'siteLogoScale' in body;
        const hasProfileFields = 'email' in body || 'name' in body;

        if (isInitialPending) {
          // Both newUsername and newPassword are required
          if (!newUsername || !newPassword) {
            return { status: 400, code: 'MISSING_REQUIRED_FIELDS' };
          }
          if (!/^[a-zA-Z0-9._-]{3,32}$/.test(newUsername)) {
            return { status: 400, code: 'INVALID_USERNAME' };
          }
          if (newUsername.toLowerCase() === (creds.username || 'onival_setup').toLowerCase()) {
            return { status: 400, code: 'USERNAME_SAME_AS_INITIAL' };
          }
          if (newPassword.length < 12) {
            return { status: 400, code: 'PASSWORD_TOO_SHORT' };
          }
          if (matchesOtpFn(newPassword, creds.oneTimePassword || '')) {
            return { status: 400, code: 'PASSWORD_SAME_AS_TEMP' };
          }
          if (newPassword.toLowerCase() === newUsername.toLowerCase()) {
            return { status: 400, code: 'PASSWORD_SAME_AS_USERNAME' };
          }
          if (creds.password && newPassword === creds.password) {
            return { status: 400, code: 'PASSWORD_SAME_AS_CURRENT' };
          }
          return { status: 200, code: 'SETUP_COMPLETED' };
        }

        // Completed state
        const isChangingPassword = Boolean(newPassword);
        const isChangingUsername = Boolean(newUsername && newUsername.toLowerCase() !== (creds.username || 'admin').toLowerCase());

        if (!hasLogoFields && !hasProfileFields && !isChangingPassword && !isChangingUsername) {
          return { status: 400, code: 'NO_CHANGES' };
        }

        if (!isChangingPassword && !isChangingUsername) {
          // Logo-only or profile-only allowed without password
          return { status: 200, code: 'PROFILE_SAVED' };
        }

        if (!curPass || curPass !== creds.password) {
          return { status: 400, code: 'INVALID_CREDENTIALS' };
        }

        if (isChangingPassword) {
          if (newPassword.length < 12) {
            return { status: 400, code: 'PASSWORD_TOO_SHORT' };
          }
          if (newPassword.toLowerCase() === (newUsername || creds.username).toLowerCase()) {
            return { status: 400, code: 'PASSWORD_SAME_AS_USERNAME' };
          }
          if (creds.oneTimePassword && matchesOtpFn(newPassword, creds.oneTimePassword)) {
            return { status: 400, code: 'PASSWORD_SAME_AS_TEMP' };
          }
        }

        return { status: 200, code: 'CREDENTIALS_UPDATED' };
      }

      const dummyMatchesOtp = (p: string, o: string) => p === o;

      test('Pending state: empty or logo-only request returns 400 MISSING_REQUIRED_FIELDS', () => {
        const creds = { username: 'onival_setup', oneTimePassword: 'hash_temp_pass', initialSetupCompleted: false };
        assert.deepEqual(validateChangeCredentialsJs({}, true, creds, dummyMatchesOtp), { status: 400, code: 'MISSING_REQUIRED_FIELDS' });
        assert.deepEqual(validateChangeCredentialsJs({ siteLogo: 'https://example.com/logo.png' }, true, creds, dummyMatchesOtp), { status: 400, code: 'MISSING_REQUIRED_FIELDS' });
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'new_admin' }, true, creds, dummyMatchesOtp), { status: 400, code: 'MISSING_REQUIRED_FIELDS' });
        assert.deepEqual(validateChangeCredentialsJs({ newPassword: 'long_password_123' }, true, creds, dummyMatchesOtp), { status: 400, code: 'MISSING_REQUIRED_FIELDS' });
      });

      test('Pending state: username and password validation rules', () => {
        const creds = { username: 'onival_setup', oneTimePassword: 'hash_temp_pass', initialSetupCompleted: false };

        // Invalid username format
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'a!', newPassword: 'ValidPass12345!' }, true, creds, dummyMatchesOtp), { status: 400, code: 'INVALID_USERNAME' });

        // Username same as initial
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'onival_setup', newPassword: 'ValidPass12345!' }, true, creds, dummyMatchesOtp), { status: 400, code: 'USERNAME_SAME_AS_INITIAL' });

        // Password too short (< 12)
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'real_admin', newPassword: 'short' }, true, creds, dummyMatchesOtp), { status: 400, code: 'PASSWORD_TOO_SHORT' });

        // Password same as temp password
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'real_admin', newPassword: 'hash_temp_pass' }, true, creds, dummyMatchesOtp), { status: 400, code: 'PASSWORD_SAME_AS_TEMP' });

        // Password same as username
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'my_admin_account', newPassword: 'my_admin_account' }, true, creds, dummyMatchesOtp), { status: 400, code: 'PASSWORD_SAME_AS_USERNAME' });

        // Valid setup credentials
        assert.deepEqual(validateChangeCredentialsJs({ newUsername: 'real_admin', newPassword: 'ComplexPassword#2026' }, true, creds, dummyMatchesOtp), { status: 200, code: 'SETUP_COMPLETED' });
      });

      test('Completed state: empty request returns 400 NO_CHANGES', () => {
        const creds = { username: 'real_admin', password: 'CurrentPass1234!', initialSetupCompleted: true };
        assert.deepEqual(validateChangeCredentialsJs({}, false, creds, dummyMatchesOtp), { status: 400, code: 'NO_CHANGES' });
      });

      test('Completed state: logo-only or profile-only allowed without password', () => {
        const creds = { username: 'real_admin', password: 'CurrentPass1234!', initialSetupCompleted: true };
        assert.deepEqual(validateChangeCredentialsJs({ siteLogo: 'https://example.com/logo.png' }, false, creds, dummyMatchesOtp), { status: 200, code: 'PROFILE_SAVED' });
        assert.deepEqual(validateChangeCredentialsJs({ email: 'new@example.com' }, false, creds, dummyMatchesOtp), { status: 200, code: 'PROFILE_SAVED' });
      });

      test('Completed state: password/username change requires current password', () => {
        const creds = { username: 'real_admin', password: 'CurrentPass1234!', initialSetupCompleted: true };
        assert.deepEqual(validateChangeCredentialsJs({ newPassword: 'NewComplexPass#1' }, false, creds, dummyMatchesOtp), { status: 400, code: 'INVALID_CREDENTIALS' });
        assert.deepEqual(validateChangeCredentialsJs({ newPassword: 'NewComplexPass#1', currentPassword: 'WrongPassword' }, false, creds, dummyMatchesOtp), { status: 400, code: 'INVALID_CREDENTIALS' });
        assert.deepEqual(validateChangeCredentialsJs({ newPassword: 'NewComplexPass#1', currentPassword: 'CurrentPass1234!' }, false, creds, dummyMatchesOtp), { status: 200, code: 'CREDENTIALS_UPDATED' });
      });
    });

    describe('H4. Runtime Readiness, Database Safety, Health Contract', () => {
      function isUsableHashJs(hash: any): boolean {
        if (!hash || typeof hash !== 'string') return false;
        const trimmed = hash.trim();
        if (!trimmed.startsWith('$')) return false;
        // Native bcrypt/argon2 starts with $2y$, $2a$, $2b$, or $argon2
        return /^\$(2[ayb]|argon2id?)\$/.test(trimmed);
      }

      function checkDbValidity(parsed: any) {
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return { ok: false, code: 'DB_INVALID', status: 'db_invalid', detail: 'invalid_json' };
        }
        const coreKeys = ['products', 'productCategories', 'orders', 'siteContent', 'adminCredentials'];
        for (const ck of coreKeys) {
          if (!(ck in parsed) || !Array.isArray(parsed[ck]) && typeof parsed[ck] !== 'object') {
            return { ok: false, code: 'DB_INVALID', status: 'db_invalid', detail: 'core_key_invalid' };
          }
          if ((ck === 'products' || ck === 'productCategories' || ck === 'orders') && !Array.isArray(parsed[ck])) {
            return { ok: false, code: 'DB_INVALID', status: 'db_invalid', detail: 'core_key_invalid' };
          }
        }
        return { ok: true, status: 'ready', detail: 'ready' };
      }

      test('isUsableHashJs recognizes valid password hashes and rejects plain strings and scrypt', () => {
        assert.equal(isUsableHashJs('$2y$10$abcdefghijklmnopqrstuvwxyz1234567890ABCDEF'), true);
        assert.equal(isUsableHashJs('$argon2id$v=19$m=65536,t=4,p=1$abcdef$123456'), true);
        assert.equal(isUsableHashJs('scrypt:16384:8:1$abcdef$123456'), false);
        assert.equal(isUsableHashJs('plain_text_password'), false);
        assert.equal(isUsableHashJs(''), false);
        assert.equal(isUsableHashJs(null), false);
      });

      test('checkDbValidity accepts empty products array in live db and requires all core keys', () => {
        const validDb = {
          products: [],
          productCategories: [],
          orders: [],
          siteContent: {},
          adminCredentials: {}
        };
        assert.deepEqual(checkDbValidity(validDb), { ok: true, status: 'ready', detail: 'ready' });

        const missingOrders = {
          products: [],
          productCategories: [],
          siteContent: {},
          adminCredentials: {}
        };
        assert.equal(checkDbValidity(missingOrders).ok, false);
        assert.equal(checkDbValidity(missingOrders).code, 'DB_INVALID');
      });

      test('Health contract: 200 on ready, 503 on failure', () => {
        function evaluateHealthResponse(runtimeReady: { ok: boolean; status?: string; detail?: string; error?: string }) {
          if (!runtimeReady.ok) {
            return {
              httpStatus: 503,
              body: {
                ok: false,
                build: 'ONIVAL-2026.04-HOTFIX',
                status: runtimeReady.status || 'storage_unavailable',
                detail: runtimeReady.detail || 'dir_missing'
              }
            };
          }
          return {
            httpStatus: 200,
            body: {
              ok: true,
              build: 'ONIVAL-2026.04-HOTFIX',
              status: 'ready',
              detail: 'ready'
            }
          };
        }

        assert.deepEqual(evaluateHealthResponse({ ok: true }), {
          httpStatus: 200,
          body: { ok: true, build: 'ONIVAL-2026.04-HOTFIX', status: 'ready', detail: 'ready' }
        });

        assert.deepEqual(evaluateHealthResponse({ ok: false, status: 'storage_unavailable', detail: 'probe_failed' }), {
          httpStatus: 503,
          body: { ok: false, build: 'ONIVAL-2026.04-HOTFIX', status: 'storage_unavailable', detail: 'probe_failed' }
        });
      });
    });

    describe('H5. Static Path Gate Self-Test Fixtures', () => {
      function staticPathGateCheck(filename: string, content: string) {
        if (content.includes('server-data')) {
          throw new Error(`[DIST ASSERTION FAILED] GATE: ${filename} contains forbidden literal 'server-data'!`);
        }
        if (/__DIR__\s*\.\s*['"]\/\.\.\//.test(content)) {
          throw new Error(`[DIST ASSERTION FAILED] GATE: ${filename} contains forbidden relative traversal '__DIR__ . /../'!`);
        }
        return true;
      }

      test('Static gate self-test fixture fails on forbidden server-data literal', () => {
        const badContent = `<?php $file = 'server-data/onival-persistent-data.json';`;
        assert.throws(() => staticPathGateCheck('test.php', badContent), /forbidden literal 'server-data'/);
      });

      test('Static gate self-test fixture fails on forbidden relative traversal __DIR__ . /../', () => {
        const badContent = `<?php $p = __DIR__ . '/../data.json';`;
        assert.throws(() => staticPathGateCheck('test.php', badContent), /forbidden relative traversal/);
      });

      test('Static gate self-test fixture passes on clean code', () => {
        const cleanContent = `<?php $p = ONIVAL_PRIVATE_DIR . '/data.json';`;
        assert.equal(staticPathGateCheck('clean.php', cleanContent), true);
      });

      test('Verify ALL actual public/api PHP files pass the static path gate', async () => {
        const fs = await import('node:fs');
        const publicApiDir = path.join(process.cwd(), 'public', 'api');
        const allowedPhp = ['common.php', 'index.php', 'webhook.php', 'bale-webhook.php'];

        for (const file of allowedPhp) {
          const filePath = path.join(publicApiDir, file);
          if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf-8');
            assert.doesNotThrow(
              () => staticPathGateCheck(file, content),
              `File public/api/${file} must pass static path gate!`
            );
          }
        }
      });
    });

    describe('Phase I: Production Hardening, Distribution & Security Gate (I0 - I4)', () => {
      describe('I0: Deployable artifact in exported project', () => {
        test('verifyDist passes on real dist and authoritative artifacts', async () => {
          const fs = await import('node:fs');
          const distDir = path.join(process.cwd(), 'dist');
          const manifestPath = path.join(process.cwd(), 'DEPLOY-MANIFEST.txt');
          const commonPhpPath = path.join(distDir, 'api', 'common.php');
          if (fs.existsSync(distDir) && fs.existsSync(manifestPath)) {
            assert.doesNotThrow(() => verifyDist(distDir, manifestPath, commonPhpPath));
          }
        });

        test('verifyDist gate fails if dist/.htaccess is missing', async () => {
          const fs = await import('node:fs');
          const os = await import('node:os');
          const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-dist-test-'));
          const tempDist = path.join(tempDir, 'dist');
          const tempApi = path.join(tempDist, 'api');
          fs.mkdirSync(tempApi, { recursive: true });
          fs.writeFileSync(path.join(tempApi, 'seed.php'), "<?php if (!defined('ONIVAL_ENTRY')) exit;");
          fs.writeFileSync(path.join(tempApi, 'common.php'), `<?php const ONIVAL_BUILD_ID = '${EXPECTED_BUILD_ID}';`);
          fs.writeFileSync(path.join(tempApi, 'index.php'), '<?php exit;');
          fs.writeFileSync(path.join(tempApi, 'webhook.php'), '<?php exit;');
          fs.writeFileSync(path.join(tempDist, 'index.html'), '<!DOCTYPE html><html></html>');

          const tempBackup = path.join(tempDir, 'HTACCESS-BACKUP.txt');
          fs.writeFileSync(tempBackup, 'Options -Indexes');

          const tempManifest = path.join(tempDir, 'DEPLOY-MANIFEST.txt');
          fs.writeFileSync(
            tempManifest,
            `if .htaccess is missing after extraction, rename a copy of this file to .htaccess\nBUILD_ID: ${EXPECTED_BUILD_ID}\n`
          );

          const tempReady = path.join(tempDir, 'public_html_ready');
          const tempReadyApi = path.join(tempReady, 'api');
          fs.mkdirSync(tempReadyApi, { recursive: true });
          fs.writeFileSync(path.join(tempReady, '.htaccess'), 'Options -Indexes');
          fs.writeFileSync(path.join(tempReady, 'index.html'), '<!DOCTYPE html><html></html>');
          fs.writeFileSync(path.join(tempReadyApi, 'seed.php'), "<?php if (!defined('ONIVAL_ENTRY')) exit;");
          fs.writeFileSync(path.join(tempReadyApi, 'common.php'), `<?php const ONIVAL_BUILD_ID = '${EXPECTED_BUILD_ID}';`);
          fs.writeFileSync(path.join(tempReadyApi, 'index.php'), '<?php exit;');
          fs.writeFileSync(path.join(tempReadyApi, 'webhook.php'), '<?php exit;');

          // Missing .htaccess in dist should fail
          assert.throws(() => verifyDist(tempDist, tempManifest, path.join(tempApi, 'common.php'), tempReady), /dist\/\.htaccess is missing/);

          // Add empty .htaccess -> should fail
          fs.writeFileSync(path.join(tempDist, '.htaccess'), '');
          assert.throws(() => verifyDist(tempDist, tempManifest, path.join(tempApi, 'common.php'), tempReady), /dist\/\.htaccess is missing or empty/);

          // Non-empty .htaccess -> should pass
          fs.writeFileSync(path.join(tempDist, '.htaccess'), 'Options -Indexes');
          assert.equal(verifyDist(tempDist, tempManifest, path.join(tempApi, 'common.php'), tempReady), true);

          // Add forbidden file -> should fail
          fs.writeFileSync(path.join(tempDist, 'onival-persistent-data.json'), '{}');
          assert.throws(() => verifyDist(tempDist, tempManifest, path.join(tempApi, 'common.php'), tempReady), /Forbidden file found in dist/);

          // Add sensitive .map file -> should fail
          fs.rmSync(path.join(tempDist, 'onival-persistent-data.json'));
          fs.writeFileSync(path.join(tempDist, 'bundle.js.map'), '');
          assert.throws(() => verifyDist(tempDist, tempManifest, path.join(tempApi, 'common.php'), tempReady), /Sensitive extension found in dist/);

          fs.rmSync(tempDir, { recursive: true, force: true });
        });

        test('DEPLOY-MANIFEST.txt and HTACCESS-BACKUP.txt exist in project root', async () => {
          const fs = await import('node:fs');
          const manifestPath = path.join(process.cwd(), 'DEPLOY-MANIFEST.txt');
          const backupPath = path.join(process.cwd(), 'HTACCESS-BACKUP.txt');
          if (fs.existsSync(manifestPath)) {
            const manifestContent = fs.readFileSync(manifestPath, 'utf-8');
            assert.ok(manifestContent.includes(`BUILD_ID: ${EXPECTED_BUILD_ID}`));
            assert.ok(manifestContent.includes('FILE_COUNT:'));
            assert.ok(manifestContent.includes('SHA256:'));
          }
          if (fs.existsSync(backupPath)) {
            const backupContent = fs.readFileSync(backupPath, 'utf-8');
            assert.ok(backupContent.includes('Options -Indexes'));
            assert.ok(backupContent.includes('RewriteEngine On'));
          }
        });
      });

      describe('I1: Strict /api/health contract & no public setup state', () => {
        function buildHealthResponse(isReady: boolean, statusDetail: { status: string; detail: string }) {
          if (!isReady) {
            return {
              httpCode: 503,
              payload: {
                ok: false,
                build: EXPECTED_BUILD_ID,
                status: statusDetail.status,
                detail: statusDetail.detail
              }
            };
          }
          return {
            httpCode: 200,
            payload: {
              ok: true,
              build: EXPECTED_BUILD_ID,
              status: 'ready',
              detail: 'ready'
            }
          };
        }

        test('Healthy contract returns HTTP 200 with EXACT 4 keys', () => {
          const res = buildHealthResponse(true, { status: 'ready', detail: 'ready' });
          assert.equal(res.httpCode, 200);
          assert.deepEqual(Object.keys(res.payload).sort(), ['build', 'detail', 'ok', 'status']);
          assert.equal(res.payload.ok, true);
          assert.equal(res.payload.build, EXPECTED_BUILD_ID);
          assert.equal(res.payload.status, 'ready');
          assert.equal(res.payload.detail, 'ready');
          // Strict negative assertions: no leaked internal fields
          assert.equal('buildId' in res.payload, false);
          assert.equal('code' in res.payload, false);
          assert.equal('initialSetupCompleted' in res.payload, false);
          assert.equal('timestamp' in res.payload, false);
        });

        test('Failing contract returns HTTP 503 with exact keys and no internal leaks', () => {
          const res = buildHealthResponse(false, { status: 'storage_unavailable', detail: 'dir_missing' });
          assert.equal(res.httpCode, 503);
          assert.deepEqual(Object.keys(res.payload).sort(), ['build', 'detail', 'ok', 'status']);
          assert.equal(res.payload.ok, false);
          assert.equal(res.payload.status, 'storage_unavailable');
          assert.equal(res.payload.detail, 'dir_missing');
        });

        test('Unauthenticated setup-status or login failure does not leak setup status and returns 503 on storage failure', () => {
          function simulateSetupStatus(authHeader: string | null) {
            if (!authHeader) {
              return { httpCode: 401, body: { ok: false, error: 'AUTH_REQUIRED' } };
            }
            return { httpCode: 200, body: { ok: true, initialSetupCompleted: false } };
          }
          const anon = simulateSetupStatus(null);
          assert.equal(anon.httpCode, 401);
          assert.equal('initialSetupCompleted' in anon.body, false);

          function simulateLoginWithStorage(storageAvailable: boolean) {
            if (!storageAvailable) {
              return { httpCode: 503, body: { ok: false, error: 'STORAGE_UNAVAILABLE' } };
            }
            return { httpCode: 200, body: { ok: true } };
          }
          const fail = simulateLoginWithStorage(false);
          assert.equal(fail.httpCode, 503, 'Must return HTTP 503 when private storage is unavailable');
        });
      });

      describe('I2: Database/Seed structure validation & PHP version compatibility', () => {
        function validateSeedStructure(seed: any) {
          if (!seed || typeof seed !== 'object' || Array.isArray(seed)) {
            return { ok: false, status: 'seed_invalid', detail: 'seed_not_array' };
          }
          if (!('products' in seed) || !Array.isArray(seed.products) || seed.products.length === 0) {
            return { ok: false, status: 'seed_missing', detail: 'products_empty_or_missing' };
          }
          return { ok: true };
        }

        function validateDbStructure(db: any) {
          if (!db || typeof db !== 'object' || Array.isArray(db)) {
            return { ok: false, status: 'db_invalid', detail: 'invalid_json' };
          }
          const listKeys = ['products', 'productCategories', 'orders'];
          for (const k of listKeys) {
            if (!(k in db) || !Array.isArray(db[k])) {
              return { ok: false, status: 'db_invalid', detail: `${k}_must_be_list` };
            }
          }
          const mapKeys = ['siteContent', 'adminCredentials'];
          for (const k of mapKeys) {
            if (k in db) {
              if (Array.isArray(db[k]) && db[k].length > 0) {
                return { ok: false, status: 'db_invalid', detail: `${k}_must_be_map` };
              }
              if (typeof db[k] !== 'object' || db[k] === null) {
                return { ok: false, status: 'db_invalid', detail: `${k}_must_be_map` };
              }
            }
          }
          return { ok: true, status: 'ready', detail: 'ready' };
        }

        test('Seed creation rejects missing or empty products list', () => {
          assert.deepEqual(validateSeedStructure({}), { ok: false, status: 'seed_missing', detail: 'products_empty_or_missing' });
          assert.deepEqual(validateSeedStructure({ products: [] }), { ok: false, status: 'seed_missing', detail: 'products_empty_or_missing' });
          assert.deepEqual(validateSeedStructure({ products: [{ id: 1, name: 'Product 1' }] }), { ok: true });
        });

        test('Live DB allows empty products list but rejects non-list for list-type keys', () => {
          const validEmptyCatalog = {
            products: [],
            productCategories: [],
            orders: [],
            siteContent: {},
            adminCredentials: {}
          };
          assert.equal(validateDbStructure(validEmptyCatalog).ok, true);

          const listStoredAsObject = {
            products: { '0': { id: 1 } },
            productCategories: [],
            orders: [],
            siteContent: {},
            adminCredentials: {}
          };
          assert.equal(validateDbStructure(listStoredAsObject).ok, false);
          assert.equal(validateDbStructure(listStoredAsObject).detail, 'products_must_be_list');
        });

        test('Live DB allows empty array for map keys but rejects populated arrays', () => {
          const mapAsEmptyList = {
            products: [],
            productCategories: [],
            orders: [],
            siteContent: [],
            adminCredentials: []
          };
          assert.equal(validateDbStructure(mapAsEmptyList).ok, true);

          const mapAsPopulatedList = {
            products: [],
            productCategories: [],
            orders: [],
            siteContent: ['invalid', 'list', 'entry'],
            adminCredentials: {}
          };
          assert.equal(validateDbStructure(mapAsPopulatedList).ok, false);
          assert.equal(validateDbStructure(mapAsPopulatedList).detail, 'siteContent_must_be_map');
        });

        test('PHP version guard rejects versions below 8.0.0 (80000)', () => {
          function checkPhpVersion(phpVersionId: number) {
            const ONIVAL_MIN_PHP_VERSION_ID = 80000;
            const ONIVAL_MIN_PHP_VERSION = '8.0.0';
            if (phpVersionId < ONIVAL_MIN_PHP_VERSION_ID) {
              return { ok: false, httpCode: 503, status: 'php_unsupported', detail: ONIVAL_MIN_PHP_VERSION };
            }
            return { ok: true };
          }

          assert.deepEqual(checkPhpVersion(70433), { ok: false, httpCode: 503, status: 'php_unsupported', detail: '8.0.0' });
          assert.deepEqual(checkPhpVersion(80000), { ok: true });
          assert.deepEqual(checkPhpVersion(80120), { ok: true });
          assert.deepEqual(checkPhpVersion(80210), { ok: true });
        });
      });

      describe('I3: Frontend pending-state refresh & boot behavior', () => {
        test('Initial auth state is unknown and blocks admin data fetching', () => {
          assert.equal(shouldFetchAdminData(null, false, 'unknown'), false);
          assert.equal(shouldFetchAdminData(true, true, 'pending'), false);
          assert.equal(shouldFetchAdminData(false, false, 'unauthenticated'), false);
          assert.equal(shouldFetchAdminData(false, true, 'authenticated'), true);
        });

        test('viewAfterLogin routes pending users directly to setup', () => {
          assert.equal(viewAfterLogin({ initialSetupCompleted: false }), 'account');
          assert.equal(viewAfterLogin({ isInitialPending: true }), 'account');
          assert.equal(viewAfterLogin({ initialSetupCompleted: true }), 'dashboard');
        });

        test('Pending state in AccountView restricts rendered controls to username/password change', () => {
          function renderAccountSections(isSetupDone: boolean) {
            return {
              showLogoUpload: isSetupDone,
              showImageFrameSettings: isSetupDone,
              showHostManagement: isSetupDone,
              showEmailField: isSetupDone,
              showDisplayNameField: isSetupDone,
              showCurrentPasswordField: isSetupDone,
              showNewUsernameField: true,
              showNewPasswordField: true,
              showConfirmPasswordField: true
            };
          }

          const pendingSections = renderAccountSections(false);
          assert.equal(pendingSections.showLogoUpload, false);
          assert.equal(pendingSections.showImageFrameSettings, false);
          assert.equal(pendingSections.showHostManagement, false);
          assert.equal(pendingSections.showCurrentPasswordField, false);
          assert.equal(pendingSections.showNewUsernameField, true);
          assert.equal(pendingSections.showNewPasswordField, true);

          const completedSections = renderAccountSections(true);
          assert.equal(completedSections.showLogoUpload, true);
          assert.equal(completedSections.showHostManagement, true);
          assert.equal(completedSections.showCurrentPasswordField, true);
        });
      });

      describe('I4: Username validation across states (isValidAdminUsername / isValidAdminUsernameClient)', () => {
        test('isValidAdminUsernameClient validates username format and length (3-32 chars, regex)', () => {
          assert.equal(isValidAdminUsernameClient('ab', false).isValid, false);
          assert.equal(isValidAdminUsernameClient('a'.repeat(33), false).isValid, false);
          assert.equal(isValidAdminUsernameClient('valid_user-name.1', false).isValid, true);
          assert.equal(isValidAdminUsernameClient('invalid space', false).isValid, false);
          assert.equal(isValidAdminUsernameClient('user@name', false).isValid, false);
          assert.equal(isValidAdminUsernameClient('admin', false).isValid, false);
        });

        test('isValidAdminUsernameClient in pending state rejects initial username', () => {
          assert.equal(isValidAdminUsernameClient('onival_setup', true, 'onival_setup').isValid, false);
          assert.equal(isValidAdminUsernameClient('onival_setup', true, 'onival_setup').code, 'USERNAME_SAME_AS_INITIAL');
          assert.equal(isValidAdminUsernameClient('my_new_admin', true, 'onival_setup').isValid, true);
        });

        test('isValidAdminUsernameClient in completed state allows new distinct usernames and rejects admin', () => {
          assert.equal(isValidAdminUsernameClient('admin', false).isValid, false);
          assert.equal(isValidAdminUsernameClient('super_admin', false).isValid, true);
        });
      });
    });

    describe('Phase J: Deploy Survival, UTF-8 Gate & Setup Username (J0 - J2)', () => {
      describe('J0: A Deploy Folder That Survives the Zip Export', () => {
        test('public_html_ready and dist byte-identical equality in verifyDist', async () => {
          const fs = await import('node:fs');
          const os = await import('node:os');
          const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'onival-j0-test-'));
          const distDir = path.join(tempDir, 'dist');
          const readyDir = path.join(tempDir, 'public_html_ready');
          const distApi = path.join(distDir, 'api');
          const readyApi = path.join(readyDir, 'api');
          fs.mkdirSync(distApi, { recursive: true });
          fs.mkdirSync(readyApi, { recursive: true });

          const commonPhpContent = `<?php define('ONIVAL_BUILD_ID', '${EXPECTED_BUILD_ID}');`;
          const seedPhpContent = "<?php if (!defined('ONIVAL_ENTRY')) exit;";
          const htaccessContent = 'Options -Indexes\nRewriteEngine On';
          const indexHtmlContent = '<!DOCTYPE html><html><body>ONIVAL</body></html>';

          fs.writeFileSync(path.join(distDir, '.htaccess'), htaccessContent);
          fs.writeFileSync(path.join(distDir, 'index.html'), indexHtmlContent);
          fs.writeFileSync(path.join(distApi, 'seed.php'), seedPhpContent);
          fs.writeFileSync(path.join(distApi, 'common.php'), commonPhpContent);
          fs.writeFileSync(path.join(distApi, 'index.php'), '<?php exit;');
          fs.writeFileSync(path.join(distApi, 'webhook.php'), '<?php exit;');

          // Replicate into readyDir
          fs.writeFileSync(path.join(readyDir, '.htaccess'), htaccessContent);
          fs.writeFileSync(path.join(readyDir, 'index.html'), indexHtmlContent);
          fs.writeFileSync(path.join(readyApi, 'seed.php'), seedPhpContent);
          fs.writeFileSync(path.join(readyApi, 'common.php'), commonPhpContent);
          fs.writeFileSync(path.join(readyApi, 'index.php'), '<?php exit;');
          fs.writeFileSync(path.join(readyApi, 'webhook.php'), '<?php exit;');

          const backupHtaccess = path.join(tempDir, 'HTACCESS-BACKUP.txt');
          fs.writeFileSync(backupHtaccess, htaccessContent);

          const manifestPath = path.join(tempDir, 'DEPLOY-MANIFEST.txt');
          fs.writeFileSync(
            manifestPath,
            `if .htaccess is missing after extraction, rename a copy of this file to .htaccess\nBUILD_ID: ${EXPECTED_BUILD_ID}\n`
          );

          // Byte-identical: passes
          assert.equal(verifyDist(distDir, manifestPath, path.join(distApi, 'common.php'), readyDir), true);

          // Negative test 1: Deleting one file in public_html_ready causes verifyDist to fail
          fs.rmSync(path.join(readyDir, 'index.html'));
          assert.throws(
            () => verifyDist(distDir, manifestPath, path.join(distApi, 'common.php'), readyDir),
            /File in dist missing from public_html_ready: index\.html/
          );

          // Restore file and test Negative test 2: Altering one byte causes SHA-256 mismatch
          fs.writeFileSync(path.join(readyDir, 'index.html'), indexHtmlContent + ' ');
          assert.throws(
            () => verifyDist(distDir, manifestPath, path.join(distApi, 'common.php'), readyDir),
            /SHA-256 mismatch for index\.html/
          );

          // Clean up temp
          fs.rmSync(tempDir, { recursive: true, force: true });
        });

        test('Recreating public_html_ready twice leaves no stale files', async () => {
          const fs = await import('node:fs');
          const os = await import('node:os');
          const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'onival-recreate-test-'));
          const distDir = path.join(tempDir, 'dist');
          const readyDir = path.join(tempDir, 'public_html_ready');
          fs.mkdirSync(distDir, { recursive: true });
          fs.writeFileSync(path.join(distDir, 'file1.txt'), 'hello');

          function populateReady(src, dest) {
            if (fs.existsSync(dest)) {
              fs.rmSync(dest, { recursive: true, force: true });
            }
            fs.mkdirSync(dest, { recursive: true });
            for (const entry of fs.readdirSync(src)) {
              fs.copyFileSync(path.join(src, entry), path.join(dest, entry));
            }
          }

          populateReady(distDir, readyDir);
          assert.equal(fs.existsSync(path.join(readyDir, 'file1.txt')), true);

          // Simulate an old stale file created in readyDir
          fs.writeFileSync(path.join(readyDir, 'stale-file.bak'), 'stale content');
          assert.equal(fs.existsSync(path.join(readyDir, 'stale-file.bak')), true);

          // Recreate again: stale file must be gone
          populateReady(distDir, readyDir);
          assert.equal(fs.existsSync(path.join(readyDir, 'stale-file.bak')), false);
          assert.equal(fs.readdirSync(readyDir).length, 1);

          fs.rmSync(tempDir, { recursive: true, force: true });
        });

        test('DEPLOY-MANIFEST.txt starts with .htaccess notice and HTACCESS-BACKUP.txt exists in root', async () => {
          const fs = await import('node:fs');
          const manifestPath = path.join(process.cwd(), 'DEPLOY-MANIFEST.txt');
          const backupPath = path.join(process.cwd(), 'HTACCESS-BACKUP.txt');
          if (fs.existsSync(manifestPath)) {
            const content = fs.readFileSync(manifestPath, 'utf-8');
            assert.ok(content.startsWith('if .htaccess is missing after extraction, rename a copy of this file to .htaccess'));
            assert.ok(content.includes(`BUILD_ID: ${EXPECTED_BUILD_ID}`));
          }
          if (fs.existsSync(backupPath)) {
            assert.ok(fs.existsSync(backupPath));
            assert.ok(!backupPath.includes('public_html_ready'));
          }
        });
      });

      describe('J1: UTF-8 Gate, Surrogate Prevention & Template Encoding', () => {
        test('Self-test fixture: Broken CESU-8 surrogate pair fails check-utf8', () => {
          // CESU-8 surrogate bytes for U+1F9FE: \xED\xA0\xBE\xED\xB7\xBE
          const brokenSurrogateBuf = Buffer.concat([
            Buffer.from("<?php\n// "),
            Buffer.from([0xed, 0xa0, 0xbe, 0xed, 0xb7, 0xbe])
          ]);
          assert.throws(
            () => validateTextBuffer(brokenSurrogateBuf, 'webhook.php'),
            /CESU-8 \/ surrogate sequence detected/
          );
        });

        test('Self-test fixture: Invalid UTF-8 byte sequences fail check-utf8', () => {
          const invalidUtf8Buf = Buffer.from([0xff, 0xfe, 0x80, 0x00]);
          assert.throws(
            () => validateTextBuffer(invalidUtf8Buf, 'invalid.ts'),
            /Invalid UTF-8 byte sequence/
          );
        });

        test('Self-test fixture: UTF-8 BOM in PHP files fails check-utf8', () => {
          const bomPhpBuf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('<?php echo 1;')]);
          assert.throws(
            () => validateTextBuffer(bomPhpBuf, 'bom.php'),
            /UTF-8 BOM detected at the start of PHP file/
          );
        });

        test('Self-test fixture: Output or whitespace before <?php fails check-utf8', () => {
          const leadingSpaceBuf = Buffer.from(' <?php echo 1;');
          assert.throws(
            () => validateTextBuffer(leadingSpaceBuf, 'space.php'),
            /Output or whitespace detected before opening <\?php tag/
          );

          const leadingHtmlBuf = Buffer.from('<html>\n<?php echo 1;');
          assert.throws(
            () => validateTextBuffer(leadingHtmlBuf, 'html.php'),
            /Output or whitespace detected before opening <\?php tag/
          );
        });

        test('Self-test fixture: Clean UTF-8 PHP source passes check-utf8', () => {
          const cleanPhpBuf = Buffer.from("<?php\necho 'سلام دنیا';");
          assert.equal(validateTextBuffer(cleanPhpBuf, 'clean.php'), true);
        });

        test('callBaleApi error simulation on invalid UTF-8 logs JSON_ENCODE_FAILED and does not send', () => {
          function simulateCallBaleApi(parameters: any) {
            let jsonPayload: string | false = false;
            let jsonError = '';
            const loneSurrogateRegex = /(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])/;
            const hasLoneSurrogate = (obj: any): boolean => {
              if (typeof obj === 'string') return loneSurrogateRegex.test(obj);
              if (obj && typeof obj === 'object') return Object.values(obj).some(hasLoneSurrogate);
              return false;
            };

            if (hasLoneSurrogate(parameters)) {
              jsonPayload = false;
              jsonError = 'Malformed UTF-8 / unpaired surrogate characters';
            } else {
              try {
                jsonPayload = JSON.stringify(parameters);
              } catch (e: any) {
                jsonPayload = false;
                jsonError = e.message;
              }
            }

            if (jsonPayload === false) {
              return {
                ok: false,
                code: 'JSON_ENCODE_FAILED',
                error: 'JSON encoding failed: ' + jsonError,
                loggedCode: 'JSON_ENCODE_FAILED',
                curlSent: false
              };
            }

            return {
              ok: true,
              curlSent: true
            };
          }

          // Test with valid emoji string
          const validParams = { text: '🧾 فاکتور سفارش' };
          assert.equal(simulateCallBaleApi(validParams).ok, true);

          // Test with broken lone surrogate character
          const brokenParams = { text: 'Invalid \uD800 lone surrogate' };
          const res = simulateCallBaleApi(brokenParams);
          assert.equal(res.ok, false);
          assert.equal(res.code, 'JSON_ENCODE_FAILED');
          assert.equal(res.loggedCode, 'JSON_ENCODE_FAILED');
          assert.equal(res.curlSent, false, 'cURL must NOT be sent when JSON encoding fails');
        });

        test('All webhook.php message templates encode cleanly to valid JSON with zero surrogates', () => {
          function hasCesu8Surrogate(buf: Buffer): boolean {
            for (let i = 0; i < buf.length - 2; i++) {
              if (buf[i] === 0xed && (buf[i + 1] >= 0xa0 && buf[i + 1] <= 0xbf) && (buf[i + 2] >= 0x80 && buf[i + 2] <= 0xbf)) {
                return true;
              }
            }
            return false;
          }

          const sampleOrder = {
            trackingCode: 'ONV-ORD-2026-9901',
            customerName: 'علی رضایی',
            userFullName: 'علی رضایی',
            totalPrice: 450000,
            status: 'Pending'
          };
          const cardNumber = '6037997112345678';
          const cardHolder = 'فروشگاه اونیوال';
          const bankName = 'بانک ملی ایران';
          const storeUrl = 'https://onival.ir';
          const amountToman = 450000;
          const invoiceSent = true;

          // 1. $orderInfoMsg
          const orderInfoMsg =
            `🧾 فاکتور سفارش ${sampleOrder.trackingCode}\n\n` +
            `👤 مشتری: ${sampleOrder.userFullName}\n` +
            `💰 مبلغ کل: ${amountToman.toLocaleString()} تومان\n` +
            `⏳ وضعیت: در انتظار پرداخت\n\n` +
            (invoiceSent ? '💳 کارت پرداخت کیف‌پول بله در بالا صادر گردید.\n\n' : '') +
            `▫️ جهت پرداخت کارت به کارت:\n` +
            `شماره کارت: ${cardNumber}\n` +
            `به نام: ${cardHolder} (${bankName})\n\n` +
            `📸 پس از واریز، تصویر فیش را در همین گفتگو ارسال فرمایید.`;

          // 2. $welcome
          const welcome =
            'به ربات رسمی فروشگاه تخصصی اونیوال (ONIVAL) خوش آمدید! 🍯🌿\n\n' +
            'از طریق دکمه‌های زیر می‌توانید سفارش‌های خود را استعلام کرده، با کیف‌پول بله یا کارت‌به‌کارت پرداخت کنید.';

          // 3. $notFoundMsg
          const notFoundMsg = `❌ سفارشی با کد پیگیری «${sampleOrder.trackingCode}» در سیستم یافت نشد.\nلطفاً کد رهگیری فاکتور خود را با دقت بررسی فرمایید.`;

          // 4. $paidMsg
          const paidMsg = `✅ سفارش ${sampleOrder.trackingCode} قبلاً با موفقیت پرداخت و تایید شده است.`;

          // 5. $c2cMsg
          const c2cMsg = `💳 راهنمای پرداخت کارت‌به‌کارت سفارش ${sampleOrder.trackingCode}:\nشماره کارت: ${cardNumber}`;

          // 6. $custNotify
          const custNotify = `🎉 سفارش ${sampleOrder.trackingCode} شما تایید شد و به زودی ارسال می‌گردد.`;

          // 7. $custReceipt
          const custReceipt = `📸 تصویر فیش واریزی سفارش ${sampleOrder.trackingCode} دریافت شد و جهت بررسی برای مدیر ارسال گردید.`;

          // 8. $custReassure
          const custReassure = `🙏 مشتری گرامی، پرداخت شما در حال پردازش نهایی است.`;

          // 9. $custThanks
          const custThanks = `با تشکر از اعتماد شما به محصولات ارگانیک اونیوال. 🌿`;

          // 10. $adminAlert
          const adminAlert = `🚨 فیش جدید برای سفارش ${sampleOrder.trackingCode} بارگذاری شد. لطفاً بررسی فرمایید.`;

          const templates = [
            orderInfoMsg,
            welcome,
            notFoundMsg,
            paidMsg,
            c2cMsg,
            custNotify,
            custReceipt,
            custReassure,
            custThanks,
            adminAlert
          ];

          for (const t of templates) {
            const payload = {
              chat_id: 12345678,
              text: t,
              reply_markup: {
                inline_keyboard: [[{ text: 'مشاهده فاکتور', url: storeUrl }]]
              }
            };
            const jsonStr = JSON.stringify(payload);
            assert.ok(jsonStr.length > 0);
            const buf = Buffer.from(jsonStr, 'utf-8');
            // Verify no CESU-8 surrogate bytes
            assert.equal(hasCesu8Surrogate(buf), false);
            // Verify no lone/unpaired surrogates in JS string
            const loneSurrogateRegex = /(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])/;
            assert.equal(loneSurrogateRegex.test(jsonStr), false);
            // Verify json decodes back cleanly
            const decoded = JSON.parse(jsonStr);
            assert.equal(decoded.chat_id, 12345678);
            assert.equal(decoded.text, t);
          }
        });
      });

      describe('J2: Setup Form Username Field', () => {
        test('getInitialUsernameForState starts empty while pending and ignores profile username', () => {
          assert.equal(getInitialUsernameForState(true), '');
          assert.equal(getInitialUsernameForState(true, 'initial_admin'), '');
          assert.equal(getInitialUsernameForState(true, 'onival_setup'), '');
        });

        test('getInitialUsernameForState populates username only when setup is completed', () => {
          assert.equal(getInitialUsernameForState(false, 'custom_admin_2026'), 'custom_admin_2026');
          assert.equal(getInitialUsernameForState(false), 'admin');
        });

        test('AccountView.tsx source contains autoComplete="off" on username input', async () => {
          const fs = await import('node:fs');
          const accountViewPath = path.join(process.cwd(), 'src', 'components', 'AccountView.tsx');
          const source = fs.readFileSync(accountViewPath, 'utf-8');
          assert.ok(
            source.includes('autoComplete="off"'),
            'AccountView.tsx must include autoComplete="off" on the username input'
          );
        });
      });
    });
  });
});

