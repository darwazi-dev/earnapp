const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const { getPayoutProvider } = require('./lib/payout-providers');
const {
  AFN_SCALE,
  minorToAfn,
  afnToMinor,
  calculateProviderRewardMinor
} = require('./lib/financial-math');

const app = express();

app.disable('x-powered-by');

app.use(
  helmet({
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "base-uri": ["'self'"],
        "object-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "form-action": ["'self'"],
        "img-src": ["'self'", "data:", "blob:"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "script-src": ["'self'"],
        "script-src-attr": ["'none'"],
        "connect-src": ["'self'", "https://*.cpx-research.com", "https://*.cpxresearch.com"],
        "frame-src": ["'self'", "https://*.cpx-research.com", "https://*.cpxresearch.com"],
        "upgrade-insecure-requests": []
      }
    }
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'درخواست‌های زیادی ارسال شده است. کمی بعد دوباره تلاش کنید.'
  }
});

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'درخواست‌های زیادی ارسال شده است. کمی بعد دوباره تلاش کنید.'
  }
});

// Earning-provider links are intentionally stricter than ordinary API reads.
// This limits automated refresh/open loops without punishing normal browsing.
const earningAccessLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: req => String(req.userId || req.ip || 'anonymous'),
  message: {
    error: 'تعداد تلاش برای بازکردن فرصت‌های درآمد زیاد است. چند دقیقه بعد دوباره تلاش کنید.'
  }
});

const PORT = process.env.PORT || 3000;

// =====================================================
// ENV
// =====================================================

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const VONAGE_API_KEY = String(process.env.VONAGE_API_KEY || '').trim();
const VONAGE_API_SECRET = String(process.env.VONAGE_API_SECRET || '').trim();
const OTP_BRAND = String(process.env.OTP_BRAND || 'Kariyab').trim();

const CPX_APP_ID = String(process.env.CPX_APP_ID || '36387').trim();
const CPX_SECURE_HASH = String(process.env.CPX_SECURE_HASH || '').trim();
const IPQS_API_KEY = String(process.env.IPQS_API_KEY || '').trim();

const DEFAULT_AFN_PER_USD = String(process.env.AFN_PER_USD || '68');
const DEFAULT_USER_SHARE = String(process.env.USER_SHARE || '0.55');
const DEFAULT_HOLD_HOURS = Number(process.env.EARNING_HOLD_HOURS || 72);

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing');
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is missing');
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error('FATAL: ADMIN_PASSWORD is missing');
  process.exit(1);
}

// =====================================================
// DATABASE
// =====================================================

const pool = new Pool({
  connectionString: DATABASE_URL
});

async function ensureRuntimeSchema() {
  await pool.query(
    `ALTER TABLE identity_verifications
       ADD COLUMN IF NOT EXISTS metadata JSONB
       NOT NULL DEFAULT '{}'::jsonb`
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS devices (
       id BIGSERIAL PRIMARY KEY,
       user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       device_key VARCHAR(255),
       ip_address INET,
       user_agent TEXT,
       last_seen_at TIMESTAMPTZ,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
     )`
  );

  await pool.query(
    `DELETE FROM devices a
     USING devices b
     WHERE a.id < b.id
       AND a.user_id = b.user_id
       AND a.device_key = b.device_key
       AND a.device_key IS NOT NULL`
  );

  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_devices_device_key
       ON devices(device_key)`
  );

  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_device
       ON devices(user_id, device_key)
       WHERE device_key IS NOT NULL`
  );
}

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json({ limit: '350kb' }));
app.use(express.urlencoded({ extended: false }));

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// =====================================================
// HELPERS
// =====================================================

function safeCompare(left, right) {
  const leftBuffer = Buffer.from(String(left), 'utf8');
  const rightBuffer = Buffer.from(String(right), 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function md5(value) {
  return crypto
    .createHash('md5')
    .update(String(value))
    .digest('hex');
}

function requestIp(req) {
  // Railway documents X-Real-IP as the client remote IP on public HTTP traffic.
  // Do not trust client-supplied X-Forwarded-For for fraud decisions.
  return String(req.headers['x-real-ip'] || req.socket?.remoteAddress || '')
    .trim()
    .replace(/^::ffff:/, '');
}

function publicIp(value) {
  const ip = String(value || '').trim();
  if (!ip) return false;
  // IPQS validates the address itself; this only prevents obviously unsafe URL input.
  return /^[0-9a-fA-F:.]{3,45}$/.test(ip);
}

async function assessNetworkRisk(req) {
  if (!IPQS_API_KEY) return { configured: false, detected: false };

  const ip = requestIp(req);
  if (!publicIp(ip)) return { configured: true, detected: false, unavailable: true };

  const params = new URLSearchParams({
    strictness: '0',
    allow_public_access_points: 'true',
    lighter_penalties: 'true'
  });
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 500);
  const language = String(req.headers['accept-language'] || '').slice(0, 100);
  if (userAgent) params.set('user_agent', userAgent);
  if (language) params.set('user_language', language);

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    let response;
    try {
      response = await fetch(
        'https://ipqualityscore.com/api/json/ip/' +
        encodeURIComponent(IPQS_API_KEY) + '/' +
        encodeURIComponent(ip) + '?' + params.toString(),
        { signal: controller.signal }
      );
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      const providerBody = await response.text().catch(() => '');
      console.warn(
        'Network risk lookup HTTP error:',
        response.status,
        providerBody.slice(0, 500)
      );
      return {
        configured: true,
        detected: false,
        unavailable: true,
        reason: 'HTTP_' + response.status
      };
    }

    const data = await response.json();
    if (data.success === false) {
      console.warn('Network risk lookup rejected:', Array.isArray(data.errors) ? data.errors.join('; ') : data.message || 'unknown error');
      return { configured: true, detected: false, unavailable: true, reason: 'PROVIDER_REJECTED' };
    }

    const vpn = data.vpn === true || data.active_vpn === true;
    const proxy = data.proxy === true;
    const tor = data.tor === true || data.active_tor === true;
    return {
      configured: true,
      detected: vpn || proxy || tor,
      vpn,
      proxy,
      tor,
      requestId: String(data.request_id || '').slice(0, 120) || null,
      countryCode: String(data.country_code || '').slice(0, 2) || null,
      connectionType: String(data.connection_type || '').slice(0, 40) || null,
      fraudScore: Number.isFinite(Number(data.fraud_score)) ? Number(data.fraud_score) : null
    };
  } catch (error) {
    const reason = error?.name === 'AbortError' ? 'TIMEOUT' : 'REQUEST_ERROR';
    console.warn('Network risk lookup unavailable:', reason, error.message);
    return { configured: true, detected: false, unavailable: true, reason };
  }
}

async function recordDeviceSignal(userId, req) {
  const rawDeviceKey = String(req.headers['x-kariyab-device'] || '').trim();
  if (!/^[A-Za-z0-9_-]{20,120}$/.test(rawDeviceKey)) return;

  const deviceKey = crypto
    .createHash('sha256')
    .update(rawDeviceKey)
    .digest('hex');
  const ip = requestIp(req);
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 1000);

  await pool.query(
    `INSERT INTO devices (user_id, device_key, ip_address, user_agent, last_seen_at)
     VALUES ($1, $2, NULLIF($3, '')::inet, $4, NOW())
     ON CONFLICT (user_id, device_key) WHERE device_key IS NOT NULL
     DO UPDATE SET
       ip_address = EXCLUDED.ip_address,
       user_agent = EXCLUDED.user_agent,
       last_seen_at = NOW()`,
    [userId, deviceKey, ip, userAgent]
  );

  const shared = await pool.query(
    `SELECT COUNT(DISTINCT user_id)::int AS users
     FROM devices
     WHERE device_key = $1`,
    [deviceKey]
  );

  const sharedUsers = Number(shared.rows[0]?.users || 0);
  if (sharedUsers > 1) {
    await pool.query(
      `INSERT INTO fraud_flags (user_id, flag_type, severity, reason, metadata)
       SELECT $1, 'SHARED_DEVICE', 'REVIEW',
              'This device has been observed on more than one Kariyab account.',
              $2::jsonb
       WHERE NOT EXISTS (
         SELECT 1 FROM fraud_flags
         WHERE user_id = $1
           AND flag_type = 'SHARED_DEVICE'
           AND status IN ('OPEN', 'UNDER_REVIEW')
       )`,
      [
        userId,
        JSON.stringify({
          signal_only: true,
          distinct_accounts: sharedUsers
        })
      ]
    );
  }

  // Multiple accounts sharing the same device is a review signal, not automatic fraud.
  // Escalate only when the same device is observed across several accounts.
  if (sharedUsers >= 3) {
    await pool.query(
      `INSERT INTO fraud_flags (user_id, flag_type, severity, reason, metadata)
       SELECT $1, 'DEVICE_ACCOUNT_VELOCITY', 'HIGH',
              'This device has been observed across three or more Kariyab accounts.',
              $2::jsonb
       WHERE NOT EXISTS (
         SELECT 1 FROM fraud_flags
         WHERE user_id = $1
           AND flag_type = 'DEVICE_ACCOUNT_VELOCITY'
           AND status IN ('OPEN', 'UNDER_REVIEW')
       )`,
      [
        userId,
        JSON.stringify({
          distinct_accounts: sharedUsers,
          threshold: 3,
          automated_signal: true
        })
      ]
    );
  }
}

function publicId(prefix) {
  return (
    prefix +
    '_' +
    Date.now() +
    '_' +
    crypto.randomBytes(8).toString('hex')
  );
}

async function getSetting(key, fallback, client = pool) {
  try {
    const result = await client.query(
      `
      SELECT value
      FROM system_settings
      WHERE key = $1
      LIMIT 1
      `,
      [key]
    );

    if (!result.rows.length) {
      return fallback;
    }

    return result.rows[0].value;
  } catch (error) {
    console.error('Setting error:', key, error.message);
    return fallback;
  }
}

async function getRuntimeSettings(client = pool) {
  const minimumWithdrawalMinor =
    await getSetting(
      'minimum_withdrawal_minor',
      50000,
      client
    );

  const revenueShare =
    await getSetting(
      'user_revenue_share',
      DEFAULT_USER_SHARE,
      client
    );

  const afnPerUsd =
    await getSetting(
      'afn_per_usd',
      DEFAULT_AFN_PER_USD,
      client
    );

  const holdHours =
    await getSetting(
      'earning_hold_hours',
      DEFAULT_HOLD_HOURS,
      client
    );

  return {
    minimumWithdrawalMinor:
      Number(minimumWithdrawalMinor || 50000),

    revenueShare:
      String(revenueShare ?? DEFAULT_USER_SHARE),

    afnPerUsd:
      String(afnPerUsd ?? DEFAULT_AFN_PER_USD),

    holdHours:
      Number(holdHours ?? DEFAULT_HOLD_HOURS)
  };
}

async function getWallet(userId, client = pool) {
  const result = await client.query(
    `
    SELECT *
    FROM wallets
    WHERE user_id = $1
    LIMIT 1
    `,
    [userId]
  );

  return result.rows[0] || null;
}

// =====================================================
// AUTH
// =====================================================

function userSessionKey(passwordHash) {
  return crypto
    .createHash('sha256')
    .update(String(passwordHash || ''))
    .digest('hex');
}

async function authRequired(req, res, next) {
  const header = req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: 'وارد نشده‌اید'
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET,
      {
        issuer: 'kariyab',
        audience: 'kariyab-user'
      }
    );

    if (
      decoded.type !== 'USER_SESSION' ||
      !decoded.userId ||
      !decoded.sessionKey
    ) {
      throw new Error('Invalid user session');
    }

    const sessionResult = await pool.query(
      `SELECT password_hash, status
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [String(decoded.userId)]
    );

    const sessionUser = sessionResult.rows[0];

    if (
      !sessionUser ||
      sessionUser.status !== 'ACTIVE' ||
      !safeCompare(
        decoded.sessionKey,
        userSessionKey(sessionUser.password_hash)
      )
    ) {
      throw new Error('Revoked user session');
    }

    req.userId = String(decoded.userId);
    next();
  } catch {
    return res.status(401).json({
      error: 'نشست شما منقضی شده، دوباره وارد شوید'
    });
  }
}

function adminRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      error: 'نشست ادمین معتبر نیست'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'kariyab',
      audience: 'kariyab-admin'
    });

    if (decoded.role !== 'ADMIN' || decoded.type !== 'ADMIN_SESSION') {
      throw new Error('Invalid admin session');
    }

    req.adminSession = decoded;
    next();
  } catch {
    return res.status(401).json({
      error: 'نشست ادمین منقضی یا نامعتبر است'
    });
  }
}

// =====================================================
// PROFILE
// =====================================================

app.get('/api/profile', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.name,
         u.phone,
         u.email,
         u.phone_verified,
         u.email_verified,
         COALESCE(up.metadata->>'profile_photo', '') AS profile_photo,
         COALESCE(up.metadata->>'language', 'fa-AF') AS language,
         COALESCE((up.metadata->>'notifications_enabled')::boolean, TRUE) AS notifications_enabled
       FROM users u
       LEFT JOIN user_profiles up ON up.user_id = u.id
       WHERE u.id = $1 LIMIT 1`,
      [req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'کاربر یافت نشد' });
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Profile read failed:', error);
    res.status(500).json({ error: 'دریافت پروفایل انجام نشد' });
  }
});

app.post('/api/profile/settings', authRequired, sensitiveLimiter, async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const language = String(req.body?.language || 'fa-AF').trim();
    const notificationsEnabled = req.body?.notificationsEnabled !== false;

    if (name.length < 2 || name.length > 120) {
      return res.status(400).json({ error: 'نام باید بین ۲ تا ۱۲۰ کاراکتر باشد' });
    }
    if (!['fa-AF', 'ps-AF', 'en'].includes(language)) {
      return res.status(400).json({ error: 'زبان انتخاب‌شده معتبر نیست' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const identityLock = await client.query(
        `SELECT u.name AS current_name, iv.status AS identity_status
         FROM users u
         LEFT JOIN LATERAL (
           SELECT status
           FROM identity_verifications
           WHERE user_id = u.id
           ORDER BY submitted_at DESC, id DESC
           LIMIT 1
         ) iv ON TRUE
         WHERE u.id = $1
         FOR UPDATE OF u`,
        [req.userId]
      );

      const currentName = String(identityLock.rows[0]?.current_name || '').replace(/\s+/g, ' ').trim();
      const normalizedCurrentName = currentName.normalize('NFKC').toLocaleLowerCase().replace(/[\u200c\u200d]/g, '').replace(/[^\p{L}\p{M}]/gu, '');
      const normalizedNewName = name.normalize('NFKC').toLocaleLowerCase().replace(/[\u200c\u200d]/g, '').replace(/[^\p{L}\p{M}]/gu, '');

      if (
        identityLock.rows[0]?.identity_status === 'VERIFIED' &&
        normalizedCurrentName !== normalizedNewName
      ) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'پس از تایید هویت، نام حساب بدون احراز هویت مجدد قابل تغییر نیست'
        });
      }

      await client.query(
        `UPDATE users SET name = $2, updated_at = NOW() WHERE id = $1`,
        [req.userId, name]
      );
      await client.query(
        `INSERT INTO user_profiles (user_id, metadata)
         VALUES ($1, jsonb_build_object('language', $2::text, 'notifications_enabled', $3::boolean))
         ON CONFLICT (user_id) DO UPDATE
         SET metadata = COALESCE(user_profiles.metadata, '{}'::jsonb)
           || jsonb_build_object('language', $2::text, 'notifications_enabled', $3::boolean),
             updated_at = NOW()`,
        [req.userId, language, notificationsEnabled]
      );
      await client.query('COMMIT');
      res.json({ ok: true, name, language, notifications_enabled: notificationsEnabled });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Profile settings failed:', error);
    res.status(500).json({ error: 'ذخیره تنظیمات حساب انجام نشد' });
  }
});

app.post('/api/profile/photo', authRequired, sensitiveLimiter, async (req, res) => {
  try {
    const photo = String(req.body?.photo || '');
    if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(photo)) {
      return res.status(400).json({ error: 'فرمت تصویر معتبر نیست' });
    }
    if (Buffer.byteLength(photo, 'utf8') > 250000) {
      return res.status(400).json({ error: 'حجم تصویر زیاد است' });
    }
    await pool.query(
      `INSERT INTO user_profiles (user_id, metadata)
       VALUES ($1, jsonb_build_object('profile_photo', $2::text))
       ON CONFLICT (user_id) DO UPDATE
       SET metadata = COALESCE(user_profiles.metadata, '{}'::jsonb) || jsonb_build_object('profile_photo', $2::text),
           updated_at = NOW()`,
      [req.userId, photo]
    );
    res.json({ ok: true, photo });
  } catch (error) {
    console.error('Profile photo failed:', error);
    res.status(500).json({ error: 'ذخیره تصویر پروفایل انجام نشد' });
  }
});

// =====================================================
// PENDING -> APPROVED
// =====================================================

async function promotePendingEarnings(userId) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const settings =
      await getRuntimeSettings(client);

    if (
      !Number.isFinite(settings.holdHours) ||
      settings.holdHours < 0
    ) {
      throw new Error(
        'Invalid earning_hold_hours'
      );
    }

    const pending = await client.query(
      `
      SELECT
        id,
        amount_minor
      FROM transactions
      WHERE
        user_id = $1
        AND type = 'EARNING'
        AND status = 'PENDING'
        -- A callback and elapsed hold time do not prove provider settlement.
        -- Keep earnings pending until settlement is independently verified.
        AND metadata->>'settlement_verified' = 'true'
        AND created_at <=
          NOW() - make_interval(hours => $2::int)
      ORDER BY id
      FOR UPDATE
      `,
      [
        userId,
        Math.floor(settings.holdHours)
      ]
    );

    if (!pending.rows.length) {
      await client.query('COMMIT');

      return {
        promoted: 0,
        amountMinor: 0
      };
    }

    let totalMinor = 0;

    for (const transaction of pending.rows) {
      const amount =
        Number(transaction.amount_minor);

      if (
        !Number.isSafeInteger(amount) ||
        amount <= 0
      ) {
        throw new Error(
          'Invalid pending transaction amount'
        );
      }

      if (!Number.isSafeInteger(totalMinor + amount)) {
        throw new Error('Pending promotion total exceeds safe integer range');
      }

      totalMinor += amount;

      await client.query(
        `
        UPDATE transactions
        SET
          status = 'APPROVED',
          updated_at = NOW()
        WHERE
          id = $1
          AND status = 'PENDING'
        `,
        [transaction.id]
      );

      await client.query(
        `
        INSERT INTO wallet_ledger (
          user_id,
          transaction_id,
          entry_type,
          amount_minor,
          currency,
          status,
          metadata
        )
        VALUES (
          $1,
          $2,
          'EARNING_APPROVED',
          $3,
          'AFN',
          'APPROVED',
          $4::jsonb
        )
        `,
        [
          userId,
          transaction.id,
          amount,
          JSON.stringify({
            event: 'pending_to_available',
            from_balance: 'PENDING',
            to_balance: 'AVAILABLE'
          })
        ]
      );

      await client.query(
        `
        INSERT INTO notifications (user_id, title, body)
        VALUES ($1, 'درآمد تایید شد', $2)
        `,
        [
          userId,
          `مبلغ ؋${(amount / 100).toFixed(2)} از حالت در حال بررسی به موجودی قابل برداشت منتقل شد.`
        ]
      );

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'EARNING_PROMOTED',
          'TRANSACTION',
          $1,
          $2::jsonb
        )
        `,
        [
          String(transaction.id),
          JSON.stringify({
            user_id: String(userId),
            amount_minor: amount,
            source: 'SETTLEMENT_VERIFIED_HOLD_COMPLETE'
          })
        ]
      );
    }

    const walletUpdate = await client.query(
      `
      UPDATE wallets
      SET
        pending_balance_minor =
          pending_balance_minor - $2,

        available_balance_minor =
          available_balance_minor + $2,

        lifetime_earnings_minor =
          lifetime_earnings_minor + $2,

        updated_at = NOW()

      WHERE
        user_id = $1
        AND pending_balance_minor >= $2
        AND available_balance_minor <= $3
        AND lifetime_earnings_minor <= $3

      RETURNING *
      `,
      [
        userId,
        totalMinor,
        Number.MAX_SAFE_INTEGER - totalMinor
      ]
    );

    if (!walletUpdate.rows.length) {
      throw new Error(
        'Wallet pending balance mismatch'
      );
    }

    await client.query('COMMIT');

    console.log(
      `Promoted ${pending.rows.length} earnings for user ${userId}: ${totalMinor} minor`
    );

    return {
      promoted: pending.rows.length,
      amountMinor: totalMinor
    };
  } catch (error) {
    await client.query('ROLLBACK');

    console.error(
      'Promote pending earnings failed:',
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

// =====================================================
// AUTH RECOVERY HELPERS
// =====================================================

function normalizePhone(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';

  const compact = raw.replace(/[\s().-]/g, '');

  if (/^00\d+$/.test(compact)) {
    return '+' + compact.slice(2);
  }

  if (/^\+\d+$/.test(compact)) {
    return compact;
  }

  if (/^\d+$/.test(compact)) {
    return compact;
  }

  return '';
}

function maskPhone(value) {
  const phone = normalizePhone(value);
  if (phone.length <= 4) return '****';
  return phone.slice(0, 3) + '***' + phone.slice(-3);
}

// =====================================================
// OTP / ACCOUNT RECOVERY
// =====================================================

function vonageConfigured() {
  return Boolean(VONAGE_API_KEY && VONAGE_API_SECRET);
}

function vonageAuthHeader() {
  return 'Basic ' + Buffer.from(VONAGE_API_KEY + ':' + VONAGE_API_SECRET).toString('base64');
}

async function vonageRequest(pathname, options = {}) {
  if (!vonageConfigured()) {
    const error = new Error('OTP provider is not configured');
    error.code = 'OTP_NOT_CONFIGURED';
    throw error;
  }

  const response = await fetch('https://api.nexmo.com' + pathname, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': vonageAuthHeader(),
      ...(options.headers || {})
    }
  });

  let data = {};
  try { data = await response.json(); } catch {}

  if (!response.ok) {
    const error = new Error('OTP provider request failed');
    error.status = response.status;
    error.providerData = data;
    throw error;
  }

  return data;
}

async function startVonageOtp(phone) {
  const to = normalizePhone(phone).replace(/^\+/, '');
  if (!/^\d{7,15}$/.test(to)) throw new Error('Invalid international phone number');

  return vonageRequest('/v2/verify', {
    method: 'POST',
    body: JSON.stringify({
      brand: OTP_BRAND.slice(0, 18),
      code_length: 6,
      workflow: [{ channel: 'sms', to }]
    })
  });
}

async function checkVonageOtp(requestId, code) {
  return vonageRequest('/v2/verify/' + encodeURIComponent(requestId), {
    method: 'POST',
    body: JSON.stringify({ code })
  });
}

const phoneOtpSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: req => String(req.userId || req.ip || 'anonymous'),
  message: {
    error: 'تعداد درخواست کد تأیید زیاد است. بعداً دوباره تلاش کنید.'
  }
});

app.post('/api/auth/phone-verification/send',
  authRequired, phoneOtpSendLimiter, async (req, res) => {
    try {
      const userResult = await pool.query(
        'SELECT id, phone, phone_verified FROM users WHERE id = $1 LIMIT 1',
        [req.userId]
      );
      const user = userResult.rows[0];
      if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
      if (user.phone_verified) return res.json({ ok: true, alreadyVerified: true });

      const provider = await startVonageOtp(user.phone);
      if (!provider.request_id) throw new Error('OTP provider did not return request_id');

      await pool.query(
        `UPDATE otp_verifications
         SET status = 'CANCELLED'
         WHERE user_id = $1 AND purpose = 'PHONE_VERIFY' AND status = 'REQUESTED'`,
        [req.userId]
      );
      await pool.query(
        `INSERT INTO otp_verifications
          (user_id, phone, purpose, provider, provider_request_id, status, expires_at)
         VALUES ($1, $2, 'PHONE_VERIFY', 'VONAGE', $3, 'REQUESTED', NOW() + INTERVAL '10 minutes')`,
        [req.userId, normalizePhone(user.phone), provider.request_id]
      );

      res.json({ ok: true, phone: maskPhone(user.phone), expiresInSeconds: 600 });
    } catch (error) {
      console.error('Phone OTP send failed:', error.message);
      res.status(error.code === 'OTP_NOT_CONFIGURED' ? 503 : 502).json({
        error: error.code === 'OTP_NOT_CONFIGURED'
          ? 'سرویس تایید شماره هنوز فعال نشده است'
          : 'ارسال کد تایید انجام نشد'
      });
    }
  }
);

app.post('/api/auth/phone-verification/verify',
  authRequired, sensitiveLimiter, async (req, res) => {
    const code = String(req.body?.code || '').trim();
    if (!/^\d{4,10}$/.test(code)) return res.status(400).json({ error: 'کد تایید معتبر نیست' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT * FROM otp_verifications
         WHERE user_id = $1 AND purpose = 'PHONE_VERIFY' AND status = 'REQUESTED'
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
        [req.userId]
      );
      const otp = result.rows[0];
      if (!otp || new Date(otp.expires_at) <= new Date()) {
        if (otp) await client.query("UPDATE otp_verifications SET status = 'EXPIRED' WHERE id = $1", [otp.id]);
        await client.query('COMMIT');
        return res.status(400).json({ error: 'کد منقضی شده یا درخواست فعالی وجود ندارد' });
      }
      if (Number(otp.attempts) >= 3) {
        await client.query("UPDATE otp_verifications SET status = 'FAILED' WHERE id = $1", [otp.id]);
        await client.query('COMMIT');
        return res.status(429).json({ error: 'تعداد تلاش‌های مجاز تمام شده است' });
      }

      await client.query('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = $1', [otp.id]);
      let checked;
      try { checked = await checkVonageOtp(otp.provider_request_id, code); }
      catch {
        await client.query('COMMIT');
        return res.status(400).json({ error: 'کد تایید نادرست یا نامعتبر است' });
      }
      if (String(checked.status || '').toLowerCase() !== 'completed') {
        await client.query('COMMIT');
        return res.status(400).json({ error: 'تایید شماره کامل نشد' });
      }

      await client.query(
        "UPDATE otp_verifications SET status = 'VERIFIED', verified_at = NOW() WHERE id = $1",
        [otp.id]
      );
      await client.query(
        'UPDATE users SET phone_verified = TRUE, updated_at = NOW() WHERE id = $1',
        [req.userId]
      );
      await client.query('COMMIT');
      res.json({ ok: true, phoneVerified: true });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Phone OTP verify failed:', error.message);
      res.status(500).json({ error: 'تایید شماره انجام نشد' });
    } finally { client.release(); }
  }
);

app.post('/api/auth/password/forgot',
  authLimiter, sensitiveLimiter, async (req, res) => {
    const phone = normalizePhone(req.body?.phone);
    const generic = { ok: true, message: 'اگر حسابی با این شماره وجود داشته باشد، کد بازیابی ارسال می‌شود.' };
    if (!phone) return res.status(400).json({ error: 'شماره معتبر وارد کنید' });
    // Respond identically for known and unknown numbers when SMS is unavailable.
    if (!vonageConfigured()) {
      return res.status(503).json({ error: 'سرویس بازیابی رمز هنوز فعال نشده است' });
    }

    try {
      const userResult = await pool.query('SELECT id, phone FROM users WHERE phone = $1 LIMIT 1', [phone]);
      const user = userResult.rows[0];
      if (!user) return res.json(generic);

      const provider = await startVonageOtp(user.phone);
      if (!provider.request_id) throw new Error('OTP provider did not return request_id');

      await pool.query(
        "UPDATE otp_verifications SET status = 'CANCELLED' WHERE user_id = $1 AND purpose = 'PASSWORD_RESET' AND status = 'REQUESTED'",
        [user.id]
      );
      await pool.query(
        `INSERT INTO otp_verifications
          (user_id, phone, purpose, provider, provider_request_id, status, expires_at)
         VALUES ($1, $2, 'PASSWORD_RESET', 'VONAGE', $3, 'REQUESTED', NOW() + INTERVAL '10 minutes')`,
        [user.id, phone, provider.request_id]
      );
      res.json(generic);
    } catch (error) {
      console.error('Password recovery OTP send failed:', error.message);
      if (error.code === 'OTP_NOT_CONFIGURED') {
        return res.status(503).json({ error: 'سرویس بازیابی رمز هنوز فعال نشده است' });
      }
      res.status(502).json({ error: 'ارسال کد بازیابی انجام نشد' });
    }
  }
);

app.post('/api/auth/password/verify-code',
  authLimiter, sensitiveLimiter, async (req, res) => {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || '').trim();
    if (!phone || !/^\d{4,10}$/.test(code)) return res.status(400).json({ error: 'شماره یا کد معتبر نیست' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `SELECT o.* FROM otp_verifications o
         JOIN users u ON u.id = o.user_id
         WHERE o.phone = $1 AND u.phone = $1
           AND o.purpose = 'PASSWORD_RESET' AND o.status = 'REQUESTED'
         ORDER BY o.created_at DESC LIMIT 1 FOR UPDATE`,
        [phone]
      );
      const otp = result.rows[0];
      if (!otp || new Date(otp.expires_at) <= new Date()) {
        if (otp) await client.query("UPDATE otp_verifications SET status = 'EXPIRED' WHERE id = $1", [otp.id]);
        await client.query('COMMIT');
        return res.status(400).json({ error: 'کد منقضی شده یا نامعتبر است' });
      }
      if (Number(otp.attempts) >= 3) {
        await client.query("UPDATE otp_verifications SET status = 'FAILED' WHERE id = $1", [otp.id]);
        await client.query('COMMIT');
        return res.status(429).json({ error: 'تعداد تلاش‌های مجاز تمام شده است' });
      }

      await client.query('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = $1', [otp.id]);
      let checked;
      try { checked = await checkVonageOtp(otp.provider_request_id, code); }
      catch {
        await client.query('COMMIT');
        return res.status(400).json({ error: 'کد بازیابی نادرست یا نامعتبر است' });
      }
      if (String(checked.status || '').toLowerCase() !== 'completed') {
        await client.query('COMMIT');
        return res.status(400).json({ error: 'تایید کد کامل نشد' });
      }

      await client.query(
        "UPDATE otp_verifications SET status = 'VERIFIED', verified_at = NOW() WHERE id = $1",
        [otp.id]
      );
      const resetToken = jwt.sign(
        { userId: String(otp.user_id), otpId: String(otp.id), type: 'PASSWORD_RESET' },
        JWT_SECRET,
        { expiresIn: '10m', issuer: 'kariyab', audience: 'kariyab-password-reset' }
      );
      await client.query('COMMIT');
      res.json({ ok: true, resetToken, expiresInSeconds: 600 });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Password recovery verify failed:', error.message);
      res.status(500).json({ error: 'تایید کد بازیابی انجام نشد' });
    } finally { client.release(); }
  }
);

app.post('/api/auth/password/reset',
  authLimiter, sensitiveLimiter, async (req, res) => {
    const resetToken = String(req.body?.resetToken || '');
    const password = String(req.body?.password || '');
    if (password.length < 8) return res.status(400).json({ error: 'رمز عبور باید حداقل ۸ کاراکتر باشد' });

    try {
      const decoded = jwt.verify(resetToken, JWT_SECRET, {
        issuer: 'kariyab',
        audience: 'kariyab-password-reset'
      });
      if (decoded.type !== 'PASSWORD_RESET' || !decoded.userId || !decoded.otpId) throw new Error('Invalid reset token');

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const otpResult = await client.query(
          `SELECT id FROM otp_verifications
           WHERE id = $1 AND user_id = $2 AND purpose = 'PASSWORD_RESET'
             AND status = 'VERIFIED' AND verified_at >= NOW() - INTERVAL '10 minutes'
           LIMIT 1 FOR UPDATE`,
          [decoded.otpId, decoded.userId]
        );
        if (!otpResult.rows.length) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'مجوز بازیابی منقضی یا استفاده شده است' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        await client.query(
          'UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1',
          [decoded.userId, passwordHash]
        );
        await client.query(
          "UPDATE otp_verifications SET status = 'CANCELLED' WHERE id = $1",
          [decoded.otpId]
        );
        await client.query('COMMIT');
        res.json({ ok: true });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally { client.release(); }
    } catch (error) {
      console.error('Password reset failed:', error.message);
      res.status(400).json({ error: 'مجوز بازیابی معتبر نیست یا منقضی شده است' });
    }
  }
);

// =====================================================
// HEALTH
// =====================================================

app.get('/api/health', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    await pool.query('SELECT 1');

    const providerResult = await pool.query(
      `SELECT 1 FROM providers WHERE code = 'CPX' LIMIT 1`
    );

    const methodResult = await pool.query(
      `SELECT COUNT(*)::int AS count FROM withdrawal_methods WHERE enabled = TRUE`
    );

    const schemaResult = await pool.query(
      `SELECT
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'identity_verifications'
             AND column_name = 'metadata'
         ) AS identity_metadata,
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'withdrawals'
             AND column_name = 'is_test'
         ) AS withdrawal_is_test,
         EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'withdrawals'
             AND column_name = 'environment'
         ) AS withdrawal_environment`
    );

    const schema = schemaResult.rows[0] || {};
    const productionSchemaReady =
      schema.identity_metadata === true &&
      schema.withdrawal_is_test === true &&
      schema.withdrawal_environment === true;

    res.status(productionSchemaReady ? 200 : 503).json({
      ok: productionSchemaReady,
      database: 'postgresql',
      checks: {
        cpxConfigured: Boolean(CPX_SECURE_HASH),
        cpxAppIdConfigured: Boolean(CPX_APP_ID),
        cpxProviderReady: providerResult.rows.length === 1,
        networkRiskConfigured: Boolean(IPQS_API_KEY),
        phoneOtpConfigured: vonageConfigured(),
        withdrawalMethodsEnabled: Number(methodResult.rows[0]?.count || 0),
        jwtConfigured: Boolean(JWT_SECRET),
        adminConfigured: Boolean(ADMIN_PASSWORD),
        productionSchemaReady,
        identityMetadataReady: schema.identity_metadata === true,
        withdrawalTestFlagReady: schema.withdrawal_is_test === true,
        withdrawalEnvironmentReady: schema.withdrawal_environment === true
      }
    });
  } catch (error) {
    res.status(503).json({
      ok: false,
      database: 'error'
    });
  }
});

// =====================================================
// REGISTER
// =====================================================

app.post('/api/register',
  authLimiter, async (req, res) => {
  const name =
    String(req.body.name || '').trim();

  const phone =
    normalizePhone(req.body.phone);

  const password =
    String(req.body.password || '');

  if (!name || !phone || !password) {
    return res.status(400).json({
      error: 'همه فیلدها لازم است'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error:
        'رمز عبور باید حداقل ۸ کاراکتر باشد'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const passwordHash =
      await bcrypt.hash(password, 12);

    const userResult =
      await client.query(
        `
        INSERT INTO users (
          name,
          phone,
          password_hash
        )
        VALUES ($1, $2, $3)
        RETURNING id, name, phone
        `,
        [
          name,
          phone,
          passwordHash
        ]
      );

    const user =
      userResult.rows[0];

    await client.query(
      `
      INSERT INTO wallets (
        user_id,
        currency,
        available_balance_minor,
        pending_balance_minor,
        lifetime_earnings_minor,
        lifetime_withdrawals_minor
      )
      VALUES (
        $1,
        'AFN',
        0,
        0,
        0,
        0
      )
      `,
      [user.id]
    );

    await client.query(
      `
      INSERT INTO user_profiles (
        user_id,
        language
      )
      VALUES ($1, 'fa')
      ON CONFLICT (user_id)
      DO NOTHING
      `,
      [user.id]
    );

    await client.query('COMMIT');

    const token = jwt.sign(
      {
        userId: String(user.id),
        type: 'USER_SESSION',
        sessionKey: userSessionKey(passwordHash)
      },
      JWT_SECRET,
      {
        expiresIn: '30d',
        issuer: 'kariyab',
        audience: 'kariyab-user'
      }
    );

    await recordDeviceSignal(user.id, req).catch(error => {
      console.error('Registration device signal recording failed:', error.message);
    });

    const networkRisk = await assessNetworkRisk(req);
    const networkWarning = networkRisk.detected
      ? {
          code: 'VPN_OR_PROXY_DETECTED',
          message: 'VPN یا Proxy شناسایی شد. برای استفاده از فرصت‌های درآمدی آن را خاموش کنید.'
        }
      : null;

    res.json({
      token,
      name: user.name,
      balance: 0,
      networkWarning
    });
  } catch (error) {
    await client.query('ROLLBACK');

    console.error(
      'Register failed:',
      error
    );

    if (error.code === '23505') {
      return res.status(400).json({
        error:
          'این شماره قبلاً ثبت‌نام کرده است'
      });
    }

    res.status(500).json({
      error: 'ثبت‌نام انجام نشد'
    });
  } finally {
    client.release();
  }
});

// =====================================================
// LOGIN
// =====================================================

app.post('/api/login',
  authLimiter, async (req, res) => {
  const phone =
    normalizePhone(req.body.phone);

  const password =
    String(req.body.password || '');

  if (!phone || !password) {
    return res.status(400).json({
      error:
        'شماره و رمز عبور را وارد کنید'
    });
  }

  try {
    const result = await pool.query(
      `
      SELECT
        u.id,
        u.name,
        u.password_hash,
        u.status,
        COALESCE(
          w.available_balance_minor,
          0
        ) AS available_balance_minor
      FROM users u
      LEFT JOIN wallets w
        ON w.user_id = u.id
      WHERE u.phone = $1
      LIMIT 1
      `,
      [phone]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({
        error: 'با این شماره تلفن حسابی وجود ندارد'
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {
      return res.status(400).json({
        error:
          'شماره یا رمز عبور اشتباه است'
      });
    }

    if (user.status !== 'ACTIVE') {
      return res.status(403).json({
        error: 'این حساب فعال نیست'
      });
    }

    const token = jwt.sign(
      {
        userId: String(user.id),
        type: 'USER_SESSION',
        sessionKey: userSessionKey(user.password_hash)
      },
      JWT_SECRET,
      {
        expiresIn: '30d',
        issuer: 'kariyab',
        audience: 'kariyab-user'
      }
    );

    await recordDeviceSignal(user.id, req).catch(error => {
      console.error('Device signal recording failed:', error.message);
    });

    const networkRisk = await assessNetworkRisk(req);
    const networkWarning = networkRisk.detected
      ? {
          code: 'VPN_OR_PROXY_DETECTED',
          message: 'VPN یا Proxy شناسایی شد. برای استفاده از فرصت‌های درآمدی آن را خاموش کنید.'
        }
      : null;

    res.json({
      token,
      name: user.name,
      balance:
        minorToAfn(
          user.available_balance_minor
        ),
      networkWarning
    });
  } catch (error) {
    console.error(
      'Login failed:',
      error
    );

    res.status(500).json({
      error: 'ورود انجام نشد'
    });
  }
});

// =====================================================
// PASSWORD RECOVERY STATUS
// =====================================================

app.post(
  '/api/auth/password-recovery/request',
  authLimiter,
  async (req, res) => {
    const phone = normalizePhone(req.body?.phone);

    if (!phone || phone.length < 7) {
      return res.status(400).json({
        error: 'شماره موبایل معتبر وارد کنید'
      });
    }

    // This legacy route does not send a code. Do not look up the phone or
    // reveal whether it belongs to an account.
    return res.status(503).json({
      error: 'بازیابی رمز از این مسیر فعال نیست',
      recoveryAvailable: false
    });
  }
);

// =====================================================
// ACCOUNT DELETION
// =====================================================

app.post(
  '/api/account/delete',
  authRequired,
  sensitiveLimiter,
  async (req, res) => {
    const password = String(req.body?.password || '');
    const confirmation = String(req.body?.confirmation || '').trim();

    if (!password || confirmation !== 'DELETE') {
      return res.status(400).json({
        error: 'رمز عبور و تایید حذف حساب لازم است'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const userResult = await client.query(
        `SELECT id, password_hash, status
         FROM users
         WHERE id = $1
         LIMIT 1
         FOR UPDATE`,
        [req.userId]
      );

      const user = userResult.rows[0];

      if (!user || user.status !== 'ACTIVE') {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'حساب فعال یافت نشد' });
      }

      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'رمز عبور اشتباه است' });
      }

      const activeWithdrawal = await client.query(
        `SELECT 1
         FROM withdrawals
         WHERE user_id = $1
           AND status IN ('REQUESTED','UNDER_REVIEW','APPROVED','PROCESSING')
         LIMIT 1`,
        [req.userId]
      );

      if (activeWithdrawal.rows.length) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'تا پایان درخواست برداشت فعال، حذف حساب ممکن نیست'
        });
      }

      // Financial/provider records are retained for audit integrity.
      // Personal access is revoked and reusable identifiers are anonymized.
      const deletedMarker = `deleted-${req.userId}-${Date.now()}`;
      const revokedHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);

      await client.query(
        `UPDATE users
         SET name = 'Deleted User',
             phone = $2,
             email = NULL,
             password_hash = $3,
             status = 'DELETED',
             updated_at = NOW()
         WHERE id = $1`,
        [req.userId, deletedMarker, revokedHash]
      );

      await client.query(
        `UPDATE user_profiles
         SET metadata = COALESCE(metadata, '{}'::jsonb)
           - 'profile_photo'
           - 'date_of_birth'
           - 'address'
         WHERE user_id = $1`,
        [req.userId]
      ).catch(error => {
        if (error.code !== '42P01') throw error;
      });

      await client.query(
        `INSERT INTO admin_actions (
           action_type, entity_type, entity_id, metadata
         )
         VALUES (
           'USER_SELF_DELETED', 'USER', $1,
           $2::jsonb
         )`,
        [
          String(req.userId),
          JSON.stringify({ source: 'SELF_SERVICE', financial_records_retained: true })
        ]
      );

      await client.query('COMMIT');
      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Account deletion failed:', error);
      res.status(500).json({ error: 'حذف حساب انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// TASKS
// =====================================================

app.get(
  '/api/tasks',
  authRequired,
  async (req, res) => {
    try {
      await promotePendingEarnings(
        req.userId
      );

      const wallet =
        await getWallet(req.userId);

      if (!wallet) {
        return res.status(404).json({
          error: 'کیف پول یافت نشد'
        });
      }

      res.json({
        tasks: [],

        balance:
          minorToAfn(
            wallet.available_balance_minor
          ),

        realOffersAvailable:
          Boolean(CPX_SECURE_HASH)
      });
    } catch (error) {
      console.error(
        'Tasks failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت فرصت‌ها انجام نشد'
      });
    }
  }
);

app.post(
  '/api/tasks/:id/complete',
  authRequired,
  (req, res) => {
    res.status(410).json({
      error:
        'تسک آزمایشی غیرفعال است'
    });
  }
);

// =====================================================
// CPX OFFERWALL
// =====================================================

app.get(
  '/api/cpx/offerwall-link',
  authRequired,
  earningAccessLimiter,
  async (req, res) => {
    if (!CPX_SECURE_HASH) {
      return res.status(503).json({
        error:
          'ارائه‌دهنده فرصت‌ها فعال نیست'
      });
    }

    try {
      const networkRisk = await assessNetworkRisk(req);
      if (networkRisk.unavailable) {
        console.warn('Earning access blocked because network risk verification is unavailable:', networkRisk.reason || 'UNKNOWN');
        return res.status(503).json({
          error: 'بررسی امنیت اتصال فعلاً انجام نشد. کمی بعد دوباره تلاش کنید.',
          code: 'NETWORK_RISK_UNAVAILABLE'
        });
      }

      if (networkRisk.detected) {
        return res.status(403).json({
          error: 'VPN یا Proxy شناسایی شد. برای استفاده از فرصت‌های درآمدی آن را خاموش کرده و دوباره تلاش کنید.',
          code: 'VPN_OR_PROXY_DETECTED'
        });
      }

      const blockingFraud = await pool.query(
        `
        SELECT 1
        FROM fraud_flags
        WHERE
          user_id = $1
          AND severity IN ('HIGH', 'CRITICAL')
          AND status IN ('OPEN', 'UNDER_REVIEW')
        LIMIT 1
        `,
        [req.userId]
      );

      if (blockingFraud.rows.length) {
        return res.status(403).json({
          error: 'فرصت‌های درآمد تا پایان بررسی امنیتی حساب موقتاً متوقف است'
        });
      }

      const userResult =
        await pool.query(
          `
          SELECT id, status
          FROM users
          WHERE id = $1
          LIMIT 1
          `,
          [req.userId]
        );

      const user =
        userResult.rows[0];

      if (
        !user ||
        user.status !== 'ACTIVE'
      ) {
        return res.status(403).json({
          error: 'حساب فعال نیست'
        });
      }

      const userId =
        String(user.id);

      const secureHash =
        md5(
          `${userId}-${CPX_SECURE_HASH}`
        );

      const url =
        'https://offers.cpx-research.com/index.php' +
        `?app_id=${encodeURIComponent(CPX_APP_ID)}` +
        `&ext_user_id=${encodeURIComponent(userId)}` +
        `&secure_hash=${encodeURIComponent(secureHash)}`;

      res.json({ url });
    } catch (error) {
      console.error(
        'CPX link failed:',
        error
      );

      res.status(500).json({
        error:
          'لینک فرصت‌ها ساخته نشد'
      });
    }
  }
);

// =====================================================
// CPX POSTBACK
// =====================================================

app.get(
  '/api/cpx/postback',
  async (req, res) => {
    const status =
      String(req.query.status || '');

    const transId =
      String(req.query.trans_id || '').trim();

    const userId =
      String(req.query.user_id || '').trim();

    const amountUsd =
      String(req.query.amount_usd || '').trim();

    const offerId =
      String(req.query.offer_id || '').trim();

    const suppliedHash =
      String(
        req.query.hash ||
        req.query.secure_hash ||
        ''
      ).trim();

    if (!CPX_SECURE_HASH) {
      return res
        .status(503)
        .send('provider disabled');
    }

    if (
      !transId ||
      !userId ||
      !suppliedHash ||
      !['1', '2'].includes(status) ||
      !/^\d+$/.test(userId) ||
      transId.length > 200 ||
      userId.length > 32 ||
      offerId.length > 200 ||
      suppliedHash.length !== 32 ||
      !/^[a-fA-F0-9]{32}$/.test(suppliedHash)
    ) {
      return res
        .status(400)
        .send('invalid request');
    }

    const expectedHash =
      md5(
        `${transId}-${CPX_SECURE_HASH}`
      );

    if (
      !safeCompare(
        suppliedHash.toLowerCase(),
        expectedHash.toLowerCase()
      )
    ) {
      return res
        .status(403)
        .send('invalid hash');
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      // Serialize completion and reversal for one provider transaction.
      // A reversal that arrived first must never be followed by a credit.
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))',
        ['CPX', transId]
      );

      const providerResult =
        await client.query(
          `
          SELECT id, code
          FROM providers
          WHERE code = 'CPX'
          LIMIT 1
          `
        );

      if (!providerResult.rows.length) {
        throw new Error(
          'CPX provider missing'
        );
      }

      const provider =
        providerResult.rows[0];

      const userResult =
        await client.query(
          `
          SELECT id, status
          FROM users
          WHERE id = $1
          LIMIT 1
          `,
          [userId]
        );

      const user =
        userResult.rows[0];

      if (
        !user ||
        user.status !== 'ACTIVE'
      ) {
        await client.query('ROLLBACK');

        return res
          .status(404)
          .send('user not found');
      }

      const eventId =
        `${transId}:${status}`;

      const eventInsert =
        await client.query(
          `
          INSERT INTO offer_events (
            provider_id,
            user_id,
            provider_event_id,
            event_type,
            raw_payload,
            validation_status,
            received_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5::jsonb,
            'VALID',
            NOW()
          )
          ON CONFLICT (
            provider_id,
            provider_event_id
          )
          DO NOTHING
          RETURNING id
          `,
          [
            provider.id,
            user.id,
            eventId,
            status === '1'
              ? 'COMPLETED'
              : 'REVERSED',
            JSON.stringify(req.query)
          ]
        );

      // Duplicate event: acknowledge, do nothing.
      if (!eventInsert.rows.length) {
        await client.query('COMMIT');
        return res.status(200).send('1');
      }

      // ---------------------------------------------
      // COMPLETION
      // ---------------------------------------------

      if (status === '1') {
        const priorReversal = await client.query(
          `SELECT id FROM offer_events
           WHERE provider_id = $1
             AND provider_event_id = $2
             AND event_type = 'REVERSED'
           LIMIT 1`,
          [provider.id, `${transId}:2`]
        );

        if (priorReversal.rows.length) {
          await client.query(
            `UPDATE offer_events
             SET validation_status = 'REQUIRES_REVIEW', processed_at = NOW()
             WHERE id = $1`,
            [eventInsert.rows[0].id]
          );
          await client.query('COMMIT');
          return res.status(200).send('1');
        }

        if (
          !/^\d+(\.\d+)?$/.test(amountUsd)
        ) {
          throw new Error(
            'Invalid CPX USD amount'
          );
        }

        const existing =
          await client.query(
            `
            SELECT id
            FROM transactions
            WHERE
              provider_id = $1
              AND provider_transaction_id = $2
            LIMIT 1
            `,
            [
              provider.id,
              transId
            ]
          );

        if (!existing.rows.length) {
          const settings =
            await getRuntimeSettings(client);

          const rewardMinor =
            calculateProviderRewardMinor(
              amountUsd,
              settings.afnPerUsd,
              settings.revenueShare
            );

          if (rewardMinor <= 0) {
            throw new Error(
              'Invalid calculated reward'
            );
          }

          // High-value provider events are not auto-blocked; they are
          // flagged for manual review while the earning remains pending.
          const highValueThresholdMinor = 50000;
          if (rewardMinor >= highValueThresholdMinor) {
            const existingFlag = await client.query(
              `
              SELECT id
              FROM fraud_flags
              WHERE user_id = $1
                AND flag_type = 'HIGH_VALUE_PROVIDER_EVENT'
                AND status IN ('OPEN', 'UNDER_REVIEW')
                AND metadata->>'provider_transaction_id' = $2
              LIMIT 1
              `,
              [user.id, transId]
            );

            if (!existingFlag.rows.length) {
              await client.query(
                `
                INSERT INTO fraud_flags (
                  user_id, flag_type, severity, status, reason, metadata
                )
                VALUES (
                  $1, 'HIGH_VALUE_PROVIDER_EVENT', 'HIGH', 'OPEN',
                  'High-value provider event requires review', $2::jsonb
                )
                `,
                [
                  user.id,
                  JSON.stringify({
                    provider: 'CPX',
                    provider_transaction_id: transId,
                    reward_minor: rewardMinor,
                    amount_usd: amountUsd
                  })
                ]
              );
            }
          }

          const transactionId =
            publicId('CPX');

          const txResult =
            await client.query(
              `
              INSERT INTO transactions (
                transaction_id,
                user_id,
                provider_id,
                provider_transaction_id,
                type,
                amount_minor,
                currency,
                status,
                metadata
              )
              VALUES (
                $1,
                $2,
                $3,
                $4,
                'EARNING',
                $5,
                'AFN',
                'PENDING',
                $6::jsonb
              )
              RETURNING id
              `,
              [
                transactionId,
                user.id,
                provider.id,
                transId,
                rewardMinor,
                JSON.stringify({
                  provider: 'CPX',
                  amount_usd: amountUsd,
                  offer_id: offerId
                })
              ]
            );

          const tx =
            txResult.rows[0];

          await client.query(
            `
            INSERT INTO wallet_ledger (
              user_id,
              transaction_id,
              entry_type,
              amount_minor,
              currency,
              status,
              metadata
            )
            VALUES (
              $1,
              $2,
              'EARNING',
              $3,
              'AFN',
              'PENDING',
              $4::jsonb
            )
            `,
            [
              user.id,
              tx.id,
              rewardMinor,
              JSON.stringify({
                provider: 'CPX',
                provider_transaction_id:
                  transId
              })
            ]
          );

          const creditedWallet = await client.query(
            `
            UPDATE wallets
            SET
              pending_balance_minor =
                pending_balance_minor + $2,
              updated_at = NOW()
            WHERE
              user_id = $1
              AND pending_balance_minor <= $3
            RETURNING id
            `,
            [
              user.id,
              rewardMinor,
              Number.MAX_SAFE_INTEGER - rewardMinor
            ]
          );

          if (!creditedWallet.rows.length) {
            throw new Error(
              'Pending wallet credit failed or exceeds safe integer range'
            );
          }

          await client.query(
            `
            INSERT INTO notifications (user_id, title, body)
            VALUES ($1, 'درآمد ثبت شد', $2)
            `,
            [
              user.id,
              `مبلغ ؋${(rewardMinor / 100).toFixed(2)} ثبت شد و تا پایان دوره بررسی در موجودی در حال بررسی می‌ماند.`
            ]
          );
        }
      }

      // ---------------------------------------------
      // REVERSAL
      // ---------------------------------------------

      if (status === '2') {
        const txResult =
          await client.query(
            `
            SELECT
              id,
              amount_minor,
              status
            FROM transactions
            WHERE
              provider_id = $1
              AND provider_transaction_id = $2
              AND type = 'EARNING'
            LIMIT 1
            FOR UPDATE
            `,
            [
              provider.id,
              transId
            ]
          );

        const tx =
          txResult.rows[0];

        if (tx) {
          const amount = Number(tx.amount_minor);
          if (!Number.isSafeInteger(amount) || amount <= 0) {
            throw new Error('Invalid reversal transaction amount');
          }
        }

        if (tx && tx.status !== 'REVERSED') {
          const amount =
            Number(tx.amount_minor);

          if (tx.status === 'PENDING') {
            const walletResult =
              await client.query(
                `
                UPDATE wallets
                SET
                  pending_balance_minor =
                    pending_balance_minor - $2,
                  updated_at = NOW()
                WHERE
                  user_id = $1
                  AND pending_balance_minor >= $2
                RETURNING id
                `,
                [
                  user.id,
                  amount
                ]
              );

            if (!walletResult.rows.length) {
              throw new Error(
                'Pending wallet mismatch during reversal'
              );
            }
          }

          if (tx.status === 'APPROVED') {
            const existingReversalFlag = await client.query(
              `
              SELECT id
              FROM fraud_flags
              WHERE user_id = $1
                AND flag_type = 'APPROVED_EARNING_REVERSED'
                AND status IN ('OPEN', 'UNDER_REVIEW')
                AND metadata->>'provider_transaction_id' = $2
              LIMIT 1
              `,
              [user.id, transId]
            );

            if (!existingReversalFlag.rows.length) {
              await client.query(
                `
                INSERT INTO fraud_flags (
                  user_id, flag_type, severity, status, reason, metadata
                )
                VALUES (
                  $1, 'APPROVED_EARNING_REVERSED', 'HIGH', 'OPEN',
                  'Approved earning reversed by provider', $2::jsonb
                )
                `,
                [
                  user.id,
                  JSON.stringify({
                    provider: 'CPX',
                    provider_transaction_id: transId,
                    amount_minor: amount
                  })
                ]
              );
            }

            const approvedWalletResult =
              await client.query(
                `
                UPDATE wallets
                SET
                  available_balance_minor =
                    available_balance_minor - $2,

                  lifetime_earnings_minor =
                    lifetime_earnings_minor - $2,

                  updated_at = NOW()

                WHERE
                  user_id = $1
                  AND available_balance_minor >= $2
                  AND lifetime_earnings_minor >= $2
                RETURNING id
                `,
                [
                  user.id,
                  amount
                ]
              );

            if (!approvedWalletResult.rows.length) {
              // The earning was already approved but is no longer fully
              // recoverable from available balance (for example, it may
              // have been reserved/withdrawn). Do not lose the provider
              // reversal by rolling back the raw event and fraud evidence.
              // Keep the original earning transaction unchanged, mark this
              // event for manual review, and block withdrawals via a HIGH
              // fraud flag until an administrator resolves the debt.
              await client.query(
                `
                UPDATE offer_events
                SET
                  validation_status = 'REQUIRES_REVIEW',
                  processed_at = NOW()
                WHERE id = $1
                `,
                [eventInsert.rows[0].id]
              );

              await client.query(
                `
                INSERT INTO notifications (user_id, title, body)
                VALUES ($1, 'بررسی حساب لازم است', $2)
                `,
                [
                  user.id,
                  'یک اصلاح درآمد توسط ارائه‌دهنده ثبت شده است و حساب برای بررسی مالی علامت‌گذاری شد.'
                ]
              );

              await client.query('COMMIT');
              return res.status(200).send('1');
            }
          }

          await client.query(
            `
            UPDATE transactions
            SET
              status = 'REVERSED',
              updated_at = NOW()
            WHERE id = $1
            `,
            [tx.id]
          );

          await client.query(
            `
            INSERT INTO wallet_ledger (
              user_id,
              transaction_id,
              entry_type,
              amount_minor,
              currency,
              status,
              metadata
            )
            VALUES (
              $1,
              $2,
              'REVERSAL',
              $3,
              'AFN',
              'REVERSED',
              $4::jsonb
            )
            `,
            [
              user.id,
              tx.id,
              -amount,
              JSON.stringify({
                provider: 'CPX',
                provider_transaction_id:
                  transId
              })
            ]
          );

          await client.query(
            `
            INSERT INTO notifications (user_id, title, body)
            VALUES ($1, 'اصلاح درآمد', $2)
            `,
            [
              user.id,
              `یک درآمد به مبلغ ؋${(amount / 100).toFixed(2)} توسط ارائه‌دهنده برگشت داده شد و کیف پول مطابق آن اصلاح شد.`
            ]
          );
        }
      }

      await client.query(
        `
        UPDATE offer_events
        SET processed_at = NOW()
        WHERE id = $1
        `,
        [eventInsert.rows[0].id]
      );

      await client.query('COMMIT');

      return res.status(200).send('1');
    } catch (error) {
      await client.query('ROLLBACK');

      console.error(
        'CPX postback failed:',
        error
      );

      return res
        .status(500)
        .send('error');
    } finally {
      client.release();
    }
  }
);

// =====================================================
// WALLET
// =====================================================

app.get(
  '/api/wallet',
  authRequired,
  async (req, res) => {
    try {
      // IMPORTANT:
      // Promotion is executed every time wallet is loaded.
      await promotePendingEarnings(
        req.userId
      );

      const wallet =
        await getWallet(req.userId);

      if (!wallet) {
        return res.status(404).json({
          error: 'کیف پول یافت نشد'
        });
      }

      const settings =
        await getRuntimeSettings();

      const withdrawalsResult =
        await pool.query(
          `
          SELECT
            w.id,
            w.withdrawal_id,
            w.amount_minor,
            w.status,
            w.created_at,
            (
              COALESCE(w.is_test, FALSE)
              OR COALESCE(w.payment_reference, '') ~* '^TEST([[:space:]_-]|$)'
              OR w.withdrawal_id ~* '^TEST([[:space:]_-]|$)'
            ) AS is_test,
            wm.name AS method
          FROM withdrawals w
          LEFT JOIN withdrawal_methods wm
            ON wm.id = w.method_id
          WHERE w.user_id = $1
          ORDER BY w.created_at DESC
          LIMIT 50
          `,
          [req.userId]
        );

      const ledgerResult =
        await pool.query(
          `
          SELECT
            wl.id,
            wl.entry_type,
            wl.amount_minor,
            wl.status,
            wl.created_at
          FROM wallet_ledger wl
          WHERE wl.user_id = $1
          ORDER BY wl.created_at DESC, wl.id DESC
          LIMIT 100
          `,
          [req.userId]
        );

      res.json({
        available:
          minorToAfn(
            wallet.available_balance_minor
          ),

        pending:
          minorToAfn(
            wallet.pending_balance_minor
          ),

        lifetimeEarnings:
          minorToAfn(
            wallet.lifetime_earnings_minor
          ),

        lifetimeWithdrawals:
          minorToAfn(
            wallet.lifetime_withdrawals_minor
          ),

        minWithdraw:
          minorToAfn(
            settings.minimumWithdrawalMinor
          ),

        withdrawals:
          withdrawalsResult.rows.map(w => ({
            id: w.id,
            withdrawalId:
              w.withdrawal_id,
            amount:
              minorToAfn(w.amount_minor),
            method:
              w.method,
            isTest: Boolean(w.is_test),
            rawStatus: w.status,
            status:
              w.status === 'REJECTED'
                ? 'rejected'
                : w.status === 'PAID'
                ? 'approved'
                : 'pending',
            createdAt: w.created_at
          })),

        ledger:
          ledgerResult.rows.map(row => ({
            id: row.id,
            type: row.entry_type,
            amount:
              minorToAfn(row.amount_minor),
            status: row.status,
            createdAt: row.created_at
          }))
      });
    } catch (error) {
      console.error(
        'Wallet failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت کیف پول انجام نشد'
      });
    }
  }
);

// =====================================================
// NOTIFICATIONS
// =====================================================

app.get('/api/notifications', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, body, read_at, created_at
       FROM notifications
       WHERE user_id = $1
       ORDER BY created_at DESC, id DESC
       LIMIT 50`,
      [req.userId]
    );
    const unread = result.rows.reduce((count, row) => count + (row.read_at ? 0 : 1), 0);
    res.json({
      unread,
      notifications: result.rows.map(row => ({
        id: row.id,
        title: row.title,
        body: row.body,
        read: Boolean(row.read_at),
        createdAt: row.created_at
      }))
    });
  } catch (error) {
    console.error('Notifications failed:', error);
    res.status(500).json({ error: 'دریافت اعلان‌ها انجام نشد' });
  }
});

app.post('/api/notifications/:id/read', authRequired, async (req, res) => {
  const notificationId = String(req.params.id || '').trim();
  if (!/^\d+$/.test(notificationId)) {
    return res.status(400).json({ error: 'شناسه اعلان معتبر نیست' });
  }

  try {
    const result = await pool.query(
      `UPDATE notifications
       SET read_at = COALESCE(read_at, NOW())
       WHERE id = $1 AND user_id = $2
       RETURNING id, read_at`,
      [notificationId, req.userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'اعلان یافت نشد' });
    res.json({ ok: true });
  } catch (error) {
    console.error('Notification read failed:', error);
    res.status(500).json({ error: 'به‌روزرسانی اعلان انجام نشد' });
  }
});

app.post('/api/notifications/read-all', authRequired, async (req, res) => {
  try {
    await pool.query(
      `UPDATE notifications SET read_at = NOW()
       WHERE user_id = $1 AND read_at IS NULL`,
      [req.userId]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Notifications read-all failed:', error);
    res.status(500).json({ error: 'به‌روزرسانی اعلان‌ها انجام نشد' });
  }
});

// =====================================================
// IDENTITY VERIFICATION
// =====================================================

function validIdentityImage(value) {
  const image = String(value || '');
  return /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(image) &&
    Buffer.byteLength(image, 'utf8') <= 700000;
}

app.get('/api/identity-verification', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT verification_id, document_type, document_number_last4,
              status, rejection_reason, submitted_at, reviewed_at
       FROM identity_verifications
       WHERE user_id = $1
       ORDER BY submitted_at DESC, id DESC
       LIMIT 1`,
      [req.userId]
    );
    const row = result.rows[0];
    res.json({
      status: row?.status || 'UNVERIFIED',
      verification: row || null
    });
  } catch (error) {
    console.error('Identity verification status failed:', error);
    res.status(500).json({ error: 'دریافت وضعیت احراز هویت انجام نشد' });
  }
});

app.post('/api/identity-verification', authRequired, sensitiveLimiter, async (req, res) => {
  const documentType = String(req.body?.documentType || '').trim().toUpperCase();
  const documentNumber = String(req.body?.documentNumber || '').replace(/\s+/g, '').trim();
  const documentName = String(req.body?.documentName || '').replace(/\s+/g, ' ').trim();
  const documentImage = String(req.body?.documentImage || '');
  const selfieImage = String(req.body?.selfieImage || '');

  if (!['NATIONAL_ID', 'PASSPORT', 'OTHER'].includes(documentType)) {
    return res.status(400).json({ error: 'نوع مدرک معتبر نیست' });
  }
  if (
    documentNumber.length < 4 ||
    documentNumber.length > 80 ||
    !/^[\p{L}\p{N}._\/-]+$/u.test(documentNumber)
  ) {
    return res.status(400).json({ error: 'شماره مدرک معتبر نیست' });
  }
  if (documentName.length < 3 || documentName.length > 120 || !/^[\p{L}\p{M} .'-]+$/u.test(documentName)) {
    return res.status(400).json({ error: 'نام مطابق مدرک هویتی معتبر نیست' });
  }
  if (!validIdentityImage(documentImage) || !validIdentityImage(selfieImage)) {
    return res.status(400).json({ error: 'تصویر مدرک یا سلفی معتبر نیست یا حجم آن زیاد است' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const accountResult = await client.query(
      `SELECT name FROM users WHERE id = $1 AND status = 'ACTIVE' LIMIT 1`,
      [req.userId]
    );
    const accountName = String(accountResult.rows[0]?.name || '').replace(/\s+/g, ' ').trim();
    const normalizeName = value => String(value || '')
      .normalize('NFKC')
      .toLocaleLowerCase()
      .replace(/[\u200c\u200d]/g, '')
      .replace(/[^\p{L}\p{M}]/gu, '');

    if (!accountName || normalizeName(accountName) !== normalizeName(documentName)) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'نام درج‌شده در حساب باید با نام روی مدرک هویتی یکسان باشد'
      });
    }

    const existing = await client.query(
      `SELECT id, status
       FROM identity_verifications
       WHERE user_id = $1
       ORDER BY submitted_at DESC, id DESC
       LIMIT 1
       FOR UPDATE`,
      [req.userId]
    );

    if (existing.rows[0]?.status === 'VERIFIED') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'هویت این حساب قبلاً تایید شده است' });
    }
    if (existing.rows[0]?.status === 'UNDER_REVIEW') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'درخواست احراز هویت شما در حال بررسی است' });
    }

    const verificationId = publicId('KYC');
    const last4 = documentNumber.slice(-4);

    await client.query(
      `INSERT INTO identity_verifications
        (verification_id, user_id, document_type, document_number_last4,
         document_image, selfie_image, status, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, 'UNDER_REVIEW',
               jsonb_build_object('document_name', $7, 'account_name', $8, 'name_match', true))`,
      [verificationId, req.userId, documentType, last4, documentImage, selfieImage, documentName, accountName]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, body)
       VALUES ($1, 'احراز هویت در حال بررسی است',
               'مدرک و سلفی شما دریافت شد. نتیجه پس از بررسی اعلام می‌شود.')`,
      [req.userId]
    );

    await client.query('COMMIT');
    res.status(201).json({ ok: true, verificationId, status: 'UNDER_REVIEW' });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Identity verification submission failed:', error);
    res.status(500).json({ error: 'ثبت درخواست احراز هویت انجام نشد' });
  } finally {
    client.release();
  }
});

// =====================================================
// WITHDRAWAL METHODS
// =====================================================

app.get(
  '/api/withdrawal-methods',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT code, name
        FROM withdrawal_methods
        WHERE enabled = TRUE
        ORDER BY id
        `
      );

      res.json({
        methods: result.rows.map(row => {
          const code = String(row.code || '').toUpperCase();
          const field =
            code === 'HESABPAY'
              ? {
                  accountLabel: 'شماره موبایل حساب HesabPay',
                  accountPlaceholder: 'شماره موبایل ثبت‌شده در HesabPay',
                  accountType: 'phone'
                }
              : code === 'M-PAISA' || code === 'MPAISA'
              ? {
                  accountLabel: 'شماره موبایل M-Paisa',
                  accountPlaceholder: 'شماره موبایل ثبت‌شده در M-Paisa',
                  accountType: 'phone'
                }
              : {
                  accountLabel: 'نمبر حساب / شماره تماس',
                  accountPlaceholder: 'مشخصات حساب دریافت‌کننده',
                  accountType: 'text'
                };

          return {
            code: row.code,
            name: row.name,
            ...field
          };
        })
      });
    } catch (error) {
      console.error('Withdrawal methods failed:', error);
      res.status(500).json({
        error: 'دریافت روش‌های برداشت انجام نشد'
      });
    }
  }
);

// =====================================================
// WITHDRAW
// =====================================================

app.post(
  '/api/withdraw',
  authRequired,
  sensitiveLimiter,
  async (req, res) => {
    const amountMinor =
      afnToMinor(req.body.amount);

    const methodCode =
      String(req.body.method || '').trim();

    const account =
      String(req.body.account || '').trim();

    if (
      !amountMinor ||
      !methodCode ||
      !account
    ) {
      return res.status(400).json({
        error:
          'اطلاعات برداشت کامل نیست'
      });
    }

    if (methodCode.length > 50 || !/^[A-Za-z0-9_-]+$/.test(methodCode)) {
      return res.status(400).json({ error: 'روش برداشت معتبر نیست' });
    }

    if (account.length < 3 || account.length > 200 || /[\u0000-\u001F\u007F]/.test(account)) {
      return res.status(400).json({ error: 'مشخصات حساب دریافت‌کننده معتبر نیست' });
    }

    const client =
      await pool.connect();

    try {
      await promotePendingEarnings(
        req.userId
      );

      await client.query('BEGIN');

      const settings =
        await getRuntimeSettings(client);

      // Lock the wallet before checking for an active withdrawal, so two
      // concurrent requests from the same user cannot both pass the check.
      const lockedWallet = await client.query(
        `SELECT id FROM wallets WHERE user_id = $1 FOR UPDATE`,
        [req.userId]
      );
      if (!lockedWallet.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'کیف پول یافت نشد' });
      }

      const existingWithdrawal = await client.query(
        `
        SELECT withdrawal_id, status
        FROM withdrawals
        WHERE
          user_id = $1
          AND status IN ('REQUESTED', 'UNDER_REVIEW', 'APPROVED', 'PROCESSING')
        LIMIT 1
        FOR UPDATE
        `,
        [req.userId]
      );

      if (existingWithdrawal.rows.length) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'یک درخواست برداشت فعال دارید؛ تا نهایی‌شدن آن درخواست جدید ثبت نمی‌شود',
          code: 'ACTIVE_WITHDRAWAL_EXISTS',
          withdrawalId: existingWithdrawal.rows[0].withdrawal_id,
          status: existingWithdrawal.rows[0].status
        });
      }

      const identityResult = await client.query(
        `SELECT iv.status,
                iv.metadata->>'document_name' AS document_name,
                COALESCE((iv.metadata->>'name_match')::boolean, FALSE) AS name_match,
                u.name AS account_name
         FROM identity_verifications iv
         JOIN users u ON u.id = iv.user_id
         WHERE iv.user_id = $1
         ORDER BY iv.submitted_at DESC, iv.id DESC
         LIMIT 1`,
        [req.userId]
      );

      const identity = identityResult.rows[0];
      const normalizeIdentityName = value => String(value || '')
        .normalize('NFKC')
        .toLocaleLowerCase()
        .replace(/[\u200c\u200d]/g, '')
        .replace(/[^\p{L}\p{M}]/gu, '');
      const verifiedNameMatch =
        identity?.name_match === true &&
        normalizeIdentityName(identity?.account_name) === normalizeIdentityName(identity?.document_name);

      if (identity?.status !== 'VERIFIED' || !verifiedNameMatch) {
        await client.query('ROLLBACK');
        const identityStatus = identity?.status || 'UNVERIFIED';
        return res.status(403).json({
          error: identityStatus === 'UNDER_REVIEW'
            ? 'احراز هویت شما هنوز در حال بررسی است'
            : 'برای برداشت پول ابتدا باید احراز هویت حساب تکمیل شود',
          code: 'IDENTITY_VERIFICATION_REQUIRED',
          identityStatus
        });
      }

      if (
        amountMinor <
        settings.minimumWithdrawalMinor
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            `حداقل برداشت ${minorToAfn(
              settings.minimumWithdrawalMinor
            )} افغانی است`
        });
      }

      const methodResult =
        await client.query(
          `
          SELECT id, code, name
          FROM withdrawal_methods
          WHERE
            code = $1
            AND enabled = TRUE
          LIMIT 1
          `,
          [methodCode]
        );

      if (!methodResult.rows.length) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'روش برداشت فعال نیست'
        });
      }

      const openFraud = await client.query(
        `
        SELECT id
        FROM fraud_flags
        WHERE user_id = $1
          AND status IN ('OPEN', 'UNDER_REVIEW')
          AND severity IN ('HIGH', 'CRITICAL')
        LIMIT 1
        `,
        [req.userId]
      );

      if (openFraud.rows.length) {
        await client.query('ROLLBACK');
        return res.status(423).json({
          error: 'برداشت این حساب برای بررسی امنیتی موقتاً متوقف است'
        });
      }

      const walletResult =
        await client.query(
          `
          SELECT *
          FROM wallets
          WHERE user_id = $1
          LIMIT 1
          FOR UPDATE
          `,
          [req.userId]
        );

      const wallet =
        walletResult.rows[0];

      if (
        !wallet ||
        Number(
          wallet.available_balance_minor
        ) < amountMinor
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'موجودی قابل برداشت کافی نیست'
        });
      }

      const transactionId =
        publicId('WD');

      const withdrawalId =
        publicId('WITHDRAWAL');

      const txResult =
        await client.query(
          `
          INSERT INTO transactions (
            transaction_id,
            user_id,
            type,
            amount_minor,
            currency,
            status,
            metadata
          )
          VALUES (
            $1,
            $2,
            'WITHDRAWAL',
            $3,
            'AFN',
            'PENDING',
            $4::jsonb
          )
          RETURNING id
          `,
          [
            transactionId,
            req.userId,
            -amountMinor,
            JSON.stringify({
              withdrawal_id:
                withdrawalId
            })
          ]
        );

      const tx =
        txResult.rows[0];

      await client.query(
        `
        INSERT INTO withdrawals (
          withdrawal_id,
          user_id,
          method_id,
          amount_minor,
          currency,
          status,
          account_details
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          'AFN',
          'REQUESTED',
          $5
        )
        `,
        [
          withdrawalId,
          req.userId,
          methodResult.rows[0].id,
          amountMinor,
          account
        ]
      );

      await client.query(
        `
        INSERT INTO wallet_ledger (
          user_id,
          transaction_id,
          entry_type,
          amount_minor,
          currency,
          status,
          metadata
        )
        VALUES (
          $1,
          $2,
          'WITHDRAWAL_RESERVED',
          $3,
          'AFN',
          'PENDING',
          $4::jsonb
        )
        `,
        [
          req.userId,
          tx.id,
          -amountMinor,
          JSON.stringify({
            withdrawal_id:
              withdrawalId
          })
        ]
      );

      const updated =
        await client.query(
          `
          UPDATE wallets
          SET
            available_balance_minor =
              available_balance_minor - $2,
            updated_at = NOW()
          WHERE
            user_id = $1
            AND available_balance_minor >= $2
          RETURNING *
          `,
          [
            req.userId,
            amountMinor
          ]
        );

      if (!updated.rows.length) {
        throw new Error(
          'Wallet reservation failed'
        );
      }

      await client.query(
        `INSERT INTO notifications (user_id, title, body)
         VALUES ($1, 'درخواست برداشت ثبت شد', $2)`,
        [
          req.userId,
          `درخواست برداشت ؋${(amountMinor / 100).toFixed(2)} از طریق ${methodResult.rows[0].name} ثبت شد و در انتظار بررسی است.`
        ]
      );

      await client.query('COMMIT');

      res.json({
        ok: true,
        withdrawalId,
        balance:
          minorToAfn(
            updated.rows[0]
              .available_balance_minor
          )
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(
        'Withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'درخواست برداشت ثبت نشد'
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// SUPPORT TICKETS
// =====================================================

app.post(
  '/api/support/tickets',
  authRequired,
  async (req, res) => {
    const allowedCategories = new Set([
      'EARNING_NOT_RECORDED',
      'TASK_NOT_APPROVED',
      'WITHDRAWAL_NOT_PAID',
      'ACCOUNT',
      'OTHER'
    ]);

    const category = String(req.body.category || '').trim().toUpperCase();
    const subject = String(req.body.subject || '').trim().slice(0, 255);
    const message = String(req.body.message || '').trim();

    if (!allowedCategories.has(category)) {
      return res.status(400).json({ error: 'دسته‌بندی درخواست معتبر نیست' });
    }

    if (message.length < 5 || message.length > 5000) {
      return res.status(400).json({ error: 'متن درخواست باید بین ۵ تا ۵۰۰۰ کاراکتر باشد' });
    }

    try {
      const ticketId = 'KRY-SUP-' + crypto.randomBytes(8).toString('hex').toUpperCase();

      const result = await pool.query(
        `
        INSERT INTO support_tickets (
          ticket_id,
          user_id,
          category,
          subject,
          message,
          status
        )
        VALUES ($1, $2, $3, $4, $5, 'OPEN')
        RETURNING
          ticket_id,
          category,
          subject,
          message,
          status,
          created_at
        `,
        [ticketId, req.userId, category, subject || null, message]
      );

      res.status(201).json({ ticket: result.rows[0] });
    } catch (error) {
      console.error('Create support ticket failed:', error);
      res.status(500).json({ error: 'ثبت درخواست پشتیبانی انجام نشد' });
    }
  }
);

app.get(
  '/api/support/tickets',
  authRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          ticket_id,
          category,
          subject,
          message,
          status,
          created_at,
          updated_at
        FROM support_tickets
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 100
        `,
        [req.userId]
      );

      res.json({ tickets: result.rows });
    } catch (error) {
      console.error('List support tickets failed:', error);
      res.status(500).json({ error: 'دریافت درخواست‌های پشتیبانی انجام نشد' });
    }
  }
);

// =====================================================
// ADMIN ACCOUNT RECOVERY (temporary until real OTP is enabled)
// =====================================================

app.post(
  '/api/admin/users/recover-password',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const phone = normalizePhone(req.body.phone);
    const newPassword = String(req.body.newPassword || '');

    if (!phone || phone.length < 7) {
      return res.status(400).json({ error: 'شماره موبایل معتبر وارد کنید' });
    }

    if (newPassword.length < 12) {
      return res.status(400).json({ error: 'رمز جدید باید حداقل ۱۲ کاراکتر باشد' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userResult = await client.query(
        'SELECT id, status FROM users WHERE phone = $1 LIMIT 1 FOR UPDATE',
        [phone]
      );
      const user = userResult.rows[0];
      if (!user) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'حساب یافت نشد' });
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);
      await client.query(
        'UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1',
        [user.id, passwordHash]
      );

      await client.query(
        `INSERT INTO admin_actions (action_type, entity_type, entity_id, metadata)
         VALUES ('USER_PASSWORD_RECOVERY', 'USER', $1, $2::jsonb)`,
        [
          String(user.id),
          JSON.stringify({
            method: 'TEMPORARY_ADMIN_RECOVERY',
            reason: 'OTP_PROVIDER_NOT_ENABLED'
          })
        ]
      );

      await client.query(
        `INSERT INTO notifications (user_id, title, body)
         VALUES ($1, 'رمز عبور بازیابی شد', 'رمز عبور حساب توسط روند بازیابی مدیریتی تغییر کرد. اگر این درخواست از طرف شما نبود، با پشتیبانی تماس بگیرید.')`,
        [user.id]
      );

      await client.query('COMMIT');
      return res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Admin account recovery failed:', error.message);
      return res.status(500).json({ error: 'بازیابی حساب انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN LOGIN
// =====================================================

app.post(
  '/api/admin/login',
  authLimiter,
  sensitiveLimiter,
  (req, res) => {
    const password = String(req.body.password || '');

    if (!password || !safeCompare(password, ADMIN_PASSWORD)) {
      return res.status(401).json({
        error: 'رمز ادمین اشتباه است'
      });
    }

    const token = jwt.sign(
      {
        role: 'ADMIN',
        type: 'ADMIN_SESSION'
      },
      JWT_SECRET,
      {
        expiresIn: '30m',
        issuer: 'kariyab',
        audience: 'kariyab-admin'
      }
    );

    res.json({
      ok: true,
      token,
      expiresInSeconds: 1800
    });
  }
);

// =====================================================
// ADMIN STATS
// =====================================================

app.get(
  '/api/admin/stats',
  adminRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          (SELECT COUNT(*) FROM users WHERE status = 'ACTIVE') AS total_users,

          (
            SELECT COALESCE(SUM(w.available_balance_minor + w.pending_balance_minor), 0)
            FROM wallets w
            JOIN users u ON u.id = w.user_id
            WHERE u.status = 'ACTIVE'
          ) AS total_balance,

          (
            SELECT COUNT(*)
            FROM withdrawals w
            JOIN users u ON u.id = w.user_id
            WHERE u.status = 'ACTIVE'
              AND COALESCE(w.is_test, FALSE) = FALSE
              AND COALESCE(w.environment, 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(w.payment_reference, '') !~* '^TEST([[:space:]_-]|$)'
              AND w.withdrawal_id !~* '^TEST([[:space:]_-]|$)'
              AND w.status IN ('REQUESTED', 'UNDER_REVIEW', 'APPROVED', 'PROCESSING')
          ) AS pending_count,

          (
            SELECT COALESCE(SUM(w.amount_minor), 0)
            FROM withdrawals w
            JOIN users u ON u.id = w.user_id
            WHERE u.status = 'ACTIVE'
              AND COALESCE(w.is_test, FALSE) = FALSE
              AND COALESCE(w.environment, 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(w.payment_reference, '') !~* '^TEST([[:space:]_-]|$)'
              AND w.withdrawal_id !~* '^TEST([[:space:]_-]|$)'
              AND w.status IN ('REQUESTED', 'UNDER_REVIEW', 'APPROVED', 'PROCESSING')
          ) AS pending_amount,

          (
            SELECT COALESCE(SUM(w.amount_minor), 0)
            FROM withdrawals w
            JOIN users u ON u.id = w.user_id
            WHERE u.status = 'ACTIVE'
              AND COALESCE(w.is_test, FALSE) = FALSE
              AND COALESCE(w.environment, 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(w.payment_reference, '') !~* '^TEST([[:space:]_-]|$)'
              AND w.withdrawal_id !~* '^TEST([[:space:]_-]|$)'
              AND w.status = 'PAID'
          ) AS paid_out,

          (
            SELECT COALESCE(SUM(
              CASE
                WHEN COALESCE(t.metadata->>'amount_usd', '') ~ '^[0-9]+([.][0-9]+)?$'
                THEN (t.metadata->>'amount_usd')::numeric
                ELSE 0
              END
            ), 0)
            FROM transactions t
            JOIN users u ON u.id = t.user_id
            WHERE u.status = 'ACTIVE'
              AND t.type = 'EARNING'
              AND t.status <> 'REVERSED'
              AND t.metadata->>'provider' = 'CPX'
              AND COALESCE(t.metadata->>'environment', 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(t.metadata->>'is_test', 'false') <> 'true'
          ) AS provider_revenue_usd,

          (
            SELECT COALESCE(SUM(t.amount_minor), 0)
            FROM transactions t
            JOIN users u ON u.id = t.user_id
            WHERE u.status = 'ACTIVE'
              AND t.type = 'EARNING'
              AND t.status <> 'REVERSED'
              AND t.metadata->>'provider' = 'CPX'
              AND COALESCE(t.metadata->>'environment', 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(t.metadata->>'is_test', 'false') <> 'true'
          ) AS user_earnings,

          (
            SELECT COUNT(*)
            FROM transactions t
            JOIN users u ON u.id = t.user_id
            WHERE u.status = 'ACTIVE'
              AND t.type = 'EARNING'
              AND t.status <> 'REVERSED'
              AND t.metadata->>'provider' = 'CPX'
              AND COALESCE(t.metadata->>'environment', 'PRODUCTION') = 'PRODUCTION'
              AND COALESCE(t.metadata->>'is_test', 'false') <> 'true'
          ) AS completed_earnings
        `
      );

      const row = result.rows[0];
      const settings = await getRuntimeSettings();
      const providerRevenueUsd = Number(row.provider_revenue_usd || 0);
      const userEarningsAfn = minorToAfn(row.user_earnings);
      const afnPerUsd = Number(settings.afnPerUsd || DEFAULT_AFN_PER_USD);

      res.json({
        scope: 'ACTIVE_PRODUCTION',
        totalUsers: Number(row.total_users || 0),
        totalBalanceHeld: minorToAfn(row.total_balance),
        pendingCount: Number(row.pending_count || 0),
        pendingAmount: minorToAfn(row.pending_amount),
        paidOut: minorToAfn(row.paid_out),
        providerRevenueUsd,
        userEarnings: userEarningsAfn,
        platformShareUsd: Math.max(0, providerRevenueUsd - (userEarningsAfn / afnPerUsd)),
        completedEarnings: Number(row.completed_earnings || 0)
      });
    } catch (error) {
      console.error('Admin stats failed:', error);
      res.status(500).json({ error: 'دریافت آمار انجام نشد' });
    }
  }
);

// =====================================================
// ADMIN CPX SETTLEMENT REVIEW
// =====================================================

app.get(
  '/api/admin/cpx/pending-settlements',
  adminRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          t.id,
          t.transaction_id,
          t.provider_transaction_id,
          t.user_id,
          t.amount_minor,
          t.status,
          t.metadata,
          t.created_at
        FROM transactions t
        WHERE t.type = 'EARNING'
          AND t.status = 'PENDING'
          AND t.metadata->>'provider' = 'CPX'
          AND COALESCE(t.metadata->>'settlement_verified', 'false') <> 'true'
        ORDER BY t.created_at ASC
        LIMIT 200
        `
      );

      res.json({
        settlements: result.rows.map(row => ({
          id: row.id,
          transactionId: row.transaction_id,
          providerTransactionId: row.provider_transaction_id,
          userId: row.user_id,
          amount: minorToAfn(row.amount_minor),
          publisherAmountUsd: Number(row.metadata?.amount_usd || 0),
          offerId: row.metadata?.offer_id || '',
          createdAt: row.created_at
        }))
      });
    } catch (error) {
      console.error('CPX pending settlements failed:', error);
      res.status(500).json({ error: 'دریافت تسویه‌های CPX انجام نشد' });
    }
  }
);

app.post(
  '/api/admin/cpx/settlements/:id/verify',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const reference = String(req.body?.reference || '').trim();

    if (!reference || reference.length > 200 || /[\\u0000-\\u001F\\u007F]/.test(reference)) {
      return res.status(400).json({
        error: 'مرجع تایید تسویه الزامی و حداکثر ۲۰۰ کاراکتر باشد'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        `
        SELECT id, user_id, transaction_id, provider_transaction_id, status, metadata
        FROM transactions
        WHERE id = $1
          AND type = 'EARNING'
          AND metadata->>'provider' = 'CPX'
        LIMIT 1
        FOR UPDATE
        `,
        [req.params.id]
      );

      const transaction = result.rows[0];

      if (!transaction) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'تراکنش CPX یافت نشد' });
      }

      if (transaction.status !== 'PENDING') {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'فقط درآمد Pending قابل تایید تسویه است' });
      }

      if (transaction.metadata?.settlement_verified === true ||
          transaction.metadata?.settlement_verified === 'true') {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'این تسویه قبلاً تایید شده است' });
      }

      await client.query(
        `
        UPDATE transactions
        SET metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb,
            updated_at = NOW()
        WHERE id = $1
        `,
        [
          transaction.id,
          JSON.stringify({
            settlement_verified: true,
            settlement_reference: reference,
            settlement_verified_at: new Date().toISOString(),
            settlement_verified_by: 'ADMIN'
          })
        ]
      );

      await client.query(
        `
        INSERT INTO admin_actions (action_type, entity_type, entity_id, metadata)
        VALUES ('CPX_SETTLEMENT_VERIFIED', 'TRANSACTION', $1, $2::jsonb)
        `,
        [
          String(transaction.id),
          JSON.stringify({
            transaction_id: transaction.transaction_id,
            provider_transaction_id: transaction.provider_transaction_id,
            reference
          })
        ]
      );

      await client.query('COMMIT');

      // Promotion remains subject to the configured earning hold period.
      const promotion = await promotePendingEarnings(String(transaction.user_id));

      res.json({
        ok: true,
        promoted: promotion.promoted,
        promotedAmount: minorToAfn(promotion.amountMinor)
      });
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('CPX settlement verification failed:', error);
      res.status(500).json({ error: 'تایید تسویه CPX انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN FINANCIAL DIAGNOSTICS
// =====================================================

app.get(
  '/api/admin/financial-diagnostics/:userId',
  adminRequired,
  async (req, res) => {
    try {
      const userId = String(req.params.userId);
      if (!/^\\d+$/.test(userId)) {
        return res.status(400).json({ error: 'شناسه کاربر معتبر نیست' });
      }

      const [wallet, transactions, ledger, withdrawals] = await Promise.all([
        pool.query(
          `SELECT * FROM wallets WHERE user_id = $1 LIMIT 1`,
          [userId]
        ),
        pool.query(
          `
          SELECT id, transaction_id, type, amount_minor, status,
                 provider_transaction_id, metadata, created_at, updated_at
          FROM transactions
          WHERE user_id = $1
          ORDER BY id
          `,
          [userId]
        ),
        pool.query(
          `
          SELECT id, transaction_id, entry_type, amount_minor, status,
                 metadata, created_at
          FROM wallet_ledger
          WHERE user_id = $1
          ORDER BY id
          `,
          [userId]
        ),
        pool.query(
          `
          SELECT id, withdrawal_id, amount_minor, status,
                 payment_reference, created_at, updated_at
          FROM withdrawals
          WHERE user_id = $1
          ORDER BY id
          `,
          [userId]
        )
      ]);

      res.json({
        userId,
        wallet: wallet.rows[0] || null,
        transactions: transactions.rows,
        ledger: ledger.rows,
        withdrawals: withdrawals.rows
      });
    } catch (error) {
      console.error('Financial diagnostics failed:', error);
      res.status(500).json({ error: 'دریافت جزئیات مالی انجام نشد' });
    }
  }
);

// =====================================================
// ADMIN FRAUD FLAGS
// =====================================================

app.get(
  '/api/admin/fraud-flags',
  adminRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          f.id,
          f.user_id,
          u.name AS user_name,
          f.flag_type,
          f.severity,
          f.status,
          f.reason AS details,
          f.created_at,
          f.reviewed_at AS updated_at
        FROM fraud_flags f
        LEFT JOIN users u ON u.id = f.user_id
        ORDER BY
          CASE f.status WHEN 'OPEN' THEN 0 WHEN 'UNDER_REVIEW' THEN 1 ELSE 2 END,
          f.created_at DESC
        LIMIT 200
        `
      );
      res.json({ flags: result.rows });
    } catch (error) {
      console.error('Admin fraud flags failed:', error);
      res.status(500).json({ error: 'دریافت هشدارهای امنیتی انجام نشد' });
    }
  }
);

app.post(
  '/api/admin/fraud-flags/:id/status',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const status = String(req.body.status || '').trim().toUpperCase();
    const allowed = new Set(['OPEN', 'UNDER_REVIEW', 'RESOLVED', 'DISMISSED']);
    if (!allowed.has(status)) {
      return res.status(400).json({ error: 'وضعیت معتبر نیست' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const current = await client.query(
        'SELECT * FROM fraud_flags WHERE id = $1 FOR UPDATE',
        [req.params.id]
      );
      if (!current.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'هشدار یافت نشد' });
      }

      const oldStatus = current.rows[0].status;
      const updated = await client.query(
        `
        UPDATE fraud_flags
        SET status = $2, reviewed_at = NOW()
        WHERE id = $1
        RETURNING *
        `,
        [req.params.id, status]
      );

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type, entity_type, entity_id, old_value, new_value, metadata
        )
        VALUES (
          'FRAUD_FLAG_STATUS_CHANGED', 'FRAUD_FLAG', $1, $2, $3, $4::jsonb
        )
        `,
        [
          String(req.params.id),
          oldStatus,
          status,
          JSON.stringify({ user_id: current.rows[0].user_id })
        ]
      );

      await client.query('COMMIT');
      res.json({ ok: true, flag: updated.rows[0] });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Fraud flag update failed:', error);
      res.status(500).json({ error: 'تغییر وضعیت هشدار انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN WALLET RECONCILIATION
// =====================================================

app.get(
  '/api/admin/wallet-reconciliation',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          u.id AS user_id,
          u.name,
          u.phone,
          COALESCE(w.available_balance_minor, 0)::bigint AS available_minor,
          COALESCE(w.pending_balance_minor, 0)::bigint AS pending_minor,

          COALESCE((
            SELECT SUM(t.amount_minor)
            FROM transactions t
            WHERE t.user_id = u.id
              AND t.type = 'EARNING'
              AND t.status = 'PENDING'
          ), 0)::bigint AS expected_pending_minor,

          COALESCE((
            SELECT SUM(
              CASE
                WHEN wl.entry_type = 'EARNING_APPROVED' THEN
                  COALESCE(
                    NULLIF(wl.amount_minor, 0),
                    (
                      SELECT ABS(t2.amount_minor)
                      FROM transactions t2
                      WHERE t2.id = wl.transaction_id
                      LIMIT 1
                    ),
                    0
                  )
                WHEN wl.entry_type IN (
                  'REVERSAL',
                  'WITHDRAWAL_RESERVED',
                  'WITHDRAWAL_REFUND',
                  'LEGACY_RECONCILIATION_BASELINE'
                ) THEN wl.amount_minor
                ELSE 0
              END
            )
            FROM wallet_ledger wl
            WHERE wl.user_id = u.id
          ), 0)::bigint AS expected_available_minor

        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        ORDER BY u.id
        LIMIT 500
        `
      );

      const users = result.rows.map(row => {
        const available = Number(row.available_minor);
        const pending = Number(row.pending_minor);
        const expectedAvailable = Number(row.expected_available_minor);
        const expectedPending = Number(row.expected_pending_minor);

        return {
          userId: row.user_id,
          name: row.name,
          phone: row.phone,
          available: minorToAfn(available),
          pending: minorToAfn(pending),
          expectedAvailable: minorToAfn(expectedAvailable),
          expectedPending: minorToAfn(expectedPending),
          availableDifference: minorToAfn(available - expectedAvailable),
          pendingDifference: minorToAfn(pending - expectedPending),
          ok:
            available === expectedAvailable &&
            pending === expectedPending
        };
      });

      const mismatchUsers = users.filter(user => !user.ok);

      res.json({
        ok: mismatchUsers.length === 0,
        checkedUsers: users.length,
        mismatches: mismatchUsers.length,
        users,
        mismatchUsers
      });
    } catch (error) {
      console.error('Wallet reconciliation failed:', error);
      res.status(500).json({
        error: 'بررسی تطبیق کیف پول انجام نشد'
      });
    }
  }
);

// =====================================================
// ADMIN LEGACY WALLET BASELINE
// =====================================================

app.post(
  '/api/admin/wallet-reconciliation/:userId/baseline',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const userId = String(req.params.userId || '').trim();
    if (!/^\d+$/.test(userId)) {
      return res.status(400).json({ error: 'شناسه کاربر معتبر نیست' });
    }
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const walletResult = await client.query(
        `SELECT available_balance_minor
         FROM wallets
         WHERE user_id = $1
         FOR UPDATE`,
        [userId]
      );

      if (!walletResult.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'کیف پول یافت نشد' });
      }

      const ledgerResult = await client.query(
        `
        SELECT COALESCE(SUM(
          CASE
            WHEN wl.entry_type = 'EARNING_APPROVED' THEN
              COALESCE(
                NULLIF(wl.amount_minor, 0),
                (
                  SELECT ABS(t.amount_minor)
                  FROM transactions t
                  WHERE t.id = wl.transaction_id
                  LIMIT 1
                ),
                0
              )
            WHEN wl.entry_type IN (
              'REVERSAL',
              'WITHDRAWAL_RESERVED',
              'WITHDRAWAL_REFUND',
              'LEGACY_RECONCILIATION_BASELINE'
            ) THEN wl.amount_minor
            ELSE 0
          END
        ), 0)::bigint AS expected_available_minor
        FROM wallet_ledger wl
        WHERE wl.user_id = $1
        `,
        [userId]
      );

      const current = Number(walletResult.rows[0].available_balance_minor);
      const expected = Number(ledgerResult.rows[0].expected_available_minor);
      const adjustment = current - expected;

      if (!Number.isSafeInteger(adjustment)) {
        throw new Error('Invalid reconciliation adjustment');
      }

      if (adjustment === 0) {
        await client.query('COMMIT');
        return res.json({ ok: true, adjusted: false });
      }

      const existing = await client.query(
        `SELECT id FROM wallet_ledger
         WHERE user_id = $1
           AND entry_type = 'LEGACY_RECONCILIATION_BASELINE'
         LIMIT 1`,
        [userId]
      );

      if (existing.rows.length) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'Baseline قبلاً برای این کاربر ثبت شده است'
        });
      }

      await client.query(
        `
        INSERT INTO wallet_ledger (
          user_id, transaction_id, entry_type, amount_minor,
          currency, status, metadata
        )
        VALUES (
          $1, NULL, 'LEGACY_RECONCILIATION_BASELINE', $2,
          'AFN', 'APPROVED', $3::jsonb
        )
        `,
        [
          userId,
          adjustment,
          JSON.stringify({
            reason: 'One-time baseline for pre-canonical test ledger history',
            wallet_available_minor: current,
            reconstructed_available_minor: expected
          })
        ]
      );

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type, entity_type, entity_id, metadata
        )
        VALUES (
          'LEGACY_WALLET_BASELINE_CREATED', 'WALLET', $1, $2::jsonb
        )
        `,
        [
          userId,
          JSON.stringify({
            adjustment_minor: adjustment,
            wallet_available_minor: current,
            reconstructed_available_minor: expected
          })
        ]
      );

      await client.query('COMMIT');
      res.json({
        ok: true,
        adjusted: true,
        adjustment: minorToAfn(adjustment)
      });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Legacy wallet baseline failed:', error);
      res.status(500).json({ error: 'ثبت baseline مالی انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN IDENTITY VERIFICATION
// =====================================================

app.get('/api/admin/identity-verifications', adminRequired, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT iv.id, iv.verification_id, iv.user_id, iv.document_type,
              iv.document_number_last4,
              (iv.document_image IS NOT NULL) AS has_document_image,
              (iv.selfie_image IS NOT NULL) AS has_selfie_image,
              iv.status, iv.rejection_reason, iv.submitted_at, iv.reviewed_at,
              iv.metadata->>'document_name' AS document_name,
              COALESCE((iv.metadata->>'name_match')::boolean, FALSE) AS name_match,
              u.name AS user_name, u.phone AS user_phone
       FROM identity_verifications iv
       JOIN users u ON u.id = iv.user_id
        AND u.status = 'ACTIVE'
       ORDER BY CASE iv.status WHEN 'UNDER_REVIEW' THEN 0 ELSE 1 END,
                iv.submitted_at DESC
       LIMIT 200`
    );
    res.json({ verifications: result.rows });
  } catch (error) {
    console.error('Admin identity verifications failed:', error);
    res.status(500).json({ error: 'دریافت درخواست‌های احراز هویت انجام نشد' });
  }
});

app.get('/api/admin/identity-verifications/:id/evidence/:kind', adminRequired, sensitiveLimiter, async (req, res) => {
  const adminEntityId = String(req.params.id || '').trim();
  if (!/^\\d+$/.test(adminEntityId)) return res.status(400).json({ error: 'شناسه معتبر نیست' });
  const kind = String(req.params.kind || '').toLowerCase();
  const column = kind === 'document' ? 'document_image' : kind === 'selfie' ? 'selfie_image' : null;
  const verificationRowId = String(req.params.id || '').trim();
  if (!/^\d+$/.test(verificationRowId)) {
    return res.status(400).json({ error: 'شناسه احراز هویت معتبر نیست' });
  }
  if (!column) return res.status(400).json({ error: 'نوع تصویر معتبر نیست' });
  try {
    const result = await pool.query(
      `SELECT ${column} AS image FROM identity_verifications WHERE id = $1 LIMIT 1`,
      [verificationRowId]
    );
    if (!result.rows.length || !result.rows[0].image) {
      return res.status(404).json({ error: 'تصویر موجود نیست' });
    }
    res.set('Cache-Control', 'no-store, private');
    res.set('Pragma', 'no-cache');
    res.json({ image: result.rows[0].image });
  } catch (error) {
    console.error('Admin identity evidence failed:', error);
    res.status(500).json({ error: 'دریافت تصویر احراز هویت انجام نشد' });
  }
});

app.post('/api/admin/identity-verifications/:id/review', adminRequired, sensitiveLimiter, async (req, res) => {
  const adminEntityId = String(req.params.id || '').trim();
  if (!/^\\d+$/.test(adminEntityId)) return res.status(400).json({ error: 'شناسه معتبر نیست' });
  const decision = String(req.body?.decision || '').trim().toUpperCase();
  const reason = String(req.body?.reason || '').trim().slice(0, 1000);
  const verificationRowId = String(req.params.id || '').trim();
  if (!/^\d+$/.test(verificationRowId)) {
    return res.status(400).json({ error: 'شناسه احراز هویت معتبر نیست' });
  }

  if (!['VERIFIED', 'REJECTED'].includes(decision)) {
    return res.status(400).json({ error: 'تصمیم بررسی معتبر نیست' });
  }
  if (decision === 'REJECTED' && reason.length < 3) {
    return res.status(400).json({ error: 'برای رد درخواست دلیل بنویسید' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query(
      'SELECT * FROM identity_verifications WHERE id = $1 FOR UPDATE',
      [verificationRowId]
    );
    if (!current.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'درخواست احراز هویت یافت نشد' });
    }
    const verification = current.rows[0];
    if (verification.status !== 'UNDER_REVIEW') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'این درخواست قبلاً بررسی شده است' });
    }

    if (
      decision === 'VERIFIED' &&
      (
        verification.metadata?.name_match !== true ||
        !String(verification.metadata?.document_name || '').trim()
      )
    ) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'تطبیق نام حساب با نام مدرک تایید نشده است'
      });
    }

    await client.query(
      `UPDATE identity_verifications
       SET status = $2, rejection_reason = $3, reviewed_at = NOW(),
           document_image = NULL, selfie_image = NULL, updated_at = NOW()
       WHERE id = $1`,
      [verification.id, decision, decision === 'REJECTED' ? reason : null]
    );

    await client.query(
      `INSERT INTO admin_actions
        (action_type, entity_type, entity_id, old_value, new_value, reason, metadata)
       VALUES ('IDENTITY_VERIFICATION_REVIEWED', 'IDENTITY_VERIFICATION',
               $1, $2::jsonb, $3::jsonb, $4, $5::jsonb)`,
      [
        String(verification.id),
        JSON.stringify({ status: verification.status }),
        JSON.stringify({ status: decision }),
        decision === 'REJECTED' ? reason : null,
        JSON.stringify({
          verification_id: verification.verification_id,
          user_id: verification.user_id
        })
      ]
    );

    await client.query(
      `INSERT INTO notifications (user_id, title, body)
       VALUES ($1, $2, $3)`,
      decision === 'VERIFIED'
        ? [verification.user_id, 'احراز هویت تایید شد', 'هویت حساب شما تایید شد. اکنون در صورت داشتن شرایط لازم می‌توانید درخواست برداشت ثبت کنید.']
        : [verification.user_id, 'احراز هویت تایید نشد', 'درخواست احراز هویت شما رد شد. دلیل: ' + reason]
    );

    await client.query('COMMIT');
    res.json({ ok: true, status: decision });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('Admin identity review failed:', error);
    res.status(500).json({ error: 'بررسی احراز هویت انجام نشد' });
  } finally {
    client.release();
  }
});

// =====================================================
// ADMIN SUPPORT TICKETS
// =====================================================

app.get(
  '/api/admin/support/tickets',
  adminRequired,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          s.id,
          s.ticket_id,
          s.category,
          s.subject,
          s.message,
          s.status,
          s.created_at,
          s.updated_at,
          u.name AS user_name,
          u.phone AS user_phone
        FROM support_tickets s
        JOIN users u ON u.id = s.user_id
        ORDER BY s.created_at DESC
        LIMIT 200
        `
      );

      res.json({ tickets: result.rows });
    } catch (error) {
      console.error('Admin support tickets failed:', error);
      res.status(500).json({ error: 'دریافت درخواست‌های پشتیبانی انجام نشد' });
    }
  }
);

app.post(
  '/api/admin/support/tickets/:id/status',
  adminRequired,
  async (req, res) => {
    const status = String(req.body.status || '').trim().toUpperCase();
    const allowed = new Set(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']);

    if (!allowed.has(status)) {
      return res.status(400).json({ error: 'وضعیت پشتیبانی معتبر نیست' });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        `
        UPDATE support_tickets
        SET status = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING id, ticket_id, status
        `,
        [req.params.id, status]
      );

      if (!result.rows.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'درخواست پشتیبانی یافت نشد' });
      }

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'SUPPORT_STATUS_CHANGED',
          'SUPPORT_TICKET',
          $1,
          $2::jsonb
        )
        `,
        [
          String(result.rows[0].id),
          JSON.stringify({
            ticket_id: result.rows[0].ticket_id,
            status
          })
        ]
      );

      await client.query('COMMIT');
      res.json({ ok: true, ticket: result.rows[0] });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Update support ticket failed:', error);
      res.status(500).json({ error: 'تغییر وضعیت پشتیبانی انجام نشد' });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN WITHDRAWALS
// =====================================================

app.get(
  '/api/admin/withdrawals',
  adminRequired,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            w.id,
            w.withdrawal_id,
            w.amount_minor,
            w.status,
            w.account_details,
            w.payment_reference,
            w.created_at,
            (
              COALESCE(w.is_test, FALSE)
              OR COALESCE(w.payment_reference, '') ~* '^TEST([[:space:]_-]|$)'
              OR w.withdrawal_id ~* '^TEST([[:space:]_-]|$)'
            ) AS is_test,
            CASE WHEN (
              COALESCE(w.is_test, FALSE)
              OR COALESCE(w.payment_reference, '') ~* '^TEST([[:space:]_-]|$)'
              OR w.withdrawal_id ~* '^TEST([[:space:]_-]|$)'
            ) THEN 'TEST' ELSE COALESCE(w.environment, 'PRODUCTION') END AS environment,
            u.name AS user_name,
            u.phone AS user_phone,
            wm.name AS method
          FROM withdrawals w
          JOIN users u
            ON u.id = w.user_id
           AND u.status = 'ACTIVE'
          LEFT JOIN withdrawal_methods wm
            ON wm.id = w.method_id
          ORDER BY w.created_at DESC
          LIMIT 200
          `
        );

      res.json({
        withdrawals:
          result.rows.map(w => ({
            id: w.id,
            withdrawalId:
              w.withdrawal_id,
            userName:
              w.user_name,
            userPhone:
              w.user_phone,
            amount:
              minorToAfn(
                w.amount_minor
              ),
            method:
              w.method,
            account:
              w.account_details,
            rawStatus:
              w.status,
            status:
              w.status === 'PAID'
                ? 'approved'
                : w.status === 'REJECTED'
                ? 'rejected'
                : 'pending',
            paymentReference:
              w.payment_reference,
            isTest:
              Boolean(w.is_test),
            environment:
              w.environment
          }))
      });
    } catch (error) {
      console.error(
        'Admin withdrawals failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت درخواست‌ها انجام نشد'
      });
    }
  }
);

// =====================================================
// ADMIN APPROVE
// =====================================================

app.post(
  '/api/admin/withdrawals/:id/approve',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const result =
        await client.query(
          `
          SELECT *
          FROM withdrawals
          WHERE id = $1
          LIMIT 1
          FOR UPDATE
          `,
          [req.params.id]
        );

      const withdrawal =
        result.rows[0];

      if (!withdrawal) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error:
            'درخواست یافت نشد'
        });
      }

      if (
        ![
          'REQUESTED',
          'UNDER_REVIEW'
        ].includes(withdrawal.status)
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'این درخواست قابل تایید نیست'
        });
      }

      const blockingFraud = await client.query(
        `
        SELECT 1
        FROM fraud_flags
        WHERE
          user_id = $1
          AND severity IN ('HIGH', 'CRITICAL')
          AND status IN ('OPEN', 'UNDER_REVIEW')
        LIMIT 1
        `,
        [withdrawal.user_id]
      );

      if (blockingFraud.rows.length) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'این برداشت به دلیل هشدار امنیتی باز قابل تایید نیست'
        });
      }

      await client.query(
        `
        UPDATE withdrawals
        SET
          status = 'APPROVED',
          reviewed_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
        `,
        [withdrawal.id]
      );

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'WITHDRAWAL_APPROVED',
          'WITHDRAWAL',
          $1,
          $2::jsonb
        )
        `,
        [
          String(withdrawal.id),
          JSON.stringify({
            withdrawal_id:
              withdrawal.withdrawal_id
          })
        ]
      );

      await client.query(
        `INSERT INTO notifications (user_id, title, body)
         VALUES ($1, 'برداشت تایید شد', $2)`,
        [
          withdrawal.user_id,
          `درخواست برداشت ؋${(Number(withdrawal.amount_minor) / 100).toFixed(2)} تایید شد و برای پردازش آماده است.`
        ]
      );

      await client.query('COMMIT');

      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');

      console.error(
        'Approve withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'تایید انجام نشد'
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN REJECT
// =====================================================

app.post(
  '/api/admin/withdrawals/:id/reject',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const rejectionReason = String(req.body.reason || '').trim();

    if (
      !rejectionReason ||
      rejectionReason.length > 500 ||
      /[\u0000-\u001F\u007F]/.test(rejectionReason)
    ) {
      return res.status(400).json({
        error: 'دلیل رد درخواست الزامی و حداکثر ۵۰۰ کاراکتر باشد'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const result =
        await client.query(
          `
          SELECT *
          FROM withdrawals
          WHERE id = $1
          LIMIT 1
          FOR UPDATE
          `,
          [req.params.id]
        );

      const withdrawal =
        result.rows[0];

      if (!withdrawal) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error:
            'درخواست یافت نشد'
        });
      }

      if (
        ![
          'REQUESTED',
          'UNDER_REVIEW',
          'APPROVED'
        ].includes(withdrawal.status)
      ) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'این درخواست قابل رد نیست'
        });
      }

      await client.query(
        `
        UPDATE withdrawals
        SET
          status = 'REJECTED',
          rejection_reason = $2,
          reviewed_at = COALESCE(reviewed_at, NOW()),
          updated_at = NOW()
        WHERE id = $1
        `,
        [
          withdrawal.id,
          String(
            req.body.reason || ''
          ).trim()
        ]
      );

      const refundAmount = Number(withdrawal.amount_minor);
      if (!Number.isSafeInteger(refundAmount) || refundAmount <= 0) {
        throw new Error('Invalid withdrawal refund amount');
      }

      const txResult =
        await client.query(
          `
          SELECT id
          FROM transactions
          WHERE
            user_id = $1
            AND type = 'WITHDRAWAL'
            AND metadata->>'withdrawal_id' = $2
          LIMIT 1
          FOR UPDATE
          `,
          [
            withdrawal.user_id,
            withdrawal.withdrawal_id
          ]
        );

      if (!txResult.rows.length) {
        throw new Error('Withdrawal transaction missing');
      }

      const refundedWallet = await client.query(
        `
        UPDATE wallets
        SET
          available_balance_minor =
            available_balance_minor + $2,
          updated_at = NOW()
        WHERE
          user_id = $1
          AND available_balance_minor <= $3
        RETURNING id
        `,
        [
          withdrawal.user_id,
          refundAmount,
          Number.MAX_SAFE_INTEGER - refundAmount
        ]
      );

      if (!refundedWallet.rows.length) {
        throw new Error('Wallet refund failed or exceeds safe integer range');
      }

      {
        await client.query(
          `
          UPDATE transactions
          SET
            status = 'REJECTED',
            updated_at = NOW()
          WHERE id = $1
          `,
          [txResult.rows[0].id]
        );

        await client.query(
          `
          INSERT INTO wallet_ledger (
            user_id,
            transaction_id,
            entry_type,
            amount_minor,
            currency,
            status,
            metadata
          )
          VALUES (
            $1,
            $2,
            'WITHDRAWAL_REFUND',
            $3,
            'AFN',
            'APPROVED',
            $4::jsonb
          )
          `,
          [
            withdrawal.user_id,
            txResult.rows[0].id,
            Number(
              withdrawal.amount_minor
            ),
            JSON.stringify({
              withdrawal_id:
                withdrawal.withdrawal_id
            })
          ]
        );
      }

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'WITHDRAWAL_REJECTED',
          'WITHDRAWAL',
          $1,
          $2::jsonb
        )
        `,
        [
          String(withdrawal.id),
          JSON.stringify({
            withdrawal_id:
              withdrawal.withdrawal_id
          })
        ]
      );

      await client.query(
        `INSERT INTO notifications (user_id, title, body)
         VALUES ($1, 'برداشت رد شد', $2)`,
        [
          withdrawal.user_id,
          `درخواست برداشت ؋${(Number(withdrawal.amount_minor) / 100).toFixed(2)} رد شد.${rejectionReason ? ' دلیل: ' + rejectionReason : ''} مبلغ رزروشده به موجودی قابل برداشت برگشت داده شد.`
        ]
      );

      await client.query('COMMIT');

      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');

      console.error(
        'Reject withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'رد درخواست انجام نشد'
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN MARK PROCESSING
// =====================================================

app.post(
  '/api/admin/withdrawals/:id/processing',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        `
        UPDATE withdrawals
        SET
          status = 'PROCESSING',
          updated_at = NOW()
        WHERE
          id = $1
          AND status = 'APPROVED'
        RETURNING id, withdrawal_id
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'درخواست قابل انتقال به پردازش نیست'
        });
      }

      const withdrawal = result.rows[0];

      const processingDetails = await client.query(
        `SELECT
           w.user_id,
           w.amount_minor,
           wm.code AS method
         FROM withdrawals w
         LEFT JOIN withdrawal_methods wm ON wm.id = w.method_id
         WHERE w.id = $1
         LIMIT 1`,
        [withdrawal.id]
      );

      const processingRow = processingDetails.rows[0];

      if (!processingRow) {
        throw new Error('Withdrawal processing details missing');
      }

      const blockingFraud = await client.query(
        `
        SELECT 1
        FROM fraud_flags
        WHERE
          user_id = $1
          AND severity IN ('HIGH', 'CRITICAL')
          AND status IN ('OPEN', 'UNDER_REVIEW')
        LIMIT 1
        `,
        [processingRow.user_id]
      );

      if (blockingFraud.rows.length) {
        throw new Error('Withdrawal blocked by open fraud review');
      }

      const payoutProvider = getPayoutProvider(processingRow.method);
      const payoutPlan = await payoutProvider.initiate({
        withdrawal_id: withdrawal.withdrawal_id,
        amount_minor: processingRow?.amount_minor,
        method: processingRow?.method
      });

      if (
        processingRow.method === 'HESABPAY' &&
        (payoutPlan.mode === 'MANUAL_FALLBACK' || payoutPlan.status === 'NOT_CONFIGURED')
      ) {
        await client.query('ROLLBACK');
        return res.status(503).json({
          error: 'پرداخت واقعی HesabPay هنوز پیکربندی نشده است؛ درخواست به‌صورت کاذب وارد Processing نمی‌شود',
          code: 'PAYOUT_PROVIDER_NOT_CONFIGURED'
        });
      }

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'WITHDRAWAL_PROCESSING',
          'WITHDRAWAL',
          $1,
          $2::jsonb
        )
        `,
        [
          String(withdrawal.id),
          JSON.stringify({
            withdrawal_id: withdrawal.withdrawal_id,
            payout_provider: payoutPlan.provider,
            payout_mode: payoutPlan.mode,
            payout_status: payoutPlan.status
          })
        ]
      );

      if (processingDetails.rows.length) {
        await client.query(
          `INSERT INTO notifications (user_id, title, body)
           VALUES ($1, 'برداشت در حال پردازش است', $2)`,
          [
            processingDetails.rows[0].user_id,
            `برداشت ؋${(Number(processingDetails.rows[0].amount_minor) / 100).toFixed(2)} وارد مرحله پردازش پرداخت شد.`
          ]
        );
      }

      await client.query('COMMIT');
      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');

      console.error(
        'Processing withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'تغییر وضعیت انجام نشد'
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// ADMIN MARK PAID
// =====================================================

app.post(
  '/api/admin/withdrawals/:id/paid',
  adminRequired,
  sensitiveLimiter,
  async (req, res) => {
    const paymentReference =
      String(
        req.body.paymentReference || ''
      ).trim();

    if (
      !paymentReference ||
      paymentReference.length > 200 ||
      /[\u0000-\u001F\u007F]/.test(paymentReference)
    ) {
      return res.status(400).json({
        error:
          'Payment Reference معتبر و حداکثر ۲۰۰ کاراکتر باشد'
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const result =
        await client.query(
          `
          SELECT *
          FROM withdrawals
          WHERE id = $1
          LIMIT 1
          FOR UPDATE
          `,
          [req.params.id]
        );

      const withdrawal =
        result.rows[0];

      if (!withdrawal) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error:
            'درخواست یافت نشد'
        });
      }

      if (withdrawal.status !== 'PROCESSING') {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            'درخواست آماده پرداخت نیست'
        });
      }

      await client.query(
        `
        UPDATE withdrawals
        SET
          status = 'PAID',
          payment_reference = $2,
          reviewed_at = COALESCE(reviewed_at, NOW()),
          paid_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
        `,
        [
          withdrawal.id,
          paymentReference
        ]
      );

      const txResult =
        await client.query(
          `
          SELECT id
          FROM transactions
          WHERE
            user_id = $1
            AND type = 'WITHDRAWAL'
            AND metadata->>'withdrawal_id' = $2
          LIMIT 1
          FOR UPDATE
          `,
          [
            withdrawal.user_id,
            withdrawal.withdrawal_id
          ]
        );

      if (!txResult.rows.length) {
        throw new Error(
          'Withdrawal transaction missing'
        );
      }

      await client.query(
        `
        UPDATE transactions
        SET
          status = 'APPROVED',
          updated_at = NOW()
        WHERE id = $1
        `,
        [txResult.rows[0].id]
      );

      await client.query(
        `
        INSERT INTO wallet_ledger (
          user_id,
          transaction_id,
          entry_type,
          amount_minor,
          currency,
          status,
          metadata
        )
        VALUES (
          $1,
          $2,
          'WITHDRAWAL_PAID',
          0,
          'AFN',
          'APPROVED',
          $3::jsonb
        )
        `,
        [
          withdrawal.user_id,
          txResult.rows[0].id,
          JSON.stringify({
            withdrawal_id:
              withdrawal.withdrawal_id,
            payment_reference:
              paymentReference
          })
        ]
      );

      const paidAmount = Number(withdrawal.amount_minor);
      if (!Number.isSafeInteger(paidAmount) || paidAmount <= 0) {
        throw new Error('Invalid paid withdrawal amount');
      }

      const paidWallet = await client.query(
        `
        UPDATE wallets
        SET
          lifetime_withdrawals_minor =
            lifetime_withdrawals_minor + $2,
          updated_at = NOW()
        WHERE
          user_id = $1
          AND lifetime_withdrawals_minor <= $3
        RETURNING id
        `,
        [
          withdrawal.user_id,
          paidAmount,
          Number.MAX_SAFE_INTEGER - paidAmount
        ]
      );

      if (!paidWallet.rows.length) {
        throw new Error('Lifetime withdrawal total exceeds safe integer range');
      }

      await client.query(
        `
        INSERT INTO admin_actions (
          action_type,
          entity_type,
          entity_id,
          metadata
        )
        VALUES (
          'WITHDRAWAL_PAID',
          'WITHDRAWAL',
          $1,
          $2::jsonb
        )
        `,
        [
          String(withdrawal.id),
          JSON.stringify({
            withdrawal_id:
              withdrawal.withdrawal_id,
            payment_reference:
              paymentReference
          })
        ]
      );

      await client.query(
        `
        INSERT INTO notifications (user_id, title, body)
        VALUES ($1, 'برداشت پرداخت شد', $2)
        `,
        [
          withdrawal.user_id,
          `درخواست برداشت ؋${(Number(withdrawal.amount_minor) / 100).toFixed(2)} با مرجع پرداخت ${paymentReference} پرداخت شد.`
        ]
      );

      await client.query('COMMIT');

      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK');

      console.error(
        'Mark paid failed:',
        error
      );

      res.status(500).json({
        error:
          'ثبت پرداخت انجام نشد'
      });
    } finally {
      client.release();
    }
  }
);

// =====================================================
// 404 API
// =====================================================

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API یافت نشد'
  });
});

// =====================================================
// ERROR HANDLER
// =====================================================

app.use((error, req, res, next) => {
  console.error(
    'Unhandled error:',
    error
  );

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: 'خطای داخلی سرور'
  });
});

// =====================================================
// START
// =====================================================

async function startServer() {
  try {
    await ensureRuntimeSchema();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(
        `Kariyab server running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error('FATAL: runtime schema check failed', error);
    process.exit(1);
  }
}

startServer();
