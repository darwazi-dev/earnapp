const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ======================================================
// ENV
// ======================================================

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const CPX_APP_ID = String(
  process.env.CPX_APP_ID || '36387'
).trim();

const CPX_SECURE_HASH = String(
  process.env.CPX_SECURE_HASH || ''
).trim();

const DEFAULT_AFN_PER_USD =
  process.env.AFN_PER_USD || '68';

const DEFAULT_USER_SHARE =
  process.env.USER_SHARE || '0.55';

const DEFAULT_HOLD_HOURS = Number(
  process.env.EARNING_HOLD_HOURS || 72
);

const AFN_SCALE = 100;

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

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
});

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false }));

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// ======================================================
// HELPERS
// ======================================================

function md5(value) {
  return crypto
    .createHash('md5')
    .update(String(value))
    .digest('hex');
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

function normalizePhone(phone) {
  return String(phone || '').trim();
}

function safeCompare(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    left,
    right
  );
}

function minorToAfn(value) {
  return Number(value || 0) / AFN_SCALE;
}

function afnToMinor(value) {
  const raw = String(value ?? '').trim();

  if (!/^\d+(\.\d{1,2})?$/.test(raw)) {
    return null;
  }

  const [whole, fraction = ''] =
    raw.split('.');

  const minor =
    BigInt(whole) * 100n +
    BigInt(
      (fraction + '00').slice(0, 2)
    );

  if (
    minor <= 0n ||
    minor > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return null;
  }

  return Number(minor);
}

// Exact decimal arithmetic for financial calculations.

function decimalFraction(value) {
  let text = String(value ?? '').trim();

  if (!text) {
    throw new Error('Invalid decimal');
  }

  if (!/^-?\d+(\.\d+)?$/.test(text)) {
    throw new Error('Invalid decimal');
  }

  let negative = false;

  if (text.startsWith('-')) {
    negative = true;
    text = text.slice(1);
  }

  const parts = text.split('.');
  const whole = parts[0] || '0';
  const fraction = parts[1] || '';

  const scale =
    10n ** BigInt(fraction.length);

  let numerator = BigInt(
    whole + fraction
  );

  if (negative) {
    numerator = -numerator;
  }

  return {
    numerator,
    denominator: scale,
  };
}

function multiplyDecimalsRounded(...values) {
  let numerator = 1n;
  let denominator = 1n;

  for (const value of values) {
    const fraction =
      decimalFraction(value);

    numerator *= fraction.numerator;
    denominator *= fraction.denominator;
  }

  if (numerator < 0n) {
    throw new Error(
      'Negative financial amount'
    );
  }

  const result =
    (numerator + denominator / 2n) /
    denominator;

  if (
    result >
    BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new Error(
      'Financial amount too large'
    );
  }

  return Number(result);
}

async function getSetting(
  key,
  fallback,
  client = pool
) {
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
    console.error(
      `Setting read failed: ${key}`,
      error.message
    );

    return fallback;
  }
}

async function getRuntimeSettings(
  client = pool
) {
  const [
    minimumWithdrawalMinor,
    revenueShare,
    afnPerUsd,
    holdHours,
  ] = await Promise.all([
    getSetting(
      'minimum_withdrawal_minor',
      50000,
      client
    ),

    getSetting(
      'user_revenue_share',
      DEFAULT_USER_SHARE,
      client
    ),

    getSetting(
      'afn_per_usd',
      DEFAULT_AFN_PER_USD,
      client
    ),

    getSetting(
      'earning_hold_hours',
      DEFAULT_HOLD_HOURS,
      client
    ),
  ]);

  return {
    minimumWithdrawalMinor:
      Number(
        minimumWithdrawalMinor || 50000
      ),

    revenueShare:
      String(
        revenueShare ??
        DEFAULT_USER_SHARE
      ),

    afnPerUsd:
      String(
        afnPerUsd ??
        DEFAULT_AFN_PER_USD
      ),

    holdHours:
      Number(
        holdHours ||
        DEFAULT_HOLD_HOURS
      ),
  };
}

async function getUser(
  userId,
  client = pool
) {
  const result = await client.query(
    `
      SELECT
        id,
        name,
        phone,
        email,
        password_hash,
        role,
        status,
        created_at
      FROM users
      WHERE id = $1
      LIMIT 1
    `,
    [userId]
  );

  return result.rows[0] || null;
}

async function getWallet(
  userId,
  client = pool
) {
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

// ======================================================
// AUTH
// ======================================================

function authRequired(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: 'وارد نشده‌اید',
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.userId =
      String(decoded.userId);

    next();
  } catch (error) {
    return res.status(401).json({
      error:
        'نشست شما منقضی شده، دوباره وارد شوید',
    });
  }
}

function adminRequired(req, res, next) {
  const supplied =
    req.headers['x-admin-password'];

  if (
    !supplied ||
    !safeCompare(
      supplied,
      ADMIN_PASSWORD
    )
  ) {
    return res.status(401).json({
      error: 'رمز ادمین اشتباه است',
    });
  }

  next();
}

// ======================================================
// PROMOTE PENDING EARNINGS
// ======================================================

async function promotePendingEarnings(
  userId
) {
  const client =
    await pool.connect();

  try {
    await client.query('BEGIN');

    const settings =
      await getRuntimeSettings(client);

    const pending =
      await client.query(
        `
          SELECT
            id,
            amount_minor
          FROM transactions
          WHERE
            user_id = $1
            AND type = 'EARNING'
            AND status = 'PENDING'
            AND created_at <=
              NOW() -
              ($2 * INTERVAL '1 hour')
          FOR UPDATE
        `,
        [
          userId,
          settings.holdHours,
        ]
      );

    if (!pending.rows.length) {
      await client.query('COMMIT');
      return;
    }

    let totalMinor = 0;

    for (const tx of pending.rows) {
      const amount =
        Number(tx.amount_minor);

      totalMinor += amount;

      await client.query(
        `
          UPDATE transactions
          SET
            status = 'APPROVED',
            updated_at = NOW()
          WHERE id = $1
        `,
        [tx.id]
      );

      // Existing ledger entry represents
      // the original pending event.
      // Add an audit transition entry instead
      // of deleting financial history.

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
            0,
            'AFN',
            'APPROVED',
            $3::jsonb
          )
        `,
        [
          userId,
          tx.id,
          JSON.stringify({
            transition:
              'PENDING_TO_APPROVED',
          }),
        ]
      );
    }

    await client.query(
      `
        UPDATE wallets
        SET
          pending_balance_minor =
            pending_balance_minor - $1,

          available_balance_minor =
            available_balance_minor + $1,

          lifetime_earnings_minor =
            lifetime_earnings_minor + $1,

          updated_at = NOW()

        WHERE user_id = $2
      `,
      [
        totalMinor,
        userId,
      ]
    );

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');

    console.error(
      'promotePendingEarnings failed:',
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

// ======================================================
// HEALTH
// ======================================================

app.get(
  '/api/health',
  async (req, res) => {
    try {
      await pool.query('SELECT 1');

      res.json({
        ok: true,
        database: 'postgresql',
      });
    } catch (error) {
      res.status(503).json({
        ok: false,
        database: 'unavailable',
      });
    }
  }
);

// ======================================================
// REGISTER
// ======================================================

app.post(
  '/api/register',
  async (req, res) => {
    const name =
      String(req.body.name || '').trim();

    const phone =
      normalizePhone(req.body.phone);

    const password =
      String(req.body.password || '');

    if (
      !name ||
      !phone ||
      !password
    ) {
      return res.status(400).json({
        error:
          'نام، شماره تلفن و رمز عبور لازم است',
      });
    }

    if (
      name.length > 120 ||
      phone.length > 40
    ) {
      return res.status(400).json({
        error:
          'اطلاعات واردشده معتبر نیست',
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error:
          'رمز عبور باید حداقل ۸ کاراکتر باشد',
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const exists =
        await client.query(
          `
            SELECT id
            FROM users
            WHERE phone = $1
            LIMIT 1
          `,
          [phone]
        );

      if (exists.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
          error:
            'این شماره قبلاً ثبت‌نام کرده است',
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const userResult =
        await client.query(
          `
            INSERT INTO users (
              name,
              phone,
              password_hash
            )
            VALUES ($1, $2, $3)
            RETURNING
              id,
              name,
              phone
          `,
          [
            name,
            phone,
            passwordHash,
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
          userId:
            String(user.id),
        },
        JWT_SECRET,
        {
          expiresIn: '30d',
        }
      );

      return res.json({
        token,
        name: user.name,
        balance: 0,
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Register failed:',
        error
      );

      if (error.code === '23505') {
        return res
          .status(400)
          .json({
            error:
              'این شماره قبلاً ثبت‌نام کرده است',
          });
      }

      return res
        .status(500)
        .json({
          error:
            'ثبت‌نام انجام نشد',
        });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// LOGIN
// ======================================================

app.post(
  '/api/login',
  async (req, res) => {
    const phone =
      normalizePhone(req.body.phone);

    const password =
      String(req.body.password || '');

    if (!phone || !password) {
      return res.status(400).json({
        error:
          'شماره و رمز عبور را وارد کنید',
      });
    }

    try {
      const result =
        await pool.query(
          `
            SELECT
              u.id,
              u.name,
              u.password_hash,
              u.status,
              COALESCE(
                w.available_balance_minor,
                0
              )
              AS available_balance_minor
            FROM users u
            LEFT JOIN wallets w
              ON w.user_id = u.id
            WHERE u.phone = $1
            LIMIT 1
          `,
          [phone]
        );

      const user =
        result.rows[0];

      if (!user) {
        return res.status(400).json({
          error:
            'شماره یا رمز عبور اشتباه است',
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
            'شماره یا رمز عبور اشتباه است',
        });
      }

      if (
        user.status !== 'ACTIVE'
      ) {
        return res.status(403).json({
          error:
            'این حساب فعال نیست',
        });
      }

      const token = jwt.sign(
        {
          userId:
            String(user.id),
        },
        JWT_SECRET,
        {
          expiresIn: '30d',
        }
      );

      res.json({
        token,
        name: user.name,
        balance:
          minorToAfn(
            user.available_balance_minor
          ),
      });
    } catch (error) {
      console.error(
        'Login failed:',
        error
      );

      res.status(500).json({
        error:
          'ورود انجام نشد',
      });
    }
  }
);

// ======================================================
// TASKS / OPPORTUNITIES
// ======================================================

app.get(
  '/api/tasks',
  authRequired,
  async (req, res) => {
    try {
      await promotePendingEarnings(
        req.userId
      );

      const wallet =
        await getWallet(
          req.userId
        );

      if (!wallet) {
        return res
          .status(404)
          .json({
            error:
              'کیف پول یافت نشد',
          });
      }

      res.json({
        tasks: [],

        balance:
          minorToAfn(
            wallet
              .available_balance_minor
          ),

        realOffersAvailable:
          Boolean(
            CPX_SECURE_HASH
          ),
      });
    } catch (error) {
      console.error(
        'Tasks failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت فرصت‌ها انجام نشد',
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
        'تسک آزمایشی غیرفعال شده است. از فرصت‌های واقعی استفاده کنید.',
    });
  }
);

// ======================================================
// CPX OFFERWALL
// ======================================================

app.get(
  '/api/cpx/offerwall-link',
  authRequired,
  async (req, res) => {
    if (!CPX_SECURE_HASH) {
      return res
        .status(503)
        .json({
          error:
            'CPX هنوز فعال نشده است',
        });
    }

    try {
      const user =
        await getUser(
          req.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            error:
              'کاربر یافت نشد',
          });
      }

      const userId =
        String(user.id);

      const secureHash =
        md5(
          `${userId}-${CPX_SECURE_HASH}`
        );

      const params =
        new URLSearchParams({
          app_id:
            CPX_APP_ID,

          ext_user_id:
            userId,

          secure_hash:
            secureHash,

          username:
            user.name,
        });

      res.json({
        url:
          `https://offers.cpx-research.com/index.php?${params.toString()}`,
      });
    } catch (error) {
      console.error(
        'CPX link failed:',
        error
      );

      res.status(500).json({
        error:
          'باز کردن فرصت‌ها انجام نشد',
      });
    }
  }
);

// ======================================================
// CPX POSTBACK
// ======================================================

app.get(
  '/api/cpx/postback',
  async (req, res) => {
    const {
      status,
      trans_id,
      user_id,
      amount_usd,
      amount_local,
      offer_id,
      hash,
    } = req.query;

    if (!CPX_SECURE_HASH) {
      return res
        .status(503)
        .send(
          'provider disabled'
        );
    }

    if (
      !status ||
      !trans_id ||
      !user_id ||
      !hash
    ) {
      return res
        .status(400)
        .send(
          'missing params'
        );
    }

    const expectedHash =
      md5(
        `${trans_id}-${CPX_SECURE_HASH}`
      );

    if (
      !safeCompare(
        hash,
        expectedHash
      )
    ) {
      return res
        .status(403)
        .send(
          'invalid hash'
        );
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const settings =
        await getRuntimeSettings(
          client
        );

      const providerResult =
        await client.query(
          `
            SELECT
              id,
              enabled
            FROM providers
            WHERE code = 'CPX'
            LIMIT 1
          `
        );

      if (
        !providerResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(503)
          .send(
            'provider missing'
          );
      }

      const provider =
        providerResult.rows[0];

      const providerId =
        provider.id;

      const userResult =
        await client.query(
          `
            SELECT id
            FROM users
            WHERE
              id = $1
              AND status = 'ACTIVE'
            LIMIT 1
          `,
          [user_id]
        );

      if (
        !userResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .send(
            'user not found'
          );
      }

      // Store raw event.
      // Unique provider_event_id gives
      // event-level idempotency.

      const eventId =
        `${trans_id}:${status}`;

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
              processed_at
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
            providerId,
            user_id,
            eventId,
            String(status),
            JSON.stringify(
              req.query
            ),
          ]
        );

      // Exact same provider event already
      // processed -> acknowledge safely.

      if (
        !eventInsert.rows.length
      ) {
        await client.query(
          'COMMIT'
        );

        return res.send('1');
      }

      // ================================================
      // STATUS 1 = COMPLETED
      // ================================================

      if (
        String(status) === '1'
      ) {
        const duplicate =
          await client.query(
            `
              SELECT id
              FROM transactions
              WHERE
                provider_id = $1
                AND
                provider_transaction_id = $2
              LIMIT 1
            `,
            [
              providerId,
              trans_id,
            ]
          );

        if (
          duplicate.rows.length
        ) {
          await client.query(
            'COMMIT'
          );

          return res.send('1');
        }

        let rewardMinor;

        try {
          rewardMinor =
            multiplyDecimalsRounded(
              amount_usd,
              settings.afnPerUsd,
              settings.revenueShare,
              AFN_SCALE
            );
        } catch (error) {
          await client.query(
            'ROLLBACK'
          );

          return res
            .status(400)
            .send(
              'invalid amount'
            );
        }

        if (
          !rewardMinor ||
          rewardMinor <= 0
        ) {
          await client.query(
            'ROLLBACK'
          );

          return res
            .status(400)
            .send(
              'invalid reward'
            );
        }

        const transactionId =
          publicId('CPX');

        const transactionResult =
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
              user_id,
              providerId,
              trans_id,
              rewardMinor,
              JSON.stringify({
                provider:
                  'CPX',

                amount_usd:
                  amount_usd ||
                  null,

                amount_local:
                  amount_local ||
                  null,

                offer_id:
                  offer_id ||
                  null,
              }),
            ]
          );

        const txDbId =
          transactionResult
            .rows[0]
            .id;

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
            user_id,
            txDbId,
            rewardMinor,

            JSON.stringify({
              provider:
                'CPX',

              provider_transaction_id:
                trans_id,
            }),
          ]
        );

        await client.query(
          `
            UPDATE wallets
            SET
              pending_balance_minor =
                pending_balance_minor + $1,

              updated_at = NOW()

            WHERE user_id = $2
          `,
          [
            rewardMinor,
            user_id,
          ]
        );
      }

      // ================================================
      // STATUS 2 = REVERSAL / CANCELED
      // ================================================

      else if (
        String(status) === '2'
      ) {
        const transactionResult =
          await client.query(
            `
              SELECT
                id,
                user_id,
                amount_minor,
                status
              FROM transactions
              WHERE
                provider_id = $1
                AND
                provider_transaction_id = $2
              LIMIT 1
              FOR UPDATE
            `,
            [
              providerId,
              trans_id,
            ]
          );

        // CPX can send cancellation before
        // local completion exists.
        // Keep event and acknowledge.

        if (
          !transactionResult
            .rows.length
        ) {
          await client.query(
            'COMMIT'
          );

          return res.send('1');
        }

        const tx =
          transactionResult.rows[0];

        if (
          tx.status ===
          'REVERSED'
        ) {
          await client.query(
            'COMMIT'
          );

          return res.send('1');
        }

        const amountMinor =
          Number(
            tx.amount_minor
          );

        if (
          tx.status ===
          'PENDING'
        ) {
          const walletResult =
            await client.query(
              `
                SELECT
                  pending_balance_minor
                FROM wallets
                WHERE user_id = $1
                FOR UPDATE
              `,
              [tx.user_id]
            );

          const pending =
            Number(
              walletResult
                .rows[0]
                .pending_balance_minor
            );

          if (
            pending <
            amountMinor
          ) {
            throw new Error(
              'Wallet pending reconciliation failed'
            );
          }

          await client.query(
            `
              UPDATE wallets
              SET
                pending_balance_minor =
                  pending_balance_minor - $1,
                updated_at = NOW()
              WHERE user_id = $2
            `,
            [
              amountMinor,
              tx.user_id,
            ]
          );
        }

        if (
          tx.status ===
          'APPROVED'
        ) {
          // A provider reversal may happen
          // after approval. Negative available
          // balance preserves the financial debt
          // instead of silently losing money.

          await client.query(
            `
              UPDATE wallets
              SET
                available_balance_minor =
                  available_balance_minor - $1,

                lifetime_earnings_minor =
                  lifetime_earnings_minor - $1,

                updated_at = NOW()

              WHERE user_id = $2
            `,
            [
              amountMinor,
              tx.user_id,
            ]
          );
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
            tx.user_id,
            tx.id,
            -amountMinor,

            JSON.stringify({
              provider:
                'CPX',

              provider_transaction_id:
                trans_id,
            }),
          ]
        );
      } else {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .send(
            'invalid status'
          );
      }

      await client.query(
        'COMMIT'
      );

      return res.send('1');
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'CPX postback failed:',
        error
      );

      if (
        error.code === '23505'
      ) {
        return res.send('1');
      }

      return res
        .status(500)
        .send('error');
    } finally {
      client.release();
    }
  }
);

// ======================================================
// WALLET
// ======================================================

app.get(
  '/api/wallet',
  authRequired,
  async (req, res) => {
    try {
      await promotePendingEarnings(
        req.userId
      );

      const settings =
        await getRuntimeSettings();

      const wallet =
        await getWallet(
          req.userId
        );

      if (!wallet) {
        return res
          .status(404)
          .json({
            error:
              'کیف پول یافت نشد',
          });
      }

      const withdrawalsResult =
        await pool.query(
          `
            SELECT
              w.id,
              w.withdrawal_id,
              w.amount_minor,
              w.status,
              w.account_details,
              w.payment_reference,
              w.rejection_reason,
              w.requested_at,
              w.reviewed_at,
              w.paid_at,
              wm.code
                AS method_code,
              wm.name
                AS method_name
            FROM withdrawals w
            LEFT JOIN withdrawal_methods wm
              ON wm.id = w.method_id
            WHERE w.user_id = $1
            ORDER BY
              w.requested_at DESC
            LIMIT 100
          `,
          [req.userId]
        );

      const ledgerResult =
        await pool.query(
          `
            SELECT
              id,
              entry_type,
              amount_minor,
              currency,
              status,
              metadata,
              created_at
            FROM wallet_ledger
            WHERE user_id = $1
            ORDER BY
              created_at DESC,
              id DESC
            LIMIT 100
          `,
          [req.userId]
        );

      const withdrawals =
        withdrawalsResult.rows.map(
          w => {
            let uiStatus =
              String(
                w.status
              ).toLowerCase();

            if (
              [
                'REQUESTED',
                'UNDER_REVIEW',
                'APPROVED',
                'PROCESSING',
              ].includes(
                w.status
              )
            ) {
              uiStatus =
                'pending';
            }

            if (
              w.status ===
              'PAID'
            ) {
              uiStatus =
                'approved';
            }

            if (
              [
                'REJECTED',
                'FAILED',
                'CANCELLED',
              ].includes(
                w.status
              )
            ) {
              uiStatus =
                'rejected';
            }

            return {
              id: w.id,

              withdrawalId:
                w.withdrawal_id,

              amount:
                minorToAfn(
                  w.amount_minor
                ),

              method:
                w.method_name ||
                w.method_code ||
                'نامشخص',

              account:
                w.account_details,

              status:
                uiStatus,

              rawStatus:
                w.status,

              paymentReference:
                w.payment_reference,

              rejectionReason:
                w.rejection_reason,

              createdAt:
                w.requested_at,

              reviewedAt:
                w.reviewed_at,

              paidAt:
                w.paid_at,
            };
          }
        );

      const ledger =
        ledgerResult.rows.map(
          row => ({
            id: row.id,

            type:
              row.entry_type,

            amount:
              minorToAfn(
                row.amount_minor
              ),

            currency:
              row.currency,

            status:
              row.status,

            metadata:
              row.metadata,

            createdAt:
              row.created_at,
          })
        );

      res.json({
        available:
          minorToAfn(
            wallet
              .available_balance_minor
          ),

        pending:
          minorToAfn(
            wallet
              .pending_balance_minor
          ),

        lifetimeEarnings:
          minorToAfn(
            wallet
              .lifetime_earnings_minor
          ),

        lifetimeWithdrawals:
          minorToAfn(
            wallet
              .lifetime_withdrawals_minor
          ),

        withdrawals,
        ledger,

        minWithdraw:
          minorToAfn(
            settings
              .minimumWithdrawalMinor
          ),

        earningHoldHours:
          settings.holdHours,
      });
    } catch (error) {
      console.error(
        'Wallet failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت کیف پول انجام نشد',
      });
    }
  }
);

// ======================================================
// WITHDRAWAL
// ======================================================

app.post(
  '/api/withdraw',
  authRequired,
  async (req, res) => {
    const amountMinor =
      afnToMinor(
        req.body.amount
      );

    const method =
      String(
        req.body.method || ''
      ).trim();

    const account =
      String(
        req.body.account || ''
      ).trim();

    if (!amountMinor) {
      return res
        .status(400)
        .json({
          error:
            'مبلغ برداشت معتبر نیست',
        });
    }

    if (
      !method ||
      !account
    ) {
      return res
        .status(400)
        .json({
          error:
            'روش پرداخت و شماره حساب را وارد کنید',
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query('BEGIN');

      const settings =
        await getRuntimeSettings(
          client
        );

      if (
        amountMinor <
        settings
          .minimumWithdrawalMinor
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              `حداقل مبلغ برداشت ${minorToAfn(
                settings
                  .minimumWithdrawalMinor
              )} افغانی است`,
          });
      }

      const walletResult =
        await client.query(
          `
            SELECT *
            FROM wallets
            WHERE user_id = $1
            FOR UPDATE
          `,
          [req.userId]
        );

      if (
        !walletResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'کیف پول یافت نشد',
          });
      }

      const wallet =
        walletResult.rows[0];

      if (
        Number(
          wallet
            .available_balance_minor
        ) <
        amountMinor
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'موجودی قابل‌برداشت شما کافی نیست',
          });
      }

      const methodResult =
        await client.query(
          `
            SELECT
              id,
              code,
              name
            FROM withdrawal_methods
            WHERE
              code = $1
              AND enabled = TRUE
            LIMIT 1
          `,
          [method]
        );

      if (
        !methodResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'روش پرداخت معتبر نیست',
          });
      }

      const methodRow =
        methodResult.rows[0];

      const withdrawalId =
        publicId('WD');

      const transactionId =
        publicId('WDTX');

      const transactionResult =
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
                withdrawalId,

              method:
                methodRow.code,
            }),
          ]
        );

      const transactionDbId =
        transactionResult
          .rows[0]
          .id;

      const withdrawalResult =
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
            RETURNING *
          `,
          [
            withdrawalId,
            req.userId,
            methodRow.id,
            amountMinor,
            account,
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
          transactionDbId,
          -amountMinor,

          JSON.stringify({
            withdrawal_id:
              withdrawalId,

            method:
              methodRow.code,
          }),
        ]
      );

      await client.query(
        `
          UPDATE wallets
          SET
            available_balance_minor =
              available_balance_minor - $1,

            updated_at = NOW()

          WHERE user_id = $2
        `,
        [
          amountMinor,
          req.userId,
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        balance:
          minorToAfn(
            Number(
              wallet
                .available_balance_minor
            ) -
            amountMinor
          ),

        withdrawal: {
          id:
            withdrawalResult
              .rows[0]
              .id,

          withdrawalId,

          amount:
            minorToAfn(
              amountMinor
            ),

          method:
            methodRow.name,

          account,

          status:
            'pending',

          rawStatus:
            'REQUESTED',
        },
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'ثبت درخواست برداشت انجام نشد',
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// ADMIN LOGIN
// ======================================================

app.post(
  '/api/admin/login',
  (req, res) => {
    const password =
      String(
        req.body.password || ''
      );

    if (
      !safeCompare(
        password,
        ADMIN_PASSWORD
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            'رمز اشتباه است',
        });
    }

    res.json({
      ok: true,
    });
  }
);

// ======================================================
// ADMIN WITHDRAWALS
// ======================================================

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
              w.requested_at,
              w.reviewed_at,
              w.paid_at,
              w.payment_reference,
              w.rejection_reason,

              u.id
                AS user_id,

              u.name
                AS user_name,

              u.phone
                AS user_phone,

              wm.code
                AS method_code,

              wm.name
                AS method_name

            FROM withdrawals w

            JOIN users u
              ON u.id = w.user_id

            LEFT JOIN withdrawal_methods wm
              ON wm.id = w.method_id

            ORDER BY
              w.requested_at DESC

            LIMIT 500
          `
        );

      const withdrawals =
        result.rows.map(
          w => {
            let status =
              'pending';

            if (
              w.status ===
              'PAID'
            ) {
              status =
                'approved';
            }

            if (
              [
                'REJECTED',
                'FAILED',
                'CANCELLED',
              ].includes(
                w.status
              )
            ) {
              status =
                'rejected';
            }

            return {
              id: w.id,

              withdrawalId:
                w.withdrawal_id,

              userId:
                w.user_id,

              userName:
                w.user_name,

              userPhone:
                w.user_phone,

              amount:
                minorToAfn(
                  w.amount_minor
                ),

              method:
                w.method_name ||
                w.method_code ||
                'نامشخص',

              account:
                w.account_details,

              status,

              rawStatus:
                w.status,

              paymentReference:
                w.payment_reference,

              rejectionReason:
                w.rejection_reason,

              createdAt:
                w.requested_at,

              reviewedAt:
                w.reviewed_at,

              paidAt:
                w.paid_at,
            };
          }
        );

      res.json({
        withdrawals,
      });
    } catch (error) {
      console.error(
        'Admin withdrawals failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت درخواست‌ها انجام نشد',
      });
    }
  }
);

// ======================================================
// ADMIN STATS
// ======================================================

app.get(
  '/api/admin/stats',
  adminRequired,
  async (req, res) => {
    try {
      const [
        usersResult,
        walletsResult,
        pendingResult,
        paidResult,
      ] = await Promise.all([
        pool.query(
          `
            SELECT
              COUNT(*)::bigint
                AS count
            FROM users
          `
        ),

        pool.query(
          `
            SELECT
              COALESCE(
                SUM(
                  available_balance_minor
                ),
                0
              ) AS available,

              COALESCE(
                SUM(
                  pending_balance_minor
                ),
                0
              ) AS pending

            FROM wallets
          `
        ),

        pool.query(
          `
            SELECT
              COUNT(*)::bigint
                AS count,

              COALESCE(
                SUM(
                  amount_minor
                ),
                0
              ) AS amount

            FROM withdrawals

            WHERE status IN (
              'REQUESTED',
              'UNDER_REVIEW',
              'APPROVED',
              'PROCESSING'
            )
          `
        ),

        pool.query(
          `
            SELECT
              COALESCE(
                SUM(
                  amount_minor
                ),
                0
              ) AS amount

            FROM withdrawals

            WHERE status =
              'PAID'
          `
        ),
      ]);

      const availableMinor =
        Number(
          walletsResult
            .rows[0]
            .available
        );

      const pendingWalletMinor =
        Number(
          walletsResult
            .rows[0]
            .pending
        );

      const pendingWithdrawalMinor =
        Number(
          pendingResult
            .rows[0]
            .amount
        );

      const paidMinor =
        Number(
          paidResult
            .rows[0]
            .amount
        );

      res.json({
        totalUsers:
          Number(
            usersResult
              .rows[0]
              .count
          ),

        totalBalanceHeld:
          minorToAfn(
            availableMinor +
            pendingWalletMinor
          ),

        totalAvailable:
          minorToAfn(
            availableMinor
          ),

        totalPending:
          minorToAfn(
            pendingWalletMinor
          ),

        pendingCount:
          Number(
            pendingResult
              .rows[0]
              .count
          ),

        pendingAmount:
          minorToAfn(
            pendingWithdrawalMinor
          ),

        paidOut:
          minorToAfn(
            paidMinor
          ),

        pendingWithdrawCount:
          Number(
            pendingResult
              .rows[0]
              .count
          ),

        pendingWithdrawAmount:
          minorToAfn(
            pendingWithdrawalMinor
          ),
      });
    } catch (error) {
      console.error(
        'Admin stats failed:',
        error
      );

      res.status(500).json({
        error:
          'دریافت آمار انجام نشد',
      });
    }
  }
);

// ======================================================
// ADMIN APPROVE WITHDRAWAL
// ======================================================

app.post(
  '/api/admin/withdrawals/:id/approve',
  adminRequired,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
            SELECT *
            FROM withdrawals
            WHERE id = $1
            FOR UPDATE
          `,
          [req.params.id]
        );

      if (
        !result.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'درخواست یافت نشد',
          });
      }

      const withdrawal =
        result.rows[0];

      if (
        ![
          'REQUESTED',
          'UNDER_REVIEW',
        ].includes(
          withdrawal.status
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'این درخواست قابل تایید نیست',
          });
      }

      await client.query(
        `
          UPDATE withdrawals
          SET
            status =
              'APPROVED',

            reviewed_at =
              NOW(),

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          withdrawal.id,
        ]
      );

      // Financial transaction remains
      // PENDING until actual payment.

      await client.query(
        `
          INSERT INTO admin_actions (
            action,
            target_type,
            target_id,
            new_value
          )
          VALUES (
            'WITHDRAWAL_APPROVED',
            'withdrawal',
            $1,
            $2::jsonb
          )
        `,
        [
          withdrawal
            .withdrawal_id,

          JSON.stringify({
            status:
              'APPROVED',
          }),
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        status:
          'APPROVED',
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Approve withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'تایید درخواست انجام نشد',
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// ADMIN PROCESSING WITHDRAWAL
// ======================================================

app.post(
  '/api/admin/withdrawals/:id/processing',
  adminRequired,
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
            SELECT *
            FROM withdrawals
            WHERE id = $1
            FOR UPDATE
          `,
          [req.params.id]
        );

      if (
        !result.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'درخواست یافت نشد',
          });
      }

      const withdrawal =
        result.rows[0];

      if (
        withdrawal.status !==
        'APPROVED'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'ابتدا درخواست را تایید کنید',
          });
      }

      await client.query(
        `
          UPDATE withdrawals
          SET
            status =
              'PROCESSING',

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          withdrawal.id,
        ]
      );

      await client.query(
        `
          INSERT INTO admin_actions (
            action,
            target_type,
            target_id,
            new_value
          )
          VALUES (
            'WITHDRAWAL_PROCESSING',
            'withdrawal',
            $1,
            $2::jsonb
          )
        `,
        [
          withdrawal
            .withdrawal_id,

          JSON.stringify({
            status:
              'PROCESSING',
          }),
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        status:
          'PROCESSING',
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Processing withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'تغییر وضعیت انجام نشد',
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// ADMIN PAID WITHDRAWAL
// ======================================================

app.post(
  '/api/admin/withdrawals/:id/paid',
  adminRequired,
  async (req, res) => {
    const paymentReference =
      String(
        req.body
          .paymentReference ||
        ''
      ).trim();

    if (!paymentReference) {
      return res
        .status(400)
        .json({
          error:
            'شماره مرجع پرداخت الزامی است',
        });
    }

    if (
      paymentReference.length >
      255
    ) {
      return res
        .status(400)
        .json({
          error:
            'شماره مرجع پرداخت معتبر نیست',
        });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
            SELECT *
            FROM withdrawals
            WHERE id = $1
            FOR UPDATE
          `,
          [req.params.id]
        );

      if (
        !result.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'درخواست یافت نشد',
          });
      }

      const withdrawal =
        result.rows[0];

      if (
        ![
          'APPROVED',
          'PROCESSING',
        ].includes(
          withdrawal.status
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'این درخواست آماده ثبت پرداخت نیست',
          });
      }

      const transactionResult =
        await client.query(
          `
            SELECT id
            FROM transactions
            WHERE
              user_id = $1
              AND
              type = 'WITHDRAWAL'
              AND
              metadata->>'withdrawal_id'
                = $2
            LIMIT 1
            FOR UPDATE
          `,
          [
            withdrawal.user_id,
            withdrawal
              .withdrawal_id,
          ]
        );

      if (
        !transactionResult
          .rows.length
      ) {
        throw new Error(
          'Withdrawal transaction missing'
        );
      }

      const transactionDbId =
        transactionResult
          .rows[0]
          .id;

      await client.query(
        `
          UPDATE withdrawals
          SET
            status =
              'PAID',

            payment_reference =
              $1,

            paid_at =
              NOW(),

            updated_at =
              NOW()

          WHERE id = $2
        `,
        [
          paymentReference,
          withdrawal.id,
        ]
      );

      await client.query(
        `
          UPDATE transactions
          SET
            status =
              'APPROVED',

            updated_at =
              NOW()

          WHERE id = $1
        `,
        [
          transactionDbId,
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
            'WITHDRAWAL_PAID',
            0,
            'AFN',
            'APPROVED',
            $3::jsonb
          )
        `,
        [
          withdrawal.user_id,
          transactionDbId,

          JSON.stringify({
            withdrawal_id:
              withdrawal
                .withdrawal_id,

            payment_reference:
              paymentReference,
          }),
        ]
      );

      await client.query(
        `
          UPDATE wallets
          SET
            lifetime_withdrawals_minor =
              lifetime_withdrawals_minor
              + $1,

            updated_at =
              NOW()

          WHERE user_id = $2
        `,
        [
          Number(
            withdrawal
              .amount_minor
          ),

          withdrawal.user_id,
        ]
      );

      await client.query(
        `
          INSERT INTO admin_actions (
            action,
            target_type,
            target_id,
            new_value
          )
          VALUES (
            'WITHDRAWAL_PAID',
            'withdrawal',
            $1,
            $2::jsonb
          )
        `,
        [
          withdrawal
            .withdrawal_id,

          JSON.stringify({
            status:
              'PAID',

            payment_reference:
              paymentReference,
          }),
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        status:
          'PAID',
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Mark withdrawal paid failed:',
        error
      );

      res.status(500).json({
        error:
          'ثبت پرداخت انجام نشد',
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// ADMIN REJECT WITHDRAWAL
// ======================================================

app.post(
  '/api/admin/withdrawals/:id/reject',
  adminRequired,
  async (req, res) => {
    const reason =
      String(
        req.body.reason || ''
      ).trim();

    const client =
      await pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
            SELECT *
            FROM withdrawals
            WHERE id = $1
            FOR UPDATE
          `,
          [req.params.id]
        );

      if (
        !result.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'درخواست یافت نشد',
          });
      }

      const withdrawal =
        result.rows[0];

      if (
        ![
          'REQUESTED',
          'UNDER_REVIEW',
          'APPROVED',
          'PROCESSING',
        ].includes(
          withdrawal.status
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'این درخواست قابل رد نیست',
          });
      }

      const transactionResult =
        await client.query(
          `
            SELECT id
            FROM transactions
            WHERE
              user_id = $1
              AND
              type =
                'WITHDRAWAL'
              AND
              metadata->>'withdrawal_id'
                = $2
            LIMIT 1
            FOR UPDATE
          `,
          [
            withdrawal.user_id,
            withdrawal
              .withdrawal_id,
          ]
        );

      await client.query(
        `
          UPDATE withdrawals
          SET
            status =
              'REJECTED',

            rejection_reason =
              $1,

            reviewed_at =
              COALESCE(
                reviewed_at,
                NOW()
              ),

            updated_at =
              NOW()

          WHERE id = $2
        `,
        [
          reason ||
          'رد شده توسط ادمین',

          withdrawal.id,
        ]
      );

      // Return reserved funds.

      await client.query(
        `
          UPDATE wallets
          SET
            available_balance_minor =
              available_balance_minor
              + $1,

            updated_at =
              NOW()

          WHERE user_id = $2
        `,
        [
          Number(
            withdrawal
              .amount_minor
          ),

          withdrawal.user_id,
        ]
      );

      if (
        transactionResult
          .rows.length
      ) {
        const transactionDbId =
          transactionResult
            .rows[0]
            .id;

        await client.query(
          `
            UPDATE transactions
            SET
              status =
                'REJECTED',

              updated_at =
                NOW()

            WHERE id = $1
          `,
          [
            transactionDbId,
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
              'WITHDRAWAL_REFUND',
              $3,
              'AFN',
              'REJECTED',
              $4::jsonb
            )
          `,
          [
            withdrawal.user_id,
            transactionDbId,

            Number(
              withdrawal
                .amount_minor
            ),

            JSON.stringify({
              withdrawal_id:
                withdrawal
                  .withdrawal_id,

              reason:
                reason ||
                'رد شده توسط ادمین',
            }),
          ]
        );
      }

      await client.query(
        `
          INSERT INTO admin_actions (
            action,
            target_type,
            target_id,
            new_value,
            reason
          )
          VALUES (
            'WITHDRAWAL_REJECTED',
            'withdrawal',
            $1,
            $2::jsonb,
            $3
          )
        `,
        [
          withdrawal
            .withdrawal_id,

          JSON.stringify({
            status:
              'REJECTED',
          }),

          reason ||
          null,
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        status:
          'REJECTED',
      });
    } catch (error) {
      await client.query(
        'ROLLBACK'
      );

      console.error(
        'Reject withdrawal failed:',
        error
      );

      res.status(500).json({
        error:
          'رد درخواست انجام نشد',
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// API 404
// ======================================================

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      error:
        'مسیر API یافت نشد',
    });
  }
);

// ======================================================
// ERROR HANDLER
// ======================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      'Unhandled error:',
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      error:
        'خطای داخلی سرور',
    });
  }
);

// ======================================================
// START
// ======================================================

async function startServer() {
  try {
    await pool.query(
      'SELECT 1'
    );

    console.log(
      'PostgreSQL connection successful.'
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `Kariyab server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      'FATAL: PostgreSQL connection failed:',
      error
    );

    process.exit(1);
  }
}

startServer();
