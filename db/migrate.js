const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function migrate() {
  const client = await pool.connect();

  try {
    console.log("Starting Kariyab database migration...");
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        phone VARCHAR(40) NOT NULL UNIQUE,
        email VARCHAR(255) UNIQUE,
        password_hash TEXT NOT NULL,
        phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        role VARCHAR(20) NOT NULL DEFAULT 'USER',
        status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS user_profiles (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL UNIQUE
          REFERENCES users(id) ON DELETE CASCADE,
        language VARCHAR(10) NOT NULL DEFAULT 'fa',
        country VARCHAR(100),
        province VARCHAR(100),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS devices (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,
        device_key VARCHAR(255),
        ip_address INET,
        user_agent TEXT,
        last_seen_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS providers (
        id BIGSERIAL PRIMARY KEY,
        code VARCHAR(50) NOT NULL UNIQUE,
        name VARCHAR(120) NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS offers (
        id BIGSERIAL PRIMARY KEY,
        provider_id BIGINT
          REFERENCES providers(id) ON DELETE SET NULL,
        external_offer_id VARCHAR(255),
        title VARCHAR(255) NOT NULL,
        description TEXT,
        offer_type VARCHAR(50),
        reward_minor BIGINT,
        currency VARCHAR(10) NOT NULL DEFAULT 'AFN',
        active BOOLEAN NOT NULL DEFAULT TRUE,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(provider_id, external_offer_id)
      );

      CREATE TABLE IF NOT EXISTS offer_events (
        id BIGSERIAL PRIMARY KEY,
        provider_id BIGINT
          REFERENCES providers(id) ON DELETE SET NULL,
        user_id BIGINT
          REFERENCES users(id) ON DELETE SET NULL,
        provider_event_id VARCHAR(255),
        event_type VARCHAR(100),
        raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        validation_status VARCHAR(30),
        failure_reason TEXT,
        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processed_at TIMESTAMPTZ,
        UNIQUE(provider_id, provider_event_id)
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id BIGSERIAL PRIMARY KEY,
        transaction_id VARCHAR(100) NOT NULL UNIQUE,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE RESTRICT,
        provider_id BIGINT
          REFERENCES providers(id) ON DELETE SET NULL,
        offer_id BIGINT
          REFERENCES offers(id) ON DELETE SET NULL,
        provider_transaction_id VARCHAR(255),
        type VARCHAR(50) NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency VARCHAR(10) NOT NULL DEFAULT 'AFN',
        status VARCHAR(20) NOT NULL
          CHECK (status IN ('PENDING','APPROVED','REJECTED','REVERSED')),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(provider_id, provider_transaction_id)
      );

      CREATE TABLE IF NOT EXISTS wallets (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL UNIQUE
          REFERENCES users(id) ON DELETE RESTRICT,
        currency VARCHAR(10) NOT NULL DEFAULT 'AFN',
        available_balance_minor BIGINT NOT NULL DEFAULT 0,
        pending_balance_minor BIGINT NOT NULL DEFAULT 0,
        lifetime_earnings_minor BIGINT NOT NULL DEFAULT 0,
        lifetime_withdrawals_minor BIGINT NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS wallet_ledger (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE RESTRICT,
        transaction_id BIGINT
          REFERENCES transactions(id) ON DELETE RESTRICT,
        entry_type VARCHAR(60) NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency VARCHAR(10) NOT NULL DEFAULT 'AFN',
        status VARCHAR(20) NOT NULL
          CHECK (status IN ('PENDING','APPROVED','REJECTED','REVERSED')),
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS withdrawal_methods (
        id BIGSERIAL PRIMARY KEY,
        code VARCHAR(50) NOT NULL UNIQUE,
        name VARCHAR(120) NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS withdrawals (
        id BIGSERIAL PRIMARY KEY,
        withdrawal_id VARCHAR(100) NOT NULL UNIQUE,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE RESTRICT,
        method_id BIGINT
          REFERENCES withdrawal_methods(id) ON DELETE SET NULL,
        amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
        currency VARCHAR(10) NOT NULL DEFAULT 'AFN',
        status VARCHAR(30) NOT NULL DEFAULT 'REQUESTED'
          CHECK (
            status IN (
              'REQUESTED',
              'UNDER_REVIEW',
              'APPROVED',
              'PROCESSING',
              'PAID',
              'REJECTED',
              'CANCELLED',
              'FAILED'
            )
          ),
        payment_reference TEXT,
        rejection_reason TEXT,
        requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        reviewed_at TIMESTAMPTZ,
        paid_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS support_tickets (
        id BIGSERIAL PRIMARY KEY,
        ticket_id VARCHAR(100) NOT NULL UNIQUE,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE RESTRICT,
        category VARCHAR(100) NOT NULL,
        subject VARCHAR(255),
        message TEXT NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        body TEXT NOT NULL,
        read_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS referrals (
        id BIGSERIAL PRIMARY KEY,
        referrer_user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE RESTRICT,
        referred_user_id BIGINT NOT NULL UNIQUE
          REFERENCES users(id) ON DELETE RESTRICT,
        status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (referrer_user_id <> referred_user_id)
      );

      CREATE TABLE IF NOT EXISTS fraud_flags (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT
          REFERENCES users(id) ON DELETE SET NULL,
        transaction_id BIGINT
          REFERENCES transactions(id) ON DELETE SET NULL,
        flag_type VARCHAR(100) NOT NULL,
        severity VARCHAR(30) NOT NULL DEFAULT 'REVIEW',
        reason TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        reviewed_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS admin_actions (
        id BIGSERIAL PRIMARY KEY,
        admin_id BIGINT
          REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(100) NOT NULL,
        target_id VARCHAR(255),
        old_value JSONB,
        new_value JSONB,
        reason TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS system_settings (
        key VARCHAR(120) PRIMARY KEY,
        value JSONB NOT NULL,
        description TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_transactions_user
        ON transactions(user_id);

      CREATE INDEX IF NOT EXISTS idx_transactions_status
        ON transactions(status);

      CREATE INDEX IF NOT EXISTS idx_ledger_user_created
        ON wallet_ledger(user_id, created_at DESC);

      CREATE INDEX IF NOT EXISTS idx_withdrawals_user
        ON withdrawals(user_id);

      CREATE INDEX IF NOT EXISTS idx_withdrawals_status
        ON withdrawals(status);

      CREATE INDEX IF NOT EXISTS idx_offer_events_user
        ON offer_events(user_id);

      CREATE INDEX IF NOT EXISTS idx_fraud_flags_user
        ON fraud_flags(user_id);

      CREATE INDEX IF NOT EXISTS idx_support_tickets_user
        ON support_tickets(user_id);
    `);

    await client.query(
      `
      INSERT INTO providers (code, name, enabled)
      VALUES ('CPX', 'CPX Research', FALSE)
      ON CONFLICT (code) DO NOTHING
      `
    );

    await client.query(
      `
      INSERT INTO system_settings (key, value, description)
      VALUES
        (
          'currency',
          '"AFN"'::jsonb,
          'User-facing currency'
        ),
        (
          'minimum_withdrawal_minor',
          '50000'::jsonb,
          'Minimum withdrawal in AFN minor units; configurable'
        ),
        (
          'user_revenue_share',
          '0.55'::jsonb,
          'Current configurable user revenue share assumption'
        )
      ON CONFLICT (key) DO NOTHING
      `
    );

    await client.query("COMMIT");

    console.log("Kariyab database migration completed successfully.");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Migration failed:", error);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
