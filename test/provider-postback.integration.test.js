'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { Pool } = require('pg');

const databaseUrl = process.env.TEST_DATABASE_URL;

test('provider reversal and completion remain consistent across retries and delivery order',
  { skip: !databaseUrl && 'Requires a disposable TEST_DATABASE_URL' },
  async t => {
    const secret = 'integration-test-only-hash';
    const env = {
      ...process.env,
      DATABASE_URL: databaseUrl,
      CPX_SECURE_HASH: secret,
      JWT_SECRET: 'integration-test-only-jwt',
      ADMIN_PASSWORD: 'integration-test-only-admin',
      PORT: '38697'
    };
    execFileSync(process.execPath, ['db/migrate.js'], { env, timeout: 15000 });

    const pool = new Pool({ connectionString: databaseUrl });
    const server = spawn(process.execPath, ['server.js'], { env, stdio: 'ignore' });
    t.after(async () => {
      server.kill();
      await pool.end();
    });

    const base = 'http://127.0.0.1:38697';
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if (server.exitCode !== null) throw new Error('Test server exited before startup');
      try {
        const res = await fetch(base + '/api/health');
        if (res.ok) { ready = true; break; }
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(ready, 'Test server did not become ready');

    const user = await pool.query(
      `INSERT INTO users (name, phone, password_hash)
       VALUES ('Integration test', $1, 'unused') RETURNING id`,
      ['test-' + crypto.randomUUID()]
    );
    const userId = String(user.rows[0].id);
    await pool.query('INSERT INTO wallets (user_id) VALUES ($1)', [userId]);

    async function postback(transId, status) {
      const params = new URLSearchParams({
        user_id: userId,
        trans_id: transId,
        status,
        amount_usd: '1.00',
        hash: crypto.createHash('md5').update(`${transId}-${secret}`).digest('hex')
      });
      const res = await fetch(base + '/api/cpx/postback?' + params);
      assert.equal(res.status, 200, await res.text());
    }

    const reversedFirst = 'rev-first-' + crypto.randomUUID();
    await postback(reversedFirst, '2');
    await postback(reversedFirst, '1');
    await postback(reversedFirst, '1');

    const reversedAfter = 'rev-after-' + crypto.randomUUID();
    await postback(reversedAfter, '1');
    await postback(reversedAfter, '1');
    await postback(reversedAfter, '2');
    await postback(reversedAfter, '2');

    const concurrent = 'concurrent-' + crypto.randomUUID();
    await Promise.all([postback(concurrent, '1'), postback(concurrent, '2')]);

    const wallet = await pool.query(
      `SELECT pending_balance_minor, available_balance_minor
       FROM wallets WHERE user_id = $1`, [userId]
    );
    assert.equal(Number(wallet.rows[0].pending_balance_minor), 0);
    assert.equal(Number(wallet.rows[0].available_balance_minor), 0);

    const ledger = await pool.query(
      `SELECT COALESCE(SUM(amount_minor), 0) AS total
       FROM wallet_ledger WHERE user_id = $1`, [userId]
    );
    assert.equal(Number(ledger.rows[0].total), 0);

    const earnings = await pool.query(
      `SELECT provider_transaction_id, status
       FROM transactions WHERE user_id = $1 AND type = 'EARNING'`, [userId]
    );
    assert.ok(!earnings.rows.some(row => row.provider_transaction_id === reversedFirst));
    assert.ok(earnings.rows.every(row => row.status === 'REVERSED'));
  }
);
