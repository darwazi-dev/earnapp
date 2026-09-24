'use strict';

/**
 * Payout provider boundary.
 *
 * Financial state remains owned by server.js / PostgreSQL ledger.
 * Providers only describe or initiate the external transfer.
 * Never mark a withdrawal PAID from a provider response alone.
 */
class PayoutProvider {
  constructor(code) {
    this.code = code;
  }

  isConfigured() {
    return false;
  }

  async initiate() {
    throw new Error('PAYOUT_PROVIDER_NOT_IMPLEMENTED');
  }
}

class ManualPayoutProvider extends PayoutProvider {
  constructor() {
    super('MANUAL');
  }

  isConfigured() {
    return true;
  }

  async initiate(withdrawal) {
    return {
      provider: this.code,
      mode: 'MANUAL',
      status: 'AWAITING_EXTERNAL_PAYMENT',
      withdrawalId: withdrawal.withdrawal_id
    };
  }
}

class HesabPayPayoutProvider extends PayoutProvider {
  constructor(env = process.env) {
    super('HESABPAY');
    this.apiBaseUrl = String(env.HESABPAY_API_BASE_URL || '').trim();
    this.apiKey = String(env.HESABPAY_API_KEY || '').trim();
  }

  isConfigured() {
    return Boolean(this.apiBaseUrl && this.apiKey);
  }

  async initiate() {
    // Deliberately disabled until the exact HesabPay merchant payout
    // endpoint, authentication contract, idempotency rules, and response
    // verification are confirmed from official merchant documentation.
    // This prevents a fake or guessed payment integration.
    if (!this.isConfigured()) {
      return {
        provider: this.code,
        mode: 'MANUAL_FALLBACK',
        status: 'NOT_CONFIGURED'
      };
    }

    throw new Error('HESABPAY_PAYOUT_CONTRACT_NOT_VERIFIED');
  }
}

function getPayoutProvider(methodCode, env = process.env) {
  const code = String(methodCode || '').trim().toUpperCase();

  if (code === 'HESABPAY') {
    return new HesabPayPayoutProvider(env);
  }

  return new ManualPayoutProvider();
}

module.exports = {
  PayoutProvider,
  ManualPayoutProvider,
  HesabPayPayoutProvider,
  getPayoutProvider
};
