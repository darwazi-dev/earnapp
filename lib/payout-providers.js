'use strict';

const crypto = require('crypto');

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

class MobileMoneyPayoutProvider extends PayoutProvider {
  constructor(env = process.env) {
    super('MOMO');
    this.apiBaseUrl = String(env.MOMO_API_BASE_URL || 'https://sandbox.momodeveloper.mtn.com').trim().replace(/\/$/, '');
    this.subscriptionKey = String(env.MOMO_SUBSCRIPTION_KEY || '').trim();
    this.apiUser = String(env.MOMO_API_USER || '').trim();
    this.apiKey = String(env.MOMO_API_KEY || '').trim();
    this.targetEnvironment = String(env.MOMO_TARGET_ENVIRONMENT || 'sandbox').trim();
    this.currency = String(env.MOMO_CURRENCY || '').trim().toUpperCase();
    this.callbackUrl = String(env.MOMO_CALLBACK_URL || '').trim();
  }

  isConfigured() {
    const validUrl = /^https:\/\//i.test(this.apiBaseUrl);
    const validEnvironment = /^[a-z0-9_-]{2,40}$/i.test(this.targetEnvironment);
    const validCurrency = /^[A-Z]{3}$/.test(this.currency);

    return Boolean(
      validUrl &&
      this.subscriptionKey &&
      this.apiUser &&
      this.apiKey &&
      validEnvironment &&
      validCurrency
    );
  }

  async getAccessToken() {
    const basic = Buffer.from(this.apiUser + ':' + this.apiKey).toString('base64');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let response;

    try {
      response = await fetch(
        this.apiBaseUrl + '/disbursement/token/',
        {
          method: 'POST',
          headers: {
            Authorization: 'Basic ' + basic,
            'Ocp-Apim-Subscription-Key': this.subscriptionKey
          },
          signal: controller.signal
        }
      );
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error('MOMO_TOKEN_TIMEOUT');
      throw error;
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error('MOMO_TOKEN_HTTP_' + response.status);
    }

    const body = await response.json();
    const token = String(body.access_token || '').trim();
    if (!token) throw new Error('MOMO_TOKEN_MISSING');
    return token;
  }

  async initiate(withdrawal) {
    if (!this.isConfigured()) {
      return {
        provider: this.code,
        mode: 'MANUAL_FALLBACK',
        status: 'NOT_CONFIGURED'
      };
    }

    const accountRaw = String(withdrawal.account_details || '').trim();
    const account = accountRaw.replace(/[\s()-]/g, '');
    if (!/^\+?[1-9]\d{7,14}$/.test(account)) {
      throw new Error('MOMO_PAYEE_INVALID');
    }

    // Store/send only the normalized MSISDN representation.
    // Do not log the destination number or expose it in provider errors.
    const payeeMsisdn = account.startsWith('+') ? account.slice(1) : account;

    const amountMinor = Number(withdrawal.amount_minor);
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      throw new Error('MOMO_AMOUNT_INVALID');
    }

    const referenceId = crypto.randomUUID();
    const token = await this.getAccessToken();
    const headers = {
      Authorization: 'Bearer ' + token,
      'Ocp-Apim-Subscription-Key': this.subscriptionKey,
      'X-Target-Environment': this.targetEnvironment,
      'X-Reference-Id': referenceId,
      'Content-Type': 'application/json'
    };
    if (this.callbackUrl) {
      headers['X-Callback-Url'] = this.callbackUrl;
    }

    const transferController = new AbortController();
    const transferTimeout = setTimeout(() => transferController.abort(), 20000);
    let response;

    try {
      response = await fetch(
        this.apiBaseUrl + '/disbursement/v1_0/transfer',
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            amount: (amountMinor / 100).toFixed(2),
            currency: this.currency,
            externalId: String(withdrawal.withdrawal_id),
            payee: {
              partyIdType: 'MSISDN',
              partyId: payeeMsisdn
            },
            payerMessage: 'Kariyab withdrawal',
            payeeNote: 'Kariyab withdrawal'
          }),
          signal: transferController.signal
        }
      );
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error('MOMO_TRANSFER_TIMEOUT');
      throw error;
    } finally {
      clearTimeout(transferTimeout);
    }

    if (response.status !== 202) {
      const providerBody = await response.text().catch(() => '');
      const error = new Error('MOMO_TRANSFER_HTTP_' + response.status);
      error.providerBody = providerBody.slice(0, 1000);
      throw error;
    }

    return {
      provider: this.code,
      mode: 'API',
      status: 'PROCESSING',
      referenceId
    };
  }

  async getStatus(referenceId) {
    if (!this.isConfigured()) throw new Error('MOMO_NOT_CONFIGURED');
    const ref = String(referenceId || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(ref)) {
      throw new Error('MOMO_REFERENCE_INVALID');
    }

    const token = await this.getAccessToken();
    const statusController = new AbortController();
    const statusTimeout = setTimeout(() => statusController.abort(), 15000);
    let response;

    try {
      response = await fetch(
        this.apiBaseUrl + '/disbursement/v1_0/transfer/' + encodeURIComponent(ref),
        {
          headers: {
            Authorization: 'Bearer ' + token,
            'Ocp-Apim-Subscription-Key': this.subscriptionKey,
            'X-Target-Environment': this.targetEnvironment
          },
          signal: statusController.signal
        }
      );
    } catch (error) {
      if (error?.name === 'AbortError') throw new Error('MOMO_STATUS_TIMEOUT');
      throw error;
    } finally {
      clearTimeout(statusTimeout);
    }

    if (!response.ok) {
      throw new Error('MOMO_STATUS_HTTP_' + response.status);
    }

    const body = await response.json();
    const status = String(body?.status || '').trim().toUpperCase();
    const allowed = new Set(['PENDING', 'SUCCESSFUL', 'FAILED']);
    if (!allowed.has(status)) {
      throw new Error('MOMO_STATUS_INVALID');
    }

    return { ...body, status };
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

  if (code === 'MOMO' || code === 'M-PAISA') {
    return new MobileMoneyPayoutProvider(env);
  }

  return new ManualPayoutProvider();
}

module.exports = {
  PayoutProvider,
  ManualPayoutProvider,
  HesabPayPayoutProvider,
  MobileMoneyPayoutProvider,
  getPayoutProvider
};
