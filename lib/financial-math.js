'use strict';

const AFN_SCALE = 100;

function minorToAfn(value) {
  return Number(value || 0) / AFN_SCALE;
}

function afnToMinor(value) {
  const text = String(value ?? '').trim();
  if (!/^\d+(\.\d{1,2})?$/.test(text)) return null;
  const [whole, fraction = ''] = text.split('.');
  const minor = BigInt(whole) * 100n + BigInt((fraction + '00').slice(0, 2));
  if (minor <= 0n || minor > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(minor);
}

function decimalFraction(value) {
  const text = String(value ?? '').trim();
  if (!/^\d+(\.\d+)?$/.test(text)) throw new Error('Invalid decimal');
  const [whole, fraction = ''] = text.split('.');
  return {
    numerator: BigInt(whole + fraction),
    denominator: 10n ** BigInt(fraction.length)
  };
}

function multiplyDecimalsRounded(...values) {
  let numerator = 1n;
  let denominator = 1n;
  for (const value of values) {
    const f = decimalFraction(value);
    numerator *= f.numerator;
    denominator *= f.denominator;
  }
  const result = (numerator + denominator / 2n) / denominator;
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Financial amount too large');
  return Number(result);
}

function calculateProviderRewardMinor(amountUsd, afnPerUsd, revenueShare) {
  const rewardMinor = multiplyDecimalsRounded(amountUsd, afnPerUsd, revenueShare, '100');
  if (!Number.isSafeInteger(rewardMinor) || rewardMinor <= 0) {
    throw new Error('Invalid calculated reward');
  }
  return rewardMinor;
}

module.exports = {
  AFN_SCALE,
  minorToAfn,
  afnToMinor,
  decimalFraction,
  multiplyDecimalsRounded,
  calculateProviderRewardMinor
};
