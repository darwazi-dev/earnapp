'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  afnToMinor,
  minorToAfn,
  multiplyDecimalsRounded,
  calculateProviderRewardMinor
} = require('../lib/financial-math');

test('wallet money parsing uses integer minor units', () => {
  assert.equal(afnToMinor('500'), 50000);
  assert.equal(afnToMinor('500.25'), 50025);
  assert.equal(minorToAfn(50025), 500.25);
  assert.equal(afnToMinor('0'), null);
  assert.equal(afnToMinor('-1'), null);
  assert.equal(afnToMinor('1.234'), null);
});

test('CPX reward calculation is exact and rounded to AFN minor units', () => {
  assert.equal(calculateProviderRewardMinor('0.50', '68', '0.55'), 1870);
  assert.equal(calculateProviderRewardMinor('1.00', '68', '0.55'), 3740);
  assert.equal(calculateProviderRewardMinor('1.23', '68', '0.55'), 4600);
});

test('decimal multiplication avoids floating point drift', () => {
  assert.equal(multiplyDecimalsRounded('0.1', '0.2', '100'), 2);
  assert.throws(() => multiplyDecimalsRounded('abc', '68'), /Invalid decimal/);
});

test('invalid or zero provider rewards are rejected', () => {
  assert.throws(() => calculateProviderRewardMinor('0', '68', '0.55'), /Invalid calculated reward/);
});
