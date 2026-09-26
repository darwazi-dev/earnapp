const { CapacitorConfig } = require('@capacitor/cli');

/** @type {CapacitorConfig} */
const config = {
  appId: 'com.karyab.app',
  appName: 'Karyab',
  webDir: 'public',
  server: {
    url: 'https://earnapp-production.up.railway.app',
    cleartext: false
  },
  android: {
    allowMixedContent: false
  }
};

module.exports = config;
