const { CapacitorConfig } = require('@capacitor/cli');

/** @type {CapacitorConfig} */
const config = {
  appId: 'com.kariyab.app',
  appName: 'Kariyab',
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
