import { Command } from 'commander';
import { CryptoService } from '../common/crypto';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const program = new Command();
const CONFIG_PATH = path.join(process.cwd(), 'config.json');
const RELAY_URL = process.env.RELAY_URL || 'https://onion-pipe.loohive.com'; // Default to official relay

program
  .name('onion-pipe')
  .description('CLI to manage onion-pipe tunnels')
  .version('1.0.0');

program.command('init')
  .description('Generate local keypair')
  .action(async () => {
    const keys = await CryptoService.generateKeyPair();
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(keys, null, 2));
    console.log('✅ Keypair generated and saved to config.json');
    console.log('Public Key:', keys.publicKey);
  });

program.command('login')
  .description('Login via GitHub to get your API Key')
  .action(async () => {
    console.log('\n--- Onion-Pipe Login ---');
    console.log(`Open this URL in your browser:\n`);
    console.log(`   ${RELAY_URL}/auth/github?cli=true\n`);
    console.log('After logging in, you will get a 6-digit code.');
    
    // In a real terminal we would prompt, for now let's just show how it works
    console.log('To complete: onion-pipe auth <code>');
  });

program.command('auth')
  .description('Exchange a 6-digit code for a permanent API key')
  .argument('<code>', 'The 6-digit code from the dashboard')
  .action(async (code) => {
    try {
      const res = await axios.post(`${RELAY_URL}/auth/cli/exchange`, { code });
      const { api_key } = res.data;
      
      let config = {};
      if (fs.existsSync(CONFIG_PATH)) config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      
      fs.writeFileSync(CONFIG_PATH, JSON.stringify({ ...config, apiKey: api_key }, null, 2));
      console.log('✅ Success! Integrated API key saved to config.json');
    } catch (e: any) {
      console.error('❌ Exchange failed:', e.response?.data?.error || e.message);
    }
  });

program.command('register')
  .description('Register with entry relay')
  .argument('<onion-address>', 'Your .onion address (without .onion suffix)')
  .option('-k, --key <api-key>', 'Use a specific API Key')
  .action(async (onion, options) => {
    if (!fs.existsSync(CONFIG_PATH)) {
      console.error('❌ No config.json found. Run init first.');
      return;
    }
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    const apiKey = options.key || config.apiKey;

    if (!apiKey) {
      console.warn('⚠️ No API Key found. Attempting anonymous registration...');
    }
    
    try {
      const res = await axios.post(`${RELAY_URL}/register`, {
        onion_service_id: onion,
        public_key: config.publicKey,
        token: apiKey
      });
      console.log('\n✅ Registered Successfully!');
      console.log(`   Internal ID: ${res.data.token}`);
      console.log(`   Public Webhook: ${res.data.relay_url}/h/${res.data.token}\n`);
    } catch (e: any) {
      console.error('❌ Registration failed:', e.response?.data?.error || e.message);
    }
  });

program.parse();
