import { Command } from 'commander';
import { CryptoService } from '../common/crypto';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const program = new Command();
const CONFIG_PATH = path.join(process.cwd(), 'config.json');
const RELAY_URL = process.env.RELAY_URL || 'http://localhost:3000';

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

program.command('register')
  .description('Register with entry relay')
  .argument('<onion-address>', 'Your .onion address (without .onion suffix)')
  .action(async (onion) => {
    if (!fs.existsSync(CONFIG_PATH)) {
      console.error('❌ No config.json found. Run init first.');
      return;
    }
    const { publicKey } = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    
    try {
      const res = await axios.post(`${RELAY_URL}/register`, {
        onion_service_id: onion,
        public_key: publicKey
      });
      console.log('✅ Registered! Your Webhook URL is:');
      console.log(`${RELAY_URL}/h/${res.data.token}`);
    } catch (e: any) {
      console.error('❌ Registration failed:', e.message);
    }
  });

program.parse();
