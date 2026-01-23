import { RedisService } from './src/common/redis';
import * as dotenv from 'dotenv';
dotenv.config();

async function main() {
    const redis = new RedisService(process.env.REDIS_URL || 'redis://localhost:6379');
    await redis.connect();
    await (redis as any).client.del('user_mfa:admin');
    console.log('✅ Admin MFA has been reset.');
    process.exit(0);
}

main().catch(console.error);
