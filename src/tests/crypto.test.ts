import { CryptoService } from '../common/crypto';
import assert from 'assert';

async function testCrypto() {
    console.log('Testing CryptoService...');
    
    // 1. Generate keys
    const keys = await CryptoService.generateKeyPair();
    console.log('✅ Keys generated');

    // 2. Encrypt
    const originalPayload = JSON.stringify({ hello: 'world', secret: 'abc' });
    const encrypted = await CryptoService.encrypt(originalPayload, keys.publicKey);
    console.log('✅ Encrypted');

    // 3. Decrypt
    const decrypted = await CryptoService.decrypt(encrypted, keys.publicKey, keys.privateKey);
    console.log('✅ Decrypted');

    // 4. Verify
    assert.strictEqual(decrypted, originalPayload);
    console.log('✅ Integrity verified');

    // 5. Test failure with wrong key
    const otherKeys = await CryptoService.generateKeyPair();
    try {
        await CryptoService.decrypt(encrypted, otherKeys.publicKey, otherKeys.privateKey);
        console.error('❌ Decryption should have failed with wrong key');
    } catch (e) {
        console.log('✅ Decryption failed as expected with wrong key');
    }
}

testCrypto().catch(console.error);
