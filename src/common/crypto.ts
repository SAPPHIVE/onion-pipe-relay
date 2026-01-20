import sodium from 'libsodium-wrappers';

export interface EncryptedPayload {
    ciphertext: string; // base64
    ephemeralPublicKey: string; // base64
    nonce: string; // base64
}

export class CryptoService {
    private static ready = false;

    static async init() {
        if (!this.ready) {
            await sodium.ready;
            this.ready = true;
        }
    }

    /**
     * Encrypts a payload for a specific public key.
     * Uses anonymous sealed box pattern (ephemeral key per message).
     */
    static async encrypt(payload: string, recipientPublicKeyBase64: string): Promise<string> {
        await this.init();
        const publicKey = sodium.from_base64(recipientPublicKeyBase64);
        const payloadBytes = sodium.from_string(payload);
        
        // sodium.crypto_box_seal creates a "sealed box" which includes the ephemeral public key
        const sealedBox = sodium.crypto_box_seal(payloadBytes, publicKey);
        return sodium.to_base64(sealedBox);
    }

    /**
     * Decrypts a payload using the private key.
     */
    static async decrypt(sealedBoxBase64: string, recipientPublicKeyBase64: string, recipientPrivateKeyBase64: string): Promise<string> {
        await this.init();
        const sealedBox = sodium.from_base64(sealedBoxBase64);
        const publicKey = sodium.from_base64(recipientPublicKeyBase64);
        const privateKey = sodium.from_base64(recipientPrivateKeyBase64);
        
        try {
            const decrypted = sodium.crypto_box_seal_open(sealedBox, publicKey, privateKey);
            return typeof decrypted === 'string' ? decrypted : sodium.to_string(decrypted);
        } catch (e) {
            throw new Error('Decryption failed: malformed payload or incorrect key');
        }
    }

    /**
     * Generates a new X25519 key pair.
     */
    static async generateKeyPair() {
        await this.init();
        const pair = sodium.crypto_box_keypair();
        return {
            publicKey: sodium.to_base64(pair.publicKey),
            privateKey: sodium.to_base64(pair.privateKey)
        };
    }
}
