import { Router, Request, Response } from 'express';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import { authenticator } from '@otplib/preset-default';
import qrcode from 'qrcode';
import { RedisService, UserMfa, WebAuthnCredential } from '../common/redis';
import pino from 'pino';

const logger = pino({ name: 'LOOHIVE-MFA' });
const router = Router();

// Robust Origin and RP_ID configuration
let PUBLIC_URL = process.env.PUBLIC_RELAY_URL || 'http://localhost:3000';
if (!PUBLIC_URL.startsWith('http')) {
    PUBLIC_URL = 'https://' + PUBLIC_URL; 
}
const ORIGIN = PUBLIC_URL.replace(/\/$/, ''); 
const RP_ID = new URL(ORIGIN).hostname;

/**
 * Helper to ensure credential IDs are always in the correct base64url format
 * needed by both the browser and the simplewebauthn library.
 */
function toBase64Url(id: string | Uint8Array): string {
    const base64 = typeof id === 'string' ? id : Buffer.from(id).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function setupMfaRoutes(redis: RedisService) {
    
    router.get('/status', async (req: Request, res: Response) => {
        if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });
        const mfa = await redis.getUserMfa(req.user.id);
        res.json({
            totp: mfa.totp_enabled,
            webauthn: mfa.webauthn_credentials.length > 0,
            webauthn_count: mfa.webauthn_credentials.length
        });
    });

    router.post('/webauthn/register/options', async (req: Request, res: Response) => {
        if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });
        const mfa = await redis.getUserMfa(req.user.id);
        const options = await generateRegistrationOptions({
            rpName: 'Onion-Pipe Relay',
            rpID: RP_ID,
            userID: Buffer.from(req.user.id),
            userName: req.user.username,
            attestationType: 'none',
            excludeCredentials: mfa.webauthn_credentials.map(cred => ({
                id: toBase64Url(cred.credentialID),
                type: 'public-key',
            })),
            authenticatorSelection: {
                residentKey: 'preferred', // 'preferred' is more compatible across all Windows versions
                userVerification: 'preferred',
                // authenticatorAttachment: 'platform', // Removed to allow Cross-Platform (Security Keys, Android) as well
            },
        });
        await redis.setWebAuthnChallenge(req.user.id, options.challenge);
        
        // Return the exact object but ensure binary fields are base64url strings.
        // We avoid JSON.parse/stringify logic to prevent property ordering or type issues.
        const responseOptions = {
            ...options,
            challenge: toBase64Url(options.challenge),
            user: {
                ...options.user,
                id: toBase64Url(options.user.id)
            },
            excludeCredentials: options.excludeCredentials?.map(cred => ({
                ...cred,
                id: toBase64Url(cred.id)
            }))
        };
        
        res.json(responseOptions);
    });

    router.post('/webauthn/register/verify', async (req: Request, res: Response) => {
        if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
        const { body } = req;
        const expectedChallenge = await redis.getWebAuthnChallenge(req.user.id);
        if (!expectedChallenge) return res.status(400).json({ error: 'Challenge expired' });
        try {
            const verification = await verifyRegistrationResponse({
                response: body,
                expectedChallenge,
                expectedOrigin: ORIGIN,
                expectedRPID: RP_ID,
            });
            if (verification.verified && verification.registrationInfo) {
                const { credential } = verification.registrationInfo;
                const mfa = await redis.getUserMfa(req.user.id);
                
                // Fix: credential.id is already a base64url string from the library.
                // Do NOT re-encode it, or the browser will look for the wrong ID later.
                const credentialID = credential.id; 
                
                mfa.webauthn_credentials.push({
                    credentialID,
                    publicKey: Buffer.from(credential.publicKey).toString('base64'),
                    counter: credential.counter,
                    transports: body.response.transports,
                });
                await redis.updateUserMfa(req.user.id, mfa);
                (req.session as any).mfa_verified = true;
                res.json({ verified: true });
            } else res.status(400).json({ verified: false });
        } catch (error: any) {
            logger.error(error);
            res.status(400).json({ error: error.message });
        }
    });

    router.post('/webauthn/login/options', async (req, res) => {
        if (!req.user) return res.status(401).send('Unauthorized');
        const mfa = await redis.getUserMfa(req.user.id);
        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: mfa.webauthn_credentials.map(cred => ({
                id: toBase64Url(cred.credentialID),
                type: 'public-key',
                // REMOVED 'transports' to prevent browser-side filtering that causes "No passkeys available"
            })),
            userVerification: 'preferred',
        });
        await redis.setWebAuthnChallenge(req.user.id, options.challenge);
        
        // Return exactly what startAuthentication needs
        const responseOptions = {
            ...options,
            challenge: toBase64Url(options.challenge),
            allowCredentials: options.allowCredentials?.map(cred => ({
                ...cred,
                id: toBase64Url(cred.id)
            }))
        };
        
        res.json(responseOptions);
    });

    router.post('/webauthn/login/verify', async (req, res) => {
        if (!req.user) return res.status(401).send('Unauthorized');
        const { body } = req;
        const mfa = await redis.getUserMfa(req.user.id);
        const expectedChallenge = await redis.getWebAuthnChallenge(req.user.id);
        
        // Robust ID matching: handle base64 and base64url encodings
        const targetId = toBase64Url(body.id);
        const dbCred = mfa.webauthn_credentials.find(c => toBase64Url(c.credentialID) === targetId);

        if (!dbCred || !expectedChallenge) return res.status(400).json({ error: 'Invalid challenge or unknown credential' });
        try {
            const verification = await verifyAuthenticationResponse({
                response: body,
                expectedChallenge,
                expectedOrigin: ORIGIN,
                expectedRPID: RP_ID,
                credential: {
                    id: toBase64Url(dbCred.credentialID),
                    publicKey: Buffer.from(dbCred.publicKey, 'base64'),
                    counter: dbCred.counter,
                },
            });
            if (verification.verified) {
                dbCred.counter = verification.authenticationInfo.newCounter;
                await redis.updateUserMfa(req.user.id, mfa);
                (req.session as any).mfa_verified = true;
                res.json({ verified: true });
            } else res.status(400).json({ verified: false });
        } catch (err: any) {
            logger.error(err);
            res.status(400).json({ error: err.message });
        }
    });

    router.post('/totp/setup', async (req: Request, res: Response) => {
        if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(req.user.username, 'Onion-Pipe', secret);
        const qr = await qrcode.toDataURL(otpauth);
        (req.session as any).temp_totp_secret = secret;
        res.json({ qr, secret });
    });

    router.post('/totp/verify', async (req: Request, res: Response) => {
        if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
        const { code, isSetup } = req.body;
        const mfa = await redis.getUserMfa(req.user.id);
        const secret = isSetup ? (req.session as any).temp_totp_secret : mfa.totp_secret;
        if (!secret) return res.status(400).json({ error: 'TOTP not initialized' });
        if (authenticator.verify({ token: code, secret })) {
            if (isSetup) {
                mfa.totp_enabled = true;
                mfa.totp_secret = secret;
                delete (req.session as any).temp_totp_secret;
                if (!mfa.backup_codes) {
                    const codes = Array.from({ length: 10 }, () => Math.random().toString(36).substring(2, 10).toUpperCase());
                    mfa.backup_codes = codes;
                }
                await redis.updateUserMfa(req.user.id, mfa);
                if (isSetup) return res.json({ verified: true, backup_codes: mfa.backup_codes });
            }
            (req.session as any).mfa_verified = true;
            res.json({ verified: true });
        } else res.status(400).json({ verified: false });
    });

    router.post('/totp/disable', async (req, res) => {
        if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
        const mfa = await redis.getUserMfa(req.user.id);
        mfa.totp_enabled = false;
        mfa.totp_secret = undefined;
        await redis.updateUserMfa(req.user.id, mfa);
        res.json({ success: true });
    });

    router.post('/webauthn/disable', async (req, res) => {
        if (!req.isAuthenticated()) return res.status(401).send('Unauthorized');
        const mfa = await redis.getUserMfa(req.user.id);
        mfa.webauthn_credentials = [];
        await redis.updateUserMfa(req.user.id, mfa);
        res.json({ success: true });
    });

    return router;
}
