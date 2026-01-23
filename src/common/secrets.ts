import fs from 'fs';
import path from 'path';
import pino from 'pino';

const logger = pino({ name: 'SecretUtility' });

/**
 * Returns the value of a secret.
 * Priority:
 * 1. Environment variable `{name}_FILE` pointing to a file
 * 2. Default Docker secret path `/run/secrets/{name}`
 * 3. Fallback to Environment variable `{name}`
 * 
 * @param name The name of the secret (e.g. 'ADMIN_USER')
 * @param defaultValue Fallback value if no secret is found
 */
export function getSecret(name: string, defaultValue?: string): string {
    // 1. Check for {NAME}_FILE env var
    const filePath = process.env[`${name}_FILE`];
    if (filePath && fs.existsSync(filePath)) {
        try {
            return fs.readFileSync(filePath, 'utf8').trim();
        } catch (error) {
            logger.error({ err: error }, `Error reading secret file from ${name}_FILE: ${filePath}`);
        }
    }

    // 2. Check default Docker secret path
    const dockerSecretPath = path.join('/run/secrets', name.toLowerCase());
    if (fs.existsSync(dockerSecretPath)) {
        try {
            return fs.readFileSync(dockerSecretPath, 'utf8').trim();
        } catch (error) {
            logger.error({ err: error }, `Error reading default Docker secret: ${dockerSecretPath}`);
        }
    }

    // 3. Fallback to direct environment variable
    const envValue = process.env[name];
    if (envValue !== undefined) {
        return envValue;
    }

    if (defaultValue !== undefined) {
        return defaultValue;
    }

    logger.warn(`Secret ${name} not found in environment or secret files.`);
    return '';
}
