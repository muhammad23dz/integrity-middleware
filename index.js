const crypto = require('crypto');

/**
 * Signature Strategies for different payment providers.
 */
const signatureStrategies = {
    /**
     * Generic Strategy: timestamp.payload format
     */
    generic: (secret, timestamp, body) => {
        const payload = `${timestamp}.${JSON.stringify(body)}`;
        return crypto.createHmac('sha256', secret).update(payload).digest('hex');
    },

    /**
     * Stripe Strategy: v1=hash format with ordered headers
     * Matches Stripe's webhook signing behavior.
     */
    stripe: (secret, timestamp, body) => {
        const payload = `${timestamp}.${JSON.stringify(body)}`;
        return `v1=${crypto.createHmac('sha256', secret).update(payload).digest('hex')}`;
    },

    /**
     * Adyen Strategy: Uses Base64 encoding for the HMAC output.
     */
    adyen: (secret, timestamp, body) => {
        const payload = JSON.stringify(body);
        return crypto.createHmac('sha256', secret).update(payload).digest('base64');
    }
};

/**
 * validateIntegrity
 * @param {string} secret - The shared webhook secret.
 * @param {Object} options - Configuration options.
 * @param {string} options.provider - Signature strategy ('generic', 'stripe', 'adyen').
 * @param {number} options.ttlSeconds - Replay window (default 300s).
 * @returns {Function} Express middleware.
 */
const validateIntegrity = (secret, options = {}) => {
    const { provider = 'generic', ttlSeconds = 300 } = options;
    const getExpectedSignature = signatureStrategies[provider] || signatureStrategies.generic;

    return (req, res, next) => {
        const signature = req.headers['x-transaction-signature'] || req.headers['stripe-signature'];
        const timestamp = req.headers['x-timestamp'] || Date.now().toString().slice(0, 10);

        if (!signature) {
            console.warn(`[WARN] Request missing signature header from ${req.ip}`);
            return res.status(401).json({ error: 'MISSING_AUTHENTICATION_HEADERS' });
        }

        if (!secret) {
            console.error('[CRITICAL] Webhook secret not configured.');
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
        }

        // 1. Replay Prevention
        const now = Math.floor(Date.now() / 1000);
        const requestTime = parseInt(timestamp);

        if (Math.abs(now - requestTime) > ttlSeconds) {
            console.warn(`[WARN] Replay attack detected from ${req.ip}`);
            return res.status(401).json({ error: 'TIMESTAMP_EXPIRED_REPLAY_DETECTED' });
        }

        // 2. Calculate Expected Signature
        const expectedSignature = getExpectedSignature(secret, timestamp, req.body);

        // 3. Timing-Safe Comparison
        try {
            const signatureBuffer = Buffer.from(signature);
            const expectedBuffer = Buffer.from(expectedSignature);

            if (signatureBuffer.length !== expectedBuffer.length ||
                !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
                console.warn(`[WARN] Integrity check failed from ${req.ip}`);
                return res.status(403).json({ error: 'INTEGRITY_CHECK_FAILED' });
            }
        } catch (err) {
            return res.status(403).json({ error: 'INVALID_SIGNATURE_FORMAT' });
        }

        console.log(`[INFO] Valid webhook received from ${req.ip} via ${provider} strategy`);
        next();
    };
};

module.exports = { validateIntegrity, signatureStrategies };
