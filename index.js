const crypto = require('crypto');

/**
 * validateIntegrity
 * @param {string} secret - The shared webhook secret.
 * @returns {Function} Express middleware.
 */
const validateIntegrity = (secret) => {
    return (req, res, next) => {
        const signature = req.headers['x-transaction-signature'];
        const timestamp = req.headers['x-timestamp'];

        if (!signature || !timestamp) {
            return res.status(401).json({ error: 'MISSING_AUTHENTICATION_HEADERS' });
        }

        if (!secret) {
            console.error('[CRITICAL] Webhook secret not configured.');
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR' });
        }

        // 1. Replay Prevention: 300s (5min) TTL
        const now = Math.floor(Date.now() / 1000);
        const requestTime = parseInt(timestamp);

        if (Math.abs(now - requestTime) > 300) {
            return res.status(401).json({ error: 'TIMESTAMP_EXPIRED_REPLAY_DETECTED' });
        }

        // 2. Canonical Payload Construction
        // We use the timestamp as a salt to ensure the same body generates different signatures over time.
        const payload = `${timestamp}.${JSON.stringify(req.body)}`;

        const expectedSignature = crypto
            .createHmac('sha256', secret)
            .update(payload)
            .digest('hex');

        // 3. Timing-Safe Comparison
        // Prevent side-channel leakage of the secret signature.
        try {
            const signatureBuffer = Buffer.from(signature);
            const expectedBuffer = Buffer.from(expectedSignature);

            if (signatureBuffer.length !== expectedBuffer.length ||
                !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
                return res.status(403).json({ error: 'INTEGRITY_CHECK_FAILED' });
            }
        } catch (err) {
            return res.status(403).json({ error: 'INVALID_SIGNATURE_FORMAT' });
        }

        next();
    };
};

module.exports = { validateIntegrity };
