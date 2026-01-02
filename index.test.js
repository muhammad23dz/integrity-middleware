const crypto = require('crypto');
const { validateIntegrity, signatureStrategies } = require('./index');

// Mock Express request/response
const mockReq = (headers = {}, body = {}, ip = '127.0.0.1') => ({
    headers,
    body,
    ip
});

const mockRes = () => {
    const res = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res;
};

const mockNext = jest.fn();

describe('validateIntegrity Middleware', () => {
    const secret = 'test-secret-key';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const body = { event: 'payment.completed', amount: 100 };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('Generic Strategy', () => {
        const middleware = validateIntegrity(secret, { provider: 'generic' });

        it('should pass with valid signature', () => {
            const validSignature = signatureStrategies.generic(secret, timestamp, body);
            const req = mockReq({ 'x-transaction-signature': validSignature, 'x-timestamp': timestamp }, body);
            const res = mockRes();

            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
            expect(res.status).not.toHaveBeenCalled();
        });

        it('should reject invalid signature', () => {
            const req = mockReq({ 'x-transaction-signature': 'invalid-signature', 'x-timestamp': timestamp }, body);
            const res = mockRes();

            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: 'INTEGRITY_CHECK_FAILED' });
        });

        it('should reject expired timestamp (replay attack)', () => {
            const oldTimestamp = (Math.floor(Date.now() / 1000) - 600).toString(); // 10 minutes ago
            const validSignature = signatureStrategies.generic(secret, oldTimestamp, body);
            const req = mockReq({ 'x-transaction-signature': validSignature, 'x-timestamp': oldTimestamp }, body);
            const res = mockRes();

            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: 'TIMESTAMP_EXPIRED_REPLAY_DETECTED' });
        });
    });

    describe('Stripe Strategy', () => {
        const middleware = validateIntegrity(secret, { provider: 'stripe' });

        it('should pass with valid Stripe v1 signature', () => {
            const validSignature = signatureStrategies.stripe(secret, timestamp, body);
            const req = mockReq({ 'stripe-signature': validSignature, 'x-timestamp': timestamp }, body);
            const res = mockRes();

            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });
    });

    describe('Missing Headers', () => {
        const middleware = validateIntegrity(secret);

        it('should reject request with missing signature header', () => {
            const req = mockReq({ 'x-timestamp': timestamp }, body);
            const res = mockRes();

            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: 'MISSING_AUTHENTICATION_HEADERS' });
        });
    });
});
