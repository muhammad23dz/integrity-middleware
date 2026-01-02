# Payment Integrity Middleware

[![Node: 16+](https://img.shields.io/badge/Node-16+-emerald)](https://nodejs.org/)
[![Security: HMAC-SHA256](https://img.shields.io/badge/Security-HMAC--SHA256-blue)](https://en.wikipedia.org/wiki/HMAC)

A zero-trust Express.js middleware for validating the integrity and authenticity of payment webhook payloads.

## The Security Problem

Webhooks are inherently vulnerable to:
1.  **Request Tampering**: An attacker intercepting the request and modifying the payment amount.
2.  **Replay Attacks**: A valid signed request being sent multiple times to trigger duplicate payments.
3.  **Timing Attacks**: Side-channel attacks during signature comparison that reveal valid bits of the signature.

## Implementation Details

### 1. Cryptographic Signature
Uses `HMAC-SHA256` with a shared secret. The payload is constructed using a canonical string of the timestamp and the raw request body.

### 2. Time-Window Protection
Enforces a 5-minute time-to-live (TTL). Requests with timestamps outside this window are rejected, regardless of signature validity.

### 3. Constant-Time Comparison
Uses `crypto.timingSafeEqual` to prevent timing-based side-channel attacks during the verification phase.

## Installation

```bash
npm install payment-integrity-middleware
```

## Usage

```javascript
const { validateIntegrity } = require('payment-integrity-middleware');

app.post('/webhooks/payments', 
  validateIntegrity(process.env.WEBHOOK_SECRET), 
  (req, res) => {
    // Integrity verified
    res.sendStatus(200);
});
```

## Testing

```bash
npm test
```

## License
MIT
