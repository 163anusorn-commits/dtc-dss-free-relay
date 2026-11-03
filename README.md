# DSS free relay

Small Node 22 HTTPS relay for authorized exact-SIM vehicle and certificate
recipient lookup. No customer records, passwords, tokens or private signing keys
are included in this repository.

Use the Render Blueprint with the **Free** web-service plan in Singapore.
Do not add a payment method or provision a paid datastore, disk or worker.
Free hosting has quotas, idle sleep and cold starts; no uninterrupted uptime
is promised.

Enter DSS_USERNAME and DSS_PASSWORD only in Render's secret environment fields.
The public JWK in render.yaml verifies requests from the cloud gateway.
It is deliberately public and cannot create valid request signatures.
The corresponding private signing key belongs only in the gateway's secret store.

Do not set DSS_RELAY_URL or DSS_RELAY_PRIVATE_JWK on this relay.

- GET /health reports process health without contacting DSS.
- POST /lookup requires a timestamped ECDSA-P256 signature over the exact UTF-8
  JSON body in X-Service-Signature (base64url, IEEE-P1363 format).
- Each request includes timestamp, a unique nonce and request.sim.
- Unsigned requests and replayed nonces are rejected.
- The lookup uses a fresh DSS login, exact SIM/plate/box checks and Job/SO Ship To
  data. It does not expose session cookies or credentials.

Run npm run check and npm start locally. Render supplies PORT.
