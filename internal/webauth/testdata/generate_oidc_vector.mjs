// Regenerate a public-only, synthetic interoperability vector. No production
// keys, provider calls, Go helper or private-key persistence are involved.
import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const keys = await webcrypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
);
const publicKey = await webcrypto.subtle.exportKey('jwk', keys.publicKey);
const kid = 'synthetic-webcrypto-key';
const header = { alg: 'ES256', kid };
const now = Date.parse('2026-11-14T12:00:00Z') / 1000;
const claims = {
  iss: 'https://id.0g0.xyz', aud: 'synthetic-console-rp',
  sub: 'independent-webcrypto-pairwise-subject',
  iat: now - 60, exp: now + 3540, auth_time: now - 120,
  jti: 'synthetic-webcrypto-assertion-id', nonce: 'synthetic-outstanding-login-nonce',
};
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const input = `${encode(header)}.${encode(claims)}`;
const signature = await webcrypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, Buffer.from(input),
);
if (signature.byteLength !== 64 || !await webcrypto.subtle.verify(
  { name: 'ECDSA', hash: 'SHA-256' }, keys.publicKey, signature, Buffer.from(input),
)) throw new Error('WebCrypto did not produce a valid 64-byte ES256 signature');
const vector = {
  provenance: `Synthetic Node ${process.version} WebCrypto ECDSA/P-256/SHA-256, 64-byte R||S; private key discarded`,
  jwks: { keys: [{ kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y, kid, alg: 'ES256', use: 'sig', key_ops: ['verify'] }] },
  token: `${input}.${Buffer.from(signature).toString('base64url')}`,
};
writeFileSync(new URL('./oidc-es256-webcrypto.json', import.meta.url), JSON.stringify(vector, null, 2) + '\n');
