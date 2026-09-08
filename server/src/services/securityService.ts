import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';

const keyDirectory = path.resolve(process.cwd(), 'keys');
const privateKeyPath = path.join(keyDirectory, 'private.pem');
const publicKeyPath = path.join(keyDirectory, 'public.pem');

function environmentKey(value: string) {
  return value.replace(/\\n/g, '\n').trim();
}

function loadSigningKeys() {
  const privateKey = environmentKey(config.signingPrivateKey);
  const publicKey = environmentKey(config.signingPublicKey);
  if (privateKey && publicKey) return { privateKey, publicKey };

  if (config.isProduction) {
    throw new Error('Record signing is not configured. Set both signing key environment variables.');
  }

  if (!fs.existsSync(keyDirectory)) fs.mkdirSync(keyDirectory, { recursive: true });
  if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    fs.writeFileSync(privateKeyPath, pair.privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, pair.publicKey);
  }
  return { privateKey: fs.readFileSync(privateKeyPath, 'utf8'), publicKey: fs.readFileSync(publicKeyPath, 'utf8') };
}

export function canonicalRecord(record: { testId: string; timestamp: Date | string; operatorId: string; latitude: number; longitude: number; result: string; confidence: number; imageHash: string }) {
  return [record.testId, new Date(record.timestamp).toISOString(), record.operatorId, record.latitude, record.longitude, record.result, record.confidence, record.imageHash].join('|');
}

export function signRecord(record: Parameters<typeof canonicalRecord>[0]) {
  const { privateKey } = loadSigningKeys();
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(canonicalRecord(record));
  return signer.sign(privateKey, 'base64');
}

export function verifySignature(record: Parameters<typeof canonicalRecord>[0], signature: string) {
  const { publicKey } = loadSigningKeys();
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(canonicalRecord(record));
  return verifier.verify(publicKey, signature, 'base64');
}

export function hashBytes(bytes: Buffer) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
