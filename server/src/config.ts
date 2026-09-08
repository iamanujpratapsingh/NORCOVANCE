import path from 'node:path';
import dotenv from 'dotenv';

dotenv.config({ path: path.resolve(process.cwd(), 'server/.env') });
dotenv.config();

const environment = process.env.NODE_ENV ?? 'development';
const configuredOrigins = (process.env.CLIENT_ORIGIN ?? 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const requestedGeminiModel = process.env.GEMINI_MODEL ?? 'gemini-3.5-flash-lite';
// Gemini retired gemini-2.0-flash-lite. Keeping this migration guard lets a
// long-running development process recover safely after an environment update.
const geminiModel = requestedGeminiModel === 'gemini-2.0-flash-lite' ? 'gemini-3.5-flash-lite' : requestedGeminiModel;

export const config = {
  port: Number(process.env.PORT ?? 4000),
  environment,
  isProduction: environment === 'production',
  clientOrigins: configuredOrigins,
  databaseUrl: process.env.DATABASE_URL ?? 'file:../prisma/dev.db',
  geminiApiKey: process.env.GEMINI_API_KEY ?? '',
  geminiModel,
  signingPrivateKey: process.env.SIGNING_PRIVATE_KEY ?? '',
  signingPublicKey: process.env.SIGNING_PUBLIC_KEY ?? '',
  sessionDurationMs: 8 * 60 * 60 * 1000
};
