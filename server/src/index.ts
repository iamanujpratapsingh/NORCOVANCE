import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import cors from 'cors';
import express from 'express';
import multer, { MulterError } from 'multer';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { config } from './config.js';
import { prisma } from './prisma.js';
import { classifyColour } from './services/classificationService.js';
import { canonicalRecord, hashBytes, signRecord, verifySignature } from './services/securityService.js';
import { authenticateUser, createSession, requirePermission, requireRole, revokeSession, ROLES, writeAudit, type AuthenticatedRequest } from './auth.js';
import { analyzeImageWithGemini, askGemini, asksForPendingTests, authorizationRefusal, buildOperatorAIContext, buildSupervisorAIContext, operatorSystemPrompt, requestedTestIds, supervisorSystemPrompt } from './services/aiService.js';

const app = express();
const uploadDirectory = path.resolve(process.cwd(), 'uploads');
fs.mkdirSync(uploadDirectory, { recursive: true });
const upload = multer({ dest: uploadDirectory, limits: { fileSize: 8 * 1024 * 1024, files: 1 }, fileFilter: (_req, _file, callback) => callback(null, true) });
const loginAttempts = new Map<string, { count: number; resetAt: number }>();
const loginWindowMs = 15 * 60 * 1000;
const maxLoginAttempts = 5;

app.set('trust proxy', config.isProduction ? 1 : false);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self), geolocation=(self), microphone=()');
  if (config.isProduction && !req.secure) return res.status(400).json({ error: 'HTTPS is required.' });
  return next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.clientOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed.'));
  },
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  maxAge: 86400
}));
app.use(express.json({ limit: '2mb' }));

const testInput = z.object({ testType: z.string().trim().min(1).max(120), sampleReference: z.string().trim().min(1).max(160), notes: z.string().trim().max(1000).default('') });
const analysisInput = z.object({ features: z.object({ averageRgb: z.object({ r: z.number(), g: z.number(), b: z.number() }), hsv: z.object({ hue: z.number(), saturation: z.number(), brightness: z.number() }), colourDistance: z.number(), referenceDetected: z.boolean() }) });

function addAudit(event: string, testId: string, operator: string) { return prisma.auditEvent.create({ data: { event, testId, operator } }); }
function publicRecord(record: any) { return { ...record, analysisData: JSON.parse(record.analysisData), auditEvents: record.auditEvents ?? [] }; }
function idParam(req: express.Request) { return String(req.params.id); }
async function findRecord(req: express.Request) { return prisma.testRecord.findFirst({ where: { OR: [{ id: idParam(req) }, { testId: idParam(req) }] } }); }
function canAccessRecord(req: AuthenticatedRequest, operatorId: string) { return req.user?.role === ROLES.SUPERVISOR || req.user?.operatorId === operatorId; }
function canModifyEvidenceRecord(req: AuthenticatedRequest, operatorId: string) { return req.user?.operatorId === operatorId; }
function isFinalized(record: { digitalSignature: string; verificationStatus: string }) { return Boolean(record.digitalSignature) || record.verificationStatus === 'VERIFIED'; }
function removeTemporaryUpload(filePath?: string) { if (filePath && path.dirname(filePath) === uploadDirectory) fs.rmSync(filePath, { force: true }); }
function imageMimeType(bytes: Buffer) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (bytes.length >= 12 && bytes.subarray(0, 4).toString('ascii') === 'RIFF' && bytes.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  return null;
}
async function createTestId() {
  const year = new Date().getUTCFullYear();
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const testId = `FT-${year}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    if (!(await prisma.testRecord.findUnique({ where: { testId }, select: { id: true } }))) return testId;
  }
  throw new Error('Unable to create a unique test ID. Please try again.');
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.post('/api/auth/login', async (req, res) => {
  const parsed = z.object({ operatorId: z.string().trim().toUpperCase().regex(/^(?:OP|SUP)-\d{4,20}$/), password: z.string().min(1).max(128) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter operator ID and password.' });
  const clientAddress = req.ip || 'unknown';
  const now = Date.now();
  const attempt = loginAttempts.get(clientAddress);
  if (attempt && attempt.resetAt > now && attempt.count >= maxLoginAttempts) {
    res.setHeader('Retry-After', String(Math.ceil((attempt.resetAt - now) / 1000)));
    return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
  }
  if (attempt && attempt.resetAt <= now) loginAttempts.delete(clientAddress);
  const user = await prisma.user.findUnique({ where: { operatorId: parsed.data.operatorId } });
  const credentialsValid = Boolean(user?.isActive) && await bcrypt.compare(parsed.data.password, user?.passwordHash ?? '$2a$10$JpM6OGM1GSbzB4qY2Jx7Y.JPVaPnKYwMG.vlJDNEQm2d9gWn5NI8K');
  if (!credentialsValid || !user) {
    const activeAttempt = loginAttempts.get(clientAddress);
    loginAttempts.set(clientAddress, { count: activeAttempt && activeAttempt.resetAt > now ? activeAttempt.count + 1 : 1, resetAt: now + loginWindowMs });
    return res.status(401).json({ error: 'Invalid Operator ID or password.' });
  }
  loginAttempts.delete(clientAddress);
  const token = await createSession(user.id);
  await writeAudit('LOGIN', user.id, undefined, { role: user.role });
  res.json({ token, user: { id: user.id, operatorId: user.operatorId, name: user.name, role: user.role } });
});

app.get('/api/auth/me', authenticateUser, async (req: AuthenticatedRequest, res) => {
  res.json({ id: req.user!.id, operatorId: req.user!.operatorId, name: req.user!.name, role: req.user!.role });
});
app.post('/api/auth/logout', authenticateUser, async (req: AuthenticatedRequest, res) => {
  await writeAudit('LOGOUT', req.user!.id, undefined, { role: req.user!.role });
  await revokeSession(req.user!.sessionId);
  res.json({ ok: true });
});

app.get('/api/tests', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const search = String(req.query.search ?? '').slice(0, 120);
  const result = String(req.query.result ?? '').slice(0, 24);
  const scope = req.user!.role === ROLES.SUPERVISOR ? {} : { operatorId: req.user!.operatorId };
  const records = await prisma.testRecord.findMany({ where: { AND: [scope, { OR: [{ testId: { contains: search } }, { operatorId: { contains: search } }] }, ...(result ? [{ result }] : [])] }, include: { auditEvents: true }, orderBy: { timestamp: 'desc' } });
  res.json(records.map(publicRecord));
});
app.get('/api/tests/:id', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const record = await prisma.testRecord.findFirst({ where: { OR: [{ id: idParam(req) }, { testId: idParam(req) }] }, include: { auditEvents: { orderBy: { timestamp: 'asc' } } } });
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canAccessRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
  res.json(publicRecord(record));
});
app.post('/api/tests', authenticateUser, requirePermission('CREATE_TEST'), async (req: AuthenticatedRequest, res) => {
  const parsed = testInput.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Test information is incomplete.' });
  const testId = await createTestId();
  const record = await prisma.testRecord.create({ data: { ...parsed.data, operatorId: req.user!.operatorId, testId, result: 'INCONCLUSIVE', confidence: 0, analysisData: JSON.stringify({}), imagePath: '', imageHash: '', timestamp: new Date(), latitude: 0, longitude: 0, locationSource: 'PENDING', digitalSignature: '', verificationStatus: 'DRAFT' } });
  await addAudit('TEST_CREATED', testId, req.user!.operatorId);
  await writeAudit('TEST_CREATED', req.user!.id, testId);
  res.status(201).json(record);
});
app.post('/api/tests/:id/image', authenticateUser, requirePermission('CREATE_TEST'), upload.single('image'), async (req: AuthenticatedRequest, res) => {
  if (!req.file) return res.status(400).json({ error: 'Please provide a JPG, PNG, or WebP image.' });
  const uploadedBytes = fs.readFileSync(req.file.path);
  const detectedMimeType = imageMimeType(uploadedBytes);
  if (!detectedMimeType) { removeTemporaryUpload(req.file.path); return res.status(400).json({ error: 'Please provide a valid JPG, PNG, or WebP image.' }); }
  const record = await findRecord(req);
  if (!record) { removeTemporaryUpload(req.file.path); return res.status(404).json({ error: 'Test record not found.' }); }
  if (!canModifyEvidenceRecord(req, record.operatorId)) { removeTemporaryUpload(req.file.path); return res.status(403).json({ error: 'You do not have permission to modify this evidence record.' }); }
  if (isFinalized(record)) { removeTemporaryUpload(req.file.path); return res.status(409).json({ error: 'This signed record is locked and cannot be changed.' }); }
  const extension = detectedMimeType === 'image/png' ? '.png' : detectedMimeType === 'image/webp' ? '.webp' : '.jpg';
  const storedFilename = `${path.basename(req.file.filename)}${extension}`;
  const storedPath = path.join(uploadDirectory, storedFilename);
  fs.renameSync(req.file.path, storedPath);
  const imageHash = hashBytes(uploadedBytes);
  const updated = await prisma.testRecord.update({ where: { id: record.id }, data: { imagePath: `/uploads/${storedFilename}`, imageHash, aiAnalysis: null, aiConfidence: null, aiConsistency: null, aiReviewRecommended: false, aiExplanation: null, aiModel: null, aiAnalyzedAt: null } });
  if (record.imagePath) removeTemporaryUpload(path.join(uploadDirectory, path.basename(record.imagePath)));
  await addAudit('IMAGE_CAPTURED', record.testId, record.operatorId);
  await writeAudit('IMAGE_CAPTURED', req.user!.id, record.testId);
  await writeAudit('RECORD_HASHED', req.user!.id, record.testId, { algorithm: 'SHA-256' });
  res.json({ imageHash, imagePath: updated.imagePath });
});
app.post('/api/tests/:id/analyze', authenticateUser, requirePermission('ANALYZE_TEST'), async (req: AuthenticatedRequest, res) => {
  const parsed = analysisInput.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Colour features are invalid.' });
  const record = await findRecord(req);
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canModifyEvidenceRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to modify this evidence record.' });
  if (isFinalized(record)) return res.status(409).json({ error: 'This signed record is locked and cannot be changed.' });
  const analysis = classifyColour(parsed.data.features);
  let aiAssessment: Awaited<ReturnType<typeof analyzeImageWithGemini>> | null = null;
  let aiError = '';
  if (record.aiAnalysis) {
    try { aiAssessment = JSON.parse(record.aiAnalysis); } catch { aiAssessment = null; }
  }
  if (record.imagePath && record.imageHash && !record.aiAnalyzedAt && !aiAssessment) {
    try {
      const imageFile = path.join(uploadDirectory, path.basename(record.imagePath));
      if (fs.existsSync(imageFile)) {
        const extension = path.extname(imageFile).toLowerCase();
        const imageMimeType = extension === '.png' ? 'image/png' : extension === '.webp' ? 'image/webp' : 'image/jpeg';
        aiAssessment = await analyzeImageWithGemini(fs.readFileSync(imageFile), imageMimeType, analysis);
        const consistency = aiAssessment.visualAssessment === 'UNCERTAIN' || aiAssessment.imageQuality === 'POOR' || !aiAssessment.referenceCardVisible || !aiAssessment.reactionAreaVisible ? 'UNCERTAIN' : aiAssessment.visualAssessment === analysis.result ? 'MATCH' : 'MISMATCH';
        aiAssessment = { ...aiAssessment, consistencyWithAlgorithm: consistency };
      }
    } catch (error) {
      aiError = error instanceof Error ? error.message : 'AI assistance is temporarily unavailable.';
    }
  }
  const explanation = aiAssessment
    ? `${analysis.explanation} Supporting AI assessment: ${aiAssessment.visualAssessment} with ${Math.round(aiAssessment.aiConfidence * 100)}% confidence. Image quality: ${aiAssessment.imageQuality}. Consistency with the deterministic algorithm: ${aiAssessment.consistencyWithAlgorithm}. ${aiAssessment.reviewRecommended ? 'Supervisor review is recommended.' : 'No additional AI review is recommended.'}`
    : `${analysis.explanation} AI assistance is temporarily unavailable; the deterministic analysis remains the primary result.`;
  analysis.explanation = explanation;
  await prisma.testRecord.update({ where: { id: record.id }, data: { result: analysis.result, confidence: analysis.confidence, analysisData: JSON.stringify({ ...analysis, aiAssessment }), ...(aiAssessment ? { aiAnalysis: JSON.stringify(aiAssessment), aiConfidence: aiAssessment.aiConfidence, aiConsistency: aiAssessment.consistencyWithAlgorithm, aiReviewRecommended: aiAssessment.reviewRecommended || aiAssessment.consistencyWithAlgorithm !== 'MATCH', aiExplanation: aiAssessment.explanation, aiModel: config.geminiModel, aiAnalyzedAt: new Date() } : {}) } });
  await addAudit('IMAGE_ANALYZED', record.testId, record.operatorId);
  await addAudit('RESULT_GENERATED', record.testId, record.operatorId);
  await writeAudit('IMAGE_ANALYZED', req.user!.id, record.testId, { result: analysis.result });
  await writeAudit('RESULT_GENERATED', req.user!.id, record.testId, { result: analysis.result });
  if (aiAssessment) await writeAudit('AI_ANALYSIS_COMPLETED', req.user!.id, record.testId, { consistency: aiAssessment.consistencyWithAlgorithm, reviewRecommended: aiAssessment.reviewRecommended });
  res.json({ ...analysis, aiAssessment, aiAvailable: Boolean(aiAssessment), aiError: aiError || undefined, finalReviewRequired: Boolean(aiAssessment && (aiAssessment.reviewRecommended || aiAssessment.consistencyWithAlgorithm !== 'MATCH')) });
});
app.post('/api/tests/:id/location', authenticateUser, requirePermission('CREATE_TEST'), async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ latitude: z.number(), longitude: z.number(), locationSource: z.enum(['GPS', 'DEMO']) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Location is invalid.' });
  const record = await findRecord(req);
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canModifyEvidenceRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to modify this evidence record.' });
  if (isFinalized(record)) return res.status(409).json({ error: 'This signed record is locked and cannot be changed.' });
  await prisma.testRecord.update({ where: { id: record.id }, data: parsed.data });
  await addAudit('LOCATION_CAPTURED', record.testId, record.operatorId);
  await writeAudit('LOCATION_CAPTURED', req.user!.id, record.testId);
  res.json({ ok: true, ...parsed.data });
});
app.post('/api/tests/:id/sign', authenticateUser, requirePermission('CREATE_TEST'), async (req: AuthenticatedRequest, res) => {
  const record = await findRecord(req);
  if (!record || !record.imageHash) return res.status(400).json({ error: 'Capture an image before signing.' });
  if (!canModifyEvidenceRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to modify this evidence record.' });
  if (isFinalized(record)) return res.status(409).json({ error: 'This record is already signed and locked.' });
  let analysisData: unknown;
  try { analysisData = JSON.parse(record.analysisData); } catch { analysisData = null; }
  if (!analysisData || typeof analysisData !== 'object' || !('features' in analysisData)) return res.status(400).json({ error: 'Analyze the captured image before signing.' });
  const digitalSignature = signRecord(record);
  const updated = await prisma.testRecord.update({ where: { id: record.id }, data: { digitalSignature, verificationStatus: 'SIGNED' } });
  await addAudit('RECORD_SIGNED', record.testId, record.operatorId);
  await writeAudit('RECORD_SIGNED', req.user!.id, record.testId);
  res.json({ digitalSignature: updated.digitalSignature });
});
app.get('/api/tests/:id/verify', authenticateUser, requirePermission('VERIFY_TEST'), async (req: AuthenticatedRequest, res) => {
  const record = await prisma.testRecord.findFirst({ where: { OR: [{ id: idParam(req) }, { testId: idParam(req) }] }, include: { auditEvents: true } });
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canAccessRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
  const imageHashValid = Boolean(record.imagePath && record.imageHash && fs.existsSync(path.join(uploadDirectory, path.basename(record.imagePath))) && hashBytes(fs.readFileSync(path.join(uploadDirectory, path.basename(record.imagePath)))) === record.imageHash);
  const signatureValid = Boolean(record.digitalSignature) && verifySignature(record, record.digitalSignature);
  const recordIntegrityValid = imageHashValid && signatureValid;
  if (recordIntegrityValid && record.verificationStatus !== 'VERIFIED') {
    await prisma.testRecord.update({ where: { id: record.id }, data: { verificationStatus: 'VERIFIED', verifiedBy: req.user!.operatorId, verifiedAt: new Date() } });
    await addAudit('RECORD_VERIFIED', record.testId, req.user!.operatorId);
    await writeAudit('RECORD_VERIFIED', req.user!.id, record.testId);
  } else if (!recordIntegrityValid && record.verificationStatus === 'VERIFIED') {
    await prisma.testRecord.update({ where: { id: record.id }, data: { verificationStatus: 'INTEGRITY_FAILED' } });
    await addAudit('INTEGRITY_VERIFICATION_FAILED', record.testId, req.user!.operatorId);
    await writeAudit('INTEGRITY_VERIFICATION_FAILED', req.user!.id, record.testId, { imageHashValid, signatureValid });
  }
  res.json({ valid: recordIntegrityValid, imageHashValid, signatureValid, recordIntegrityValid, verificationStatus: recordIntegrityValid ? 'VERIFIED' : record.verificationStatus === 'VERIFIED' ? 'INTEGRITY_FAILED' : record.verificationStatus, verifiedBy: record.verifiedBy, verifiedAt: record.verifiedAt, canonicalData: canonicalRecord(record) });
});
app.get('/api/tests/:id/status', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const record = await findRecord(req);
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canAccessRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
  res.json({ testId: record.testId, operatorId: record.operatorId, result: record.result, reviewStatus: record.reviewStatus, verificationStatus: record.verificationStatus, verifiedBy: record.verifiedBy, verifiedAt: record.verifiedAt, reviewedBy: record.reviewedBy, reviewedAt: record.reviewedAt, reviewComment: record.reviewComment });
});
app.post('/api/tests/:id/report', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ reason: z.enum(['Incorrect information', 'Incomplete information', 'Image issue', 'Location issue', 'Test information mismatch', 'Verification issue', 'Other']), description: z.string().min(3).max(2000), priority: z.enum(['LOW', 'MEDIUM', 'HIGH']).default('LOW') }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Choose a reason and provide a description.' });
  const record = await findRecord(req);
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (!canAccessRecord(req, record.operatorId)) return res.status(403).json({ error: 'You do not have permission to report this record.' });
  const existing = await prisma.verificationException.findFirst({ where: { testId: record.testId, createdBy: req.user!.operatorId, status: { in: ['OPEN', 'UNDER_REVIEW'] } }, select: { id: true } });
  if (existing) return res.status(409).json({ error: 'You already have an open report for this record.' });
  const report = await prisma.verificationException.create({ data: { testId: record.testId, createdBy: req.user!.operatorId, reason: parsed.data.reason, description: parsed.data.description, priority: parsed.data.priority } });
  await writeAudit('REPORT_CREATED', req.user!.id, record.testId, { reason: parsed.data.reason, priority: parsed.data.priority });
  res.status(201).json(report);
});
app.get('/api/reports', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const reports = await prisma.verificationException.findMany({ where: req.user!.role === ROLES.SUPERVISOR ? {} : { createdBy: req.user!.operatorId }, include: { record: { select: { testId: true, operatorId: true, result: true, verificationStatus: true } } }, orderBy: { createdAt: 'desc' } });
  res.json(reports);
});

app.post('/api/ai/chat', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ message: z.string().trim().min(1).max(2000), conversationId: z.string().optional(), testId: z.string().optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a message for the assistant.' });
  const refusal = authorizationRefusal(req.user!.role, req.user!.operatorId, parsed.data.message);
  if (refusal) return res.json({ message: refusal, conversationId: parsed.data.conversationId ?? null, role: req.user!.role });
  try {
  const testIds = requestedTestIds(parsed.data.message, parsed.data.testId);
  for (const testId of testIds) {
    const requestedRecord = await prisma.testRecord.findUnique({ where: { testId }, select: { operatorId: true } });
    if (!requestedRecord || !canAccessRecord(req, requestedRecord.operatorId)) return res.json({ message: 'You are not authorized to access this information.', conversationId: parsed.data.conversationId ?? null, role: req.user!.role });
  }
  let conversation = parsed.data.conversationId ? await prisma.conversation.findFirst({ where: { id: parsed.data.conversationId, userId: req.user!.id, role: req.user!.role } }) : null;
  if (parsed.data.conversationId && !conversation) return res.status(403).json({ error: 'You do not have permission to access this conversation.' });
  if (!conversation) conversation = await prisma.conversation.create({ data: { userId: req.user!.id, role: req.user!.role } });
  if (asksForPendingTests(parsed.data.message)) {
    const pending = await prisma.testRecord.findMany({ where: { ...(req.user!.role === ROLES.SUPERVISOR ? {} : { operatorId: req.user!.operatorId }), reviewStatus: 'PENDING' }, orderBy: { timestamp: 'desc' }, take: 20, select: { testId: true } });
    const answer = pending.length
      ? `There ${pending.length === 1 ? 'is' : 'are'} ${pending.length} pending ${pending.length === 1 ? 'test' : 'tests'} in your authorized scope: ${pending.map((record) => record.testId).join(', ')}${pending.length === 20 ? '. Showing the first 20 pending tests.' : '.'}`
      : 'There are no pending tests in your authorized scope.';
    await prisma.message.createMany({ data: [{ conversationId: conversation.id, sender: 'USER', content: parsed.data.message }, { conversationId: conversation.id, sender: 'ASSISTANT', content: answer }] });
    return res.json({ message: answer, conversationId: conversation.id, role: req.user!.role });
  }
  const history = await prisma.message.findMany({ where: { conversationId: conversation.id }, orderBy: { timestamp: 'asc' }, take: 12, select: { sender: true, content: true } });
  const baseContext = req.user!.role === ROLES.SUPERVISOR ? await buildSupervisorAIContext() : await buildOperatorAIContext(req.user!);
  let context = baseContext;
  if (parsed.data.testId) {
    const focusedRecord = await prisma.testRecord.findFirst({ where: { testId: parsed.data.testId, ...(req.user!.role === ROLES.SUPERVISOR ? {} : { operatorId: req.user!.operatorId }) }, select: { testId: true, operatorId: true, result: true, confidence: true, reviewStatus: true, verificationStatus: true, verifiedBy: true, verifiedAt: true, reviewedBy: true, reviewedAt: true, reviewComment: true, timestamp: true } });
    if (focusedRecord) context += `\nFOCUSED AUTHORIZED RECORD:\n${JSON.stringify(focusedRecord)}`;
  }
  try {
    const answer = await askGemini(req.user!.role === ROLES.SUPERVISOR ? supervisorSystemPrompt : operatorSystemPrompt, context, history, parsed.data.message);
    await prisma.message.createMany({ data: [{ conversationId: conversation.id, sender: 'USER', content: parsed.data.message }, { conversationId: conversation.id, sender: 'ASSISTANT', content: answer }] });
    res.json({ message: answer, conversationId: conversation.id, role: req.user!.role });
  } catch (error) {
    res.status(503).json({ error: error instanceof Error ? error.message : 'AI Assistant is temporarily unavailable. You can continue using FieldVerify normally.' });
  }
  } catch (error) {
    if (!res.headersSent) res.status(503).json({ error: 'AI Assistant is temporarily unavailable. You can continue using FieldVerify normally.' });
  }
});
app.get('/api/dashboard/stats', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const records = await prisma.testRecord.findMany({ where: req.user!.role === ROLES.SUPERVISOR ? {} : { operatorId: req.user!.operatorId } });
  const today = new Date().toDateString();
  type DashboardRecord = { result: string; timestamp: Date; verificationStatus: string };
  const typedRecords = records as DashboardRecord[];
  res.json({ total: typedRecords.length, positive: typedRecords.filter((r) => r.result === 'POSITIVE').length, negative: typedRecords.filter((r) => r.result === 'NEGATIVE').length, inconclusive: typedRecords.filter((r) => r.result === 'INCONCLUSIVE').length, today: typedRecords.filter((r) => r.timestamp.toDateString() === today).length, verified: typedRecords.filter((r) => r.verificationStatus === 'VERIFIED').length });
});

app.get('/api/supervisor/analytics', authenticateUser, requireRole(ROLES.SUPERVISOR), async (_req, res) => {
  const records = await prisma.testRecord.findMany({ select: { result: true, operatorId: true, reviewStatus: true, verificationStatus: true, timestamp: true } });
  const byOperator = records.reduce<Record<string, number>>((acc, record) => { acc[record.operatorId] = (acc[record.operatorId] ?? 0) + 1; return acc; }, {});
  const byDay = records.reduce<Record<string, number>>((acc, record) => { const day = record.timestamp.toISOString().slice(0, 10); acc[day] = (acc[day] ?? 0) + 1; return acc; }, {});
  res.json({ total: records.length, results: { positive: records.filter((r) => r.result === 'POSITIVE').length, negative: records.filter((r) => r.result === 'NEGATIVE').length, inconclusive: records.filter((r) => r.result === 'INCONCLUSIVE').length }, review: { pending: records.filter((r) => r.reviewStatus === 'PENDING').length, approved: records.filter((r) => r.reviewStatus === 'APPROVED').length, rejected: records.filter((r) => r.reviewStatus === 'REJECTED').length }, verificationExceptions: records.filter((r) => r.verificationStatus !== 'VERIFIED').length, byOperator, byDay });
});

app.get('/api/supervisor/activity', authenticateUser, requirePermission('VIEW_ALL_ACTIVITY'), async (_req, res) => {
  const logs = await prisma.auditLog.findMany({ include: { user: { select: { operatorId: true, name: true, role: true } } }, orderBy: { timestamp: 'desc' }, take: 100 });
  res.json(logs.map((log) => ({ ...log, metadata: JSON.parse(log.metadata) })));
});
app.get('/api/activity', authenticateUser, requirePermission('VIEW_OWN_ACTIVITY'), async (req: AuthenticatedRequest, res) => {
  const logs = await prisma.auditLog.findMany({ where: { userId: req.user!.id }, include: { user: { select: { operatorId: true, name: true, role: true } } }, orderBy: { timestamp: 'desc' }, take: 200 });
  res.json(logs.map((log) => ({ ...log, metadata: JSON.parse(log.metadata) })));
});

app.get('/api/supervisor/reviews', authenticateUser, requirePermission('REVIEW_TEST'), async (_req, res) => {
  const records = await prisma.testRecord.findMany({ where: { reviewStatus: 'PENDING' }, include: { auditEvents: true }, orderBy: { timestamp: 'desc' } });
  res.json(records.map(publicRecord));
});

async function reviewRecord(req: AuthenticatedRequest, res: express.Response, status: 'APPROVED' | 'REJECTED') {
  const parsed = z.object({ reviewComment: z.string().max(1000).default('') }).safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'Review comment is invalid.' });
  const record = await findRecord(req);
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  if (record.reviewStatus !== 'PENDING') return res.status(409).json({ error: 'This record has already been reviewed.' });
  const imageFile = record.imagePath ? path.join(uploadDirectory, path.basename(record.imagePath)) : '';
  const imageHashValid = Boolean(imageFile && fs.existsSync(imageFile) && hashBytes(fs.readFileSync(imageFile)) === record.imageHash);
  if (!record.digitalSignature || !imageHashValid || !verifySignature(record, record.digitalSignature)) return res.status(409).json({ error: 'Record integrity must be valid before review.' });
  const updated = await prisma.testRecord.update({ where: { id: record.id }, data: { reviewStatus: status, reviewedBy: req.user!.operatorId, reviewedAt: new Date(), reviewComment: parsed.data.reviewComment } });
  await writeAudit(status === 'APPROVED' ? 'RECORD_APPROVED' : 'RECORD_REJECTED', req.user!.id, record.testId, { reviewComment: parsed.data.reviewComment });
  await addAudit(status === 'APPROVED' ? 'RECORD_APPROVED' : 'RECORD_REJECTED', record.testId, req.user!.operatorId);
  return res.json(publicRecord(updated));
}
app.post('/api/supervisor/tests/:id/approve', authenticateUser, requirePermission('APPROVE_TEST'), (req: AuthenticatedRequest, res) => reviewRecord(req, res, 'APPROVED'));
app.post('/api/supervisor/tests/:id/reject', authenticateUser, requirePermission('REJECT_TEST'), (req: AuthenticatedRequest, res) => reviewRecord(req, res, 'REJECTED'));

app.get('/api/supervisor/exceptions', authenticateUser, requirePermission('MANAGE_VERIFICATION_EXCEPTIONS'), async (_req, res) => {
  const exceptions = await prisma.verificationException.findMany({ include: { record: true, creator: { select: { operatorId: true, name: true } } }, orderBy: { createdAt: 'desc' } });
  res.json(exceptions);
});
app.post('/api/supervisor/exceptions', authenticateUser, requirePermission('MANAGE_VERIFICATION_EXCEPTIONS'), async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ testId: z.string(), reason: z.string().min(3) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Exception reason is required.' });
  const record = await prisma.testRecord.findUnique({ where: { testId: parsed.data.testId } });
  if (!record) return res.status(404).json({ error: 'Test record not found.' });
  const exception = await prisma.verificationException.create({ data: { testId: parsed.data.testId, createdBy: req.user!.operatorId, reason: parsed.data.reason } });
  await writeAudit('EXCEPTION_CREATED', req.user!.id, parsed.data.testId, { reason: parsed.data.reason });
  res.status(201).json(exception);
});
app.put('/api/supervisor/exceptions/:id', authenticateUser, requirePermission('MANAGE_VERIFICATION_EXCEPTIONS'), async (req: AuthenticatedRequest, res) => {
  const parsed = z.object({ status: z.enum(['OPEN', 'UNDER_REVIEW', 'RESOLVED', 'DISMISSED']), resolution: z.string().max(1000).optional(), description: z.string().max(2000).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Exception update is invalid.' });
  const exception = await prisma.verificationException.update({ where: { id: String(req.params.id) }, data: { ...parsed.data, resolvedBy: ['RESOLVED', 'DISMISSED'].includes(parsed.data.status) ? req.user!.operatorId : null, resolvedAt: ['RESOLVED', 'DISMISSED'].includes(parsed.data.status) ? new Date() : null } });
  await writeAudit(parsed.data.status === 'RESOLVED' ? 'REPORT_RESOLVED' : parsed.data.status === 'DISMISSED' ? 'REPORT_DISMISSED' : 'REPORT_ASSIGNED', req.user!.id, exception.testId, { resolution: parsed.data.resolution ?? '', status: parsed.data.status });
  res.json(exception);
});

app.get('/api/supervisor/audit', authenticateUser, requirePermission('VIEW_AUDIT_TRAIL'), async (req: AuthenticatedRequest, res) => {
  const logs = await prisma.auditLog.findMany({ where: { ...(req.query.eventType ? { eventType: String(req.query.eventType) } : {}) }, include: { user: { select: { operatorId: true, name: true, role: true } } }, orderBy: { timestamp: 'desc' }, take: 500 });
  res.json(logs.map((log) => ({ ...log, metadata: JSON.parse(log.metadata) })));
});
app.get('/api/supervisor/export', authenticateUser, requirePermission('EXPORT_AUDIT_REPORTS'), async (req: AuthenticatedRequest, res) => {
  const records = await prisma.testRecord.findMany({ include: { auditEvents: true }, orderBy: { timestamp: 'desc' } });
  const header = 'Test ID,Timestamp,Operator,Result,Confidence,Latitude,Longitude,Image Hash,Digital Signature,Verification Status,Review Status,Reviewer,Audit Events';
  const rows = records.map((record) => [record.testId, record.timestamp.toISOString(), record.operatorId, record.result, record.confidence, record.latitude, record.longitude, record.imageHash, record.digitalSignature, record.verificationStatus, record.reviewStatus, record.reviewedBy ?? '', record.auditEvents.map((event) => event.event).join('|')].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','));
  await writeAudit('REPORT_EXPORTED', req.user!.id, undefined, { format: 'csv', records: records.length });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="fieldverify-audit-report.csv"');
  res.send([header, ...rows].join('\n'));
});

app.get('/uploads/:filename', authenticateUser, async (req: AuthenticatedRequest, res) => {
  const filename = path.basename(String(req.params.filename));
  const record = await prisma.testRecord.findFirst({ where: { imagePath: `/uploads/${filename}` }, select: { operatorId: true } });
  if (!record || !canAccessRecord(req, record.operatorId)) return res.status(404).json({ error: 'Image not found.' });
  const filePath = path.join(uploadDirectory, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Image not found.' });
  res.sendFile(filePath);
});

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (error instanceof MulterError) {
    const message = error.code === 'LIMIT_FILE_SIZE' ? 'Image files must be 8 MB or smaller.' : 'Invalid image upload.';
    return res.status(400).json({ error: message });
  }
  console.error('FieldVerify request failed:', error instanceof Error ? error.message : 'Unknown error');
  if (!res.headersSent) res.status(500).json({ error: 'An unexpected server error occurred.' });
});

// Serve built React frontend in production
if (config.isProduction) {
  const clientDist = path.resolve(process.cwd(), '../client/dist');
  app.use(express.static(clientDist));
  app.use((_req: express.Request, res: express.Response) => res.sendFile(path.join(clientDist, 'index.html')));
}

app.listen(config.port, () => console.log(`FieldVerify API listening on http://localhost:${config.port}`));
