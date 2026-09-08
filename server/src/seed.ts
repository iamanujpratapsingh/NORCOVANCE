import bcrypt from 'bcryptjs';
import fs from 'node:fs';
import path from 'node:path';
import './config.js';
import { prisma } from './prisma.js';
import { hashBytes, signRecord } from './services/securityService.js';

async function main() {
  const uploadDirectory = path.resolve(process.cwd(), 'uploads');
  fs.mkdirSync(uploadDirectory, { recursive: true });
  const demoImage = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
  const operatorPasswordHash = await bcrypt.hash('demo123', 10);
  const supervisorPasswordHash = await bcrypt.hash('super123', 10);
  await prisma.user.upsert({ where: { operatorId: 'OP-1001' }, update: { passwordHash: operatorPasswordHash, role: 'FIELD_OPERATOR', isActive: true }, create: { operatorId: 'OP-1001', name: 'Aarav Mehta', role: 'FIELD_OPERATOR', passwordHash: operatorPasswordHash } });
  await prisma.user.upsert({ where: { operatorId: 'OP-1002' }, update: { passwordHash: operatorPasswordHash, role: 'FIELD_OPERATOR', isActive: true }, create: { operatorId: 'OP-1002', name: 'Mira Sen', role: 'FIELD_OPERATOR', passwordHash: operatorPasswordHash } });
  await prisma.user.upsert({ where: { operatorId: 'OP-1003' }, update: { passwordHash: operatorPasswordHash, role: 'FIELD_OPERATOR', isActive: true }, create: { operatorId: 'OP-1003', name: 'Kabir Das', role: 'FIELD_OPERATOR', passwordHash: operatorPasswordHash } });
  await prisma.user.upsert({ where: { operatorId: 'SUP-1001' }, update: { passwordHash: supervisorPasswordHash, role: 'SUPERVISOR', isActive: true }, create: { operatorId: 'SUP-1001', name: 'Nisha Rao', role: 'SUPERVISOR', passwordHash: supervisorPasswordHash } });
  const samples = [
    ['FT-2026-0001', 'POSITIVE', 0.94, 'OP-1001', 'Amber Marquis reagent'],
    ['FT-2026-0002', 'NEGATIVE', 0.91, 'OP-1001', 'Duquenois-Levine reagent'],
    ['FT-2026-0003', 'INCONCLUSIVE', 0.61, 'SUP-1001', 'Scott reagent'],
    ['FT-2026-0004', 'POSITIVE', 0.88, 'OP-1001', 'Marquis reagent'],
    ['FT-2026-0005', 'NEGATIVE', 0.89, 'OP-1002', 'Duquenois-Levine reagent'],
    ['FT-2026-0006', 'INCONCLUSIVE', 0.58, 'OP-1003', 'Scott reagent']
  ] as const;
  for (const [testId, result, confidence, operatorId, testType] of samples) {
    const exists = await prisma.testRecord.findUnique({ where: { testId } });
    if (exists) continue;
    const imageName = `demo-${testId}.png`;
    fs.writeFileSync(path.join(uploadDirectory, imageName), demoImage);
    const record = await prisma.testRecord.create({ data: { testId, operatorId, testType, sampleReference: `DEMO-${testId.slice(-4)}`, result, confidence, analysisData: JSON.stringify({ demo: true, explanation: 'Seeded demonstration record using fictional reference data.', averageRgb: { r: 198, g: 129, b: 75 }, hsv: { hue: 28, saturation: 0.62, brightness: 0.78 } }), imagePath: `/uploads/${imageName}`, imageHash: hashBytes(demoImage), timestamp: new Date(Date.now() - Number(testId.slice(-1)) * 86400000), latitude: 28.6139, longitude: 77.209, locationSource: 'DEMO', digitalSignature: '', verificationStatus: 'VERIFIED', reviewStatus: testId === 'FT-2026-0003' ? 'PENDING' : 'APPROVED', reviewedBy: testId === 'FT-2026-0003' ? null : 'SUP-1001', reviewedAt: testId === 'FT-2026-0003' ? null : new Date(), reviewComment: testId === 'FT-2026-0003' ? null : 'Seeded demo review.', notes: 'Seeded fictional demonstration record.' } });
    await prisma.testRecord.update({ where: { id: record.id }, data: { digitalSignature: signRecord(record), verificationStatus: 'VERIFIED' } });
    await prisma.auditEvent.create({ data: { event: 'TEST_CREATED', operator: operatorId, testId: record.testId } });
  }
  const demoReport = await prisma.verificationException.findFirst({ where: { testId: 'FT-2026-0003', reason: 'Verification issue' } });
  if (!demoReport) {
    await prisma.verificationException.create({ data: { testId: 'FT-2026-0003', createdBy: 'OP-1001', reason: 'Verification issue', description: 'DEMO: operator requests supervisor review of an inconclusive result.', priority: 'MEDIUM' } });
  }
}

main().finally(() => prisma.$disconnect());
