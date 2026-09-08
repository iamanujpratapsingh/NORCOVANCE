import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { config } from './config.js';
import { prisma } from './prisma.js';

export const ROLES = { FIELD_OPERATOR: 'FIELD_OPERATOR', SUPERVISOR: 'SUPERVISOR' } as const;
export type Role = typeof ROLES[keyof typeof ROLES];

export const permissions = {
  FIELD_OPERATOR: ['VIEW_OWN_DASHBOARD', 'CREATE_TEST', 'ANALYZE_TEST', 'VIEW_OWN_TESTS', 'VIEW_OWN_ACTIVITY'],
  SUPERVISOR: ['VIEW_OWN_DASHBOARD', 'VIEW_OWN_TESTS', 'VIEW_ALL_TESTS', 'REVIEW_TEST', 'APPROVE_TEST', 'REJECT_TEST', 'VIEW_ALL_ACTIVITY', 'VIEW_ANALYTICS', 'MANAGE_VERIFICATION_EXCEPTIONS', 'EXPORT_AUDIT_REPORTS', 'VIEW_AUDIT_TRAIL', 'VERIFY_TEST']
} as const;

export type AuthUser = { id: string; operatorId: string; name: string; role: Role; isActive: boolean; sessionId: string };
export type AuthenticatedRequest = Request & { user?: AuthUser };

function hashToken(token: string) { return crypto.createHash('sha256').update(token).digest('hex'); }

export async function createSession(userId: string) {
  const token = crypto.randomBytes(32).toString('hex');
  await prisma.session.create({ data: { tokenHash: hashToken(token), userId, expiresAt: new Date(Date.now() + config.sessionDurationMs) } });
  return token;
}

export async function revokeSession(sessionId: string) {
  await prisma.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
}

export async function authenticateUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Please log in to continue.' });
  const session = await prisma.session.findUnique({ where: { tokenHash: hashToken(token) }, include: { user: true } });
  if (!session || session.revokedAt || session.expiresAt <= new Date()) return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
  if (!session.user.isActive) return res.status(403).json({ error: 'Your account is inactive. Contact a supervisor.' });
  if (session.user.role !== ROLES.FIELD_OPERATOR && session.user.role !== ROLES.SUPERVISOR) return res.status(403).json({ error: 'Your account role is not authorized.' });
  req.user = { id: session.user.id, operatorId: session.user.operatorId, name: session.user.name, role: session.user.role as Role, isActive: session.user.isActive, sessionId: session.id };
  return next();
}

export function requireRole(...allowedRoles: Role[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: 'Please log in to continue.' });
    if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    return next();
  };
}

export function requirePermission(permission: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ error: 'Please log in to continue.' });
    if (!(permissions[req.user.role] as readonly string[]).includes(permission)) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    return next();
  };
}

export async function writeAudit(eventType: string, userId: string, testId?: string, metadata: Record<string, unknown> = {}) {
  return prisma.auditLog.create({ data: { eventType, userId, testId, metadata: JSON.stringify(metadata) } });
}
