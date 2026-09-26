import { createHash, randomBytes } from 'node:crypto';
import { hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { env } from '../config/env.js';
import { prisma } from './prisma.js';
import { AppError } from './errors.js';

export const SESSION_COOKIE = 'pbt_session';

export interface AuthUser {
  id: string;
  email: string;
  createdAt: Date;
}

function tokenHash(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function hashPassword(password: string): Promise<string> {
  return argonHash(password, { algorithm: 2, memoryCost: 19456, timeCost: 2, parallelism: 1 });
}

export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await argonVerify(passwordHash, password);
  } catch {
    return false;
  }
}

function sessionExpiresAt(): Date {
  return new Date(Date.now() + env.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
}

function setSessionCookie(reply: FastifyReply, token: string): void {
  reply.setCookie(SESSION_COOKIE, token, {
    path: '/',
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: 'lax',
    maxAge: env.SESSION_TTL_DAYS * 24 * 60 * 60
  });
}

export async function createSession(
  userId: string,
  reply: FastifyReply,
  rotateOthers = false
): Promise<void> {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = sessionExpiresAt();
  await prisma.$transaction(async (tx) => {
    if (rotateOthers) {
      await tx.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() }
      });
    }
    await tx.session.create({
      data: { userId, tokenHash: tokenHash(token), expiresAt }
    });
  });
  setSessionCookie(reply, token);
}

/**
 * 修改密码并轮换会话：密码更新、吊销全部旧会话、签发新会话在同一事务中提交。
 * 任一步骤失败都会整体回滚——旧密码与旧会话保持不变，客户端可直接重试，
 * 不会出现"旧登录已失效、新会话未签发"的半完成状态。
 */
export async function rotatePasswordAndSession(
  userId: string,
  newPasswordHash: string,
  reply: FastifyReply
): Promise<void> {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = sessionExpiresAt();
  await prisma.$transaction(async (tx) => {
    await tx.user.update({
      where: { id: userId },
      data: { passwordHash: newPasswordHash }
    });
    await tx.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() }
    });
    await tx.session.create({
      data: { userId, tokenHash: tokenHash(token), expiresAt }
    });
  });
  // 事务提交成功后才下发新会话 Cookie；失败时客户端仍持有有效的旧会话
  setSessionCookie(reply, token);
}

export async function deleteCurrentSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = request.cookies[SESSION_COOKIE];
  if (token) {
    await prisma.session.updateMany({
      where: { tokenHash: tokenHash(token), revokedAt: null },
      data: { revokedAt: new Date() }
    });
  }
  reply.clearCookie(SESSION_COOKIE, { path: '/' });
}

export async function requireAuth(request: FastifyRequest): Promise<void> {
  const token = request.cookies[SESSION_COOKIE];
  if (!token) throw new AppError(401, 'UNAUTHENTICATED', '请先登录');
  const session = await prisma.session.findUnique({
    where: { tokenHash: tokenHash(token) },
    include: { user: true }
  });
  if (
    !session ||
    session.revokedAt ||
    session.expiresAt.getTime() <= Date.now() ||
    session.user.status !== 'ACTIVE' ||
    session.user.deletedAt
  ) {
    throw new AppError(401, 'UNAUTHENTICATED', '登录状态已失效');
  }

  request.authUser = {
    id: session.user.id,
    email: session.user.email,
    createdAt: session.user.createdAt
  };

  const now = Date.now();
  const rollingInterval = 24 * 60 * 60 * 1000;
  if (session.expiresAt.getTime() - now < env.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000 - rollingInterval) {
    const expiresAt = new Date(now + env.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
    await prisma.session.update({ where: { id: session.id }, data: { expiresAt } });
  }
}

export function currentUser(request: FastifyRequest): AuthUser {
  if (!request.authUser) throw new AppError(401, 'UNAUTHENTICATED', '请先登录');
  return request.authUser;
}
