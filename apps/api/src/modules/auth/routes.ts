import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma.js';
import { AppError, zodFields } from '../../lib/errors.js';
import {
  changePasswordAndRotateSessions,
  createSession,
  currentUser,
  deleteCurrentSession,
  hashPassword,
  requireAuth,
  verifyPassword
} from '../../lib/auth.js';

const credentialsSchema = z.object({
  email: z.string().trim().email('请输入有效邮箱').max(320),
  password: z.string().min(8, '密码至少 8 位').max(128)
});

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8, '新密码至少 8 位').max(128)
});

const deleteAccountSchema = z.object({
  password: z.string().min(1, '请输入密码')
});

function normalizeEmail(email: string): string {
  return email.normalize('NFC').trim().toLowerCase();
}

function publicUser(user: { id: string; email: string; createdAt: Date }) {
  return { id: user.id, email: user.email, createdAt: user.createdAt };
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    '/register',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '1 hour'
        }
      }
    },
    async (request, reply) => {
      const parsed = credentialsSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new AppError(422, 'VALIDATION_ERROR', '注册信息无效', zodFields(parsed.error));
      }
      const email = normalizeEmail(parsed.data.email);
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) throw new AppError(409, 'EMAIL_EXISTS', '该邮箱已注册');

      const user = await prisma.user.create({
        data: { email, passwordHash: await hashPassword(parsed.data.password) }
      });
      await createSession(user.id, reply);
      return reply.status(201).send({ user: publicUser(user) });
    }
  );

  app.post(
    '/login',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '15 minutes',
          keyGenerator: (request) => {
            const body = request.body as { email?: string } | undefined;
            return `${request.ip}:${String(body?.email ?? '').toLowerCase()}`;
          }
        }
      }
    },
    async (request, reply) => {
      const parsed = credentialsSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new AppError(401, 'INVALID_CREDENTIALS', '邮箱或密码错误');
      }
      const email = normalizeEmail(parsed.data.email);
      const user = await prisma.user.findUnique({ where: { email } });
      const valid = user ? await verifyPassword(user.passwordHash, parsed.data.password) : false;
      if (!user || !valid || user.status !== 'ACTIVE' || user.deletedAt) {
        throw new AppError(401, 'INVALID_CREDENTIALS', '邮箱或密码错误');
      }
      await createSession(user.id, reply);
      return { user: publicUser(user) };
    }
  );

  app.post('/logout', { preHandler: requireAuth }, async (request, reply) => {
    await deleteCurrentSession(request, reply);
    return reply.status(204).send();
  });

  app.get('/me', { preHandler: requireAuth }, async (request) => {
    return { user: currentUser(request) };
  });

  app.patch('/password', { preHandler: requireAuth }, async (request, reply) => {
    const parsed = passwordChangeSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(422, 'VALIDATION_ERROR', '密码信息无效', zodFields(parsed.error));
    }
    const authUser = currentUser(request);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: authUser.id } });
    const valid = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
    if (!valid) throw new AppError(422, 'INVALID_PASSWORD', '当前密码不正确');

    // 哈希计算耗时较长，先在事务外完成；密码更新与会话轮换由
    // changePasswordAndRotateSessions 在同一个事务中提交，失败可安全重试。
    const newPasswordHash = await hashPassword(parsed.data.newPassword);
    await changePasswordAndRotateSessions(authUser.id, newPasswordHash, reply);
    return { ok: true };
  });

  app.delete('/account', { preHandler: requireAuth }, async (request, reply) => {
    const parsed = deleteAccountSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(422, 'VALIDATION_ERROR', '请输入密码', zodFields(parsed.error));
    }
    const authUser = currentUser(request);
    const user = await prisma.user.findUniqueOrThrow({ where: { id: authUser.id } });
    if (!(await verifyPassword(user.passwordHash, parsed.data.password))) {
      throw new AppError(422, 'INVALID_PASSWORD', '密码不正确');
    }
    const now = new Date();
    await prisma.$transaction([
      prisma.session.updateMany({
        where: { userId: authUser.id, revokedAt: null },
        data: { revokedAt: now }
      }),
      prisma.user.update({
        where: { id: authUser.id },
        data: { status: 'DELETED', deletedAt: now }
      })
    ]);
    reply.clearCookie('pbt_session', { path: '/' });
    return reply.status(204).send();
  });
};
