import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { FastifyReply } from 'fastify';

const { prismaMock, txMock } = vi.hoisted(() => {
  const txMock = {
    user: { update: vi.fn() },
    session: { updateMany: vi.fn(), create: vi.fn() }
  };
  const prismaMock = {
    $transaction: vi.fn(),
    session: { updateMany: vi.fn(), create: vi.fn() }
  };
  return { prismaMock, txMock };
});

vi.mock('./prisma.js', () => ({ prisma: prismaMock }));

import { createSession, rotatePasswordAndSession, SESSION_COOKIE } from './auth.js';

function fakeReply() {
  const reply = { setCookie: vi.fn(), clearCookie: vi.fn() };
  return reply as unknown as FastifyReply & { setCookie: typeof reply.setCookie };
}

describe('session rotation atomicity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // 模拟 Prisma 交互式事务：回调内的写操作都走 tx 客户端，整体提交或整体回滚
    prismaMock.$transaction.mockImplementation((callback: (tx: typeof txMock) => Promise<unknown>) =>
      callback(txMock)
    );
  });

  it('commits password change, revocation and new session in one transaction', async () => {
    const reply = fakeReply();

    await rotatePasswordAndSession('user-1', 'new-password-hash', reply);

    expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
    expect(txMock.user.update).toHaveBeenCalledWith({
      where: { id: 'user-1' },
      data: { passwordHash: 'new-password-hash' }
    });
    expect(txMock.session.updateMany).toHaveBeenCalledWith({
      where: { userId: 'user-1', revokedAt: null },
      data: { revokedAt: expect.any(Date) }
    });
    expect(txMock.session.create).toHaveBeenCalledTimes(1);
    // 所有写操作都必须发生在事务客户端上，不允许绕过事务直接写库
    expect(prismaMock.session.updateMany).not.toHaveBeenCalled();
    expect(prismaMock.session.create).not.toHaveBeenCalled();
    // 事务提交成功后才下发新会话 Cookie
    expect(reply.setCookie).toHaveBeenCalledTimes(1);
    expect(reply.setCookie.mock.calls[0]?.[0]).toBe(SESSION_COOKIE);
    expect(reply.setCookie.mock.calls[0]?.[1]).toEqual(expect.any(String));
  });

  it('sets no cookie and propagates the error when the transaction fails, leaving old state intact for retry', async () => {
    txMock.session.create.mockRejectedValueOnce(new Error('db write failed'));
    const reply = fakeReply();

    await expect(rotatePasswordAndSession('user-1', 'new-password-hash', reply)).rejects.toThrow(
      'db write failed'
    );

    // 失败时不得下发新 Cookie：客户端仍持有有效旧会话，可用原凭据直接重试
    expect(reply.setCookie).not.toHaveBeenCalled();
  });

  it('revokes other sessions and creates the new one atomically in createSession', async () => {
    const reply = fakeReply();

    await createSession('user-1', reply, true);

    expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
    expect(txMock.session.updateMany).toHaveBeenCalledTimes(1);
    expect(txMock.session.create).toHaveBeenCalledTimes(1);
    expect(reply.setCookie).toHaveBeenCalledTimes(1);
  });

  it('does not revoke anything when createSession is not rotating', async () => {
    const reply = fakeReply();

    await createSession('user-1', reply);

    expect(txMock.session.updateMany).not.toHaveBeenCalled();
    expect(txMock.session.create).toHaveBeenCalledTimes(1);
  });
});
