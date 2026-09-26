import { createHash } from 'node:crypto';
import type { FastifyReply } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

interface FakeUser {
  id: string;
  passwordHash: string;
}

interface FakeSession {
  id: string;
  userId: string;
  tokenHash: string;
  revokedAt: Date | null;
}

interface FakeStore {
  users: Map<string, FakeUser>;
  sessions: Map<string, FakeSession>;
}

type FailStep = 'user.update' | 'session.updateMany' | 'session.create';

// 有状态的 Prisma 假实现：$transaction 先在暂存副本上执行回调，回调成功才
// 替换主存储（提交），抛错则丢弃（回滚），以此验证密码修改与会话轮换的原子性。
// 注意假实现只暴露 $transaction 和 session.create——被测代码若绕过事务直接写库
// （例如 prisma.user.update）会立刻 TypeError，从结构上保证所有写都在事务内。
const fake = vi.hoisted(() => {
  function cloneStore(store: FakeStore): FakeStore {
    return { users: new Map(store.users), sessions: new Map(store.sessions) };
  }

  function createFakePrisma() {
    let store: FakeStore = { users: new Map(), sessions: new Map() };
    let failStep: FailStep | null = null;
    let sessionSeq = 0;
    const events: string[] = [];

    // 只失败一次，模拟瞬时故障，之后调用应能成功（可重试）。
    const maybeFail = (step: FailStep): void => {
      if (failStep === step) {
        failStep = null;
        throw new Error(`db failure at ${step}`);
      }
    };

    const applySessionCreate = (
      target: FakeStore,
      data: { userId: string; tokenHash: string; expiresAt: Date }
    ): FakeSession => {
      sessionSeq += 1;
      const session: FakeSession = {
        id: `session-${sessionSeq}`,
        userId: data.userId,
        tokenHash: data.tokenHash,
        revokedAt: null
      };
      target.sessions.set(session.id, session);
      return session;
    };

    const makeTx = (staging: FakeStore) => ({
      user: {
        update: async (args: { where: { id: string }; data: { passwordHash: string } }) => {
          events.push('user.update');
          maybeFail('user.update');
          const user = staging.users.get(args.where.id);
          if (!user) throw new Error('user not found');
          staging.users.set(args.where.id, { ...user, passwordHash: args.data.passwordHash });
          return user;
        }
      },
      session: {
        updateMany: async (args: { where: { userId: string }; data: { revokedAt: Date } }) => {
          events.push('session.updateMany');
          maybeFail('session.updateMany');
          let count = 0;
          for (const [id, session] of staging.sessions) {
            if (session.userId === args.where.userId && session.revokedAt === null) {
              staging.sessions.set(id, { ...session, revokedAt: args.data.revokedAt });
              count += 1;
            }
          }
          return { count };
        },
        create: async (args: { data: { userId: string; tokenHash: string; expiresAt: Date } }) => {
          events.push('session.create');
          maybeFail('session.create');
          return applySessionCreate(staging, args.data);
        }
      }
    });

    return {
      $transaction: async <T>(callback: (tx: ReturnType<typeof makeTx>) => Promise<T>): Promise<T> => {
        const staging = cloneStore(store);
        const result = await callback(makeTx(staging));
        store = staging;
        return result;
      },
      session: {
        create: async (args: { data: { userId: string; tokenHash: string; expiresAt: Date } }) => {
          events.push('session.create');
          maybeFail('session.create');
          return applySessionCreate(store, args.data);
        }
      },
      get data(): FakeStore {
        return store;
      },
      get events(): string[] {
        return events;
      },
      failNextAt(step: FailStep): void {
        failStep = step;
      },
      seed(user: FakeUser, sessions: FakeSession[]): void {
        store.users.set(user.id, user);
        for (const session of sessions) store.sessions.set(session.id, session);
      },
      reset(): void {
        store = { users: new Map(), sessions: new Map() };
        events.length = 0;
        failStep = null;
        sessionSeq = 0;
      }
    };
  }

  return { prisma: createFakePrisma() };
});

vi.mock('./prisma.js', () => ({ prisma: fake.prisma }));
vi.mock('../config/env.js', () => ({
  env: { SESSION_TTL_DAYS: 30, COOKIE_SECURE: false }
}));

import { SESSION_COOKIE, changePasswordAndRotateSessions, createSession } from './auth.js';

const USER_ID = 'user-1';

interface CookieCall {
  name: string;
  value: string;
}

function createReply(): { reply: FastifyReply; cookies: CookieCall[] } {
  const cookies: CookieCall[] = [];
  const reply = {
    setCookie(name: string, value: string) {
      cookies.push({ name, value });
      return reply;
    }
  };
  return { reply: reply as unknown as FastifyReply, cookies };
}

function seedUser(): void {
  fake.prisma.seed({ id: USER_ID, passwordHash: 'old-hash' }, [
    { id: 'current-device', userId: USER_ID, tokenHash: 'hash-current', revokedAt: null },
    { id: 'other-device', userId: USER_ID, tokenHash: 'hash-other', revokedAt: null }
  ]);
}

function activeSessions(): FakeSession[] {
  return [...fake.prisma.data.sessions.values()].filter((session) => session.revokedAt === null);
}

describe('changePasswordAndRotateSessions', () => {
  beforeEach(() => {
    fake.prisma.reset();
    seedUser();
  });

  it('在同一事务中更新密码、作废旧会话并签发新会话', async () => {
    const { reply, cookies } = createReply();

    await changePasswordAndRotateSessions(USER_ID, 'new-hash', reply);

    expect(fake.prisma.events).toEqual(['user.update', 'session.updateMany', 'session.create']);
    expect(fake.prisma.data.users.get(USER_ID)?.passwordHash).toBe('new-hash');
    expect(fake.prisma.data.sessions.get('current-device')?.revokedAt).toBeInstanceOf(Date);
    expect(fake.prisma.data.sessions.get('other-device')?.revokedAt).toBeInstanceOf(Date);

    const active = activeSessions();
    expect(active).toHaveLength(1);
    expect(active[0]?.userId).toBe(USER_ID);

    expect(cookies).toHaveLength(1);
    expect(cookies[0]?.name).toBe(SESSION_COOKIE);
    // Cookie 中的令牌必须正好对应事务里创建的那条新会话。
    const tokenHash = createHash('sha256').update(cookies[0]?.value ?? '').digest('hex');
    expect(active[0]?.tokenHash).toBe(tokenHash);
  });

  it.each(['session.create', 'session.updateMany', 'user.update'] as const)(
    '在 %s 失败时整体回滚：旧密码与旧会话保持有效，且不写 Cookie',
    async (step) => {
      const { reply, cookies } = createReply();
      fake.prisma.failNextAt(step);

      await expect(changePasswordAndRotateSessions(USER_ID, 'new-hash', reply)).rejects.toThrow(
        `db failure at ${step}`
      );

      expect(fake.prisma.data.users.get(USER_ID)?.passwordHash).toBe('old-hash');
      expect(fake.prisma.data.sessions.get('current-device')?.revokedAt).toBeNull();
      expect(fake.prisma.data.sessions.get('other-device')?.revokedAt).toBeNull();
      expect(fake.prisma.data.sessions.size).toBe(2);
      expect(cookies).toHaveLength(0);
    }
  );

  it('失败后重试可以恢复，不留半完成状态', async () => {
    const first = createReply();
    fake.prisma.failNextAt('session.create');
    await expect(changePasswordAndRotateSessions(USER_ID, 'new-hash', first.reply)).rejects.toThrow();

    const second = createReply();
    await changePasswordAndRotateSessions(USER_ID, 'new-hash', second.reply);

    expect(fake.prisma.data.users.get(USER_ID)?.passwordHash).toBe('new-hash');
    const active = activeSessions();
    expect(active).toHaveLength(1);
    expect(second.cookies).toHaveLength(1);
    const tokenHash = createHash('sha256').update(second.cookies[0]?.value ?? '').digest('hex');
    expect(active[0]?.tokenHash).toBe(tokenHash);
  });
});

describe('createSession', () => {
  beforeEach(() => {
    fake.prisma.reset();
    seedUser();
  });

  it('只追加新会话，不作废已有会话（登录/注册路径）', async () => {
    const { reply, cookies } = createReply();

    await createSession(USER_ID, reply);

    expect(fake.prisma.events).toEqual(['session.create']);
    expect(activeSessions()).toHaveLength(3);
    expect(cookies).toHaveLength(1);
    expect(cookies[0]?.name).toBe(SESSION_COOKIE);
  });
});
