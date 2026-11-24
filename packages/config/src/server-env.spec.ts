import { describe, it, expect } from 'vitest';
import { APPROVAL_CONSTANTS, NOSTR_CONSTANTS } from './constants.js';
import { deploymentWarnings, serverEnvSchema } from './server-env.js';

describe('serverEnvSchema', () => {
  const baseEnv = {
    DATABASE_URL: 'postgresql://localhost:5432/test',
    JWT_SECRET: 'a'.repeat(32),
    ENCRYPTION_KEY: 'b'.repeat(32),
  };

  describe('ALLOW_REGISTRATION', () => {
    it('defaults to true when omitted', () => {
      const result = serverEnvSchema.safeParse(baseEnv);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ALLOW_REGISTRATION).toBe(true);
      }
    });

    it('parses "true" as true', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ALLOW_REGISTRATION: 'true',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ALLOW_REGISTRATION).toBe(true);
      }
    });

    it('parses "false" as false', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ALLOW_REGISTRATION: 'false',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ALLOW_REGISTRATION).toBe(false);
      }
    });

    it('parses "0" as false', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ALLOW_REGISTRATION: '0',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ALLOW_REGISTRATION).toBe(false);
      }
    });

    it('parses other values as true', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ALLOW_REGISTRATION: '1',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ALLOW_REGISTRATION).toBe(true);
      }
    });
  });

  describe('production secret validation', () => {
    const strongSecrets = {
      JWT_SECRET: 'Vq8c3Jt0pN7xR2wL5kZ9bH4dM6sA1eF3gC8uY2nB7oP',
      JWT_REFRESH_SECRET: 'Zr4m9Kx2tQ7yW1aS6dG3hJ8bN5cV0fL2eR9pU4iO7kX',
      ENCRYPTION_KEY: 'Lp3n8Bx1qT6yV2aD7gH4jK9cM5sW0fR3eZ8uI2oN7bC',
    };

    it('accepts strong secrets in production', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ...strongSecrets,
        NODE_ENV: 'production',
      });
      expect(result.success).toBe(true);
    });

    it('rejects placeholder JWT_SECRET in production', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ...strongSecrets,
        NODE_ENV: 'production',
        JWT_SECRET: 'change-me-to-a-random-string-at-least-32-chars',
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path[0] === 'JWT_SECRET')).toBe(true);
      }
    });

    it('rejects placeholder ENCRYPTION_KEY in production', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ...strongSecrets,
        NODE_ENV: 'production',
        ENCRYPTION_KEY: 'change-me-to-a-secure-encryption-key-min-32',
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path[0] === 'ENCRYPTION_KEY')).toBe(true);
      }
    });

    it('rejects a single-repeated-character secret in production', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ...strongSecrets,
        NODE_ENV: 'production',
        JWT_SECRET: 'a'.repeat(40),
      });
      expect(result.success).toBe(false);
    });

    it('rejects a low-distinct-character secret (e.g. "abab…") in production', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        ...strongSecrets,
        NODE_ENV: 'production',
        ENCRYPTION_KEY: 'ab'.repeat(20), // 40 chars, only 2 distinct characters
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.path[0] === 'ENCRYPTION_KEY')).toBe(true);
      }
    });

    it('allows placeholder secrets outside production (development default)', () => {
      // baseEnv uses 'a'*32 / 'b'*32 and no NODE_ENV (=> development); must still pass.
      const result = serverEnvSchema.safeParse(baseEnv);
      expect(result.success).toBe(true);
    });
  });

  describe('NOSTR_DEFAULT_RELAYS', () => {
    it('defaults to built-in relays when omitted', () => {
      const result = serverEnvSchema.safeParse(baseEnv);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.NOSTR_DEFAULT_RELAYS).toEqual([...NOSTR_CONSTANTS.DEFAULT_RELAYS]);
      }
    });

    it('defaults to built-in when empty string', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        NOSTR_DEFAULT_RELAYS: '  ,  ',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.NOSTR_DEFAULT_RELAYS).toEqual([...NOSTR_CONSTANTS.DEFAULT_RELAYS]);
      }
    });

    it('parses comma-separated wss URLs', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        NOSTR_DEFAULT_RELAYS: 'wss://relay1.example.com, wss://relay2.example.com',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.NOSTR_DEFAULT_RELAYS).toEqual([
          'wss://relay1.example.com',
          'wss://relay2.example.com',
        ]);
      }
    });

    it('rejects invalid relay URLs', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        NOSTR_DEFAULT_RELAYS: 'not-a-url',
      });
      expect(result.success).toBe(false);
    });

    it('rejects ws:// (only wss allowed)', () => {
      const result = serverEnvSchema.safeParse({
        ...baseEnv,
        NOSTR_DEFAULT_RELAYS: 'ws://relay.example.com',
      });
      expect(result.success).toBe(false);
    });
  });
  describe('PUBLIC_BASE_URL', () => {
    const parse = (extra: Record<string, string>) =>
      serverEnvSchema.safeParse({ ...baseEnv, ...extra });

    it('is optional: unset and empty both mean no approval link', () => {
      for (const value of [undefined, '', '   ']) {
        const result = parse(value === undefined ? {} : { PUBLIC_BASE_URL: value });
        expect(result.success).toBe(true);
        if (result.success) expect(result.data.PUBLIC_BASE_URL).toBeUndefined();
      }
    });

    it('drops a trailing slash so links are built as base + /approvals/<token>', () => {
      const result = parse({ PUBLIC_BASE_URL: 'https://signer.example.test:50217/' });
      expect(result.success).toBe(true);
      if (result.success)
        expect(result.data.PUBLIC_BASE_URL).toBe('https://signer.example.test:50217');
    });

    it('accepts plain http only for this machine, and https anywhere', () => {
      for (const value of [
        'http://localhost:5173',
        'http://127.0.0.1:8080',
        'http://[::1]:8080',
        'https://[::1]:8443',
      ]) {
        const result = parse({ PUBLIC_BASE_URL: value });
        expect(result.success).toBe(true);
        if (result.success) expect(result.data.PUBLIC_BASE_URL).toBe(value);
      }
    });

    it('keeps a path prefix for a reverse proxy mounted under one', () => {
      const result = parse({ PUBLIC_BASE_URL: 'https://example.test/bunker' });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.PUBLIC_BASE_URL).toBe('https://example.test/bunker');
    });

    it.each([
      'ftp://example.test',
      'javascript:alert(1)',
      'https://user:pass@example.test',
      'https://example.test/?x=1',
      'https://example.test/#frag',
      'https://example.test?x=1',
      'https://example.test#frag',
      'https://@example.test',
      // The link carries the operator to a login page: plain http would let anyone on the path
      // swap it, so http is for this machine only.
      'http://example.test',
      'http://100.64.0.3:8080',
      'http://localhost.example.test',
      'http://localhost@evil.example',
      'not a url',
    ])('rejects %s', (value) => {
      expect(parse({ PUBLIC_BASE_URL: value }).success).toBe(false);
    });
  });

  describe('ASK_APPROVAL_TTL_MS', () => {
    const parse = (extra: Record<string, string>) =>
      serverEnvSchema.safeParse({ ...baseEnv, ...extra });

    it('defaults to 100 s, under the 240 s a BIES client waits', () => {
      const result = parse({});
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ASK_APPROVAL_TTL_MS).toBe(100_000);
        expect(result.data.ASK_APPROVAL_TTL_MS).toBe(APPROVAL_CONSTANTS.DEFAULT_TTL_MS);
      }
    });

    it('treats an empty value as unset', () => {
      const result = parse({ ASK_APPROVAL_TTL_MS: '' });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.ASK_APPROVAL_TTL_MS).toBe(100_000);
    });

    it('accepts a value in range', () => {
      const result = parse({ ASK_APPROVAL_TTL_MS: '30000' });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.ASK_APPROVAL_TTL_MS).toBe(30_000);
    });

    it.each(['1000', '250000', '-5', 'abc', '1.5'])('rejects %s', (value) => {
      expect(parse({ ASK_APPROVAL_TTL_MS: value }).success).toBe(false);
    });
  });
});

describe('deploymentWarnings', () => {
  it('warns when PUBLIC_BASE_URL is set but TRUST_PROXY is not: behind a proxy every caller shares one rate-limit bucket', () => {
    const warnings = deploymentWarnings({
      PUBLIC_BASE_URL: 'https://signer.example.test',
      TRUST_PROXY: false,
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('TRUST_PROXY');
  });

  it.each([
    [{ PUBLIC_BASE_URL: 'https://signer.example.test', TRUST_PROXY: true }],
    [{ PUBLIC_BASE_URL: undefined, TRUST_PROXY: false }],
  ])('says nothing for %j', (env) => {
    expect(deploymentWarnings(env)).toEqual([]);
  });
});
