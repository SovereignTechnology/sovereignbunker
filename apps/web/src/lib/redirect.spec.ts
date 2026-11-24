import { describe, it, expect } from 'vitest';
import { safeRedirectPath } from './redirect.js';

describe('safeRedirectPath', () => {
  it.each([
    '/approvals/abc_DEF-123',
    '/approvals',
    '/connections/clx1?tab=logs',
    '/dashboard#top',
  ])('keeps the in-app path %s', (path) => {
    expect(safeRedirectPath(path)).toBe(path);
  });

  it.each([
    ['another origin', 'https://evil.example/approvals'],
    ['a protocol-relative URL', '//evil.example/x'],
    ['a backslash read as a slash', '/\\evil.example'],
    ['a backslash anywhere', '/ok\\path'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a relative path', 'approvals'],
    ['an empty string', ''],
    ['a control character', '/approvals\n/x'],
    ['a NUL byte', '/approvals\u0000'],
    ['a path past the length bound', '/' + 'a'.repeat(600)],
    ['the login page (a loop)', '/login'],
    ['the login page with a query', '/login?redirect=/x'],
    ['the register page', '/register'],
    ['the 2fa step', '/2fa/verify'],
  ])('drops %s', (_name, value) => {
    expect(safeRedirectPath(value)).toBeUndefined();
  });

  it.each([undefined, null, 42, {}, ['/approvals']])('drops a non-string (%j)', (value) => {
    expect(safeRedirectPath(value)).toBeUndefined();
  });
});
