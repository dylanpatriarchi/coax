import { describe, expect, it } from 'vitest';
import { checkAuthorization, isLocalTarget } from './authorization.js';

describe('responsible-use gate', () => {
  it('treats file/module targets as local', () => {
    expect(isLocalTarget('./target.ts')).toBe(true);
    expect(isLocalTarget('mock')).toBe(true);
  });

  it('treats localhost URLs as local', () => {
    expect(isLocalTarget('http://localhost:11434/v1')).toBe(true);
    expect(isLocalTarget('http://127.0.0.1:8080')).toBe(true);
  });

  it('treats public URLs as remote', () => {
    expect(isLocalTarget('https://api.example.com')).toBe(false);
  });

  it('allows local targets without any flag', () => {
    expect(checkAuthorization({ target: 'mock' }).allowed).toBe(true);
  });

  it('blocks remote targets without acknowledgement', () => {
    const r = checkAuthorization({ target: 'https://api.example.com' });
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/authoriz/i);
  });

  it('allows remote targets with the flag or env acknowledgement', () => {
    expect(checkAuthorization({ target: 'https://api.example.com', flag: true }).allowed).toBe(true);
    expect(checkAuthorization({ target: 'https://api.example.com', env: 'true' }).allowed).toBe(true);
    expect(checkAuthorization({ target: 'https://api.example.com', env: 'nope' }).allowed).toBe(false);
  });
});
