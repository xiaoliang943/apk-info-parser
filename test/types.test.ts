import { describe, expect, it } from 'vitest';
import { signatureName, type Signature } from '../src/types.js';

describe('signatureName', () => {
  it('returns correct name for v1', () => {
    const sig: Signature = { type: 'v1', certificates: [] };
    expect(signatureName(sig)).toBe('v1');
  });

  it('returns correct name for v2', () => {
    const sig: Signature = { type: 'v2', certificates: [] };
    expect(signatureName(sig)).toBe('v2');
  });

  it('returns correct name for v3', () => {
    const sig: Signature = { type: 'v3', certificates: [] };
    expect(signatureName(sig)).toBe('v3');
  });

  it('returns correct name for v31', () => {
    const sig: Signature = { type: 'v31', certificates: [] };
    expect(signatureName(sig)).toBe('v3.1');
  });

  it('returns correct name for unknown', () => {
    const sig: Signature = { type: 'unknown' };
    expect(signatureName(sig)).toBe('unknown');
  });
});
