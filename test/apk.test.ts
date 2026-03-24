import { describe, expect, it, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { APK } from '../src/apk.js';
import type { Signature, CertificateInfo } from '../src/types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.join(__dirname, 'fixtures');

// Ensure fixtures exist before running tests
beforeAll(() => {
  if (
    !fs.existsSync(path.join(FIXTURE_DIR, 'test-v1.apk')) ||
    !fs.existsSync(path.join(FIXTURE_DIR, 'test-v1v2.apk'))
  ) {
    throw new Error(
      'Test fixtures not found.',
    );
  }
});

describe('APK - manifest info', () => {
  it('extracts manifest info from APK', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const manifestInfo = apk.getManifestInfo();
    expect(manifestInfo.package).toBe('apk.info.test');
    expect(manifestInfo.versionCode).toBe(1);
    expect(manifestInfo.versionName).toBe('1.0');
  });

  it('extracts SDK version info', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const manifestInfo = apk.getManifestInfo();
    expect(manifestInfo.minSdkVersion).toBeDefined();
    expect(manifestInfo.targetSdkVersion).toBeDefined();
  });

  it('extracts permissions array', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const manifestInfo = apk.getManifestInfo();
    expect(Array.isArray(manifestInfo.permissions)).toBe(true);
  });

  it('extracts receivers array', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const manifestInfo = apk.getManifestInfo();
    expect(Array.isArray(manifestInfo.receivers)).toBe(true);
  });

  it('throws error for missing AndroidManifest.xml', async () => {
    const AdmZip = (await import('adm-zip')).default;
    const zip = new AdmZip();
    zip.addFile('test.txt', Buffer.from('test'));
    const buf = zip.toBuffer();

    const apk = new APK(buf);
    expect(() => apk.getManifestInfo()).toThrow('AndroidManifest.xml not found');
  });
});

describe('APK - resources', () => {
  it('extracts resources from APK', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const resources = apk.getResources();
    const manifestInfo = apk.getManifestInfo();
    if (typeof manifestInfo.applicationLabel === 'number') {
      const resolved = resources.resolve(manifestInfo.applicationLabel);
      for (const resource of resolved) {
        expect(resource.value).toBe('apk-info-test');
      }
    }
    expect(resources).toBeDefined();
    expect(resources.table).toBeDefined();
  });

  it('throws error for missing resources.arsc', async () => {
    const AdmZip = (await import('adm-zip')).default;
    const zip = new AdmZip();
    zip.addFile('test.txt', Buffer.from('test'));
    const buf = zip.toBuffer();

    const apk = new APK(buf);
    expect(() => apk.getResources()).toThrow('resources.arsc not found');
  });
});

describe('APK - V1 signature', () => {
  it('extracts V1 signature from a signed APK', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const sigs = apk.getSignatures();

    // Should have at least V1
    const v1 = sigs.find((s) => s.type === 'v1');
    expect(v1).toBeDefined();
    expect(v1!.type).toBe('v1');

    if (v1!.type === 'v1') {
      expect(v1!.certificates.length).toBeGreaterThan(0);

      const cert = v1!.certificates[0];
      assertCertificateInfoShape(cert);

      expect(cert.subject).toContain('CN=apkinfo, OU=apkinfo, O=apkinfo');
      expect(cert.subject).toContain('O=apkinfo');
      expect(cert.subject).toContain('CN=apkinfo, OU=apkinfo, O=apkinfo');
      expect(cert.issuer).toContain('CN=apkinfo, OU=apkinfo, O=apkinfo');
      expect(cert.serialNumber).toBe('01');
      expect(cert.validFrom).toContain('2026');
      expect(cert.validUntil).toContain('2051');
      expect(cert.md5Fingerprint).toBe('5896b3260060f4d1a4bafc0ea4ca695a');
      expect(cert.sha1Fingerprint).toBe('4ad8e4ae44f507f767cef994e620da8d7d8fdea0');
      expect(cert.sha256Fingerprint).toBe('8e0072c820c01c32d9bf5723282e0f53a1a0dab16ae7cc6b0567395f40e8e639');
    }
  });

  it('returns V1 signature via getSignatureV1()', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const v1 = apk.getSignatureV1();

    expect(v1).not.toBeNull();
    expect(v1!.type).toBe('v1');
  });
});

describe('APK - V2 signature block', () => {
  it('extracts V2 signature from APK with signing block', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1v2.apk'));
    const sigs = apk.getSignatures();

    const v2 = sigs.find((s) => s.type === 'v2');
    expect(v2).toBeDefined();
    expect(v2!.type).toBe('v2');

    if (v2!.type === 'v2') {
      expect(v2!.certificates.length).toBeGreaterThan(0);

      const cert = v2!.certificates[0];
      assertCertificateInfoShape(cert);

      expect(cert.subject).toContain('CN=apkinfo, OU=apkinfo, O=apkinfo');
      expect(cert.serialNumber).toBe('01');
      expect(cert.md5Fingerprint).toBe('5896b3260060f4d1a4bafc0ea4ca695a');
      expect(cert.sha1Fingerprint).toBe('4ad8e4ae44f507f767cef994e620da8d7d8fdea0');
      expect(cert.sha256Fingerprint).toBe('8e0072c820c01c32d9bf5723282e0f53a1a0dab16ae7cc6b0567395f40e8e639');
    }
  });

  it('extracts both V1 and V2 signatures', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1v2.apk'));
    const sigs = apk.getSignatures();

    const types = sigs.map((s) => s.type);
    expect(types).toContain('v1');
    expect(types).toContain('v2');
  });

  it('returns V2 via getSignaturesFromBlock()', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1v2.apk'));
    const blockSigs = apk.getSignaturesFromBlock();

    expect(blockSigs.length).toBeGreaterThan(0);
    expect(blockSigs[0].type).toBe('v2');
  });
});

describe('APK - file operations', () => {
  it('lists file names in the APK', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const names = apk.getFileNames();

    expect(names).toContain('AndroidManifest.xml');
    expect(names).toContain('META-INF/CERT.RSA');
    expect(names).toContain('META-INF/MANIFEST.MF');
    expect(names).toContain('META-INF/CERT.SF');
  });

  it('reads a file from the APK', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const data = apk.readFile('AndroidManifest.xml');

    expect(data).not.toBeNull();
    expect(data!.length).toBeGreaterThan(0);
  });

  it('returns null for non-existent file', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const data = apk.readFile('does-not-exist.xml');
    expect(data).toBeNull();
  });
});

describe('APK - constructor', () => {
  it('accepts a file path', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    expect(apk.getFileNames().length).toBeGreaterThan(0);
  });

  it('accepts a Buffer', () => {
    const buf = fs.readFileSync(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const apk = new APK(buf);
    expect(apk.getFileNames().length).toBeGreaterThan(0);
  });
});

describe('APK - edge cases', () => {
  it('returns empty signatures for unsigned ZIP', async () => {
    // Create a ZIP with no META-INF and no signing block
    const AdmZip = (await import('adm-zip')).default;
    const zip = new AdmZip();
    zip.addFile('AndroidManifest.xml', Buffer.from('<manifest/>'));
    const buf = zip.toBuffer();

    const apk = new APK(buf);
    const sigs = apk.getSignatures();
    expect(sigs.length).toBe(0);
  });

  it('handles APK with only V1 signature gracefully', () => {
    const apk = new APK(path.join(FIXTURE_DIR, 'test-v1.apk'));
    const blockSigs = apk.getSignaturesFromBlock();
    // No signing block in V1-only APK
    expect(blockSigs.length).toBe(0);
  });
});

/**
 * Assert that a CertificateInfo has the expected shape with all fields populated.
 */
function assertCertificateInfoShape(cert: CertificateInfo) {
  expect(typeof cert.serialNumber).toBe('string');
  expect(cert.serialNumber.length).toBeGreaterThan(0);

  expect(typeof cert.subject).toBe('string');
  expect(cert.subject.length).toBeGreaterThan(0);

  expect(typeof cert.issuer).toBe('string');
  expect(cert.issuer.length).toBeGreaterThan(0);

  expect(typeof cert.validFrom).toBe('string');
  expect(cert.validFrom.length).toBeGreaterThan(0);

  expect(typeof cert.validUntil).toBe('string');
  expect(cert.validUntil.length).toBeGreaterThan(0);

  expect(typeof cert.signatureType).toBe('string');
  expect(cert.signatureType.length).toBeGreaterThan(0);

  // Fingerprints: hex strings of known lengths
  expect(cert.md5Fingerprint).toMatch(/^[0-9a-f]{32}$/);
  expect(cert.sha1Fingerprint).toMatch(/^[0-9a-f]{40}$/);
  expect(cert.sha256Fingerprint).toMatch(/^[0-9a-f]{64}$/);
}
