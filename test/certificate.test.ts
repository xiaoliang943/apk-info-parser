import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { certToCertificateInfo, parseDerCertificate } from '../src/certificate.js';

/**
 * Helper: generate a self-signed X.509 certificate for testing.
 */
function generateTestCert(): {
  cert: forge.pki.Certificate;
  derBuffer: Buffer;
} {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2025-12-31T23:59:59Z');

  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: 'Test Signer' },
    { name: 'organizationName', value: 'Test Org' },
    { name: 'countryName', value: 'US' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certAsn1 = forge.pki.certificateToAsn1(cert);
  const certDer = forge.asn1.toDer(certAsn1);
  const derBuffer = Buffer.from(certDer.getBytes(), 'binary');

  return { cert, derBuffer };
}

describe('certToCertificateInfo', () => {
  it('extracts all fields from a certificate', () => {
    const { cert, derBuffer } = generateTestCert();
    const info = certToCertificateInfo(cert, derBuffer);

    expect(info.serialNumber).toBe('01');
    expect(info.subject).toContain('CN=Test Signer');
    expect(info.subject).toContain('O=Test Org');
    expect(info.subject).toContain('C=US');
    expect(info.issuer).toContain('CN=Test Signer');
    expect(info.validFrom).toContain('2024');
    expect(info.validUntil).toContain('2025');
    expect(info.signatureType).toBeTruthy();

    // Fingerprints should be hex strings of known lengths
    expect(info.md5Fingerprint).toMatch(/^[0-9a-f]{32}$/);
    expect(info.sha1Fingerprint).toMatch(/^[0-9a-f]{40}$/);
    expect(info.sha256Fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces consistent fingerprints for same input', () => {
    const { cert, derBuffer } = generateTestCert();
    const info1 = certToCertificateInfo(cert, derBuffer);
    const info2 = certToCertificateInfo(cert, derBuffer);

    expect(info1.md5Fingerprint).toBe(info2.md5Fingerprint);
    expect(info1.sha1Fingerprint).toBe(info2.sha1Fingerprint);
    expect(info1.sha256Fingerprint).toBe(info2.sha256Fingerprint);
  });
});

describe('parseDerCertificate', () => {
  it('parses a valid DER certificate', () => {
    const { derBuffer } = generateTestCert();
    const info = parseDerCertificate(derBuffer);

    expect(info).not.toBeNull();
    expect(info!.serialNumber).toBe('01');
    expect(info!.subject).toContain('CN=Test Signer');
  });

  it('returns null for invalid DER data', () => {
    const info = parseDerCertificate(Buffer.from([0x00, 0x01, 0x02]));
    expect(info).toBeNull();
  });

  it('returns null for empty buffer', () => {
    const info = parseDerCertificate(Buffer.alloc(0));
    expect(info).toBeNull();
  });
});
