/**
 * Converts an X.509 certificate (node-forge or raw DER) into a CertificateInfo.
 */
import crypto from 'node:crypto';
import forge from 'node-forge';
import type { CertificateInfo } from './types.js';

/**
 * Convert a node-forge certificate object + its DER bytes into CertificateInfo.
 */
export function certToCertificateInfo(
  cert: forge.pki.Certificate,
  derBytes: Buffer,
): CertificateInfo {
  return {
    serialNumber: cert.serialNumber,
    subject: dnToString(cert.subject.attributes),
    issuer: dnToString(cert.issuer.attributes),
    validFrom: cert.validity.notBefore.toISOString(),
    validUntil: cert.validity.notAfter.toISOString(),
    signatureType: forge.pki.oids[cert.signatureOid] ?? cert.signatureOid,
    md5Fingerprint: fingerprint(derBytes, 'md5'),
    sha1Fingerprint: fingerprint(derBytes, 'sha1'),
    sha256Fingerprint: fingerprint(derBytes, 'sha256'),
  };
}

/**
 * Parse DER-encoded X.509 certificate bytes into a CertificateInfo.
 * Returns null if parsing fails.
 */
export function parseDerCertificate(der: Buffer): CertificateInfo | null {
  try {
    const binaryStr = forge.util.binary.raw.encode(new Uint8Array(der));
    const asn1 = forge.asn1.fromDer(binaryStr);
    const cert = forge.pki.certificateFromAsn1(asn1);
    return certToCertificateInfo(cert, der);
  } catch {
    return null;
  }
}

/**
 * Convert a forge Distinguished Name to a readable string.
 * Mimics the format used by the Rust x509_cert crate's Display impl.
 */
function dnToString(attrs: forge.pki.CertificateField[]): string {
  // node-forge stores attributes in an array of objects
  // We want to produce something like: "CN=foo, O=bar, C=US"
  return attrs
    .map((attr) => {
      const name = attr.shortName ?? attr.name ?? attr.type;
      const value = attr.value;
      return `${name}=${value}`;
    })
    .join(', ');
}

/**
 * Compute a hex fingerprint using the given hash algorithm.
 */
function fingerprint(
  derBytes: Buffer,
  algorithm: 'md5' | 'sha1' | 'sha256',
): string {
  return crypto.createHash(algorithm).update(derBytes).digest('hex');
}
