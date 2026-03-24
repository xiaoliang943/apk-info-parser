/**
 * Represents detailed information about an APK signing certificate.
 */
export interface CertificateInfo {
  /** The serial number of the certificate. */
  serialNumber: string;

  /** The subject of the certificate (typically the entity that signed the APK). */
  subject: string;

  /** The issuer of the certificate. */
  issuer: string;

  /** The date and time when the certificate becomes valid. */
  validFrom: string;

  /** The date and time when the certificate expires. */
  validUntil: string;

  /** The type of signature algorithm used (e.g., RSA, ECDSA). */
  signatureType: string;

  /** MD5 fingerprint of the certificate. */
  md5Fingerprint: string;

  /** SHA-1 fingerprint of the certificate. */
  sha1Fingerprint: string;

  /** SHA-256 fingerprint of the certificate. */
  sha256Fingerprint: string;
}

/**
 * Describes used signature scheme in APK.
 */
export type Signature =
  | { type: 'v1'; certificates: CertificateInfo[] }
  | { type: 'v2'; certificates: CertificateInfo[] }
  | { type: 'v3'; certificates: CertificateInfo[] }
  | { type: 'v31'; certificates: CertificateInfo[] }
  | { type: 'unknown' };

/**
 * Returns a human-readable name for a Signature.
 */
export function signatureName(sig: Signature): string {
  switch (sig.type) {
    case 'v1':
      return 'v1';
    case 'v2':
      return 'v2';
    case 'v3':
      return 'v3';
    case 'v31':
      return 'v3.1';
    case 'unknown':
      return 'unknown';
  }
}
