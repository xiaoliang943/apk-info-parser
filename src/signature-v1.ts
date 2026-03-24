/**
 * V1 (JAR) signature parsing.
 *
 * Looks for META-INF/*.{RSA,DSA,EC} files in the ZIP, parses PKCS#7
 * ContentInfo/SignedData, and extracts X.509 certificates.
 */
import type AdmZip from 'adm-zip';
import forge from 'node-forge';
import { certToCertificateInfo } from './certificate.js';
import type { CertificateInfo, Signature } from './types.js';

/**
 * Extract V1 signature from the APK zip archive.
 * Returns `{ type: 'unknown' }` if no signature file is found.
 */
export function getSignatureV1(zip: AdmZip): Signature {
  // Find META-INF/*.RSA, *.DSA, or *.EC
  const entries = zip.getEntries();
  const sigEntry = entries.find((e) => {
    const name = e.entryName;
    return (
      name.startsWith('META-INF/') &&
      (name.endsWith('.RSA') ||
        name.endsWith('.DSA') ||
        name.endsWith('.EC'))
    );
  });

  if (!sigEntry) {
    return { type: 'unknown' };
  }

  const data = zip.readFile(sigEntry);
  if (!data || data.length === 0) {
    return { type: 'unknown' };
  }

  try {
    const certificates = parsePkcs7Certificates(data);
    if (certificates.length === 0) {
      return { type: 'unknown' };
    }
    return { type: 'v1', certificates };
  } catch {
    return { type: 'unknown' };
  }
}

/**
 * Parse PKCS#7 DER data and extract X.509 certificates.
 *
 */
function parsePkcs7Certificates(derData: Buffer): CertificateInfo[] {
  const binaryStr = forge.util.binary.raw.encode(new Uint8Array(derData));
  const asn1 = forge.asn1.fromDer(binaryStr);
  const msg = forge.pkcs7.messageFromAsn1(asn1);

  // The message should be a signed-data content info
  const certs = (msg as forge.pkcs7.PkcsSignedData).certificates;
  if (!certs || certs.length === 0) {
    return [];
  }

  const results: CertificateInfo[] = [];
  for (const cert of certs) {
    try {
      // Re-encode the certificate to DER to compute fingerprints
      const certAsn1 = forge.pki.certificateToAsn1(cert);
      const certDer = forge.asn1.toDer(certAsn1);
      const certDerBuffer = Buffer.from(certDer.getBytes(), 'binary');
      results.push(certToCertificateInfo(cert, certDerBuffer));
    } catch {
      // Skip certificates that fail to re-encode
    }
  }

  return results;
}
