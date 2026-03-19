/**
 * Script to generate a minimal signed APK for testing.
 *
 * Creates a tiny valid APK (just AndroidManifest.xml + META-INF/CERT.RSA)
 * signed with a V1 JAR signature using a self-signed certificate.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import AdmZip from 'adm-zip';
import forge from 'node-forge';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.join(__dirname, 'fixtures');

function generateKeyAndCert() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '0a1b2c3d';
  cert.validity.notBefore = new Date('2024-01-01T00:00:00Z');
  cert.validity.notAfter = new Date('2026-12-31T23:59:59Z');

  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: 'APK Test Signer' },
    { name: 'organizationName', value: 'Test Organization' },
    { name: 'countryName', value: 'US' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return { keys, cert };
}

function createSignedApk(): Buffer {
  const { keys, cert } = generateKeyAndCert();

  // Create a minimal AndroidManifest.xml (just some bytes for testing)
  const manifestContent = Buffer.from(
    '<?xml version="1.0" encoding="utf-8"?><manifest package="com.test.apk"/>',
  );

  // Create PKCS#7 signed data for META-INF/CERT.RSA
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestContent.toString('binary'));
  p7.addCertificate(cert);
  p7.addSigner({
    key: keys.privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
      },
    ],
  });
  p7.sign();

  const p7Asn1 = p7.toAsn1();
  const p7Der = forge.asn1.toDer(p7Asn1);
  const p7Buffer = Buffer.from(p7Der.getBytes(), 'binary');

  // Create a simple MANIFEST.MF
  const manifestMf =
    'Manifest-Version: 1.0\r\nCreated-By: apk-info test\r\n\r\n';

  // Create a simple CERT.SF
  const certSf =
    'Signature-Version: 1.0\r\nCreated-By: apk-info test\r\n\r\n';

  // Build the ZIP
  const zip = new AdmZip();
  zip.addFile('AndroidManifest.xml', manifestContent);
  zip.addFile('META-INF/MANIFEST.MF', Buffer.from(manifestMf));
  zip.addFile('META-INF/CERT.SF', Buffer.from(certSf));
  zip.addFile('META-INF/CERT.RSA', p7Buffer);

  return zip.toBuffer();
}

/**
 * Creates a signed APK with an APK Signature Block v2 injected.
 *
 * The APK Signing Block sits between the last ZIP entry and the Central Directory.
 * We manually construct the block and splice it into the ZIP.
 */
function createSignedApkWithV2Block(): Buffer {
  const { keys, cert } = generateKeyAndCert();

  // Create a minimal AndroidManifest.xml
  const manifestContent = Buffer.from(
    '<?xml version="1.0" encoding="utf-8"?><manifest package="com.test.apk.v2"/>',
  );

  // Build the base ZIP first (V1 signature + content)
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestContent.toString('binary'));
  p7.addCertificate(cert);
  p7.addSigner({
    key: keys.privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
      },
    ],
  });
  p7.sign();

  const p7Asn1 = p7.toAsn1();
  const p7Der = forge.asn1.toDer(p7Asn1);
  const p7Buffer = Buffer.from(p7Der.getBytes(), 'binary');

  const zip = new AdmZip();
  zip.addFile('AndroidManifest.xml', manifestContent);
  zip.addFile('META-INF/MANIFEST.MF', Buffer.from('Manifest-Version: 1.0\r\n'));
  zip.addFile('META-INF/CERT.SF', Buffer.from('Signature-Version: 1.0\r\n'));
  zip.addFile('META-INF/CERT.RSA', p7Buffer);

  const zipBuf = zip.toBuffer();

  // Now inject an APK Signing Block v2 between entries and central directory.
  // Find EOCD
  let eocdOffset = -1;
  for (let i = zipBuf.length - 22; i >= 0; i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) throw new Error('EOCD not found');

  const centralDirOffset = zipBuf.readUInt32LE(eocdOffset + 16);
  const centralDirSize = zipBuf.readUInt32LE(eocdOffset + 12);

  // Create a V2 signature block with the certificate
  const certAsn1 = forge.pki.certificateToAsn1(cert);
  const certDer = forge.asn1.toDer(certAsn1);
  const certDerBuf = Buffer.from(certDer.getBytes(), 'binary');

  // Build the V2 signer block structure:
  // signer = {
  //   signed_data = {
  //     digests = { empty },
  //     certificates = { cert },
  //     attributes = { empty }
  //   },
  //   signatures = { empty },
  //   public_key = { empty }
  // }

  // Certificate: length-prefixed DER bytes
  const certLenBuf = Buffer.alloc(4);
  certLenBuf.writeUInt32LE(certDerBuf.length);
  const certWithLen = Buffer.concat([certLenBuf, certDerBuf]);

  // certificates block: length-prefixed list of certificates
  const certsBlockLen = Buffer.alloc(4);
  certsBlockLen.writeUInt32LE(certWithLen.length);
  const certsBlock = Buffer.concat([certsBlockLen, certWithLen]);

  // digests block: empty
  const digestsBlock = Buffer.from([0x00, 0x00, 0x00, 0x00]);

  // attributes block: empty
  const attributesBlock = Buffer.from([0x00, 0x00, 0x00, 0x00]);

  // signed_data = digests + certificates + attributes
  const signedDataContent = Buffer.concat([
    digestsBlock,
    certsBlock,
    attributesBlock,
  ]);
  const signedDataLen = Buffer.alloc(4);
  signedDataLen.writeUInt32LE(signedDataContent.length);
  const signedData = Buffer.concat([signedDataLen, signedDataContent]);

  // signatures block: empty
  const signaturesBlock = Buffer.from([0x00, 0x00, 0x00, 0x00]);

  // public_key block: empty
  const publicKeyBlock = Buffer.from([0x00, 0x00, 0x00, 0x00]);

  // signer = signed_data + signatures + public_key
  const signerContent = Buffer.concat([
    signedData,
    signaturesBlock,
    publicKeyBlock,
  ]);
  const signerLen = Buffer.alloc(4);
  signerLen.writeUInt32LE(signerContent.length);
  const signer = Buffer.concat([signerLen, signerContent]);

  // signers = length-prefixed list of signers
  const signersLen = Buffer.alloc(4);
  signersLen.writeUInt32LE(signer.length);
  const signers = Buffer.concat([signersLen, signer]);

  // ID-value pair: [size: u64] [id: u32] [value]
  const v2BlockId = Buffer.alloc(4);
  v2BlockId.writeUInt32LE(0x7109871a); // SIGNATURE_SCHEME_V2_BLOCK_ID
  const pairValue = signers;
  const pairSize = Buffer.alloc(8);
  pairSize.writeBigUInt64LE(BigInt(4 + pairValue.length)); // id (4) + value
  const pair = Buffer.concat([pairSize, v2BlockId, pairValue]);

  // APK Signing Block:
  // [size_of_block: u64] [pairs...] [size_of_block: u64] [magic: "APK Sig Block 42"]
  const magic = Buffer.from('APK Sig Block 42');
  const sizeOfBlockValue = BigInt(pair.length + 8 + 16); // pairs + size_end + magic
  const sizeStart = Buffer.alloc(8);
  sizeStart.writeBigUInt64LE(sizeOfBlockValue);
  const sizeEnd = Buffer.alloc(8);
  sizeEnd.writeBigUInt64LE(sizeOfBlockValue);

  const sigBlock = Buffer.concat([sizeStart, pair, sizeEnd, magic]);

  // Now rebuild the APK:
  // [entries (0..centralDirOffset)] [sigBlock] [central directory] [EOCD with updated offset]
  const entriesPart = zipBuf.subarray(0, centralDirOffset);
  const centralDirPart = zipBuf.subarray(centralDirOffset, eocdOffset);
  const eocdPart = Buffer.from(zipBuf.subarray(eocdOffset));

  // Update the central_dir_offset in EOCD to account for the injected block
  const newCentralDirOffset = centralDirOffset + sigBlock.length;
  eocdPart.writeUInt32LE(newCentralDirOffset, 16);

  return Buffer.concat([entriesPart, sigBlock, centralDirPart, eocdPart]);
}

// Generate fixtures
fs.mkdirSync(FIXTURE_DIR, { recursive: true });

const v1Apk = createSignedApk();
fs.writeFileSync(path.join(FIXTURE_DIR, 'test-v1.apk'), v1Apk);
console.log(`Created test-v1.apk (${v1Apk.length} bytes)`);

const v2Apk = createSignedApkWithV2Block();
fs.writeFileSync(path.join(FIXTURE_DIR, 'test-v1v2.apk'), v2Apk);
console.log(`Created test-v1v2.apk (${v2Apk.length} bytes)`);
