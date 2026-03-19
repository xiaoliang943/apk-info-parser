# apk-info-parser

APK signature and certificate parser for Node.js, written in TypeScript.

A Node.js reimplementation of the signature/certificate extraction from [delvinru/apk-info](https://github.com/delvinru/apk-info) (Rust). Focuses on parsing `CertificateInfo` and `Signature` data from APK files.

## Features

- **V1 (JAR) signature** extraction from `META-INF/*.{RSA,DSA,EC}` via PKCS#7/CMS parsing
- **V2 / V3 / V3.1 signature** extraction from the [APK Signing Block](https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block)
- X.509 certificate details: serial number, subject, issuer, validity dates, signature algorithm
- Certificate fingerprints: MD5, SHA-1, SHA-256
- Read arbitrary files from the APK archive
- Full TypeScript types with a discriminated union for `Signature`

## Install

```bash
npm install apk-info-parser
```

## Usage

### Get all signatures

```typescript
import { APK } from 'apk-info-parser';

const apk = new APK('./app.apk');

for (const sig of apk.getSignatures()) {
  if (sig.type !== 'unknown') {
    console.log(`Signature scheme: ${sig.type}`);
    for (const cert of sig.certificates) {
      console.log(`  Subject:    ${cert.subject}`);
      console.log(`  Issuer:     ${cert.issuer}`);
      console.log(`  Serial:     ${cert.serialNumber}`);
      console.log(`  Valid:      ${cert.validFrom} - ${cert.validUntil}`);
      console.log(`  Algorithm:  ${cert.signatureType}`);
      console.log(`  SHA-256:    ${cert.sha256Fingerprint}`);
    }
  }
}
```

### Load from a Buffer

```typescript
import { readFileSync } from 'node:fs';
import { APK } from 'apk-info-parser';

const buf = readFileSync('./app.apk');
const apk = new APK(buf);
const sigs = apk.getSignatures();
```

### Extract a specific signature scheme

```typescript
const apk = new APK('./app.apk');

// V1 only
const v1 = apk.getSignatureV1();

// V2 / V3 / V3.1 from the APK Signing Block
const blockSigs = apk.getSignaturesFromBlock();
```

### Read files from the APK

```typescript
const apk = new APK('./app.apk');

// List all files
console.log(apk.getFileNames());

// Read a specific file
const manifest = apk.readFile('AndroidManifest.xml');
```

## API

### `new APK(input: string | Buffer)`

Create an APK instance from a file path or raw `Buffer`.

### `apk.getSignatures(): Signature[]`

Extract all signatures (V1 + V2/V3/V3.1) from the APK. Returns only successfully parsed signatures (excludes `unknown`).

### `apk.getSignatureV1(): Signature | null`

Extract the V1 (JAR) signature only. Returns `null` if not found or parsing fails.

### `apk.getSignaturesFromBlock(): Signature[]`

Extract V2/V3/V3.1 signatures from the APK Signing Block.

### `apk.getFileNames(): string[]`

List all file paths in the APK archive.

### `apk.readFile(filename: string): Buffer | null`

Read the contents of a file inside the APK. Returns `null` if the file does not exist.

### `signatureName(sig: Signature): string`

Returns a human-readable name for a signature (`"v1"`, `"v2"`, `"v3"`, `"v3.1"`, `"unknown"`).

## Types

### `Signature`

Discriminated union representing an APK signing scheme:

```typescript
type Signature =
  | { type: 'v1'; certificates: CertificateInfo[] }
  | { type: 'v2'; certificates: CertificateInfo[] }
  | { type: 'v3'; certificates: CertificateInfo[] }
  | { type: 'v31'; certificates: CertificateInfo[] }
  | { type: 'unknown' };
```

### `CertificateInfo`

```typescript
interface CertificateInfo {
  serialNumber: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
  signatureType: string;
  md5Fingerprint: string;
  sha1Fingerprint: string;
  sha256Fingerprint: string;
}
```

## Project Structure

```
src/
  index.ts              Public exports
  types.ts              CertificateInfo, Signature, signatureName
  binary-reader.ts      Cursor-based little-endian binary reader
  certificate.ts        X.509 DER -> CertificateInfo conversion
  signature-v1.ts       V1 JAR signature parsing (PKCS#7)
  signature-block.ts    APK Signing Block parsing (V2/V3/V3.1)
  apk.ts                Main APK class
```

## Development

```bash
# Install dependencies
npm install

# Type-check
npx tsc --noEmit

# Run tests
npm test

# Build
npm run build
```

## Credits

- [delvinru/apk-info](https://github.com/delvinru/apk-info) -- the original Rust implementation this project is based on

## License

Apache-2.0
