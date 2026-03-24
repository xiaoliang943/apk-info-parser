# apk-info-parser

APK information parser for Node.js, written in TypeScript.

A comprehensive toolkit for parsing APK files, including signature/certificate extraction, AndroidManifest.xml parsing, and Android resource table access.

## Features

- **V1 (JAR) signature** extraction from `META-INF/*.{RSA,DSA,EC}` via PKCS#7/CMS parsing
- **V2 / V3 / V3.1 signature** extraction from the [APK Signing Block](https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block)
- X.509 certificate details: serial number, subject, issuer, validity dates, signature algorithm
- Certificate fingerprints: MD5, SHA-1, SHA-256
- **AndroidManifest.xml parsing**: package name, version, SDK versions, permissions, receivers
- **resources.arsc parsing**: multi-language resource resolution
- Read arbitrary files from the APK archive
- Full TypeScript types with a discriminated union for `Signature`

## Install

```bash
npm install apk-info-parser
```

## Usage


### Get manifest information

```typescript
const apk = new APK('./app.apk');
const manifest = apk.getManifestInfo();

console.log(`Package: ${manifest.package}`);
console.log(`Version: ${manifest.versionName} (${manifest.versionCode})`);
console.log(`Min SDK: ${manifest.minSdkVersion}`);
console.log(`Target SDK: ${manifest.targetSdkVersion}`);
console.log(`Permissions: ${manifest.permissions.join(', ')}`);
```

### Get resources

```typescript
const apk = new APK('./app.apk');
const manifest = apk.getManifestInfo();
const resources = apk.getResources();

// Resolve a resource by ID
if (typeof manifestInfo.applicationLabel === 'number') {
  const resolved = resources.resolve(manifestInfo.applicationLabel);
  for (const resource of resolved) {
    console.log(resource.value);
  }
}
```

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
