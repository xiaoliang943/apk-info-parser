/**
 * APK Signing Block parser for V2, V3, V3.1 signatures.
 *
 * Mirrors `ZipEntry::get_signatures_other()` and `parse_apk_signatures()`
 * from `entry.rs`.
 *
 * The APK Signing Block sits between the last ZIP entry and the Central Directory.
 * Layout (reading backwards from Central Directory offset):
 *
 *   [size_of_block: u64] [id-value pairs...] [size_of_block: u64] [magic: "APK Sig Block 42"]
 *
 * See: https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block
 */
import { BinaryReader } from './binary-reader.js';
import { parseDerCertificate } from './certificate.js';
import type { CertificateInfo, Signature } from './types.js';

// Block ID constants (from the Rust implementation)
const SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
const SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;
const SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61;

// IDs we recognize but skip
const VERITY_PADDING_BLOCK_ID = 0x42726577;
const DEPENDENCY_INFO_BLOCK_ID = 0x504b4453;
const ZERO_BLOCK_ID = 0xff3b5998;
const APK_CHANNEL_BLOCK_ID = 0x71777777;
const V1_SOURCE_STAMP_BLOCK_ID = 0x2b09189e;
const V2_SOURCE_STAMP_BLOCK_ID = 0x6dff800d;
const PACKER_NG_SIG_V2 = 0x7a786b21;
const GOOGLE_PLAY_FROSTING_ID = 0x2146444e;
const VASDOLLY_V2 = 0x881155ff;

const SKIPPED_BLOCK_IDS = new Set([
  VERITY_PADDING_BLOCK_ID,
  DEPENDENCY_INFO_BLOCK_ID,
  ZERO_BLOCK_ID,
  APK_CHANNEL_BLOCK_ID,
  V1_SOURCE_STAMP_BLOCK_ID,
  V2_SOURCE_STAMP_BLOCK_ID,
  PACKER_NG_SIG_V2,
  GOOGLE_PLAY_FROSTING_ID,
  VASDOLLY_V2,
]);

const APK_SIGNATURE_MAGIC = Buffer.from('APK Sig Block 42');

/**
 * Find the EOCD (End of Central Directory) record in the APK buffer.
 * Searches backwards from the end for the EOCD magic: PK\x05\x06
 */
function findEocd(buf: Buffer): number | null {
  // EOCD is at least 22 bytes. Search backwards.
  const magic = 0x06054b50;
  // Start searching from the end, up to 65535 + 22 bytes back (max comment length)
  const searchStart = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= searchStart; i--) {
    if (buf.readUInt32LE(i) === magic) {
      return i;
    }
  }
  return null;
}

/**
 * Extract signatures from the APK Signing Block.
 *
 * Mirrors `ZipEntry::get_signatures_other()`.
 */
export function getSignaturesFromBlock(apkBuf: Buffer): Signature[] {
  const eocdOffset = findEocd(apkBuf);
  if (eocdOffset === null) {
    return [];
  }

  // Read central_dir_offset from EOCD (at offset + 16)
  const centralDirOffset = apkBuf.readUInt32LE(eocdOffset + 16);

  // Read the 24 bytes immediately before central directory:
  // [size_of_block: u64 (8)] [magic: 16 bytes "APK Sig Block 42"]
  const tailStart = centralDirOffset - 24;
  if (tailStart < 0 || tailStart + 24 > apkBuf.length) {
    return [];
  }

  const sizeOfBlock = apkBuf.readBigUInt64LE(tailStart);
  const magic = apkBuf.subarray(tailStart + 8, tailStart + 24);

  if (!magic.equals(APK_SIGNATURE_MAGIC)) {
    return [];
  }

  // Navigate to the start of the block.
  // The block layout:
  //   [size_of_block_start: u64] [id-value pairs...] [size_of_block_end: u64] [magic]
  //
  // Total block = 8 (size start) + pairs + 8 (size end) + 16 (magic)
  // size_of_block = pairs_size + 8 (size end) + 16 (magic)
  // So block start = centralDirOffset - 8 (size start) - size_of_block
  const blockStart = centralDirOffset - 8 - Number(sizeOfBlock);
  if (blockStart < 0) {
    return [];
  }

  // Verify size_of_block at start matches
  const sizeOfBlockStart = apkBuf.readBigUInt64LE(blockStart);
  if (sizeOfBlockStart !== sizeOfBlock) {
    return [];
  }

  // The ID-value pairs are between the two size fields:
  // from blockStart + 8  to  tailStart (i.e., centralDirOffset - 24)
  const pairsStart = blockStart + 8;
  const pairsEnd = tailStart; // = centralDirOffset - 24
  if (pairsStart >= pairsEnd) {
    return [];
  }

  const pairsBuf = apkBuf.subarray(pairsStart, pairsEnd);
  return parseApkSignatures(pairsBuf);
}

/**
 * Parse the ID-value pairs inside the APK Signing Block.
 *
 * Each pair:
 *   [size: u64] [id: u32] [value: size-4 bytes]
 *
 * Mirrors `parse_apk_signatures()` in `entry.rs`.
 */
function parseApkSignatures(pairsBuf: Buffer): Signature[] {
  const reader = BinaryReader.from(pairsBuf);
  const signatures: Signature[] = [];

  while (reader.remaining > 12) {
    // 12 = minimum: 8 (size) + 4 (id)
    try {
      const size = reader.readU64LE();
      const id = reader.readU32LE();
      // value length = size - 4 (the id was part of the size)
      const valueLen = Number(size) - 4;

      if (valueLen < 0 || valueLen > reader.remaining) {
        break;
      }

      const sig = parseSignatureBlock(id, reader.readBytes(valueLen));
      if (sig && sig.type !== 'unknown') {
        signatures.push(sig);
      }
    } catch {
      break;
    }
  }

  return signatures;
}

/**
 * Parse a single signature block by its ID.
 */
function parseSignatureBlock(
  id: number,
  value: Buffer,
): Signature | null {
  switch (id) {
    case SIGNATURE_SCHEME_V2_BLOCK_ID: {
      const certs = parseSignersV2(value);
      return { type: 'v2', certificates: certs };
    }
    case SIGNATURE_SCHEME_V3_BLOCK_ID: {
      const certs = parseSignersV3(value);
      return { type: 'v3', certificates: certs };
    }
    case SIGNATURE_SCHEME_V31_BLOCK_ID: {
      const certs = parseSignersV3(value); // v3.1 uses same format as v3
      return { type: 'v31', certificates: certs };
    }
    default: {
      if (SKIPPED_BLOCK_IDS.has(id)) {
        return { type: 'unknown' };
      }
      // Unknown block
      return { type: 'unknown' };
    }
  }
}

/**
 * Parse V2 signers and extract certificates.
 *
 * Mirrors `parse_signer_v2()` in `entry.rs`.
 *
 * Format:
 *   signers = length_prefixed_u32 { signer* }
 *   signer = length_prefixed_u32 {
 *     signed_data = length_prefixed_u32 {
 *       digests = length_prefixed_u32 { ... }
 *       certificates = length_prefixed_u32 { certificate* }
 *       attributes = length_prefixed_u32 { ... }
 *     }
 *     signatures = length_prefixed_u32 { ... }
 *     public_key = length_prefixed_u32 { ... }
 *   }
 *   certificate = length_prefixed_u32 { DER bytes }
 */
function parseSignersV2(data: Buffer): CertificateInfo[] {
  try {
    const reader = BinaryReader.from(data);
    const signersData = reader.readLengthPrefixedU32();
    const signersReader = BinaryReader.from(signersData);
    const allCerts: CertificateInfo[] = [];

    while (signersReader.remaining > 4) {
      try {
        const certs = parseOneSignerV2(signersReader);
        allCerts.push(...certs);
      } catch {
        break;
      }
    }

    return allCerts;
  } catch {
    return [];
  }
}

function parseOneSignerV2(reader: BinaryReader): CertificateInfo[] {
  // 1 - parse signer
  const signerData = reader.readLengthPrefixedU32();
  const signerReader = BinaryReader.from(signerData);

  // 1.1 - parse signed data
  const signedData = signerReader.readLengthPrefixedU32();
  const signedReader = BinaryReader.from(signedData);

  // 1.1.1 - parse digests (skip)
  signedReader.readLengthPrefixedU32();

  // 1.1.2 - parse certificates
  const certificatesData = signedReader.readLengthPrefixedU32();
  const certs = parseCertificatesFromBlock(certificatesData);

  // 1.1.3 - parse attributes (skip)
  // signedReader.readLengthPrefixedU32();

  // 1.2 - parse signatures (skip)
  // signerReader.readLengthPrefixedU32();

  // 1.3 - parse public key (skip)
  // signerReader.readLengthPrefixedU32();

  return certs;
}

/**
 * Parse V3/V3.1 signers and extract certificates.
 *
 * Mirrors `parse_signer_v3()` in `entry.rs`.
 *
 * Same as V2 but with additional min_sdk/max_sdk fields:
 *   signer = length_prefixed_u32 {
 *     signed_data = length_prefixed_u32 {
 *       digests = length_prefixed_u32 { ... }
 *       certificates = length_prefixed_u32 { certificate* }
 *       min_sdk: u32
 *       max_sdk: u32
 *       attributes = length_prefixed_u32 { ... }
 *     }
 *     min_sdk: u32   (duplicate)
 *     max_sdk: u32   (duplicate)
 *     signatures = length_prefixed_u32 { ... }
 *     public_key = length_prefixed_u32 { ... }
 *   }
 */
function parseSignersV3(data: Buffer): CertificateInfo[] {
  try {
    const reader = BinaryReader.from(data);
    const signersData = reader.readLengthPrefixedU32();
    const signersReader = BinaryReader.from(signersData);
    const allCerts: CertificateInfo[] = [];

    while (signersReader.remaining > 4) {
      try {
        const certs = parseOneSignerV3(signersReader);
        allCerts.push(...certs);
      } catch {
        break;
      }
    }

    return allCerts;
  } catch {
    return [];
  }
}

function parseOneSignerV3(reader: BinaryReader): CertificateInfo[] {
  // 1 - parse signer
  const signerData = reader.readLengthPrefixedU32();
  const signerReader = BinaryReader.from(signerData);

  // 1.1 - parse signed data
  const signedData = signerReader.readLengthPrefixedU32();
  const signedReader = BinaryReader.from(signedData);

  // 1.1.1 - parse digests (skip)
  signedReader.readLengthPrefixedU32();

  // 1.1.2 - parse certificates
  const certificatesData = signedReader.readLengthPrefixedU32();
  const certs = parseCertificatesFromBlock(certificatesData);

  // 1.1.3 - parse sdk's (skip)
  // signedReader.readU32LE(); // min_sdk
  // signedReader.readU32LE(); // max_sdk

  // 1.1.4 - parse attributes (skip)
  // signedReader.readLengthPrefixedU32();

  // 1.2 - parse duplicate sdk's (skip)
  // signerReader.readU32LE(); // duplicate_min_sdk
  // signerReader.readU32LE(); // duplicate_max_sdk

  // 1.3 - parse signatures (skip)
  // signerReader.readLengthPrefixedU32();

  // 1.4 - parse public key (skip)
  // signerReader.readLengthPrefixedU32();

  return certs;
}

/**
 * Parse a sequence of length-prefixed DER certificates.
 *
 * Mirrors `repeat(0.., Self::parse_certificate())` in `entry.rs`.
 */
function parseCertificatesFromBlock(data: Buffer): CertificateInfo[] {
  const reader = BinaryReader.from(data);
  const certs: CertificateInfo[] = [];

  while (reader.remaining > 4) {
    try {
      const certDer = reader.readLengthPrefixedU32();
      const info = parseDerCertificate(certDer);
      if (info) {
        certs.push(info);
      }
    } catch {
      break;
    }
  }

  return certs;
}
