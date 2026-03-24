/**
 * Main APK class.
 *
 * Provides the public API for extracting signature and certificate
 * information from an APK file.
 */
import { readFileSync } from 'node:fs';
import AdmZip from 'adm-zip';
import { getSignaturesFromBlock } from './signature-block.js';
import { getSignatureV1 } from './signature-v1.js';
import type { Signature } from './types.js';
import { Manifest } from './android.js';
import { XmlElement } from './xml.js';
import { BinaryReader } from './binary-reader.js';
import { Resources } from './resources.js';

export class APK {
  private buffer: Buffer;
  private zip: AdmZip;

  /**
   * Create an APK instance from a file path or raw buffer.
   *
   * @param input - Path to the APK file, or a Buffer containing the APK data.
   */
  constructor(input: string | Buffer) {
    if (typeof input === 'string') {
      this.buffer = readFileSync(input);
    } else {
      this.buffer = input;
    }
    this.zip = new AdmZip(this.buffer);
  }

  getManifestInfo(): Manifest {
    const entries = this.zip.getEntries();
    const sigEntry = entries.find((e) => {
      const name = e.entryName;
      return name === "AndroidManifest.xml";
    });
    if (!sigEntry) {
      throw new Error("AndroidManifest.xml not found");
    }
    const data = this.zip.readFile(sigEntry);
    if (!data || data.length === 0) {
      throw new Error("Failed to read AndroidManifest.xml");
    }
    return new Manifest(new XmlElement(new BinaryReader(data)));
  }

  getResources(): Resources {
    const entries = this.zip.getEntries();
    const sigEntry = entries.find((e) => {
      const name = e.entryName;
      return name === "resources.arsc";
    });
    if (!sigEntry) {
      throw new Error("resources.arsc not found");
    }
    const data = this.zip.readFile(sigEntry);
    if (!data || data.length === 0) {
      throw new Error("Failed to read resources.arsc");
    }
    return new Resources(new BinaryReader(data));
  }

  /**
   * Retrieve all APK signing signatures (V1, V2, V3, V3.1).
   *
   * Mirrors `Apk::get_signatures()` from `core/src/apk.rs`.
   *
   * @returns Array of Signature objects found in the APK.
   */
  getSignatures(): Signature[] {
    const signatures: Signature[] = [];

    // V1 (JAR-based)
    const v1 = this.getSignatureV1();
    if (v1 && v1.type !== 'unknown') {
      signatures.push(v1);
    }

    // V2, V3, V3.1 (APK Signing Block)
    const blockSigs = this.getSignaturesFromBlock();
    signatures.push(...blockSigs);

    return signatures;
  }

  /**
   * Extract V1 (JAR) signature only.
   */
  getSignatureV1(): Signature | null {
    try {
      return getSignatureV1(this.zip);
    } catch {
      return null;
    }
  }

  /**
   * Extract V2/V3/V3.1 signatures from the APK Signing Block.
   */
  getSignaturesFromBlock(): Signature[] {
    try {
      return getSignaturesFromBlock(this.buffer);
    } catch {
      return [];
    }
  }

  /**
   * List all file names in the APK archive.
   */
  getFileNames(): string[] {
    return this.zip.getEntries().map((e) => e.entryName);
  }

  /**
   * Read a file from the APK archive.
   *
   * @param filename - The path of the file inside the APK.
   * @returns Buffer with the file contents, or null if not found.
   */
  readFile(filename: string): Buffer | null {
    const entry = this.zip.getEntry(filename);
    if (!entry) return null;
    return this.zip.readFile(entry);
  }
}
