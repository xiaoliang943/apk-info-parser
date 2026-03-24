import { Chunk, ChunkType, parseResourceValue, StringPool } from "./common.js";
import { BinaryReader } from "./binary-reader.js";

class Table {
  public readonly packageCount: number;
  public readonly stringPool: StringPool;
  public readonly packages: Map<number, TablePackageChunk>;

  constructor(chunk: Chunk) {
    this.packageCount = chunk.headerSource.readU32LE();
    this.stringPool = new StringPool(new Chunk(chunk.chunkSource, ChunkType.STRING_POOL));
    this.packages = new Map();

    for (let i = 0; i < this.packageCount; ++i) {
      const innerChunk = new Chunk(chunk.chunkSource);
      if (innerChunk.type === ChunkType.TABLE_PACKAGE) {
        const tablePackageChunk = new TablePackageChunk(innerChunk, this.stringPool);
        this.packages.set(tablePackageChunk.id, tablePackageChunk);
      }
    }
  }
}

class TablePackageChunk {

  private static getOrCreate<K, V>(map: Map<K, V[]>, key: K): V[] {
    return (map.has(key) ? map : map.set(key, [])).get(key)!;
  }

  public readonly id: number;
  public readonly name: string;
  public readonly typeStrings: number;
  public readonly lastPublicType: number;
  public readonly keyStrings: number;
  public readonly lastPublicKey: number;

  public readonly types: Map<number, TableTypeChunk[]>;

  constructor(chunk: Chunk, stringPool: StringPool) {
    this.id = chunk.headerSource.readU32LE();
    this.name = chunk.headerSource.readUtf16String(128 * 2);
    this.typeStrings = chunk.headerSource.readU32LE();
    this.lastPublicType = chunk.headerSource.readU32LE();
    this.keyStrings = chunk.headerSource.readU32LE();
    this.lastPublicKey = chunk.headerSource.readU32LE();

    this.types = new Map();
    while (chunk.chunkSource.remaining > 0) {
      const innerChunk = new Chunk(chunk.chunkSource);
      if (innerChunk.type === ChunkType.TABLE_TYPE) {
        const tableTypeChunk = new TableTypeChunk(innerChunk, stringPool);
        TablePackageChunk.getOrCreate(this.types, tableTypeChunk.id).push(tableTypeChunk);
      }
    }
  }
}

class TableTypeChunk {

  private static readonly NO_ENTRY = 0xffffffff;

  public readonly id: number;
  public readonly flags: number;
  public readonly reserved: number;
  public readonly entryCount: number;
  public readonly entriesStart: number;
  public readonly resTableConfig: ResTableConfig;

  public readonly entries: Map<number, TableEntry>;

  constructor(chunk: Chunk, stringPool: StringPool) {
    this.id = chunk.headerSource.readU8();
    this.flags = chunk.headerSource.readU8();
    this.reserved = chunk.headerSource.readU16LE();
    this.entryCount = chunk.headerSource.readU32LE();
    this.entriesStart = chunk.headerSource.readU32LE();
    this.resTableConfig = new ResTableConfig(chunk);

    const indexes: number[] = [];
    for (let i = 0; i < this.entryCount; ++i) {
      indexes.push(chunk.chunkSource.readU32LE());
    }

    this.entries = new Map();
    for (let i = 0; i < indexes.length; ++i) {
      if (indexes[i] !== TableTypeChunk.NO_ENTRY) {
        chunk.chunkSource.moveAt(this.entriesStart - chunk.headerSize + indexes[i]);
        this.entries.set(i, new TableEntry(chunk.chunkSource, stringPool));
      }
    }
  }

  public resolve(index: number): any {
    return (this.entries.get(index) || {} as any).value;
  }
}

class ResTableConfig {
  public readonly size: number;
  public readonly imsi: number;
  public readonly locale: Locale;
  public readonly screenType: number;
  public readonly input: number;
  public readonly screenSize: number;
  public readonly version: number;

  constructor(chunk: Chunk) {
    this.size = chunk.headerSource.readU32LE();
    this.imsi = chunk.headerSource.readU32LE();
    this.locale = new Locale(chunk.headerSource);
    this.screenType = chunk.headerSource.readU32LE();
    this.input = chunk.headerSource.readU32LE();
    this.screenSize = chunk.headerSource.readU32LE();
    this.version = chunk.headerSource.readU32LE();
  }
}

export class Locale {

  private static readonly EMPTY_CODE = "\u0000\u0000";

  private readonly languageCode: string;
  private readonly countryCode: string;

  constructor(source: BinaryReader) {
    this.languageCode = source.readUtf8String(2);
    this.countryCode = source.readUtf8String(2);
  }

  private convertCode(code: string): string | undefined {
    return code !== Locale.EMPTY_CODE ? code : undefined;
  }

  get language(): string | undefined {
    return this.convertCode(this.languageCode);
  }

  get country(): string | undefined {
    return this.convertCode(this.countryCode);
  }
}

class TableEntry {
  public readonly size: number;
  public readonly flags: number;
  public readonly index: number;

  public readonly value: any;

  constructor(source: BinaryReader, stringPool: StringPool) {
    this.size = source.readU16LE();
    this.flags = source.readU16LE();
    this.index = source.readU32LE();

    this.value = this.flags % 2 === 0 ? parseResourceValue(source, stringPool) : null;
  }
}

export class Resource {

  public readonly value: any;
  public readonly locale?: Locale;
  constructor(value: any, locale: Locale) {
    this.value = value;
    if (locale.language || locale.country) {
      this.locale = locale;
    }
  }
}

export class Resources {

  public readonly table: Table;

  constructor(source: BinaryReader) {
    const chunk = new Chunk(source, ChunkType.TABLE);
    this.table = new Table(chunk);
  }

  public resolve(id: number): Resource[] {
    const packageId = Math.floor(id / Math.pow(2, 24)) % Math.pow(2, 8);
    const typeId = Math.floor(id / Math.pow(2, 16)) % Math.pow(2, 8);
    const index = id % Math.pow(2, 16);

    const packageResources = this.table.packages.get(packageId);
    if (packageResources) {
      const types = packageResources.types.get(typeId);
      if (types) {
        return types.map((type) => new Resource(type.resolve(index), type.resTableConfig.locale))
            .filter((resource) => !!resource.value);
      }
    }
    return [];
  }
}
