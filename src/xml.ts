import { Chunk, ChunkType, parseResourceValue, StringPool } from "./common.js";
import { BinaryReader } from "./binary-reader.js";

class XmlAttribute {

  public readonly name: string;
  public readonly value: any;

  constructor(source: BinaryReader, stringPool: StringPool) {
    source.skip(4); // Namespace
    this.name = stringPool.values[source.readI32LE()];
    source.skip(4); // RawValue
    this.value = parseResourceValue(source, stringPool);
  }
}

export class XmlElement {

  private static parseChildren(parent: XmlElement, source: BinaryReader, stringPool: StringPool) {
    let chunk = new Chunk(source);
    while (chunk.type !== ChunkType.XML_END_NAMESPACE && chunk.type !== ChunkType.XML_END_ELEMENT) {
      if (chunk.type === ChunkType.XML_START_ELEMENT) {
        const child = new XmlElement(chunk.chunkSource, stringPool);
        parent.children[child.tag] = parent.children[child.tag] || [];
        parent.children[child.tag].push(child);
        XmlElement.parseChildren(child, source, stringPool);
      }
      chunk = new Chunk(source);
    }
  }

  public readonly tag: string;
  public readonly attributes: {[key: string]: any} = {};
  public readonly children: {[key: string]: XmlElement[]} = {};

  constructor(source: BinaryReader, stringPool?: StringPool) {
    if (stringPool) {
      source.skip(4); // Namespace
      this.tag = stringPool.values[source.readI32LE()];

      const attributeStart = source.readU16LE();
      const attributeSize = source.readU16LE();
      const attributeCount = source.readU16LE();

      source.moveAt(attributeStart);
      for (let i = 0; i < attributeCount; ++i ) {
        const attr = new XmlAttribute(source.source(attributeSize), stringPool);
        this.attributes[attr.name] = attr.value;
      }
    } else {
      source = new Chunk(source, ChunkType.XML).chunkSource;
      stringPool = new StringPool(new Chunk(source, ChunkType.STRING_POOL));
      this.tag = "xml";
      XmlElement.parseChildren(this, source, stringPool);
    }
  }
}
