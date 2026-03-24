import { XmlElement } from "./xml.js";

export class Receiver {

  private readonly xml: XmlElement;

  constructor(xml: XmlElement) {
    this.xml = xml;
  }

  get raw(): XmlElement {
    return this.xml;
  }

  get name(): string {
    return this.xml.attributes.name;
  }

  get permission(): string {
    return this.xml.attributes.permission;
  }

  get exported(): boolean {
    return this.xml.attributes.exported;
  }
}

export class Manifest {

  private readonly xml: XmlElement;

  constructor(xml: XmlElement) {
    this.xml = xml.children.manifest[0];
  }

  get raw(): XmlElement {
    return this.xml;
  }

  get versionCode(): number {
    return Number(this.xml.attributes.versionCode);
  }

  get versionName(): string {
    return this.xml.attributes.versionName;
  }

  get package(): string {
    return this.xml.attributes.package;
  }

  get compileSdkVersion(): string {
    return this.xml.attributes.compileSdkVersion;
  }

  get minSdkVersion(): string {
    return this.xml.children["uses-sdk"][0].attributes.minSdkVersion;
  }

  get targetSdkVersion(): string {
    return this.xml.children["uses-sdk"][0].attributes.targetSdkVersion;
  }

  get allowBackup(): boolean {
    return this.xml.children.application[0].attributes.allowBackup;
  }

  get debuggable(): boolean {
    return this.xml.children.application[0].attributes.debuggable || false;
  }

  get applicationLabel(): string | number {
    return this.xml.children.application[0].attributes.label;
  }

  get applicationIcon(): number {
    return this.xml.children.application[0].attributes.icon;
  }

  get permissions(): Array<string> {
    const permissions = this.xml.children["uses-permission"] || [];
    return permissions.map((permission)=>{
      return permission.attributes.name;
    });
  }

  get receivers(): Array<Receiver> {
    const receivers = this.xml.children.application[0].children.receiver || [];
    return receivers.map((receiver)=>{
      return new Receiver(receiver);
    });
  }
}
