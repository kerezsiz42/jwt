import {
  encode as base64UrlEncode,
  decode as base64UrlDecode,
} from "base64url";

export class JWT {
  private secret: string;
  private textEncoder: TextEncoder;
  private textDecoder: TextDecoder;
  private _key?: CryptoKey;

  constructor(secret: string) {
    this.secret = secret;
    this.textEncoder = new TextEncoder();
    this.textDecoder = new TextDecoder();
  }

  private async importKey(): Promise<CryptoKey> {
    this._key = await crypto.subtle.importKey(
      "raw",
      this.textEncoder.encode(this.secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    return this._key;
  }

  private get key(): Promise<CryptoKey> | CryptoKey {
    return this._key || this.importKey();
  }

  public async encode(payload: any): Promise<string> {
    const header = {
      alg: "HS256",
      typ: "JWT",
    };
    const encodedHeaderString = base64UrlEncode(
      this.textEncoder.encode(JSON.stringify(header))
    );
    const encodedPayloadString = base64UrlEncode(
      this.textEncoder.encode(JSON.stringify(payload))
    );
    const toBeSignedString = `${encodedHeaderString}.${encodedPayloadString}`;
    const toBeSignedArray = this.textEncoder.encode(toBeSignedString);
    const signature = await crypto.subtle.sign(
      "HMAC",
      await this.key,
      toBeSignedArray
    );
    const signatureString = base64UrlEncode(signature);
    return `${toBeSignedString}.${signatureString}`;
  }

  public async decode(s: string): Promise<any> {
    const parts = s.split(".");
    if (parts.length !== 3) return undefined;
    const [encodedHeaderString, encodedPayloadString, signatureString] = parts;
    const signedString = `${encodedHeaderString}.${encodedPayloadString}`;
    const valid = await crypto.subtle.verify(
      "HMAC",
      await this.key,
      base64UrlDecode(signatureString),
      this.textEncoder.encode(signedString)
    );
    if (!valid) return undefined;
    return JSON.parse(
      this.textDecoder.decode(base64UrlDecode(encodedPayloadString))
    );
  }
}
