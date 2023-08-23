import {
  decode as base64UrlDecode,
  encode as base64UrlEncode,
} from "https://deno.land/std@0.199.0/encoding/base64url.ts";

export class JWT {
  #secret: string;
  #key?: CryptoKey;
  #te = new TextEncoder();
  #td = new TextDecoder();

  constructor(secret: string) {
    this.#secret = secret;
  }

  #importKey() {
    return crypto.subtle.importKey(
      "raw",
      this.#te.encode(this.#secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
  }

  async encode(payload: unknown) {
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeaderString = base64UrlEncode(
      this.#te.encode(JSON.stringify(header)),
    );
    const encodedPayloadString = base64UrlEncode(
      this.#te.encode(JSON.stringify(payload)),
    );
    const toBeSignedString = `${encodedHeaderString}.${encodedPayloadString}`;
    const toBeSignedArray = this.#te.encode(toBeSignedString);
    const signature = await crypto.subtle.sign(
      "HMAC",
      this.#key ??= await this.#importKey(),
      toBeSignedArray,
    );
    const signatureString = base64UrlEncode(signature);
    return `${toBeSignedString}.${signatureString}`;
  }

  async decode(s: string) {
    const [encodedHeaderString, encodedPayloadString, signatureString] = s
      .split(".");
    if (!encodedHeaderString || !encodedPayloadString || !signatureString) {
      return undefined;
    }
    const valid = await crypto.subtle.verify(
      "HMAC",
      this.#key ??= await this.#importKey(),
      base64UrlDecode(signatureString),
      this.#te.encode(`${encodedHeaderString}.${encodedPayloadString}`),
    );
    if (!valid) return undefined;
    return JSON.parse(
      this.#td.decode(base64UrlDecode(encodedPayloadString)),
    ) as unknown;
  }
}
