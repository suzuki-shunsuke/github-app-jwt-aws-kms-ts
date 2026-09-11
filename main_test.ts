import { assertEquals, assertRejects } from "@std/assert";
import type { SignCommand, SignCommandOutput } from "@aws-sdk/client-kms";
import { decodeBase64Url } from "@std/encoding/base64url";
import { createJwt, regionFromKeyId, type Signer } from "./main.ts";

const decoder = new TextDecoder();

const arnKeyId =
  "arn:aws:kms:ap-northeast-1:123456789012:key/00000000-0000-0000-0000-000000000000";

type SignInput = SignCommand["input"];

/** This class records Sign commands and returns a canned signature. */
class FakeSigner implements Signer {
  readonly inputs: SignInput[] = [];

  constructor(private readonly signature: Uint8Array | undefined) {}

  send(command: SignCommand): Promise<SignCommandOutput> {
    this.inputs.push(command.input);
    return Promise.resolve({
      $metadata: {},
      Signature: this.signature,
    });
  }
}

const parseJwt = (jwt: string) => {
  const [header, payload, signature] = jwt.split(".");
  return {
    header: JSON.parse(decoder.decode(decodeBase64Url(header))),
    payload: JSON.parse(decoder.decode(decodeBase64Url(payload))),
    signature: decodeBase64Url(signature),
  };
};

Deno.test("createJwt signs a GitHub App JSON Web Token with AWS KMS", async () => {
  const signature = new Uint8Array([251, 255, 190, 0, 1]);
  const client = new FakeSigner(signature);
  const before = Math.floor(Date.now() / 1000);
  const token = await createJwt({ keyId: "test-key", client })("123456");
  const after = Math.floor(Date.now() / 1000);

  assertEquals(client.inputs.length, 1);
  assertEquals(client.inputs[0].KeyId, "test-key");
  assertEquals(client.inputs[0].MessageType, "RAW");
  assertEquals(client.inputs[0].SigningAlgorithm, "RSASSA_PKCS1_V1_5_SHA_256");

  const parsed = parseJwt(token.jwt);
  assertEquals(parsed.header, { alg: "RS256", typ: "JWT" });
  assertEquals(parsed.payload.iss, "123456");
  assertEquals(parsed.signature, signature);

  // The token is issued 60 seconds in the past and expires within 10 minutes.
  assertEquals(parsed.payload.iat <= before - 60, true);
  assertEquals(parsed.payload.iat >= before - 61, true);
  assertEquals(parsed.payload.exp - parsed.payload.iat, 600);
  assertEquals(parsed.payload.exp <= after + 600, true);
  assertEquals(
    token.expiresAt,
    new Date(parsed.payload.exp * 1000).toISOString(),
  );

  // AWS KMS signs the header and the payload joined by a dot.
  assertEquals(
    decoder.decode(client.inputs[0].Message),
    token.jwt.split(".").slice(0, 2).join("."),
  );
});

Deno.test("createJwt caches a JSON Web Token", async () => {
  const client = new FakeSigner(new Uint8Array([1]));
  const sign = createJwt({ keyId: "test-key", client });

  const first = await sign("123456");
  const second = await sign("123456");

  assertEquals(client.inputs.length, 1);
  assertEquals(second, first);
});

Deno.test("createJwt doesn't reuse a cached token for another app", async () => {
  const client = new FakeSigner(new Uint8Array([1]));
  const sign = createJwt({ keyId: "test-key", client });

  await sign("123456");
  const token = await sign("654321");

  assertEquals(client.inputs.length, 2);
  assertEquals(parseJwt(token.jwt).payload.iss, "654321");
});

Deno.test("createJwt applies timeDifference and skips the cache", async () => {
  const client = new FakeSigner(new Uint8Array([1]));
  const sign = createJwt({ keyId: "test-key", client });

  const first = await sign("123456");
  const second = await sign("123456", 3600);

  assertEquals(client.inputs.length, 2);
  assertEquals(
    parseJwt(second.jwt).payload.iat - parseJwt(first.jwt).payload.iat,
    3600,
  );

  // A token created with a clock skew isn't cached either.
  await sign("123456");
  assertEquals(client.inputs.length, 3);
});

Deno.test("createJwt fails if AWS KMS returns no signature", async () => {
  const sign = createJwt({
    keyId: "test-key",
    client: new FakeSigner(undefined),
  });

  await assertRejects(
    () => sign("123456"),
    Error,
    "AWS KMS returned no signature",
  );
});

Deno.test("the signed JSON Web Token is verifiable with the public key", async () => {
  const algorithm = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  };
  const key = await crypto.subtle.generateKey(algorithm, false, [
    "sign",
    "verify",
  ]);

  // AWS KMS returns a raw PKCS #1 signature for RSA keys, which is what
  // SubtleCrypto returns too.
  const client: Signer = {
    send: async (command: SignCommand) => ({
      $metadata: {},
      Signature: new Uint8Array(
        await crypto.subtle.sign(
          algorithm.name,
          key.privateKey,
          command.input.Message as Uint8Array<ArrayBuffer>,
        ),
      ),
    }),
  };

  const token = await createJwt({ keyId: "test-key", client })("123456");
  const [header, payload, signature] = token.jwt.split(".");

  assertEquals(
    await crypto.subtle.verify(
      algorithm.name,
      key.publicKey,
      decodeBase64Url(signature),
      new TextEncoder().encode(`${header}.${payload}`),
    ),
    true,
  );
});

Deno.test("regionFromKeyId reads the region out of a key ARN", () => {
  assertEquals(regionFromKeyId(arnKeyId), "ap-northeast-1");
});

Deno.test("regionFromKeyId reads the region out of an alias ARN", () => {
  assertEquals(
    regionFromKeyId("arn:aws:kms:us-east-1:123456789012:alias/example"),
    "us-east-1",
  );
});

Deno.test("regionFromKeyId returns nothing for a bare key id", () => {
  assertEquals(regionFromKeyId("00000000-0000-0000-0000-000000000000"), "");
});

Deno.test("regionFromKeyId returns nothing for an alias name", () => {
  // Without a region the AWS SDK resolves one as it normally would.
  assertEquals(regionFromKeyId("alias/example"), "");
});
