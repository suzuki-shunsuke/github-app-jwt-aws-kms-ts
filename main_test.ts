import { assertEquals, assertRejects, assertStringIncludes } from "@std/assert";
import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
import { decodeBase64Url } from "@std/encoding/base64url";
import { createJwt, type Fetch, regionFromKeyId } from "./main.ts";

const decoder = new TextDecoder();

const arnKeyId =
  "arn:aws:kms:ap-northeast-1:123456789012:key/00000000-0000-0000-0000-000000000000";

const credentials = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

type SignRequest = {
  url: string;
  target: string | null;
  authorization: string | null;
  body: {
    KeyId: string;
    Message: string;
    MessageType: string;
    SigningAlgorithm: string;
  };
};

/** This records the KMS Sign requests and returns a canned signature. */
class FakeKMS {
  readonly requests: SignRequest[] = [];

  constructor(
    private readonly respond: (message: Uint8Array) => Promise<Response>,
  ) {}

  readonly fetch: Fetch = async (url, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(init?.body as string);
    this.requests.push({
      url,
      target: headers.get("x-amz-target"),
      authorization: headers.get("authorization"),
      body,
    });
    return await this.respond(decodeBase64(body.Message));
  };
}

const signatureOf = (signature: Uint8Array | undefined) => () =>
  Promise.resolve(
    new Response(
      JSON.stringify(
        signature ? { Signature: encodeBase64(signature) } : {},
      ),
      { status: 200 },
    ),
  );

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
  const kms = new FakeKMS(signatureOf(signature));
  const before = Math.floor(Date.now() / 1000);
  const token = await createJwt({
    keyId: arnKeyId,
    credentials,
    fetch: kms.fetch,
  })("123456");
  const after = Math.floor(Date.now() / 1000);

  assertEquals(kms.requests.length, 1);
  const request = kms.requests[0];
  assertEquals(request.body.KeyId, arnKeyId);
  assertEquals(request.body.MessageType, "RAW");
  assertEquals(request.body.SigningAlgorithm, "RSASSA_PKCS1_V1_5_SHA_256");
  assertEquals(request.target, "TrentService.Sign");

  // The endpoint and the signature scope both follow the key ARN's region.
  assertEquals(request.url, "https://kms.ap-northeast-1.amazonaws.com/");
  assertStringIncludes(request.authorization ?? "", "AWS4-HMAC-SHA256");
  assertStringIncludes(request.authorization ?? "", "/ap-northeast-1/kms/");

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
    decoder.decode(decodeBase64(request.body.Message)),
    token.jwt.split(".").slice(0, 2).join("."),
  );
});

Deno.test("createJwt caches a JSON Web Token", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  const sign = createJwt({ keyId: arnKeyId, credentials, fetch: kms.fetch });

  const first = await sign("123456");
  const second = await sign("123456");

  assertEquals(kms.requests.length, 1);
  assertEquals(second, first);
});

Deno.test("createJwt doesn't reuse a cached token for another app", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  const sign = createJwt({ keyId: arnKeyId, credentials, fetch: kms.fetch });

  await sign("123456");
  const token = await sign("654321");

  assertEquals(kms.requests.length, 2);
  assertEquals(parseJwt(token.jwt).payload.iss, "654321");
});

Deno.test("createJwt applies timeDifference and skips the cache", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  const sign = createJwt({ keyId: arnKeyId, credentials, fetch: kms.fetch });

  const first = await sign("123456");
  const second = await sign("123456", 3600);

  assertEquals(kms.requests.length, 2);
  assertEquals(
    parseJwt(second.jwt).payload.iat - parseJwt(first.jwt).payload.iat,
    3600,
  );

  // A token created with a clock skew isn't cached either.
  await sign("123456");
  assertEquals(kms.requests.length, 3);
});

Deno.test("createJwt calls the credentials function for every signature", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  let calls = 0;
  const sign = createJwt({
    keyId: arnKeyId,
    fetch: kms.fetch,
    credentials: () => {
      calls++;
      return credentials;
    },
  });

  await sign("123456");
  await sign("654321");

  // A cached token needs no signature, so it needs no credentials either.
  await sign("654321");

  assertEquals(calls, 2);
});

Deno.test("createJwt sends the session token of temporary credentials", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  await createJwt({
    keyId: arnKeyId,
    fetch: kms.fetch,
    credentials: { ...credentials, sessionToken: "session-token" },
  })("123456");

  assertStringIncludes(
    kms.requests[0].authorization ?? "",
    "x-amz-security-token",
  );
});

Deno.test("createJwt fails if AWS KMS returns no signature", async () => {
  const kms = new FakeKMS(signatureOf(undefined));
  const sign = createJwt({ keyId: arnKeyId, credentials, fetch: kms.fetch });

  await assertRejects(
    () => sign("123456"),
    Error,
    "AWS KMS returned no signature",
  );
});

Deno.test("createJwt reports what AWS KMS rejected", async () => {
  const kms = new FakeKMS(() =>
    Promise.resolve(
      new Response('{"__type":"AccessDeniedException"}', { status: 400 }),
    )
  );
  const sign = createJwt({ keyId: arnKeyId, credentials, fetch: kms.fetch });

  await assertRejects(
    () => sign("123456"),
    Error,
    'AWS KMS returned 400: {"__type":"AccessDeniedException"}',
  );
});

Deno.test("createJwt fails if the region can't be worked out", () => {
  assertEquals(
    (() => {
      try {
        createJwt({ keyId: "alias/example", credentials });
        return "";
      } catch (e) {
        return (e as Error).message;
      }
    })().includes("the AWS region is unknown"),
    true,
  );
});

Deno.test("createJwt fails if there are no credentials", async () => {
  const kms = new FakeKMS(signatureOf(new Uint8Array([1])));
  const sign = createJwt({ keyId: arnKeyId, fetch: kms.fetch });

  await assertRejects(() => sign("123456"), Error, "no AWS credentials");
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
  const kms = new FakeKMS(async (message) =>
    new Response(
      JSON.stringify({
        Signature: encodeBase64(
          new Uint8Array(
            await crypto.subtle.sign(
              algorithm.name,
              key.privateKey,
              message as Uint8Array<ArrayBuffer>,
            ),
          ),
        ),
      }),
      { status: 200 },
    )
  );

  const token = await createJwt({
    keyId: arnKeyId,
    credentials,
    fetch: kms.fetch,
  })("123456");
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
  // The region then comes from the region input or AWS_REGION.
  assertEquals(regionFromKeyId("alias/example"), "");
});
