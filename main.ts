/**
 * This module signs GitHub App JSON Web Tokens with AWS KMS.
 *
 * It's useful when a GitHub App private key is stored in AWS KMS and can never
 * be exported.
 * The returned callback is passed to
 * {@link https://jsr.io/@suzuki-shunsuke/github-app-token | @suzuki-shunsuke/github-app-token}'s
 * create function instead of a private key.
 *
 * @example
 * ```ts
 * import { create } from "@suzuki-shunsuke/github-app-token";
 * import { createJwt } from "@suzuki-shunsuke/github-app-jwt-aws-kms";
 *
 * const token = await create({
 *   appId: "123456",
 *   createJwt: createJwt({
 *     keyId: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000",
 *   }),
 *   owner: "suzuki-shunsuke",
 * });
 * ```
 *
 * @module
 */

import {
  KMSClient,
  SignCommand,
  type SignCommandOutput,
} from "@aws-sdk/client-kms";
import { encodeBase64Url } from "@std/encoding/base64url";

/** A signed JSON Web Token and its expiration date. */
export type Jwt = {
  jwt: string;
  expiresAt: string;
};

/**
 * A callback creating a JSON Web Token to authenticate as a GitHub App.
 *
 * This is structurally compatible with @octokit/auth-app's createJwt option and
 * with @suzuki-shunsuke/github-app-token's CreateJwt type.
 * timeDifference is a clock skew in seconds, which @octokit/auth-app passes when
 * GitHub rejects a token because the clocks are out of sync.
 */
export type CreateJwt = (
  appId: string | number,
  timeDifference?: number,
) => Promise<Jwt>;

/**
 * The part of KMSClient which this module uses.
 *
 * A KMSClient satisfies this type, so you can simply pass one.
 * It's declared structurally so that you can pass a stub in tests.
 */
export type Signer = {
  send(command: SignCommand): Promise<SignCommandOutput>;
};

/**
 * This function reads the region out of a KMS key ARN.
 *
 * An ARN looks like arn:aws:kms:<region>:<account>:key/<id>, so a caller
 * passing one has already said which region the key is in. An alias name or a
 * bare key id carries none, and an empty string is returned.
 */
export const regionFromKeyId = (keyId: string): string => {
  if (!keyId.startsWith("arn:")) {
    return "";
  }
  return keyId.split(":")[3] ?? "";
};

/** Inputs of the createJwt function. */
export type Inputs = {
  /** A key id, a key ARN, an alias name, or an alias ARN of a KMS key. */
  keyId: string;
  /**
   * The AWS region of the key.
   *
   * If it's omitted, the region is read from keyId when that's an ARN.
   * Failing that, the AWS SDK resolves it as it normally would, from
   * AWS_REGION, ~/.aws/config and so on.
   * It's ignored when client is given, as that client already has one.
   */
  region?: string;
  /**
   * A KMS client.
   *
   * If it's omitted, a new KMSClient is created.
   * Then a region and credentials are resolved from the standard AWS
   * environment variables.
   */
  client?: Signer;
};

/**
 * A JSON Web Token expires in 10 minutes at most.
 * https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
 */
const expiresIn = 600;

/**
 * A JSON Web Token is issued 60 seconds in the past so that GitHub doesn't
 * reject it even if the clock of this machine is slightly ahead.
 */
const issuedAtMargin = 60;

/** A cached JSON Web Token is reused only if it lives longer than this. */
const cacheMargin = 60;

const encoder = new TextEncoder();

const encodedHeader = encodeBase64Url(encoder.encode(JSON.stringify({
  alg: "RS256",
  typ: "JWT",
})));

type Cache = {
  appId: string;
  expiration: number;
  jwt: Jwt;
};

/**
 * This function creates a callback signing GitHub App JSON Web Tokens with AWS
 * KMS.
 *
 * The KMS key must be an RSA key whose usage is SIGN_VERIFY, and the caller
 * needs the kms:Sign permission on it.
 * The returned callback caches a JSON Web Token until it's about to expire, so
 * a KMS Sign API call isn't made for every request.
 */
export const createJwt = (inputs: Inputs): CreateJwt => {
  const client: Signer = inputs.client ??
    new KMSClient({
      // Undefined leaves the region to the AWS SDK's own resolution.
      region: inputs.region || regionFromKeyId(inputs.keyId) || undefined,
    });
  let cache: Cache | undefined;

  return async (appId: string | number, timeDifference?: number) => {
    const iss = String(appId);
    const now = Math.floor(Date.now() / 1000) + (timeDifference ?? 0);

    if (timeDifference) {
      // The clock skew was detected, so a cached token is out of date too.
      cache = undefined;
    } else if (
      cache && cache.appId === iss && cache.expiration - now > cacheMargin
    ) {
      return cache.jwt;
    }

    const iat = now - issuedAtMargin;
    const exp = iat + expiresIn;
    const encodedPayload = encodeBase64Url(encoder.encode(JSON.stringify({
      iat,
      exp,
      iss,
    })));
    const message = `${encodedHeader}.${encodedPayload}`;

    const output = await client.send(
      new SignCommand({
        KeyId: inputs.keyId,
        Message: encoder.encode(message),
        MessageType: "RAW",
        // GitHub requires RS256, which is RSASSA-PKCS1-v1_5 with SHA-256.
        SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
      }),
    );
    if (!output.Signature) {
      throw new Error("AWS KMS returned no signature");
    }

    // AWS KMS returns a raw PKCS #1 signature for RSA keys, which is exactly
    // what a JSON Web Token signature is. Only ECDSA signatures are DER encoded.
    const jwt = {
      jwt: `${message}.${encodeBase64Url(output.Signature)}`,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
    if (!timeDifference) {
      cache = { appId: iss, expiration: exp, jwt };
    }
    return jwt;
  };
};
