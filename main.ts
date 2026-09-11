/**
 * This module signs GitHub App JSON Web Tokens with AWS KMS.
 *
 * It's useful when a GitHub App private key is stored in AWS KMS and can never
 * be exported.
 * The returned callback is passed to
 * {@link https://jsr.io/@suzuki-shunsuke/github-app-token | @suzuki-shunsuke/github-app-token}'s
 * create function instead of a private key.
 *
 * Only the KMS Sign API is called, over HTTPS with a SigV4 signature, so the
 * AWS SDK isn't needed. That matters for a GitHub Action, where the SDK is
 * bundled into the action and every job downloads it: @aws-sdk/client-kms adds
 * over a megabyte to a bundle to make one API call.
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

import process from "node:process";
import { AwsClient } from "aws4fetch";
import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
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

/** AWS credentials allowed to call kms:Sign on the key. */
export type Credentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
};

/**
 * Credentials, or a function returning them.
 *
 * A function is called once per Sign call, so a provider that refreshes an
 * expiring session works. @suzuki-shunsuke/actions-aws-oidc returns one that
 * assumes an IAM role with the GitHub OIDC token.
 */
export type CredentialsProvider =
  | Credentials
  | (() => Credentials | Promise<Credentials>);

/**
 * The part of fetch which this module uses.
 *
 * globalThis.fetch satisfies this type, so it's only worth passing to stub the
 * KMS API in tests.
 */
export type Fetch = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

/** Inputs of the createJwt function. */
export type Inputs = {
  /** A key id, a key ARN, an alias name, or an alias ARN of a KMS key. */
  keyId: string;
  /**
   * The AWS region of the key.
   *
   * If it's omitted, the region is read from keyId when that's an ARN, and
   * failing that from AWS_REGION or AWS_DEFAULT_REGION.
   * An alias name or a bare key id carries no region, so one of those has to
   * supply it.
   */
  region?: string;
  /**
   * AWS credentials, or a function returning them.
   *
   * If it's omitted, they're read from AWS_ACCESS_KEY_ID,
   * AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN, which is what
   * aws-actions/configure-aws-credentials exports.
   * Pass them explicitly for any other source, such as an AWS SDK credential
   * provider or an IAM role assumed with an OIDC token.
   */
  credentials?: CredentialsProvider;
  /** It defaults to globalThis.fetch, and exists so tests can stub it. */
  fetch?: Fetch;
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

const resolveRegion = (inputs: Inputs): string => {
  const region = inputs.region || regionFromKeyId(inputs.keyId) ||
    process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
  if (!region) {
    throw new Error(
      "the AWS region is unknown: pass region, pass keyId as an ARN, or set AWS_REGION",
    );
  }
  return region;
};

const resolveCredentials = async (
  credentials: CredentialsProvider | undefined,
): Promise<Credentials> => {
  if (typeof credentials === "function") {
    return await credentials();
  }
  if (credentials) {
    return credentials;
  }
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      "no AWS credentials: pass credentials, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
    );
  }
  return {
    accessKeyId,
    secretAccessKey,
    sessionToken: process.env.AWS_SESSION_TOKEN,
  };
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
 * This function calls the KMS Sign API and returns the raw signature.
 *
 * KMS speaks JSON over HTTPS, so the request is the operation name in the
 * X-Amz-Target header and a JSON body, signed with SigV4 by aws4fetch.
 */
const sign = async (
  inputs: Inputs,
  region: string,
  message: Uint8Array,
): Promise<Uint8Array> => {
  const credentials = await resolveCredentials(inputs.credentials);
  const client = new AwsClient({ ...credentials, service: "kms", region });
  const request = await client.sign(`https://kms.${region}.amazonaws.com/`, {
    method: "POST",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": "TrentService.Sign",
    },
    body: JSON.stringify({
      KeyId: inputs.keyId,
      Message: encodeBase64(message),
      MessageType: "RAW",
      // GitHub requires RS256, which is RSASSA-PKCS1-v1_5 with SHA-256.
      SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
    }),
  });
  const doFetch = inputs.fetch ?? globalThis.fetch;
  const response = await doFetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: await request.text(),
  });
  if (!response.ok) {
    throw new Error(
      `AWS KMS returned ${response.status}: ${await response.text()}`,
    );
  }
  const { Signature } = await response.json() as { Signature?: string };
  if (!Signature) {
    throw new Error("AWS KMS returned no signature");
  }
  return decodeBase64(Signature);
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
  const region = resolveRegion(inputs);
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

    // AWS KMS returns a raw PKCS #1 signature for RSA keys, which is exactly
    // what a JSON Web Token signature is. Only ECDSA signatures are DER encoded.
    const signature = await sign(inputs, region, encoder.encode(message));

    const jwt = {
      jwt: `${message}.${encodeBase64Url(signature)}`,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
    if (!timeDifference) {
      cache = { appId: iss, expiration: exp, jwt };
    }
    return jwt;
  };
};
