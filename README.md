# github-app-jwt-aws-kms-ts

[![JSR](https://jsr.io/badges/@suzuki-shunsuke/github-app-jwt-aws-kms)](https://jsr.io/@suzuki-shunsuke/github-app-jwt-aws-kms)

github-app-jwt-aws-kms-ts is a JSR package to sign GitHub App JSON Web Tokens
with AWS KMS.

A GitHub App private key stored in AWS KMS can never be exported, so you can't
pass it to a library which expects the key itself. This package signs JSON Web
Tokens through the KMS Sign API instead, and returns a callback which
[@suzuki-shunsuke/github-app-token](https://jsr.io/@suzuki-shunsuke/github-app-token)
and [@octokit/auth-app](https://github.com/octokit/auth-app.js) accept in place
of a private key.

Only the KMS Sign API is called, over HTTPS with a SigV4 signature, so the AWS
SDK isn't a dependency. That matters most in a GitHub Action, where the action
is bundled and every job downloads it: `@aws-sdk/client-kms` adds over a
megabyte to a bundle in order to make one API call.

## Example

```ts
import { create } from "@suzuki-shunsuke/github-app-token";
import { createJwt } from "@suzuki-shunsuke/github-app-jwt-aws-kms";

const token = await create({
  appId: "123456",
  createJwt: createJwt({
    keyId:
      "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000",
  }),
  owner: "suzuki-shunsuke",
});
```

It works with @octokit/auth-app directly too.

```ts
import { createAppAuth } from "@octokit/auth-app";
import { createJwt } from "@suzuki-shunsuke/github-app-jwt-aws-kms";

const auth = createAppAuth({
  appId: "123456",
  createJwt: createJwt({ keyId: "..." }),
});
```

## KMS key

The key must be an RSA key whose usage is `SIGN_VERIFY`. GitHub App private keys
are RSA 2048, so import the existing key material into KMS to keep the public
key GitHub has registered.

Tokens are signed with `RSASSA_PKCS1_V1_5_SHA_256`, which is the `RS256`
algorithm GitHub requires.

The caller needs the `kms:Sign` permission on the key.

## The AWS region

A key ARN carries its region, so passing `keyId` as an ARN is enough and nothing
else needs setting. An alias name or a bare key id carries none, so pass
`region`, or set `AWS_REGION` or `AWS_DEFAULT_REGION`. `createJwt` throws
straight away when it can't work one out, rather than failing at the first
signature.

```ts
const sign = createJwt({ keyId: "alias/example", region: "us-east-1" });
```

## Credentials

By default credentials are read from `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, which is what
`aws-actions/configure-aws-credentials` exports on GitHub Actions.

Pass `credentials` for any other source. A function is called once per Sign API
call, so a provider that refreshes an expiring session works, and a cached token
costs no call and therefore no credentials.

```ts
import { credentials } from "@suzuki-shunsuke/actions-aws-oidc";

// Assume an IAM role with the GitHub OIDC token instead of exporting
// credentials into the job.
const sign = createJwt({
  keyId: "...",
  credentials: () => credentials({ roleArn: "..." })(),
});
```

An AWS SDK credential provider fits the same shape, so the full credential chain
is still available to anyone who wants it.

```ts
import { fromNodeProviderChain } from "@aws-sdk/credential-providers";

const sign = createJwt({ keyId: "...", credentials: fromNodeProviderChain() });
```

## Testing

`fetch` is an input, so the KMS API can be stubbed without a network.

```ts
const sign = createJwt({
  keyId: "...",
  credentials: { accessKeyId: "...", secretAccessKey: "..." },
  fetch: (url, init) => Promise.resolve(new Response("...")),
});
```

## Caching

The returned callback caches a JSON Web Token until it's about to expire.
@octokit/auth-app requests a token for every API call which authenticates as the
app, so this keeps the number of KMS Sign API calls down.

A token is not cached when @octokit/auth-app reports a clock skew, because the
cached one is out of date in that case.

## Permissions

Deno needs `--allow-net` to call AWS KMS, and `--allow-env` to read the region
and the credentials from environment variables. Neither is needed when `region`,
`credentials` and `fetch` are all passed in.
