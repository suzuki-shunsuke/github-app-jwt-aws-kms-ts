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
else needs setting. For an alias name or a bare key id, pass `region`, or leave
it to the AWS SDK, which resolves `AWS_REGION` and `~/.aws/config` as it
normally does.

```ts
const sign = createJwt({ keyId: "alias/example", region: "us-east-1" });
```

`region` is ignored when you pass your own `client`, since that client already
has one.

## AWS client

By default a `KMSClient` is created internally, so a region and credentials are
resolved from the standard AWS environment variables. On GitHub Actions,
`aws-actions/configure-aws-credentials` sets them up.

You can also pass your own client.

```ts
import { KMSClient } from "@aws-sdk/client-kms";
import { createJwt } from "@suzuki-shunsuke/github-app-jwt-aws-kms";

const sign = createJwt({
  keyId: "...",
  client: new KMSClient({ region: "us-east-1" }),
});
```

The `client` option is typed structurally as `Signer`, so a stub is accepted in
tests as well.

## Caching

The returned callback caches a JSON Web Token until it's about to expire.
@octokit/auth-app requests a token for every API call which authenticates as the
app, so this keeps the number of KMS Sign API calls down.

A token is not cached when @octokit/auth-app reports a clock skew, because the
cached one is out of date in that case.

## Permissions

Deno needs `--allow-env`, `--allow-net` and `--allow-sys` to call AWS KMS.
`--allow-read` is also needed if credentials come from `~/.aws`.
