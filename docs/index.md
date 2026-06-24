{% laika.title = "Homepage" %}

# Jots

Jots is a library for working with [JSON Web Tokens (JWTs)](https://en.wikipedia.org/wiki/JSON_Web_Token) in [Scala](https://www.scala-lang.org), [Scala.js](https://www.scala-js.org) and [Scala Native](https://scala-native.org).

- Features cross-platform [cryptography](features/cryptography.md) for Scala, Scala.js (Node.js) and Scala Native (OpenSSL).
- Supports [signing](features/signing.md) and [verification](features/verification.md) for standard ECDSA, EdDSA, HMAC and RSA algorithms.
- Provides [testing](features/testing.md) support with [ScalaCheck](https://scalacheck.org) generators and String interpolators for secrets.
- Separates token parsing and verification, so tokens can be inspected before verification.
- Handles token signature verification using keys from a [JSON Web Key Set (JWK Set)](features/verification.md#json-web-key-set).
- Based on the [cats-effect](https://typelevel.org/cats-effect), [circe-jawn](https://circe.io/circe), [literally](https://github.com/typelevel/literally) and [scodec-bits](https://github.com/scodec/scodec-bits) libraries.

Documentation is kept up-to-date, currently documenting v@VERSION@ on Scala @SCALA_DOCS_VERSION@.

## Getting Started

To get started with [sbt](https://scala-sbt.org), add the following line to your `build.sbt` file.

```scala
libraryDependencies += "@ORGANIZATION@" %% "jots" % "@VERSION@"
```

Published for Scala @SCALA_PUBLISH_VERSIONS@, Scala.js @SCALA_JS_MAJOR_MINOR_VERSION@ and Scala Native @SCALA_NATIVE_MAJOR_MINOR_VERSION@.

For changes between versions, please refer to the [release notes](https://github.com/vlovgr/jots/releases).

For Scala.js or Scala Native, replace the `%%` with `%%%` above.

Signing and verification is covered in the [introduction](introduction.md).

### Runtime Versions

The library relies on each platform's native cryptography. The minimum required runtime version depends on the platform and algorithms being used. Prefer the latest runtime version available, as it usually has the best security posture. Following is some general guidance on minimum recommended versions.

- For Scala on the JVM, use Java 17 (LTS) or a later version.
- For Scala.js on Node.js, use Node.js 22 (LTS) or a later version.
- For Scala Native using OpenSSL, use OpenSSL 3.x or a later version.

### Supported Algorithms

Refer to the table below for a list of supported signing algorithms.

| Algorithm | Algorithm Description                          |
| --------- | ---------------------------------------------- |
| `Ed25519` | EdDSA using the Ed25519 curve                  |
| `Ed448`   | EdDSA using the Ed448 curve                    |
| `ES256`   | ECDSA using P-256 and SHA-256                  |
| `ES384`   | ECDSA using P-384 and SHA-384                  |
| `ES512`   | ECDSA using P-521 and SHA-512                  |
| `HS256`   | HMAC using SHA-256                             |
| `HS384`   | HMAC using SHA-384                             |
| `HS512`   | HMAC using SHA-512                             |
| `PS256`   | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |
| `PS384`   | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |
| `PS512`   | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |
| `RS256`   | RSASSA-PKCS-v1_5 using SHA-256                 |
| `RS384`   | RSASSA-PKCS-v1_5 using SHA-384                 |
| `RS512`   | RSASSA-PKCS-v1_5 using SHA-512                 |

## Dependencies

Refer to the table below for dependencies and version support across modules.

| Module         | Dependencies                                                                                               | Scala                          |
| -------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `jots`         | `jots-crypto` and circe-jawn @CIRCE_VERSION@                                                               | Scala @SCALA_PUBLISH_VERSIONS@ |
| `jots-crypto`  | cats-effect-kernel @CATS_EFFECT_VERSION@, literally @LITERALLY_VERSION@, scodec-bits @SCODEC_BITS_VERSION@ | Scala @SCALA_PUBLISH_VERSIONS@ |
| `jots-testing` | `jots` and cats-effect @CATS_EFFECT_VERSION@, scalacheck @SCALACHECK_VERSION@                              | Scala @SCALA_PUBLISH_VERSIONS@ |

For Scala.js and Scala Native version support, refer to the following table.

| Module         | Scala.js                                                                 | Scala Native                                                                     |
| -------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `jots`         | Scala.js @SCALA_JS_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) | Scala Native @SCALA_NATIVE_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) |
| `jots-crypto`  | Scala.js @SCALA_JS_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) | Scala Native @SCALA_NATIVE_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) |
| `jots-testing` | Scala.js @SCALA_JS_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) | Scala Native @SCALA_NATIVE_MAJOR_MINOR_VERSION@ (Scala @SCALA_PUBLISH_VERSIONS@) |

## Compatibility

Backwards binary compatibility for the library is guaranteed between patch versions.

Release version `@MAJOR_VERSION@.a.b` is backwards binary compatible with `@MAJOR_VERSION@.a.c` for any `b > c`.

The compatibility guarantee is according to the [Early SemVer](https://www.scala-lang.org/blog/2021/02/16/preventing-version-conflicts-with-versionscheme.html#early-semver-and-sbt-version-policy) version scheme.

## Signatures

Stable release artifacts are signed with the [`0DF8 8F31 EB37 24D8`](https://keys.openpgp.org/search?q=0DF88F31EB3724D8A7183458981986BC3219D379) key.

## Snapshots

To use the latest snapshot release, add the following lines to your `build.sbt` file.

```scala
resolvers += Resolver.sonatypeCentralSnapshots

libraryDependencies += "@ORGANIZATION@" %% "jots" % "@SNAPSHOT_VERSION@"
```

## License

The library is distributed under the [Apache License, Version 2.0](https://github.com/vlovgr/jots/blob/main/license.txt).
