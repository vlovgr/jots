# Token Signing

Token signing involves four library types: `JwtEncoder`, `JwtBuilder`, `JwtSigning` and `SignedJwt`.

```mermaid
%%{init: {"fontFamily": "monospace"}}%%
graph LR
A --> |"JwtEncoder[A]"| JwtBuilder
JwtBuilder --> |"JwtSigning[IO]"| SignedJwt["IO[SignedJwt]"]
SignedJwt --> |"SignedJwt#show"| String["IO[String]"]
```

- The type `A` is our custom type representing the token (usually the claims).
- The `JwtEncoder[A]` describes how to encode `A` as a `JwtBuilder` instance.
- The `JwtBuilder` type describes a token being constructed, prior to signing.
- The `JwtSigning[IO]` describes how to sign `JwtBuilder` as `IO[SignedJwt]`.
- The `SignedJwt` represents a signed token (JWT) which has _not_ yet been verified.
- The `SignedJwt#show` function returns the token in its JWT `String` representation.

Having `JwtEncoder[A]` and `JwtSigning[IO]` in place, signing code look as follows.

```scala
a.asJwt.signWith(signing).map(_.show) // IO[String]
```

For a brief introduction to token signing, see the [introduction](../introduction.md#token-signing).

## Encoding Tokens

While it's possible to manually define a `JwtBuilder`, it is often easier to use `JwtEncoder`. Following is the `UserJwt` type and `JwtEncoder` as seen in the [introduction](../introduction.md#token-signing). The `JwtEncoder` uses the `Encoder.AsObject` for encoding the `UserJwt` as the claims of a `JwtBuilder`, which is likely the most common case.

```scala mdoc:silent
import io.circe.Encoder
import jots.JwtEncoder

final case class UserJwt(userId: String, expiresAt: Long, issuedAt: Long)

object UserJwt {
  given Encoder.AsObject[UserJwt] =
    Encoder.forProduct3("userId", "exp", "iat")(claims =>
      (claims.userId, claims.expiresAt, claims.issuedAt)
    )

  given JwtEncoder[UserJwt] =
    JwtEncoder.encodeClaims
}
```

It is possible to further customize the `JwtEncoder` by, for example, including additional header fields.

```scala mdoc:silent
import io.circe.syntax.*

JwtEncoder
  .encodeClaims[UserJwt]
  .mapHeader(_.add("key", "value".asJson))
```

Note signing-related header keys (e.g. `alg`) are set by `JwtSigning` during signing, and not manually.

If we don't want to define an `Encoder.AsObject`, we can use `JwtEncoder.encodeClaimsWith` instead.

```scala mdoc:silent
import jots.JwtClaims

JwtEncoder.encodeClaimsWith { (userJwt: UserJwt) =>
  JwtClaims.empty.addAll(
    "userId" -> userJwt.userId.asJson,
    "exp" -> userJwt.expiresAt.asJson,
    "iat" -> userJwt.issuedAt.asJson
  )
}
```

For full flexibility, `JwtEncoder.encodeWith` describes the entire `JwtBuilder` instance.

```scala mdoc:silent
import jots.JwtBuilder

JwtEncoder.encodeWith { (userJwt: UserJwt) =>
  JwtBuilder.default.withClaims(
    JwtClaims.empty.addAll(
      "userId" -> userJwt.userId.asJson,
      "exp" -> userJwt.expiresAt.asJson,
      "iat" -> userJwt.issuedAt.asJson
    )
  )
}
```

As seen in the examples above, a `JwtBuilder` consists of a `JwtHeader` and `JwtClaims`. `JwtBuilder.default` uses `JwtHeader.default` which includes `{"typ":"JWT"}`. There is `JwtBuilder.empty` and `JwtHeader.empty` if this is unwanted (plus the `withType` and `withoutType` functions on `JwtHeader` as options).

## Signing Tokens

Once we have a custom `UserJwt` type and `JwtEncoder[UserJwt]` defined, we also need a `JwtSigning` instance. We create instances by choosing the effect type (e.g. `IO`), selecting the algorithm, and by providing a private or secret key. Following is an example on how to create a `JwtSigning` for `ES256` (ECDSA with P-256 and SHA-256).

```scala mdoc:silent
import cats.effect.SyncIO
import cats.syntax.all.*
import jots.JwtEcdsaAlgorithm.ES256
import jots.JwtSigning
import jots.crypto.PrivateKey

val jwtSigning: SyncIO[JwtSigning[SyncIO]] =
  for {
    privateKey <- PrivateKey(
      """
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
        OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
        1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
        -----END PRIVATE KEY-----
      """
    ).liftTo[SyncIO]
    signing <- JwtSigning.default[SyncIO].ecdsa(ES256, privateKey)
  } yield signing
```

@:callout(info)
Note we use `SyncIO`, and later `unsafeRunSync()`, to show the final result. In practice, you would most likely use `IO` without `unsafeRunSync()`. We should take care to _not_ put secrets, like `PrivateKey`, in source code.
@:@

### Key Requirements

In the example above, we note creating `JwtSigning` instances returns an effect and not `JwtSigning` directly. The effect is checking whether the private or secret key is sufficiently strong or not according to the JWT specification. When the key requirements in the following list are not met, an exception will be raised. The key requirements also apply for public and secret keys when creating `JwtVerification` instances for [verifying tokens](verification.md#key-requirements).

| Algorithm | Key Requirement                   | Key Recommendation             |
| --------- | --------------------------------- | ------------------------------ |
| `Ed25519` | Exactly 256 bits (32 bytes)       |                                |
| `Ed448`   | Exactly 456 bits (57 bytes)       |                                |
| `ES256`   | Exactly 256 bits (32 bytes)       |                                |
| `ES384`   | Exactly 384 bits (48 bytes)       |                                |
| `ES512`   | Exactly 521 bits (65 or 66 bytes) |                                |
| `HS256`   | At least 256 bits (32 bytes)      |                                |
| `HS384`   | At least 384 bits (48 bytes)      |                                |
| `HS512`   | At least 512 bits (64 bytes)      |                                |
| `PS256`   | At least 2048 bits (256 bytes)    |                                |
| `PS384`   | At least 2048 bits (256 bytes)    | At least 3072 bits (384 bytes) |
| `PS512`   | At least 2048 bits (256 bytes)    | At least 4096 bits (512 bytes) |
| `RS256`   | At least 2048 bits (256 bytes)    |                                |
| `RS384`   | At least 2048 bits (256 bytes)    | At least 3072 bits (384 bytes) |
| `RS512`   | At least 2048 bits (256 bytes)    | At least 4096 bits (512 bytes) |

While it is _not_ recommended, the key requirements check can be disabled using `JwtSigningBuilder` by using the `withCheckKeyRequirements` function. It is also possible to use separate effects for creating `JwtSigning` and for signing tokens. The following example shows how both can be done.

```scala mdoc:silent
import cats.effect.IO
import jots.JwtSigningBuilder
import scala.util.Try

val jwtSigningTry: Try[JwtSigning[IO]] =
  for {
    privateKey <- PrivateKey("..").liftTo[Try]
    signing <- JwtSigningBuilder
      .default[Try]
      .signWith[IO]
      .ecdsa(ES256, privateKey)
      .withCheckKeyRequirements(false) // Not recommended
      .build
  } yield signing
```

### Signature Generation

The `JwtSigning` instance is normally reused multiple times. In the following case, we only use it once for example purposes. To generate a `SignedJwt` for a `UserJwt`, we first generate a `JwtBuilder` with `userJwt.asJwt`. Lastly, `JwtBuilder` is signed using `signWith(signing)` to generate a `SignedJwt`.

```scala mdoc:silent
import jots.SignedJwt
import jots.syntax.*

val userJwt = UserJwt(
  userId = "8d3bbd14-dfd9-47fa-aab4-d76daf00b4f1",
  expiresAt = 3345062400L,
  issuedAt = 1767225600L
)

val signedJwt: SyncIO[SignedJwt] =
  for {
    signing <- jwtSigning
    signedJwt <- userJwt.asJwt.signWith(signing)
  } yield signedJwt
```

The `SignedJwt` represent a parsed or generated token which has _not_ been verified. Since we've generated this token, we can be reasonably confident it also verifies successfully. However, in the general case, a `SignedJwt` should not be trusted before it has been verified. `VerifiedJwt` represents a verified token, covered on the [verification](verification.md) page.

Finally, let's generate the `String` representation of the token using `show`.

```scala mdoc
signedJwt.map(_.show).unsafeRunSync()
```

### JSON Web Key

There is a `Jwk` type representing a JSON Web Key (JWK). A `Jwk` can be used for signing as long as it meets all of the following criteria. For keys which do not match the criteria, an exception is raised.

1. If `key_ops` is specified, it must contain the `sign` operation.
2. If `use` is specified for the key, it must be set to `sig` (signature).

Additionally, the private or secret key must be supported by the library. This means having the `kty` parameter set with other key-type appropriate parameters. Depending on if `alg` (algorithm) is set or not on the key, the algorithm has to match with the provided algorithm.

#### JWK Example

Following is an example of signing a token using a `Jwk` private key.

```scala mdoc:silent
import jots.Jwk

val signedJwtJwk: SyncIO[SignedJwt] =
  for {
    jwk <- Jwk(
      "kty" -> "EC".asJson,
      "d" -> "J8dDt-BOCMfRm_ZNaioMeMQBGDewXEvC5WSpvijtCz4".asJson,
      "use" -> "sig".asJson,
      "crv" -> "P-256".asJson,
      "kid" -> "h7G57sMQDgpDPh-qbImQOeDLbBLZybe_GXjsGKqZwfk".asJson,
      "x" -> "lzDfLfjnBIN3ZGoc1wS9fN3wyoNiwYcq8FnAhK_Gnmo".asJson,
      "y" -> "U4Y4v5C3emBPjCSxRpce2wSQvb091uCM3tVFzqwne5c".asJson,
      "alg" -> "ES256".asJson
    ).liftTo[SyncIO]
    signing <- JwtSigning.default[SyncIO].jwk(ES256, jwk)
    jwt <- userJwt.asJwt.signWith(signing)
  } yield jwt
```

If the `Jwk` has a `kid` (Key ID) set, this will also be set in the header of the token.

```scala mdoc:to-string
signedJwtJwk.unsafeRunSync()
```

#### JWK String Interpolator

There is a `String` interpolator available for `Jwk`.

```scala mdoc:to-string
import jots.syntax.*

val jwk =
  jwk"""
    {
      "kty": "EC",
      "d": "J8dDt-BOCMfRm_ZNaioMeMQBGDewXEvC5WSpvijtCz4",
      "use": "sig",
      "crv": "P-256",
      "kid": "h7G57sMQDgpDPh-qbImQOeDLbBLZybe_GXjsGKqZwfk",
      "x": "lzDfLfjnBIN3ZGoc1wS9fN3wyoNiwYcq8FnAhK_Gnmo",
      "y": "U4Y4v5C3emBPjCSxRpce2wSQvb091uCM3tVFzqwne5c",
      "alg": "ES256"
    }
  """
```

@:callout(info)
Note the `String` interpolator can be used for private keys, public keys and secret keys. Since token signing makes use of private keys or secret keys, we should take care to _not_ put secrets in source code.
@:@

## Custom Signing

It is possible to create custom `JwtSigning` instances by using `JwtSigning.signWith` or by directly instantiating or extending `JwtSigning`. The `SignedJwt` type returned by `JwtSigning` place no restrictions on the token signature. Signatures are even allowed to be empty, which can be the case for unsecured tokens. Note [token verification](verification.md) will always reject invalid signatures and unsecured tokens.
