# Verifying Tokens

Token verification involves four library types: `SignedJwt`, `JwtVerification`, `VerifiedJwt` and `JwtDecoder`.

```mermaid
%%{init: {"fontFamily": "monospace"}}%%
graph LR
String --> |"SignedJwt.parse"| SignedJwt["IO[SignedJwt]"]
SignedJwt --> |"JwtVerification[IO]"| VerifiedJwt["IO[VerifiedJwt]"]
VerifiedJwt --> |"JwtDecoder[A]"| A["IO[A]"]
```

- The `SignedJwt.parse` function parses a signed token (JWT) into its different parts.
- The `SignedJwt` represents a signed token (JWT) which has _not_ yet been verified.
- The `JwtVerification[IO]` describes token verification (at least the signature).
- The `VerifiedJwt` type describes verified tokens (at minimum signature verified).
- The `JwtDecoder[A]` describes how to decode `VerifiedJwt` to an `A` instance.
- The type `A` is our custom type representing the token (usually the claims).

Having `JwtDecoder[A]` and `JwtVerification[IO]` in place, verification code look as follows.

```scala
verification.decodeAs[A](jwt) // IO[A]
```

For a brief introduction to token verification, see the [introduction](../introduction.md#verifying-tokens).

## Decoding Tokens

While it's possible to manually decode a `VerifiedJwt`, it is often easier to use `JwtDecoder`. Following is the `UserJwt` type and `JwtDecoder` as seen in the [introduction](../introduction.md#verifying-tokens). The `JwtDecoder` uses the `Decoder` to decode the `UserJwt` from the claims of a `VerifiedJwt`, which is likely the most common case.

```scala mdoc:silent
import io.circe.Decoder
import jots.JwtDecoder

final case class UserJwt(userId: String, expiresAt: Long, issuedAt: Long)

object UserJwt {
  given Decoder[UserJwt] =
    Decoder.forProduct3("userId", "exp", "iat")(UserJwt.apply)

  given JwtDecoder[UserJwt] =
    JwtDecoder.decodeClaims
}
```

The `JwtDecoder` is similar to `Decoder`, except it decodes from `VerifiedJwt` instead of `Json`. This includes the parsed header, claims and signature. In some cases, it's useful to extract header details in addition to the claims. We can make use of `JwtDecoder.decodeWith` to create custom `JwtDecoder` instances.

```scala mdoc:silent
final case class UserJwtNonce(nonce: String, userJwt: UserJwt)

given JwtDecoder[UserJwtNonce] =
  JwtDecoder.decodeWith { verifiedJwt =>
    for {
      nonce <- verifiedJwt.header.toJson.hcursor.get[String]("nonce")
      userJwt <- verifiedJwt.claims.toJson.as[UserJwt]
    } yield UserJwtNonce(nonce, userJwt)
  }
```

## Token Verification

Once we have a custom `UserJwt` type and `JwtDecoder[UserJwt]`, we also need a `JwtVerification` instance. We create instances by choosing the effect type (e.g. `IO`), selecting the algorithm, and by providing a public or secret key. Following is an example on how to create a `JwtVerification` for `ES256` (ECDSA with P-256 and SHA-256).

```scala mdoc:silent
import cats.effect.SyncIO
import cats.syntax.all.*
import jots.JwtEcdsaAlgorithm.ES256
import jots.JwtVerification
import jots.crypto.PublicKey

val jwtVerification: SyncIO[JwtVerification[SyncIO]] =
  for {
    publicKey <- PublicKey(
      """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
        q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        -----END PUBLIC KEY-----
      """
    ).liftTo[SyncIO]
    verification <- JwtVerification.default[SyncIO].ecdsa(ES256, publicKey)
  } yield verification
```

@:callout(info)
Note we use `SyncIO`, and later `unsafeRunSync()`, to show the final result. In practice, you would most likely use `IO` without `unsafeRunSync()`.
@:@

If we know the `PublicKey` in advance, there is also a `publicKey` String interpolator available.

```scala mdoc:silent
import jots.crypto.syntax.*

val publicKey: PublicKey =
  publicKey"""
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
    q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
    -----END PUBLIC KEY-----
  """
```

### Key Requirements

In the example above, we note creating `JwtVerification` instances returns an effect and not `JwtVerification` directly. The effect is checking whether the public or secret key is sufficiently strong or not according to the JWT specification. When the [key requirements](signing.md#key-requirements) are not met, an exception will be raised.

While it is _not_ recommended, the key requirements check can be disabled using `JwtVerificationBuilder` by using the `withCheckKeyRequirements` function. It is also possible to use separate effects for creating `JwtVerification` and for verifying tokens. The following example shows how both can be done.

```scala mdoc:silent
import cats.effect.IO
import jots.JwtVerificationBuilder
import scala.util.Try

val jwtVerificationTry: Try[JwtVerification[IO]] =
  JwtVerificationBuilder
    .default[Try]
    .verifyWith[IO]
    .ecdsa(ES256, publicKey)
    .withCheckKeyRequirements(false) // Not recommended
    .build
```

### Signature Verification

The `JwtVerification` instance is normally reused. In the following case, we only use it once for example purposes. To decode a `UserJwt` from a token `String`, going through the default verification, we can use the `decodeAs` function on `JwtVerification` once the instance is available.

```scala mdoc:silent
val jwt = "eyJ0eXAiOiJKV1QiLCJraWQiOiI2MzRjODBhMy0zN2Y5LTQyYmMtYTY1Ny0wYmY0Zjc1OWIxZTMiLCJhbGciOiJFUzI1NiJ9.eyJ1c2VySWQiOiI4ZDNiYmQxNC1kZmQ5LTQ3ZmEtYWFiNC1kNzZkYWYwMGI0ZjEiLCJleHAiOjMzNDUwNjI0MDAsImlhdCI6MTc2NzIyNTYwMH0.RRqlOw-CuSgt7-24kzsbVs5Te4WHhuOCzEVWsMZEtQTsHr2_Hkjk4qjE3PaEgFcYCOnsbs20QNQZZ5KSWm5bUQ"

val userJwt: SyncIO[UserJwt] =
  for {
    verification <- jwtVerification
    userJwt <- verification.decodeAs[UserJwt](jwt)
  } yield userJwt
```

Finally, let's run the effect to show the token could be verified and decoded successfully.

```scala mdoc
userJwt.unsafeRunSync()
```

There's also `JwtVerification#decode` for returning a `VerifiedJwt` (without `JwtDecoder` requirement). Similarly, there is `verify` for returning a `VerifiedJwt` from a `SignedJwt`, and `verifyAs` for also decoding with `JwtDecoder`. These are useful when we want to handle parsing or decoding separately from `JwtVerification`. Note these can be overridden for [custom verifications](#custom-verification).

### Default Verifications

The default `JwtVerification` instances perform the following verifications.

- The provided public or secret key must meet the [key requirements](#key-requirements).
- The signature is verified using the algorithm and public or secret key.
- The expiration claim (`exp`), when present, is verified to be in the future.
- The not-before claim (`nbf`), when present, is verified to not be in the future.
- Tokens containing a set of critical headers (`crit`) will be rejected by default.

Except for the signature verification, these checks can be adjusted using various `JwtVerificationBuilder` methods. There is also additional checks which can be enabled, like requiring certain claims to be present, and further tweaks, like accounting for clock skew. If the provided verifications are not enough, resort to [custom verifications](#custom-verification).

### JSON Web Key Set

There is a `Jwk` type representing a JSON Web Key (JWK) and a `JwkSet` type for JWK Set. A `JwkSet` can be used for verification as long as it contains at least one key that meet all of the following criteria. Keys which do not match the criteria will be filtered out, and if there are no keys available after filtering, an exception is raised.

1. The `kid` (Key ID) parameter must be specified for the key.
2. If `key_ops` is specified, it must contain the `verify` operation.
3. If `use` is specified for the key, it must be set to `sig` (signature).

Additionally, the public or secret key must be supported by the library. This means having the `kty` parameter set with other key-type appropriate parameters. Depending on if `alg` (algorithm) is set or not on the key, the algorithm has to be supported and allowed, or there must be at least one allowed algorithm for the key type.

#### JWK Set Example

Following is an example of decoding using a JWK Set. The keys are normally retrieved from an HTTP endpoint, but this is beyond the scope of the library. Instead, we provide the `Jwk` directly and create a `JwkSet` using the key. We create a `JwtVerification` instance, allowing all supported ECDSA algorithms, and finally decode the [token](#signature-verification) from before.

```scala mdoc:silent
import io.circe.syntax.*
import jots.Jwk
import jots.JwkSet
import jots.JwtEcdsaAlgorithm

val userJwtJwk: SyncIO[UserJwt] =
  for {
    jwk <- Jwk(
      "kty" -> "EC".asJson,
      "use" -> "sig".asJson,
      "key_ops" -> List("verify").asJson,
      "alg" -> "ES256".asJson,
      "kid" -> "634c80a3-37f9-42bc-a657-0bf4f759b1e3".asJson,
      "crv" -> "P-256".asJson,
      "x" -> "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84".asJson,
      "y" -> "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY".asJson
    ).liftTo[SyncIO]
    jwkSet = JwkSet(jwk)
    verification <- JwtVerification
      .default[SyncIO]
      .jwkSet(JwtEcdsaAlgorithm.All, jwkSet)
    userJwt <- verification.decodeAs[UserJwt](jwt)
  } yield userJwt
```

Note verification works because the token header has a matching `kid` (Key ID).

```scala mdoc
userJwtJwk.unsafeRunSync()
```

## Custom Verification

The `VerifiedJwt` type can only be instantiated by the default `JwtVerification` instances. So while it is possible to create custom `JwtVerification` instances, these will have to make use of the default instances. This holds true as long as your code keeps to the following rules.

1. Does _not_ make use of functions internal to the library (functions internal to the `jots` package).
2. Does _not_ use the [testing module](testing.md#unsafe-verification) to create a `VerifiedJwt` for a `SignedJwt` without verification.

It is not possible to disable signature verification for the default `JwtVerification` instances, meaning `VerifiedJwt` guarantees the token has a valid signature as long as these rules are upheld.

### Custom Example

Following is an example of a custom verification that requires the `nonce` header key to be present.

```scala mdoc:silent
val jwtNonceVerification: SyncIO[JwtVerification[SyncIO]] =
  jwtVerification.map { verification =>
    JwtVerification.verifyWith { jwt =>
      for {
        verifiedJwt <- verification.verify(jwt)
        nonce = verifiedJwt.header.toJsonObject("nonce")
        _ <- if (nonce.nonEmpty) SyncIO.unit else SyncIO.raiseError(
          new IllegalArgumentException("token is missing nonce")
        )
      } yield verifiedJwt
    }
  }
```

Let us try to verify the [token](#signature-verification) from before, which does _not_ have a nonce:

```scala mdoc:silent
val userJwtNonce: SyncIO[UserJwt] =
  for {
    verification <- jwtNonceVerification
    userJwt <- verification.decodeAs[UserJwt](jwt)
  } yield userJwt
```

and then finally run the effect to show the verification is failing as expected.

```scala mdoc
userJwtNonce.attempt.unsafeRunSync()
```
