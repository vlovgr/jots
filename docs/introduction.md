# Introduction

In the introduction we briefly cover how to sign and verify [JSON Web Tokens (JWTs)](https://en.wikipedia.org/wiki/JSON_Web_Token).

1. We start by declaring a custom `UserJwt` type for representing the claims of user tokens.
2. Then we define `JwtEncoder[UserJwt]` and sign an example token with `JwtSigning[IO]`.
3. Finally, we specify `JwtDecoder[UserJwt]` and verify the token using `JwtVerification[IO]`.

## Token Signing

We begin by defining a custom type `UserJwt` to represent the token.

```scala mdoc
final case class UserJwt(userId: String, expiresAt: Long, issuedAt: Long)
```

Then we define an `Encoder.AsObject` which encodes `UserJwt` as `JsonObject`.

```scala mdoc
import io.circe.Encoder

given Encoder.AsObject[UserJwt] =
  Encoder.forProduct3("userId", "exp", "iat")(claims =>
    (claims.userId, claims.expiresAt, claims.issuedAt)
  )
```

Similarly, we define a `JwtEncoder` which encodes `UserJwt` as `JwtBuilder`.

```scala mdoc
import jots.JwtEncoder

given JwtEncoder[UserJwt] =
  JwtEncoder.encodeClaims
```

Here, `JwtEncoder.encodeClaims` uses the `Encoder.AsObject` defined earlier to encode `UserJwt` as the claims of a `JwtBuilder`. The `JwtBuilder` type describes tokens prior to signing. Following, we create a `UserJwt` instance and use the `JwtEncoder` to generate a `JwtBuilder` instance.

```scala mdoc:to-string
import jots.syntax.*

val userJwt = UserJwt(
  userId = "8d3bbd14-dfd9-47fa-aab4-d76daf00b4f1",
  expiresAt = 3345062400L,
  issuedAt = 1767225600L
)

userJwt.asJwt
```

Finally, we need to sign the `JwtBuilder` to create a `SignedJwt`. For this we need a `JwtSigning` instance. In this case we chose to use `HS256` (HMAC with SHA-256) which requires a secret key. The `JwtSigning` instance is only created and used once here, but it is normally reused multiple times.

```scala mdoc:to-string
import cats.effect.SyncIO
import cats.syntax.all.*
import jots.JwtHmacAlgorithm.HS256
import jots.JwtSigning
import jots.crypto.SecretKey

val signedJwt =
  for {
    secretKey <- SecretKey("he2DDxdpmVMUG8UiVobZhfqnz1FNJZgP2Twpq").liftTo[SyncIO]
    signing <- JwtSigning.default[SyncIO].hmac(HS256, secretKey)
    signedJwt <- userJwt.asJwt.signWith(signing)
  } yield signedJwt

val signedJwtString =
  signedJwt.map(_.show).unsafeRunSync()
```

@:callout(info)
Note we use `SyncIO` and `unsafeRunSync()` here to show the final result. In practice, you would most likely use `IO` without `unsafeRunSync()`. We should take care to _not_ put secrets, like `SecretKey`, in source code.
@:@

Note that, since we've signed this token, we are confident the token can be verified. In general though, `SignedJwt` represents unverified signed tokens, and should _not_ be trusted before verification, which is what the next section covers. For more details on token signing, see the page on [signing](features/signing.md).

## Verifying Tokens

We begin by defining a `Decoder` which decodes `UserJwt` from `Json`.

```scala mdoc
import io.circe.Decoder

given Decoder[UserJwt] =
  Decoder.forProduct3("userId", "exp", "iat")(UserJwt.apply)
```

Similarly, we define a `JwtDecoder` which decodes `UserJwt` from `VerifiedJwt`.

```scala mdoc
import jots.JwtDecoder

given JwtDecoder[UserJwt] =
  JwtDecoder.decodeClaims
```

Here, `JwtDecoder.decodeClaims` uses the `Decoder` above to decode `UserJwt` from the claims of a `VerifiedJwt`. The `VerifiedJwt` is a `SignedJwt` for which the signature has been verified. Verification typically includes verifying header and claims in addition to the signature.

Following, we use the default `JwtVerification` and `decodeAs` to parse, verify and decode a signed token. The default verifications include extra checks in addition to verifying the signature. See the page on [verification](features/verification.md) for more details on the [default checks](features/verification.md#default-verifications), how they can be changed, and how to enable more checks.

```scala mdoc:to-string
import jots.JwtVerification

val userJwtDecoded =
  for {
    secretKey <- SecretKey("he2DDxdpmVMUG8UiVobZhfqnz1FNJZgP2Twpq").liftTo[SyncIO]
    verification <- JwtVerification.default[SyncIO].hmac(HS256, secretKey)
    userJwt <- verification.decodeAs[UserJwt](signedJwtString)
  } yield userJwt

userJwtDecoded.unsafeRunSync() == userJwt
```

@:callout(info)
Note we use `SyncIO` and `unsafeRunSync()` here to show the final result. In practice, you would most likely use `IO` without `unsafeRunSync()`. We should take care to _not_ put secrets, like `SecretKey`, in source code.
@:@

For more details on token verification, see the page on [verification](features/verification.md).
