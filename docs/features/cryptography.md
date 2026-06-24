# Cryptography

The core module is based on an independent `jots-crypto` module which contains the cross-platform cryptography needed to support signing and verification of tokens. If we need cross-platform cryptography that is independent of [JSON Web Tokens (JWTs)](https://en.wikipedia.org/wiki/JSON_Web_Token), then we can instead depend on the `jots-crypto` module.

## Getting Started

To get started with [sbt](https://scala-sbt.org), add the following line to your `build.sbt` file.

```scala
libraryDependencies += "@ORGANIZATION@" %% "jots-crypto" % "@VERSION@"
```

If you are using Scala.js or Scala Native, replace the `%%` with `%%%` above.

## Supported Features

The module provides a `Crypto[F[_]]` capability for all effect types with a `Sync[F[_]]` (e.g. `IO`). The capability includes support for HMAC, plus signing and verification using private and public keys, respectively. Support for additional cryptographic functions might be included in the future.

### HMAC with Secret Key

The `Crypto#hmac` function implements [Hash-based Message Authentication Code (HMAC)](https://en.wikipedia.org/wiki/HMAC). This requires choosing a `HashAlgorithm` and `SecretKey`, and provide the message as a `ByteVector`. Following is an example which matches the `HS256` algorithm for tokens (HMAC using SHA-256).

```scala mdoc:silent
import cats.effect.SyncIO
import cats.syntax.all.*
import jots.crypto.Crypto
import jots.crypto.HashAlgorithm
import jots.crypto.Mac
import jots.crypto.SecretKey
import scodec.bits.ByteVector

val message: ByteVector =
  ByteVector.view("message".getBytes("UTF-8"))

val mac: SyncIO[Mac] =
  for {
    secretKey <- SecretKey("gbxZ8rjekZmYQxh24wsKcaUqPuBe7jg6").liftTo[SyncIO]
    hmac = Crypto[SyncIO].hmac(HashAlgorithm.SHA256, secretKey)
    mac <- hmac(message)
  } yield mac
```

@:callout(info)
Note we use `SyncIO`, and later `unsafeRunSync()`, to show the final result. In practice, you would most likely use `IO` without `unsafeRunSync()`. We should take care to _not_ put secrets, like `SecretKey`, in source code.
@:@

The generated Message Authentication Code (MAC), represented with `Mac`, is usually represented in hexadecimal encoding, which is the default for `Mac`. When the output is used as a signature for tokens, it is instead represented using `Base64UrlNoPad` encoding using `JwtSignature.fromMac` in the core module.

```scala mdoc:to-string
mac.unsafeRunSync()
```

### Signing with Private Key

The `Crypto#sign` function implements asymmetric signing using a private key. This means an `AsymmetricAlgorithm` and matching `PrivateKey` has to be provided, in addition to the `ByteVector` message. Note the private key needs to match the algorithm, or an exception will be raised at runtime. Following is an example which matches the `ES256` algorithm for tokens (ECDSA using P-256 and SHA-256).

```scala mdoc:silent
import jots.crypto.EcdsaAlgorithm
import jots.crypto.PrivateKey
import jots.crypto.Signature

val signature: SyncIO[Signature] =
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
    sign = Crypto[SyncIO].sign(EcdsaAlgorithm.SHA256withECDSAinP1363Format, privateKey)
    signature <- sign(message)
  } yield signature
```

@:callout(info)
We should take care to _not_ put secrets, like `PrivateKey`, in source code.
@:@

The generated signature is represented with `Signature` and is usually represented in hexadecimal encoding, which is the default for `Signature`. When the output is used as a signature for tokens, it's represented using `Base64UrlNoPad` encoding using `JwtSignature.fromSignature` in the core module.

```scala mdoc:to-string
signature.unsafeRunSync()
```

### Verification with Public Key

The `Crypto#verify` function implements asymmetric verification using a public key. This means we have to provide an `AsymmetricAlgorithm` and matching `PublicKey` in addition to a `ByteVector` message and signature. Note the public key needs to match the algorithm, or an exception will be raised at runtime. Following is an example which matches the `ES256` algorithm for tokens (ECDSA using P-256 and SHA-256).

```scala mdoc:silent
import jots.crypto.PublicKey
import jots.crypto.Verified
import jots.crypto.syntax.*

val publicKey: PublicKey =
  publicKey"""
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
    q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
    -----END PUBLIC KEY-----
  """

val verified: SyncIO[Verified] =
  for {
    signature <- signature
    verify = Crypto[SyncIO].verify(EcdsaAlgorithm.SHA256withECDSAinP1363Format, publicKey)
    verified <- verify(message, signature)
  } yield verified
```

The result of verification is `Verified`, which is either `Verified.Valid` or `Verified.Invalid`.

```scala mdoc:to-string
verified.unsafeRunSync()
```
