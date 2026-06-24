# Testing

The `jots-testing` module depends on the core module and provides [ScalaCheck](https://scalacheck.org) generators and instances, and String interpolators for secrets. Importantly, the testing module also allows us to create a `VerifiedJwt` from any `SignedJwt` for testing purposes. This means the module should generally only be used for testing purposes.

## Getting Started

To get started with [sbt](https://scala-sbt.org), add the following line to your `build.sbt` file.

```scala
libraryDependencies += "@ORGANIZATION@" %% "jots-testing" % "@VERSION@" % Test
```

If you are using Scala.js or Scala Native, replace the `%%` with `%%%` above.

## Supported Features

The ScalaCheck generators and instances can be made available with `import jots.testing.*`, while the String interpolators and syntax for unsafe verification requires `import jots.testing.syntax.*`. If you're looking for usage examples, the testing module is heavily used by the library [tests](https://github.com/vlovgr/jots/tree/main/tests/shared/src/test/scala/jots).

### ScalaCheck Support

The testing module provides ScalaCheck `Gen` generators and `Arbitrary` instances. Following are some samples from a few generators. Note private and public keys (`PrivateKey` and `PublicKey`) are _not_ generated on the fly, but instead choose from a pre-defined list of keys. This is due to the generation being computationally expensive.

```scala mdoc:to-string
import cats.effect.IO
import jots.JwtBuilder
import jots.SignedJwt
import jots.VerifiedJwt
import jots.testing.*
import org.scalacheck.Arbitrary.arbitrary

// Generate an arbitrary token prior to signing
arbitrary[JwtBuilder].sample

// Generate an arbitary token with valid signature
arbitrary[SignedJwt].sample

// Generate an arbitrary token with a verified signature
arbitrary[VerifiedJwt].sample

// Generate an arbitary signing instance using ECDSA
ecdsaJwtSigningGen[IO].sample

// Generate a matching RSA private and public key
rsaKeyPairGen.sample
```

### String Interpolators

The `jots-crypto` module provides syntax for compile-time parsing of public keys (`PublicKey`). The testing module provides additional syntax for private keys (`PrivateKey`), secret keys (`SecretKey`), and tokens (`SignedJwt`). These are generally sensitive and should _not_ be in source code, except when they are non-secret for testing purposes.

```scala mdoc:silent
import jots.SignedJwt
import jots.crypto.PrivateKey
import jots.crypto.SecretKey
import jots.testing.syntax.*

val privateKey: PrivateKey =
  privateKey"""
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
    OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
    1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
    -----END PRIVATE KEY-----
  """

val secretKey: SecretKey =
  secretKey"5BpYD67PafjVoefV11a06MVMGCmr1zoLrFGL019EEuoMtZszHqqpAd6frHFFgGXZ"

val signedJwt: SignedJwt =
  signedJwt"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJ1c2VySWQiOiI4ZDNiYmQxNC1kZmQ5LTQ3ZmEtYWFiNC1kNzZkYWYwMGI0ZjEiLCJleHAiOjMzNDUwNjI0MDAsImlhdCI6MTc2NzIyNTYwMH0.8i3xidY8bcAjoBYSKktcyihSdICGXBSBnjp13JYmO_DE5v4_oxY4bSBtZxdoic7OWFKZCcE63I1fFlukzgxVZA"
```

### Unsafe Verification

It is possible to extend the default verifications for [custom verifications](verification.md#custom-verification). The core modules enforces that all instances of `VerifiedJwt` must have gone through signature verification. For testing purposes, the testing module allows us to create a `VerifiedJwt` from any `SignedJwt` without verification.

```scala mdoc:to-string
import jots.testing.syntax.*

signedJwt.toVerifiedUnsafe

VerifiedJwt.fromSignedUnsafe(signedJwt)
```
