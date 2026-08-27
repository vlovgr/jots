/*
 * Copyright 2026 Viktor Rudebeck
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jots

import cats.data.NonEmptyList
import cats.effect.IO
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import jots.JwtException.InvalidEcKeyLength
import jots.JwtException.InvalidKeyAlgorithm
import jots.JwtException.InvalidKeyId
import jots.JwtException.InvalidPrivateKey
import jots.JwtException.InvalidRsaKeyLength
import jots.JwtException.InvalidSecretKeyLength
import jots.JwtException.MissingKeyId
import jots.JwtException.RejectedKeyAlgorithm
import jots.JwtException.UnsuitableSigningKey
import jots.JwtException.UnsupportedKey
import jots.JwtHmacAlgorithm.HS256
import jots.crypto.PrivateKey
import jots.crypto.SecretKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import jots.testing.*
import jots.testing.syntax.*
import org.scalacheck.Gen
import scodec.bits.ByteVector
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object JwtSigningSuite extends SimpleIOSuite with Checkers {
  test("JwtSigning.asymmetric") {
    forall { (builder: JwtBuilder) =>
      ExampleAsymmetricJwt.All
        .traverse { example =>
          for {
            signing <- JwtSigningBuilder
              .default[IO]
              .asymmetric(example.algorithm, example.privateKey)
              .build
            verification <- JwtVerificationBuilder
              .default[IO]
              .asymmetric(NonEmptyList.of(example.algorithm), example.publicKey)
              .withCheckExpiration(false)
              .withCheckIssuedAt(false)
              .withCheckNotBefore(false)
              .build
            signed <- builder.signWith(signing)
            _ <- signed.verifyWith(verification)
          } yield success
        }
        .map(_.combineAll)
    }
  }

  test("JwtSigning.asymmetric.rejectInsecureKeys") {
    val gen =
      for {
        algorithm <- jwtRsaAlgorithmGen
        privateKey <- rsaInsecurePrivateKeyGen
      } yield (algorithm, privateKey)

    forall(gen) { case (algorithm, privateKey) =>
      JwtSigning.default[IO].rsa(algorithm, privateKey).attempt.map {
        case Left(_: InvalidRsaKeyLength) => success
        case _ => failure("unexpected case")
      }
    }
  }

  test("JwtSigning.asymmetric.rejectIndeterminateRsaKeyLength") {
    // An RSA private key (by algorithm OID) whose modulus cannot be parsed
    // must fail closed rather than silently skip the key length check.
    val privateKey =
      PrivateKey.fromPkcs8(
        Asn1.seq(
          Asn1.intZero,
          Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null),
          Asn1.octetString(ByteVector.empty)
        )
      )

    JwtSigning.default[IO].rsa(JwtRsaAlgorithm.RS256, privateKey).attempt.map {
      case Left(_: InvalidPrivateKey) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.asymmetric.rejectMismatchedEcdsaCurve") {
    forall(ecdsaP384PrivateKeyGen) { privateKey =>
      JwtSigning.default[IO].ecdsa(JwtEcdsaAlgorithm.ES256, privateKey).attempt.map {
        case Left(_: InvalidEcKeyLength) => success
        case _ => failure("unexpected case")
      }
    }
  }

  test("JwtSigning.hmac") {
    val gen =
      for {
        builder <- jwtBuilderGen
        algorithm <- jwtHmacAlgorithmGen
        minKeyLength = algorithm.minKeyLength
        secretKey <- secretKeyMinLengthGen(minKeyLength)
      } yield (algorithm, builder, secretKey)

    forall(gen) { case (algorithm, builder, secretKey) =>
      for {
        signing <- JwtSigning
          .default[IO]
          .hmac(algorithm, secretKey)
        verification <- JwtVerificationBuilder
          .default[IO]
          .hmac(algorithm, secretKey)
          .withCheckExpiration(false)
          .withCheckIssuedAt(false)
          .withCheckNotBefore(false)
          .build
        signed <- builder.signWith(signing)
        _ <- signed.verifyWith(verification)
      } yield success
    }
  }

  test("JwtSigning.hmac.rejectInsecureKeys") {
    val gen =
      for {
        algorithm <- jwtHmacAlgorithmGen
        minKeyLength = algorithm.minKeyLength
        secretKey <- secretKeyMaxLengthGen(minKeyLength - 1)
      } yield (algorithm, secretKey)

    forall(gen) { case (algorithm, secretKey) =>
      JwtSigning.default[IO].hmac(algorithm, secretKey).attempt.map {
        case Left(_: InvalidSecretKeyLength) => success
        case _ => failure("unexpected case")
      }
    }
  }

  test("JwtSigning.jwk") {
    val gen =
      for {
        builder <- jwtBuilderGen
        (algorithm, privateKey, publicKey) <- signingKeyGen
      } yield (algorithm, builder, privateKey, publicKey)

    forall(gen) { case (algorithm, builder, privateKey, publicKey) =>
      for {
        signing <- JwtSigning.default[IO].jwk(algorithm, privateKey)
        verification <- JwtVerificationBuilder
          .default[IO]
          .jwkSet(NonEmptyList.of(algorithm), JwkSet(publicKey))
          .withCheckExpiration(false)
          .withCheckIssuedAt(false)
          .withCheckNotBefore(false)
          .build
        signed <- builder.signWith(signing)
        _ <- signed.verifyWith(verification)
      } yield success
    }
  }

  test("JwtSigning.jwk.setsKeyId") {
    for {
      signing <- JwtSigning.default[IO].jwk(HS256, octJwk(secretKey))
      signed <- JwtBuilder(JwtHeader.default, JwtClaims.empty).signWith(signing)
    } yield expect.eql(Some(keyId.value), signed.header.toJsonObject("kid").flatMap(_.asString))
  }

  test("JwtSigning.jwk.rejectMissingKeyId") {
    val key =
      jwk(
        "kty" -> "oct".asJson,
        "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
      )

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(_: MissingKeyId) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectInvalidKeyId") {
    val key = octJwk(secretKey, "kid" -> 1.asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(_: InvalidKeyId) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectKeyForEncryptionUse") {
    val key = octJwk(secretKey, "use" -> "enc".asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(e: UnsuitableSigningKey) =>
        expect.eql(
          "the key with id [key-1] is not suitable for signing: " +
            "the key use (use) [\"enc\"] is not [sig]",
          e.message
        )
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.acceptsKeyForSignatureUse") {
    val key = octJwk(secretKey, "use" -> "sig".asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Right(_) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectKeyWithoutSignKeyOperation") {
    val key = octJwk(secretKey, "key_ops" -> List("verify").asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(e: UnsuitableSigningKey) =>
        expect.eql(
          "the key with id [key-1] is not suitable for signing: " +
            "the key operations (key_ops) [[\"verify\"]] do not include [sign]",
          e.message
        )
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.acceptsKeyWithSignKeyOperation") {
    val key = octJwk(secretKey, "key_ops" -> List("sign", "verify").asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Right(_) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectInvalidKeyOperations") {
    val key = octJwk(secretKey, "key_ops" -> "sign".asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(e: UnsuitableSigningKey) =>
        expect.eql(
          "the key with id [key-1] is not suitable for signing: " +
            "the key operations (key_ops) [\"sign\"] are invalid",
          e.message
        )
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.acceptsMatchingAlgorithm") {
    val key = octJwk(secretKey, "alg" -> HS256.name.asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Right(_) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectMismatchedAlgorithm") {
    val key = octJwk(secretKey, "alg" -> JwtHmacAlgorithm.HS384.name.asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(e: RejectedKeyAlgorithm) =>
        expect.eql(
          "the key with id [key-1] algorithm (alg) [HS384] was rejected, expected [HS256]",
          e.message
        )
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectInvalidAlgorithm") {
    val key = octJwk(secretKey, "alg" -> 256.asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(e: InvalidKeyAlgorithm) =>
        expect.eql("the key with id [key-1] algorithm (alg) [256] is invalid", e.message)
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectMismatchedKeyType") {
    forall(jwkEcdsaPrivateKeyGen) { key =>
      JwtSigning.default[IO].jwk(HS256, withKeyId(key)).attempt.map {
        case Left(_: UnsupportedKey) => success
        case _ => failure("unexpected case")
      }
    }
  }

  test("JwtSigning.jwk.rejectUnsupportedKeyType") {
    val key = octJwk(secretKey, "kty" -> "unknown".asJson)

    JwtSigning.default[IO].jwk(HS256, key).attempt.map {
      case Left(_: UnsupportedKey) => success
      case _ => failure("unexpected case")
    }
  }

  test("JwtSigning.jwk.rejectPublicKey") {
    val gen = Gen.oneOf(ecdsaSigningKeyGen, eddsaSigningKeyGen, rsaSigningKeyGen)

    forall(gen) { case (algorithm, _, publicKey) =>
      JwtSigning.default[IO].jwk(algorithm, publicKey).attempt.map {
        case Left(_: InvalidPrivateKey) => success
        case _ => failure("unexpected case")
      }
    }
  }

  private val keyId: JwkKeyId =
    JwkKeyId("key-1")

  private val secretKey: SecretKey =
    secretKey"a-string-secret-at-least-256-bits-long"

  /**
    * Generates an algorithm along with a private and public key for
    * the algorithm, where both keys have [[keyId]] as their key id.
    */
  private val signingKeyGen: Gen[(JwtAlgorithm, Jwk, Jwk)] =
    Gen.oneOf(ecdsaSigningKeyGen, eddsaSigningKeyGen, hmacSigningKeyGen, rsaSigningKeyGen)

  private lazy val ecdsaSigningKeyGen: Gen[(JwtAlgorithm, Jwk, Jwk)] =
    jwkEcdsaKeyPairGen.flatMap { case (privateKey, publicKey) =>
      val algorithmGen =
        privateKey.toJsonObject("crv").flatMap(_.asString) match {
          case Some("P-256") => Gen.const(JwtEcdsaAlgorithm.ES256)
          case Some("P-384") => Gen.const(JwtEcdsaAlgorithm.ES384)
          case Some("P-521") => Gen.const(JwtEcdsaAlgorithm.ES512)
          case _ => Gen.fail
        }

      algorithmGen.map { algorithm =>
        (algorithm, withKeyId(privateKey), withKeyId(publicKey))
      }
    }

  private lazy val eddsaSigningKeyGen: Gen[(JwtAlgorithm, Jwk, Jwk)] =
    jwkEddsaKeyPairGen.flatMap { case (privateKey, publicKey) =>
      val algorithmGen =
        privateKey.toJsonObject("crv").flatMap(_.asString) match {
          case Some("Ed448") => Gen.const(JwtEddsaAlgorithm.Ed448)
          case Some("Ed25519") => Gen.const(JwtEddsaAlgorithm.Ed25519)
          case _ => Gen.fail
        }

      algorithmGen.map { algorithm =>
        (algorithm, withKeyId(privateKey), withKeyId(publicKey))
      }
    }

  private lazy val hmacSigningKeyGen: Gen[(JwtAlgorithm, Jwk, Jwk)] =
    for {
      algorithm <- jwtHmacAlgorithmGen
      secretKey <- secretKeyMinLengthGen(algorithm.minKeyLength)
      key = octJwk(secretKey)
    } yield (algorithm, key, key)

  private lazy val rsaSigningKeyGen: Gen[(JwtAlgorithm, Jwk, Jwk)] =
    jwkRsaKeyPairGen.flatMap { case (privateKey, publicKey) =>
      jwtRsaAlgorithmGen.map { algorithm =>
        (algorithm, withKeyId(privateKey), withKeyId(publicKey))
      }
    }

  private def jwk(fields: (String, Json)*): Jwk =
    Jwk(fields: _*).fold(throw _, identity)

  private def octJwk(secretKey: SecretKey, fields: (String, Json)*): Jwk =
    withFields(
      jwk(
        "kty" -> "oct".asJson,
        "kid" -> keyId.asJson,
        "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
      ),
      fields: _*
    )

  private def withKeyId(key: Jwk): Jwk =
    withFields(key, "kid" -> keyId.asJson)

  private def withFields(key: Jwk, fields: (String, Json)*): Jwk =
    Jwk
      .fromJsonObject {
        fields.foldLeft(key.toJsonObject) { case (jsonObject, (name, value)) =>
          jsonObject.add(name, value)
        }
      }
      .fold(throw _, identity)
}
