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

import cats.effect.IO
import cats.syntax.all.*
import io.circe.syntax.*
import java.nio.charset.StandardCharsets.UTF_8
import jots.crypto.PublicKey
import jots.crypto.SecretKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import jots.testing.syntax.*
import scala.concurrent.duration.*
import scodec.bits.ByteVector
import weaver.SimpleIOSuite

object JwtVerificationSuite extends SimpleIOSuite {
  test("JwtVerification.rejectSignature") {
    val invalidSignature: JwtSignature =
      JwtSignature(ByteVector.view("invalidSignature".getBytes(UTF_8)))

    ExampleJwt.All
      .traverse { example =>
        for {
          verification <- example.verification
          signedJwt = example.builder.toSigned(invalidSignature)
          verifiedJwt <- signedJwt.verifyWith(verification).attempt
          _ <- matchOrFailFast[IO](verifiedJwt) { case Left(_: JwtException.InvalidSignature) => () }
        } yield success

      }
      .map(_.combineAll)
  }

  test("JwtVerification.verifyExamples") {
    ExampleJwt.All
      .traverse { example =>
        example.verifiedJwt
          .map(verifiedJwt => expect.eql(example.signedJwt, verifiedJwt.toSigned))
      }
      .map(_.combineAll)
  }

  private val algorithm: JwtHmacAlgorithm =
    JwtHmacAlgorithm.HS256

  private val secretKey: SecretKey =
    secretKey"a-string-secret-at-least-256-bits-long"

  private def sign(
    claims: JwtClaims,
    header: JwtHeader = JwtHeader.default
  ): IO[SignedJwt] =
    for {
      signing <- JwtSigning.default[IO].hmac(algorithm, secretKey)
      signed <- JwtBuilder(header, claims).signWith(signing)
    } yield signed

  /**
    * Returns a [[SignedJwt]] with the specified [[JwtHeader]] set.
    */
  private def tokenWithHeader(header: JwtHeader): SignedJwt =
    JwtBuilder(header, JwtClaims.empty).toSigned(JwtSignature.empty)

  /**
    * Returns a [[JwtHeader]] with the specified header name
    * present and a `crit` parameter with the header name.
    */
  private def criticalHeader(criticalHeader: String): JwtHeader =
    JwtHeader.default
      .add(criticalHeader, "value".asJson)
      .withCriticalHeaders(criticalHeader)

  private def octJwk(keyId: String, fields: (String, io.circe.Json)*): Jwk =
    Jwk(
      (List(
        "kty" -> "oct".asJson,
        "kid" -> keyId.asJson,
        "alg" -> "HS256".asJson,
        "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
      ) ++ fields): _*
    ).fold(throw _, identity)

  test("JwtVerification.rejectTamperedClaims") {
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson))
      tampered = signed.toBuilder
        .mapClaims(_.mapJsonObject(_.add("sub", "admin".asJson)))
        .toSigned(signed.signature)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- tampered.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidSignature) => () }
    } yield success
  }

  test("JwtVerification.rejectTamperedHeader") {
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson))
      tampered = signed.toBuilder
        .mapHeader(_.add("kid", "injected".asJson))
        .toSigned(signed.signature)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- tampered.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidSignature) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingAlgorithm") {
    for {
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- tokenWithHeader(JwtHeader.empty).verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectNoneAlgorithm") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "none".asJson))
    for {
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectMismatchedHmacAlgorithm") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "HS384".asJson))
    for {
      verification <- JwtVerification.default[IO].hmac(JwtHmacAlgorithm.HS256, secretKey)
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectAsymmetricAlgorithmWithHmacVerifier") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "RS256".asJson))
    for {
      verification <- JwtVerification.default[IO].hmac(JwtHmacAlgorithm.HS256, secretKey)
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectExpired") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (now - 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.TokenExpired) => () }
    } yield success
  }

  test("JwtVerification.toleratesExpiredWithinClockSkew") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (now - 10.seconds).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withClockSkew(1.hour)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectNotYetValid") {
    for {
      now <- IO.realTime
      claims = JwtClaims("nbf" -> (now + 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.TokenNotYetValid) => () }
    } yield success
  }

  test("JwtVerification.rejectNotYetIssued") {
    for {
      now <- IO.realTime
      claims = JwtClaims("iat" -> (now + 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withCheckIssuedAt(true)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.TokenNotYetIssued) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingIssuer") {
    for {
      signed <- sign(JwtClaims.empty)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedIssuers("accepted-issuer")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingIssuer) => () }
    } yield success
  }

  test("JwtVerification.rejectUnacceptedIssuer") {
    for {
      signed <- sign(JwtClaims("iss" -> "other-issuer".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedIssuers("accepted-issuer")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedIssuer) => () }
    } yield success
  }

  test("JwtVerification.acceptsAcceptedIssuer") {
    for {
      signed <- sign(JwtClaims("iss" -> "accepted-issuer".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedIssuers("accepted-issuer")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectUnacceptedAudience") {
    for {
      signed <- sign(JwtClaims("aud" -> "other-audience".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedAudiences("accepted-audience")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAudience) => () }
    } yield success
  }

  test("JwtVerification.rejectUnacceptedSubject") {
    for {
      signed <- sign(JwtClaims("sub" -> "other-subject".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedSubjects("accepted-subject")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedSubject) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.verifiesByKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("key-1"))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnknownKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("key-2"))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectMissingKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKeyId) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.excludesKeyForEncryptionUse") {
    val keySet = JwkSet(octJwk("key-1", "use" -> "enc".asJson))
    for {
      verification <- JwtVerification.default[IO].jwkSetAll(keySet).attempt
      _ <- matchOrFailFast[IO](verification) { case Left(_: JwtException.EmptyKeySet) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.acceptsKeyForSignatureUse") {
    val keySet = JwkSet(octJwk("key-1", "use" -> "sig".asJson))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("key-1"))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.excludesKeyWithoutVerifyKeyOp") {
    val keySet = JwkSet(octJwk("key-1", "key_ops" -> List("sign").asJson))
    for {
      verification <- JwtVerification.default[IO].jwkSetAll(keySet).attempt
      _ <- matchOrFailFast[IO](verification) { case Left(_: JwtException.EmptyKeySet) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.acceptsKeyWithVerifyKeyOp") {
    val keySet = JwkSet(octJwk("key-1", "key_ops" -> List("sign", "verify").asJson))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("key-1"))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.usesSignatureKeyFromMixedSet") {
    val keySet = JwkSet(
      octJwk("enc-key", "use" -> "enc".asJson),
      octJwk("sig-key", "use" -> "sig".asJson)
    )

    for {
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      signedSig <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("sig-key"))
      resultSig <- signedSig.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](resultSig) { case Right(_) => () }
      signedEnc <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("enc-key"))
      resultEnc <- signedEnc.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](resultEnc) { case Left(_: JwtException.MissingKey) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.excludesKeyWithoutKeyId") {
    val missingKeyIdJwk =
      Jwk(
        "kty" -> "oct".asJson,
        "alg" -> "HS256".asJson,
        "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
      ).fold(throw _, identity)

    val keySet = JwkSet(missingKeyIdJwk, octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId("key-1"))
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectUnsupportedCriticalHeader") {
    for {
      signed <- sign(JwtClaims.empty, criticalHeader("jots-example"))
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.UnsupportedCriticalHeader) => () }
    } yield success
  }

  test("JwtVerification.acceptsUnderstoodCriticalHeader") {
    for {
      signed <- sign(JwtClaims.empty, criticalHeader("jots-example"))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withCriticalHeaders("jots-example")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingCriticalHeader") {
    val header = JwtHeader.default.withCriticalHeaders("jots-example")
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withCriticalHeaders("jots-example")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingCriticalHeader) => () }
    } yield success
  }

  test("JwtVerification.rejectEmptyCriticalHeaders") {
    val header = JwtHeader.default.add("crit", List.empty[String].asJson)
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidCriticalHeaders) => () }
    } yield success
  }

  test("JwtVerification.rejectNonArrayCriticalHeaders") {
    val header = JwtHeader.default.add("crit", "jots-example".asJson)
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerification.default[IO].hmac(algorithm, secretKey)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidCriticalHeaders) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnsupportedCriticalHeader") {
    val keySet = JwkSet(octJwk("key-1"))
    val header = criticalHeader("jots-example").withKeyId("key-1")
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerification.default[IO].jwkSetAll(keySet)
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.UnsupportedCriticalHeader) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingExpiration") {
    for {
      signed <- sign(JwtClaims.empty)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withRequireExpiration(true)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingExpiration) => () }
    } yield success
  }

  test("JwtVerification.acceptsRequiredExpirationWhenPresent") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (now + 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withRequireExpiration(true)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.requireExpirationIndependence") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (now - 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withRequireExpiration(true)
        .withCheckExpiration(false)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingIssuedAt") {
    for {
      signed <- sign(JwtClaims.empty)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withRequireIssuedAt(true)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingIssuedAt) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingNotBefore") {
    for {
      signed <- sign(JwtClaims.empty)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withRequireNotBefore(true)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingNotBefore) => () }
    } yield success
  }

  test("JwtVerification.rejectIndeterminateRsaKeyLength") {
    val publicKey =
      PublicKey.fromX509Spki(
        Asn1.seq(
          Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null),
          Asn1.bitString(ByteVector(0))
        )
      )

    for {
      result <- JwtVerification.default[IO].rsa(JwtRsaAlgorithm.RS256, publicKey).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidPublicKey) => () }
    } yield success
  }

  test("JwtVerification.rejectMismatchedEcdsaCurve") {
    val publicKey = ExampleEcdsaJwt.ES384Pkcs8.publicKey

    for {
      result <- JwtVerification.default[IO].ecdsa(JwtEcdsaAlgorithm.ES256, publicKey).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidEcKeyLength) => () }
    } yield success
  }
}
