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
import io.circe.JsonNumber
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
      signing <- JwtSigningBuilder.default[IO].hmac(algorithm, secretKey).build
      signed <- JwtBuilder(header, claims).signWith(signing)
    } yield signed

  /**
    * Returns a [[SignedJwt]] with the specified [[JwtHeader]] set.
    */
  private def tokenWithHeader(header: JwtHeader): SignedJwt =
    JwtBuilder(header, JwtClaims.empty).toSigned(JwtSignature.empty)

  /**
    * Returns a [[SignedJwt]] with the specified algorithm and signature.
    */
  private def tokenWithAlgorithm(algorithm: JwtAlgorithm, signature: ByteVector): SignedJwt =
    JwtBuilder(JwtHeader.default.withAlgorithm(algorithm), JwtClaims.empty)
      .toSigned(JwtSignature(signature))

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
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
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
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- tampered.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidSignature) => () }
    } yield success
  }

  test("JwtVerification.rejectMissingAlgorithm") {
    for {
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- tokenWithHeader(JwtHeader.empty).verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectNoneAlgorithm") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "none".asJson))
    for {
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectMismatchedHmacAlgorithm") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "HS384".asJson))
    for {
      verification <- JwtVerificationBuilder.default[IO].hmac(JwtHmacAlgorithm.HS256, secretKey).build
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectAsymmetricAlgorithmWithHmacVerifier") {
    val token = tokenWithHeader(JwtHeader.empty.add("alg", "RS256".asJson))
    for {
      verification <- JwtVerificationBuilder.default[IO].hmac(JwtHmacAlgorithm.HS256, secretKey).build
      result <- token.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectExpired") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (now - 1.hour).toSeconds.asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
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
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
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

  test("JwtVerification.acceptsFractionalExpiration") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (BigDecimal((now + 1.hour).toSeconds) + BigDecimal("0.123456789")).asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectFractionalExpired") {
    for {
      now <- IO.realTime
      claims = JwtClaims("exp" -> (BigDecimal((now - 1.hour).toSeconds) + BigDecimal("0.5")).asJson)
      signed <- sign(claims)
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.TokenExpired) => () }
    } yield success
  }

  test("JwtVerification.rejectInvalidExpiration") {
    for {
      now <- IO.realTime
      expirations = List(
        (BigDecimal((now + 1.hour).toSeconds) + BigDecimal("0.1234567891")).asJson,
        Json.fromJsonNumber(JsonNumber.fromDecimalStringUnsafe("1e-100000000")),
        Json.fromJsonNumber(JsonNumber.fromDecimalStringUnsafe("1" + "0" * 1000)),
        9223372037L.asJson,
        "123".asJson
      )
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      _ <- expirations.traverse_ { expiration =>
        for {
          signed <- sign(JwtClaims("exp" -> expiration))
          result <- signed.verifyWith(verification).attempt
          _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidExpiration) => () }
        } yield ()
      }
    } yield success
  }

  test("JwtVerification.acceptsExpirationAtLimitWithClockSkew") {
    for {
      signed <- sign(JwtClaims("exp" -> 9223372036L.asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withClockSkew(1.second)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsIssuedAtAtLimitWithClockSkew") {
    for {
      signed <- sign(JwtClaims("iat" -> -9223372036L.asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withCheckIssuedAt(true)
        .withClockSkew(1.second)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsNotBeforeAtLimitWithClockSkew") {
    for {
      signed <- sign(JwtClaims("nbf" -> -9223372036L.asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withClockSkew(1.second)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
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

  test("JwtVerification.acceptsAcceptedAudience") {
    for {
      signed <- sign(JwtClaims("aud" -> List("other-audience", "accepted-audience").asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedAudiences("accepted-audience")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectUnexpectedAudience") {
    for {
      signed <- sign(JwtClaims("aud" -> "some-audience".asJson))
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.UnexpectedAudience) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnexpectedAudience") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(
        JwtClaims("aud" -> "some-audience".asJson),
        JwtHeader.default.withKeyId(JwkKeyId("key-1"))
      )
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.UnexpectedAudience) => () }
    } yield success
  }

  test("JwtVerification.acceptsMissingAudience") {
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson))
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsAnyAudience") {
    for {
      signed <- sign(JwtClaims("aud" -> "some-audience".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedAudiences(AcceptedAudiences.any)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.acceptsAnyAudience") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(
        JwtClaims("aud" -> "some-audience".asJson),
        JwtHeader.default.withKeyId(JwkKeyId("key-1"))
      )
      verification <- JwtVerificationBuilder
        .default[IO]
        .jwkSetAll(keySet)
        .withAcceptedAudiences(AcceptedAudiences.any)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsAnyIssuer") {
    for {
      signed <- sign(JwtClaims("iss" -> "other-issuer".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedIssuers("accepted-issuer")
        .withAcceptedIssuers(AcceptedIssuers.any)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsAnySubject") {
    for {
      signed <- sign(JwtClaims("sub" -> "other-subject".asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedSubjects("accepted-subject")
        .withAcceptedSubjects(AcceptedSubjects.any)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
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

  test("JwtVerification.rejectMissingType") {
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.withoutType)
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedTypes("JWT")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingType) => () }
    } yield success
  }

  test("JwtVerification.rejectUnacceptedType") {
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.withType("JWT"))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedTypes("at+jwt")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedType) => () }
    } yield success
  }

  test("JwtVerification.rejectInvalidType") {
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.add("typ", 1.asJson))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedTypes("JWT")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidType) => () }
    } yield success
  }

  test("JwtVerification.acceptsEquivalentTypes") {
    val types = List("JWT", "jwt", "application/jwt", "Application/JWT")
    (types, types).tupled
      .traverse { case (accepted, typ) =>
        for {
          signed <- sign(JwtClaims.empty, JwtHeader.default.withType(typ))
          verification <- JwtVerificationBuilder
            .default[IO]
            .hmac(algorithm, secretKey)
            .withAcceptedTypes(accepted)
            .build
          result <- signed.verifyWith(verification).attempt
          _ <- matchOrFailFast[IO](result) { case Right(_) => () }
        } yield success
      }
      .map(_.combineAll)
  }

  test("JwtVerification.acceptsMissingType") {
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.withoutType)
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.acceptsAnyType") {
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.withType("other-type"))
      verification <- JwtVerificationBuilder
        .default[IO]
        .hmac(algorithm, secretKey)
        .withAcceptedTypes("JWT")
        .withAcceptedTypes(AcceptedTypes.any)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnacceptedType") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims.empty, JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder
        .default[IO]
        .jwkSetAll(keySet)
        .withAcceptedTypes("at+jwt")
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedType) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.verifiesByKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.verifiesKeysWithSameKeyId") {
    val keySet = JwkSet(
      Jwk(
        "kty" -> "EC".asJson,
        "kid" -> "shared".asJson,
        "crv" -> "P-256".asJson,
        "x" -> "p9PE1rTE7gpF4uTVOtcx9W_6MnpGGg78q50ZA90wSPw".asJson,
        "y" -> "AEhWKMZsHgNPV7BHUCHab6gURnGfKfsCJJ6E5rlJwnc".asJson
      ).fold(throw _, identity),
      Jwk(
        "kty" -> "OKP".asJson,
        "kid" -> "shared".asJson,
        "crv" -> "Ed25519".asJson,
        "x" -> "WOi-Abi-43CqPVHQx8eQ3KxQRhYx2BrYmTOPonrKhJ8".asJson
      ).fold(throw _, identity)
    )

    val builder =
      JwtBuilder(JwtHeader.default.withKeyId(JwkKeyId("shared")), JwtClaims("sub" -> "alice".asJson))

    for {
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      ecdsa <- JwtSigningBuilder
        .default[IO]
        .ecdsa(JwtEcdsaAlgorithm.ES256, ExampleEcdsaJwt.ES256Jwk.privateKey)
        .build
      ecdsaResult <- builder.signWith(ecdsa).flatMap(_.verifyWith(verification)).attempt
      _ <- matchOrFailFast[IO](ecdsaResult) { case Right(_) => () }
      eddsa <- JwtSigningBuilder
        .default[IO]
        .eddsa(JwtEddsaAlgorithm.Ed25519, ExampleEddsaJwt.EdDSAJwk.privateKey)
        .build
      eddsaResult <- builder.signWith(eddsa).flatMap(_.verifyWith(verification)).attempt
      _ <- matchOrFailFast[IO](eddsaResult) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnknownKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-2")))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectMissingKeyId") {
    val keySet = JwkSet(octJwk("key-1"))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKeyId) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.excludesKeyForEncryptionUse") {
    val keySet = JwkSet(octJwk("key-1", "use" -> "enc".asJson))
    for {
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build.attempt
      _ <- matchOrFailFast[IO](verification) { case Left(_: JwtException.EmptyKeySet) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.acceptsKeyForSignatureUse") {
    val keySet = JwkSet(octJwk("key-1", "use" -> "sig".asJson))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.excludesKeyWithoutVerifyKeyOp") {
    val keySet = JwkSet(octJwk("key-1", "key_ops" -> List("sign").asJson))
    for {
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build.attempt
      _ <- matchOrFailFast[IO](verification) { case Left(_: JwtException.EmptyKeySet) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.acceptsKeyWithVerifyKeyOp") {
    val keySet = JwkSet(octJwk("key-1", "key_ops" -> List("sign", "verify").asJson))
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
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
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      signedSig <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("sig-key")))
      resultSig <- signedSig.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](resultSig) { case Right(_) => () }
      signedEnc <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("enc-key")))
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
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectUnsupportedCriticalHeader") {
    for {
      signed <- sign(JwtClaims.empty, criticalHeader("jots-example"))
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
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
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidCriticalHeaders) => () }
    } yield success
  }

  test("JwtVerification.rejectNonArrayCriticalHeaders") {
    val header = JwtHeader.default.add("crit", "jots-example".asJson)
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerificationBuilder.default[IO].hmac(algorithm, secretKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidCriticalHeaders) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectUnsupportedCriticalHeader") {
    val keySet = JwkSet(octJwk("key-1"))
    val header = criticalHeader("jots-example").withKeyId(JwkKeyId("key-1"))
    for {
      signed <- sign(JwtClaims.empty, header)
      verification <- JwtVerificationBuilder.default[IO].jwkSetAll(keySet).build
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
      result <- JwtVerificationBuilder.default[IO].rsa(JwtRsaAlgorithm.RS256, publicKey).build.attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidPublicKey) => () }
    } yield success
  }

  test("JwtVerification.rejectMismatchedEcdsaCurve") {
    val publicKey = ExampleEcdsaJwt.ES384Pkcs8.publicKey

    for {
      result <- JwtVerificationBuilder.default[IO].ecdsa(JwtEcdsaAlgorithm.ES256, publicKey).build.attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidEcKeyLength) => () }
    } yield success
  }

  test("JwtVerification.rejectAlgorithmForOtherEcdsaCurve") {
    val example = ExampleEcdsaJwt.ES256Pkcs8

    for {
      signing <- JwtSigningBuilder
        .default[IO]
        .ecdsa(JwtEcdsaAlgorithm.ES512, example.privateKey)
        .withCheckKeyRequirements(false)
        .build
      signed <- example.builder.signWith(signing)
      verification <- JwtVerificationBuilder.default[IO].ecdsaAll(example.publicKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectShortEcdsaSignature") {
    val jwt = ExampleEcdsaJwt.ES512Jwk.signedJwt
    val (r, s) = jwt.signature.toByteVector.splitAt(66)
    val signed = SignedJwt(jwt.header, jwt.claims, JwtSignature(r.tail ++ s.tail))

    for {
      verification <- ExampleEcdsaJwt.ES512Jwk.verification
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.InvalidSignature) => () }
    } yield expect(r.head == 0 && s.head == 0)
  }

  test("JwtVerification.eddsaAll.acceptsEdDSA") {
    val example = ExampleEddsaJwt.EdDSAPkcs8

    for {
      verification <- JwtVerificationBuilder.default[IO].eddsaAll(example.publicKey).build
      result <- example.signedJwt.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.rejectAlgorithmForOtherEddsaCurve") {
    val example = ExampleEddsaJwt.Ed25519Pkcs8
    val signed = tokenWithAlgorithm(JwtAlgorithm.Ed448, ByteVector.fill(114)(1))

    for {
      verification <- JwtVerificationBuilder.default[IO].eddsaAll(example.publicKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectPkcs1AlgorithmForPssKey") {
    val example = ExampleRsaJwt.PS256Pkcs1PssRestricted
    val signed = tokenWithAlgorithm(JwtAlgorithm.RS256, example.signedJwt.signature.toByteVector)

    for {
      verification <- JwtVerificationBuilder.default[IO].rsaAll(example.publicKey).build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedAlgorithm) => () }
    } yield success
  }

  test("JwtVerification.rejectUnusablePublicKey") {
    val publicKey = PublicKey.fromX509Spki(ByteVector(1, 2, 3))
    val signed = tokenWithAlgorithm(JwtAlgorithm.RS256, ByteVector.fill(256)(1))

    for {
      verification <- JwtVerificationBuilder
        .default[IO]
        .rsa(JwtRsaAlgorithm.RS256, publicKey)
        .withCheckKeyRequirements(false)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.SignatureVerificationFailed) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectMismatchedKeyAlgorithm") {
    val keySet = JwkSet(octJwkWithAlgorithm("key-1", "HS384".asJson))

    JwtVerificationBuilder
      .default[IO]
      .jwkSet(NonEmptyList.of(JwtAlgorithm.HS256), keySet)
      .build
      .attempt
      .map {
        case Left(e: JwtException.EmptyKeySet) =>
          expect.eql(
            "the key set has no keys for signature verification: " +
              "the key with id [key-1] and algorithm (alg) [HS384] was rejected, expected [HS256]",
            e.message
          )
        case _ => failure("unexpected case")
      }
  }

  test("JwtVerification.jwkSet.rejectInvalidKeyAlgorithm") {
    val keySet = JwkSet(octJwkWithAlgorithm("key-1", 256.asJson))

    JwtVerificationBuilder
      .default[IO]
      .jwkSet(NonEmptyList.of(JwtAlgorithm.HS256), keySet)
      .build
      .attempt
      .map {
        case Left(e: JwtException.EmptyKeySet) =>
          expect.eql(
            "the key set has no keys for signature verification: " +
              "the key with id [key-1] has invalid algorithm (alg) [256]",
            e.message
          )
        case _ => failure("unexpected case")
      }
  }

  test("JwtVerification.jwkSet.skipsUnusableKeys") {
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-1")))
      verification <- JwtVerificationBuilder
        .default[IO]
        .jwkSet(NonEmptyList.of(JwtAlgorithm.HS256), mixedKeySet)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("JwtVerification.jwkSet.rejectSkippedKey") {
    for {
      signed <- sign(JwtClaims("sub" -> "alice".asJson), JwtHeader.default.withKeyId(JwkKeyId("key-2")))
      verification <- JwtVerificationBuilder
        .default[IO]
        .jwkSet(NonEmptyList.of(JwtAlgorithm.HS256), mixedKeySet)
        .build
      result <- signed.verifyWith(verification).attempt
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield success
  }

  /**
    * A key set with a usable key (key-1), and keys which cannot be used
    * because the algorithm is not accepted (key-2), or because the key
    * type is not supported (key-3 and key-4).
    */
  private val mixedKeySet: JwkSet =
    JwkSet(
      octJwk("key-1"),
      octJwkWithAlgorithm("key-2", "HS384".asJson),
      Jwk("kty" -> "AKP".asJson, "kid" -> "key-3".asJson).fold(throw _, identity),
      Jwk("kty" -> "AKP".asJson, "kid" -> "key-4".asJson, "alg" -> "ML-DSA-44".asJson).fold(throw _, identity)
    )

  private def octJwkWithAlgorithm(keyId: String, algorithm: io.circe.Json): Jwk =
    Jwk(
      "kty" -> "oct".asJson,
      "kid" -> keyId.asJson,
      "alg" -> algorithm,
      "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
    ).fold(throw _, identity)
}
