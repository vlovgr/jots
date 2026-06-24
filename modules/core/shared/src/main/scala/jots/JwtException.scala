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

import cats.syntax.all.*
import io.circe.Json
import scala.concurrent.duration.FiniteDuration
import scala.util.control.NoStackTrace

/**
  * Exception raised when there is an issue relating to JWTs.
  */
abstract class JwtException(val message: String, val cause: Option[Throwable] = None)
  extends RuntimeException(message, cause.orNull)
  with NoStackTrace

object JwtException {

  /**
    * Exception raised when creating a [[JwtVerification]] with a
    * [[JwkSet]] that contains no keys for signature verification.
    */
  final class EmptyKeySet() extends JwtException("the key set has no keys for signature verification")

  /**
    * Exception raised when the `alg` algorithm is not a `String`.
    */
  final class InvalidAlgorithm() extends JwtException("the token algorithm (alg) is invalid")

  /**
    * Exception raised when the `aud` audience is not a `String` or array of `String`s.
    */
  final class InvalidAudience(audience: Json)
    extends JwtException(s"the token audience (aud) [${audience.noSpaces}] is invalid")

  /**
    * Exception raised when the `crit` critical headers are not a non-empty array of `String`s.
    */
  final class InvalidCriticalHeaders(criticalHeaders: Json)
    extends JwtException(s"the critical headers (crit) [${criticalHeaders.noSpaces}] are invalid")

  /**
    * Exception raised when an EC private key for [[JwtSigning]] or public
    * key for [[JwtVerification]] does not have the exact curve bit length
    * required by the accepted ECDSA algorithms.
    */
  final class InvalidEcKeyLength(bitLength: Int)
    extends JwtException(
      s"the ECDSA key length was $bitLength bits, which did not match any algorithm"
    )

  /**
    * Exception raised when an EdDSA private key for [[JwtSigning]] or public
    * key for [[JwtVerification]] does not have the exact curve bit length
    * required by the accepted EdDSA algorithms.
    */
  final class InvalidEddsaKeyLength(bitLength: Int)
    extends JwtException(
      s"the EdDSA key length was $bitLength bits, which did not match any algorithm"
    )

  /**
    * Exception raised when the `exp` expiration is not a valid expiration.
    */
  final class InvalidExpiration(expiration: Json)
    extends JwtException(s"the token expiration (exp) [${expiration.noSpaces}] is invalid")

  /**
    * Exception raised when the `kid` key identifier is not a `String`.
    */
  final class InvalidKeyId() extends JwtException("the key id (kid) is invalid")

  /**
    * Exception raised when the `kty` key type is not a `String`.
    */
  final class InvalidKeyType(keyType: Json)
    extends JwtException(s"the key type (kty) [${keyType.noSpaces}] is invalid")

  /**
    * Exception raised when the `iat` issued-at is not a valid value.
    */
  final class InvalidIssuedAt(issuedAt: Json)
    extends JwtException(s"the token issued at (iat) [${issuedAt.noSpaces}] is invalid")

  /**
    * Exception raised when the `iss` issuer is not a `String`.
    */
  final class InvalidIssuer(issuer: Json)
    extends JwtException(s"the token issuer (iss) [${issuer.noSpaces}] is invalid")

  /**
    * Exception raised when parsing a JWT signature fails.
    */
  final class InvalidJwtSignature(details: String) extends JwtException(s"the signature is invalid: $details")

  /**
    * Exception raised when the `nbf` not-before is not a valid value.
    */
  final class InvalidNotBefore(notBefore: Json)
    extends JwtException(s"the token not-before (nbf) [${notBefore.noSpaces}] is invalid")

  /**
    * Exception raised when a private key is invalid, for example when
    * [[Jwk#toPrivateKey]] fails to generate a key, or when the length
    * of a private key for [[JwtSigning]] cannot be determined.
    */
  final class InvalidPrivateKey(details: String) extends JwtException(s"invalid private key: $details")

  /**
    * Exception raised when a public key is invalid, for example when
    * [[Jwk#toPublicKey]] fails to generate a key, or when the length
    * of a public key for [[JwtVerification]] cannot be determined.
    */
  final class InvalidPublicKey(details: String) extends JwtException(s"invalid public key: $details")

  /**
    * Exception raised when an RSA private key for [[JwtSigning]]
    * or public key for [[JwtVerification]] is less than 2048 bits.
    */
  final class InvalidRsaKeyLength(bitLength: Int)
    extends JwtException(s"the RSA key length was $bitLength bits, less than the minimum 2048 bits")

  /**
    * Exception raised when [[Jwk#toSecretKey]] fails to generate a key.
    */
  final class InvalidSecretKey(details: String) extends JwtException(s"invalid secret key: $details")

  /**
    * Exception raised when a secret key for [[JwtSigning]]
    * or [[JwtVerification]] is less than the minimum key
    * length set by [[JwtHmacAlgorithm#minKeyLength]].
    */
  final class InvalidSecretKeyLength(algorithm: JwtHmacAlgorithm)
    extends JwtException(
      s"the secret key length was less than required for $algorithm (${algorithm.minKeyLength} bytes)"
    )

  /**
    * Exception raised when [[JwtVerification]] fails to verify the token signature.
    */
  final class InvalidSignature()
    extends JwtException("the token signature did not match the expected signature")

  /**
    * Exception raised when parsing a signed JWT fails.
    */
  final class InvalidSignedJwt(details: Option[String] = None, cause: Option[Throwable] = None)
    extends JwtException(s"the token is invalid${details.foldMap(details => s": $details")}", cause)

  /**
    * Exception raised when parsing JWT claims fails.
    */
  final class InvalidSignedJwtClaims(details: String, cause: Option[Throwable] = None)
    extends JwtException(s"the claims are invalid: $details", cause)

  /**
    * Exception raised when parsing a JWT header fails.
    */
  final class InvalidSignedJwtHeader(details: String, cause: Option[Throwable] = None)
    extends JwtException(s"the header is invalid: $details", cause)

  /**
    * Exception raised when the `sub` subject is not a `String`.
    */
  final class InvalidSubject(subject: Json)
    extends JwtException(s"the token subject (sub) [${subject.noSpaces}] is invalid")

  /**
    * Exception raised by [[JwtVerification]] when a token is missing the `alg` algorithm.
    */
  final class MissingAlgorithm() extends JwtException("the token header is missing the algorithm (alg)")

  /**
    * Exception raised by [[JwtVerification]] when a token is missing the `aud` audience.
    */
  final class MissingAudience() extends JwtException("the token claims are missing the audience (aud)")

  /**
    * Exception raised by [[JwtVerification]] when a `crit` critical header
    * name is not also present as a header parameter in the token header.
    */
  final class MissingCriticalHeader(criticalHeader: String)
    extends JwtException(s"the critical header [$criticalHeader] is missing from the token header")

  /**
    * Exception raised by [[JwtVerification]] when a required `exp` expiration is missing.
    */
  final class MissingExpiration() extends JwtException("the token claims are missing the expiration (exp)")

  /**
    * Exception raised by [[JwtVerification]] when a required `iat` issued-at is missing.
    */
  final class MissingIssuedAt() extends JwtException("the token claims are missing the issued at (iat)")

  /**
    * Exception raised by [[JwtVerification]] when a token is missing the `iss` issuer.
    */
  final class MissingIssuer() extends JwtException("the token claims are missing the issuer (iss)")

  /**
    * Exception raised by [[JwtVerification]] when no key in the key set matches the token key id (kid).
    */
  final class MissingKey() extends JwtException("the key set has no key matching the token key id (kid)")

  /**
    * Exception raised when a [[Jwk]] or token is missing the `kid` property.
    */
  final class MissingKeyId() extends JwtException("the key or token is missing the key id (kid)")

  /**
    * Exception raised when a [[Jwk]] is missing the `kty` key type.
    */
  final class MissingKeyType() extends JwtException("the key is missing the key type (kty)")

  /**
    * Exception raised by [[JwtVerification]] when a required `nbf` not-before is missing.
    */
  final class MissingNotBefore() extends JwtException("the token claims are missing the not-before (nbf)")

  /**
    * Exception raised when a token is missing the `sub` subject.
    */
  final class MissingSubject() extends JwtException("the token claims are missing the subject (sub)")

  /**
    * Exception raised by [[JwtVerification]] when there are no accepted
    * algorithms for a provided [[Jwk]] with the specified [[JwkKeyType]].
    */
  final class NoAcceptedAlgorithms(keyId: JwkKeyId, keyType: JwkKeyType)
    extends JwtException(
      s"no accepted algorithms for key with id [${keyId.value}] and type [${keyType.name}]"
    )

  /**
    * Exception raised by [[JwtVerification]] when a token
    * `alg` algorithm or [[Jwk]] `alg` algorithm is rejected.
    */
  final class RejectedAlgorithm() extends JwtException("the key or token algorithm (alg) was rejected")

  /**
    * Exception raised by [[JwtVerification]] when a token `aud` audience is rejected.
    */
  final class RejectedAudience(audience: List[String])
    extends JwtException(s"the token audience (aud) [${audience.mkString(",")}] was rejected")

  /**
    * Exception raised by [[JwtVerification]] when a token `iss` issuer is rejected.
    */
  final class RejectedIssuer(issuer: String)
    extends JwtException(s"the token issuer (iss) [$issuer] was rejected")

  /**
    * Exception raised by [[JwtVerification]] when a token `sub` subject is rejected.
    */
  final class RejectedSubject(subject: String)
    extends JwtException(s"the token subject (sub) [$subject] was rejected")

  /**
    * Exception raised when the `exp` expiration time has been reached.
    */
  final class TokenExpired(expiresAt: FiniteDuration)
    extends JwtException(s"the token expired at ${expiresAt.toSeconds} epoch seconds")

  /**
    * Exception raised when the `iat` issued-at time has not been reached.
    */
  final class TokenNotYetIssued(issuedAt: FiniteDuration)
    extends JwtException(s"the token is not issued before ${issuedAt.toSeconds} epoch seconds")

  /**
    * Exception raised when the `nbf` not-before time has not been reached.
    */
  final class TokenNotYetValid(notBefore: FiniteDuration)
    extends JwtException(s"the token is not valid before ${notBefore.toSeconds} epoch seconds")

  /**
    * Exception raised by [[JwtVerification]] when a token `crit` header lists a
    * critical header that the verification has not been configured to accept.
    */
  final class UnsupportedCriticalHeader(criticalHeader: String)
    extends JwtException(s"the critical header [$criticalHeader] is not supported")

  /**
    * Exception raised by [[JwtVerification]] when a provided [[Jwk]] is not supported.
    */
  final class UnsupportedKey(keyId: JwkKeyId, keyType: JwkKeyType, algorithm: Option[JwtAlgorithm] = None)
    extends JwtException({
      val details = algorithm.foldMap(algorithm => s" and algorithm [${algorithm.name}]")
      s"the key with id [${keyId.value}] and type [${keyType.name}]${details} is not supported"
    })

  /**
    * Exception raised when a [[JwkKeyType]] is not recognized.
    */
  final class UnsupportedKeyType(keyType: String)
    extends JwtException(s"the key type (kty) [$keyType] is not supported")
}
