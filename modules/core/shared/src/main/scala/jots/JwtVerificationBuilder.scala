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

import cats.ApplicativeThrow
import cats.MonadThrow
import cats.data.NonEmptyList
import cats.data.NonEmptyMap
import cats.effect.kernel.Clock
import jots.crypto.Crypto
import jots.crypto.PublicKey
import jots.crypto.SecretKey
import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

/**
  * [[JwtVerification]] builder that allows customizing verification.
  *
  * The default instances perform the following verifications.
  *
  * - Public and secret keys must meet the key requirement of the algorithm
  *   used, as detailed by [[JwtVerificationBuilder#checkKeyRequirements]].
  * - If the token has an audience (aud), then the token is rejected, since
  *   the default accepted audiences are [[AcceptedAudiences.none]]. Use the
  *   `withAcceptedAudiences` function to specify the accepted audiences.
  * - The expiration (exp), when present, is verified to be in the future.
  * - The not-before (nbf), when present, is verified to not be in the future.
  * - If the token contains a `crit` header, then the token is rejected. The
  *   `withCriticalHeaders` function can be used to specify the set of
  *   accepted critical headers.
  *
  * The expiration (exp) and not-before (nbf) claims are only verified
  * when present. Their presence can additionally be required, in which
  * case a token missing the claim is rejected.
  *
  * The verifications above are in addition to verifying the signature
  * and, while not recommended, can be explicitly disabled. It is also
  * recommended to enable additional verifications when appropriate.
  *
  * For even more verifications, resort to custom [[JwtVerification]]s.
  */
sealed abstract class JwtVerificationBuilder[F[_], G[_]] {

  /**
    * Returns the accepted audiences (aud).
    *
    * Default: [[AcceptedAudiences.none]], which means tokens with an
    * audience are rejected, while tokens without an audience are accepted.
    */
  def acceptedAudiences: AcceptedAudiences

  /**
    * Sets the accepted audiences (aud).
    *
    * Use [[AcceptedAudiences.any]] to accept tokens with any audience.
    */
  def withAcceptedAudiences(audiences: AcceptedAudiences): JwtVerificationBuilder[F, G]

  /**
    * Sets the specified audiences as the only accepted audiences.
    */
  def withAcceptedAudiences(audience: String, audiences: String*): JwtVerificationBuilder[F, G] =
    withAcceptedAudiences(AcceptedAudiences(audience, audiences: _*))

  /**
    * Returns the accepted issuers (iss).
    *
    * Default: [[AcceptedIssuers.any]], which means all issuers are accepted.
    */
  def acceptedIssuers: AcceptedIssuers

  /**
    * Sets the accepted issuers (iss).
    */
  def withAcceptedIssuers(issuers: AcceptedIssuers): JwtVerificationBuilder[F, G]

  /**
    * Sets the specified issuers as the only accepted issuers.
    */
  def withAcceptedIssuers(issuer: String, issuers: String*): JwtVerificationBuilder[F, G] =
    withAcceptedIssuers(AcceptedIssuers(issuer, issuers: _*))

  /**
    * Returns the accepted subjects (sub).
    *
    * Default: [[AcceptedSubjects.any]], which means all subjects are accepted.
    */
  def acceptedSubjects: AcceptedSubjects

  /**
    * Sets the accepted subjects (sub).
    */
  def withAcceptedSubjects(subjects: AcceptedSubjects): JwtVerificationBuilder[F, G]

  /**
    * Sets the specified subjects as the only accepted subjects.
    */
  def withAcceptedSubjects(subject: String, subjects: String*): JwtVerificationBuilder[F, G] =
    withAcceptedSubjects(AcceptedSubjects(subject, subjects: _*))

  /**
    * Returns the accepted types (typ).
    *
    * Default: [[AcceptedTypes.any]], which means all types are accepted.
    */
  def acceptedTypes: AcceptedTypes

  /**
    * Sets the accepted types (typ).
    */
  def withAcceptedTypes(types: AcceptedTypes): JwtVerificationBuilder[F, G]

  /**
    * Sets the specified types as the only accepted types.
    */
  def withAcceptedTypes(`type`: String, types: String*): JwtVerificationBuilder[F, G] =
    withAcceptedTypes(AcceptedTypes(`type`, types: _*))

  /**
    * Returns `true` if the expiration (exp) should be verified when present; `false` otherwise.
    *
    * Default: `true`.
    */
  def checkExpiration: Boolean

  /**
    * Sets whether the expiration (exp) should be verified when present.
    */
  def withCheckExpiration(checkExpiration: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns `true` if the expiration (exp) is required to be present; `false` otherwise.
    *
    * When `true`, a token without an expiration is rejected. This is independent
    * of [[checkExpiration]], which controls verification when the claim is present.
    *
    * Default: `false`.
    */
  def requireExpiration: Boolean

  /**
    * Sets whether the expiration (exp) is required to be present.
    */
  def withRequireExpiration(requireExpiration: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns `true` if the issued at (iat) should be verified when present; `false` otherwise.
    *
    * Default: `false`.
    */
  def checkIssuedAt: Boolean

  /**
    * Sets whether the issued at (iat) should be verified when present.
    */
  def withCheckIssuedAt(checkIssuedAt: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns `true` if the issued at (iat) is required to be present; `false` otherwise.
    *
    * When `true`, a token without an issued at is rejected. This is independent
    * of [[checkIssuedAt]], which controls verification when the claim is present.
    *
    * Default: `false`.
    */
  def requireIssuedAt: Boolean

  /**
    * Sets whether the issued at (iat) is required to be present.
    */
  def withRequireIssuedAt(requireIssuedAt: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns whether public and secret key requirements are checked.
    *
    * For HMAC algorithms, a [[JwtHmacAlgorithm#minKeyLength]]
    * minimum secret key length is required.
    *
    * For RSA algorithms, a minimum key length (also known as RSA
    * modulus bit length) of 2048 bits is required.
    *
    * For ECDSA and EdDSA algorithms, the public key must use the
    * exact curve bit length required by an accepted algorithm.
    *
    * Default: `true`.
    */
  def checkKeyRequirements: Boolean

  /**
    * Sets whether public and secret key requirements are checked.
    */
  def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns `true` if the not-before (nbf) should be verified when present; `false` otherwise.
    *
    * Default: `true`.
    */
  def checkNotBefore: Boolean

  /**
    * Sets whether the not-before (nbf) should be verified when present.
    */
  def withCheckNotBefore(checkNotBefore: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns `true` if the not-before (nbf) is required to be present; `false` otherwise.
    *
    * When `true`, a token without a not-before is rejected. This is independent
    * of [[checkNotBefore]], which controls verification when the claim is present.
    *
    * Default: `false`.
    */
  def requireNotBefore: Boolean

  /**
    * Sets whether the not-before (nbf) is required to be present.
    */
  def withRequireNotBefore(requireNotBefore: Boolean): JwtVerificationBuilder[F, G]

  /**
    * Returns the allowed clock skew when checking:
    *
    * - expiration (exp),
    * - issued at (iat), and
    * - not-before (nbf) values.
    *
    * Default: `Duration.Zero`.
    */
  def clockSkew: FiniteDuration

  /**
    * Sets the allowed clock skew when checking:
    *
    * - expiration (exp),
    * - issued at (iat), and
    * - not-before (nbf) values.
    */
  def withClockSkew(clockSkew: FiniteDuration): JwtVerificationBuilder[F, G]

  /**
    * Returns the critical headers (crit) which should be accepted.
    *
    * When a token with a `crit` header is being verified:
    *
    * - every listed header name must be one of these headers, and also
    * - every listed header name must be present in the header.
    *
    * Intepreting the semantics of the headers are left to the application.
    *
    * Default: `List.empty` meaning any token with a `crit` header is rejected.
    */
  def criticalHeaders: List[String]

  /**
    * Sets the specified header names as the only accepted critical headers.
    */
  def withCriticalHeaders(criticalHeaders: List[String]): JwtVerificationBuilder[F, G]

  /**
    * Sets the specified header names as the only accepted critical headers.
    */
  def withCriticalHeaders(criticalHeader: String, criticalHeaders: String*): JwtVerificationBuilder[F, G] =
    withCriticalHeaders(criticalHeader :: criticalHeaders.toList)

  /**
    * Returns a new [[JwtVerification]] instance using the builder settings.
    */
  def build: F[JwtVerification[G]]
}

object JwtVerificationBuilder {
  def default[F[_]]: JwtVerificationBuilderDefault[F, F] =
    new JwtVerificationBuilderDefault[F, F] {}

  sealed abstract class JwtVerificationBuilderDefault[F[_], G[_]] {
    private[jots] def asymmetric(
      algorithms: NonEmptyList[JwtAsymmetricAlgorithm],
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      JwtAsymmetricVerificationBuilder.default(algorithms, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using the specified ECDSA algorithm and public key.
      */
    def ecdsa(
      algorithm: JwtEcdsaAlgorithm,
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      ecdsa(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of ECDSA algorithms and a public key.
      * Only the algorithm for the curve of the public key is accepted.
      */
    def ecdsa(
      algorithms: NonEmptyList[JwtEcdsaAlgorithm],
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      asymmetric(algorithms, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using the specified EdDSA algorithm and public key.
      */
    def eddsa(
      algorithm: JwtEddsaAlgorithm,
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      eddsa(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of EdDSA algorithms and a public key.
      * Only the algorithm for the curve of the public key is accepted.
      */
    def eddsa(
      algorithms: NonEmptyList[JwtEddsaAlgorithm],
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      asymmetric(algorithms, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using the specified HMAC algorithm and secret key.
      */
    def hmac(
      algorithm: JwtHmacAlgorithm,
      secretKey: SecretKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      hmac(NonEmptyList.of(algorithm), secretKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of HMAC algorithms and a secret key.
      */
    def hmac(
      algorithms: NonEmptyList[JwtHmacAlgorithm],
      secretKey: SecretKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      JwtHmacVerificationBuilder.default(algorithms, secretKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using the specified algorithm and keys in a [[JwkSet]].
      *
      * Keys which cannot be used for signature verification are excluded
      * from the key set; a token referencing such a key is rejected. A
      * key is excluded when it has no key id (kid), since keys are
      * selected by key id, or when its `use` or `key_ops` parameters
      * indicate it is not meant for signature verification. Keys
      * which are not supported, or have no accepted algorithm, are
      * also excluded.
      */
    def jwkSet(
      algorithm: JwtAlgorithm,
      keySet: JwkSet
    )(implicit
      F: MonadThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      jwkSet(NonEmptyList.of(algorithm), keySet)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of algorithms and keys in a [[JwkSet]].
      *
      * Keys which cannot be used for signature verification are excluded
      * from the key set; a token referencing such a key is rejected. A
      * key is excluded when it has no key id (kid), since keys are
      * selected by key id, or when its `use` or `key_ops` parameters
      * indicate it is not meant for signature verification. Keys
      * which are not supported, or have no accepted algorithm, are
      * also excluded.
      */
    def jwkSet(
      algorithms: NonEmptyList[JwtAlgorithm],
      keySet: JwkSet
    )(implicit
      F: MonadThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      JwtJwkSetVerificationBuilder.default(algorithms, keySet)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using the specified RSA algorithm and public key.
      */
    def rsa(
      algorithm: JwtRsaAlgorithm,
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      rsa(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of RSA algorithms and a public key.
      * Only RSA-PSS algorithms are accepted for RSA-PSS public keys.
      */
    def rsa(
      algorithms: NonEmptyList[JwtRsaAlgorithm],
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      asymmetric(algorithms, publicKey)

    /**
      * Create [[JwtVerification]] instances that verify with the specified type.
      */
    def verifyWith[H[_]]: JwtVerificationBuilderDefault[F, H] =
      new JwtVerificationBuilderDefault[F, H] {}
  }
}

private[jots] final case class JwtHmacVerificationBuilder[
  F[_]: ApplicativeThrow,
  G[_]: Clock: Crypto: MonadThrow
](
  override val acceptedAudiences: AcceptedAudiences,
  override val acceptedIssuers: AcceptedIssuers,
  override val acceptedSubjects: AcceptedSubjects,
  override val acceptedTypes: AcceptedTypes,
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: List[String],
  algorithms: NonEmptyList[JwtHmacAlgorithm],
  secretKey: SecretKey
) extends JwtVerificationBuilder[F, G] {
  private val algorithmByName: NonEmptyMap[String, JwtHmacAlgorithm] =
    algorithms.groupByNem(_.name).map(_.head)

  def algorithmWithName(name: String): Option[JwtHmacAlgorithm] =
    algorithmByName(name)

  override def withAcceptedAudiences(audiences: AcceptedAudiences): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuers(issuers: AcceptedIssuers): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjects(subjects: AcceptedSubjects): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

  override def withAcceptedTypes(types: AcceptedTypes): JwtVerificationBuilder[F, G] =
    copy(acceptedTypes = types)

  override def withCheckExpiration(checkExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkExpiration = checkExpiration)

  override def withCheckIssuedAt(checkIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkIssuedAt = checkIssuedAt)

  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def withCheckNotBefore(checkNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkNotBefore = checkNotBefore)

  override def withRequireExpiration(requireExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireExpiration = requireExpiration)

  override def withRequireIssuedAt(requireIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireIssuedAt = requireIssuedAt)

  override def withRequireNotBefore(requireNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireNotBefore = requireNotBefore)

  override def withClockSkew(clockSkew: FiniteDuration): JwtVerificationBuilder[F, G] =
    copy(clockSkew = clockSkew)

  override def withCriticalHeaders(criticalHeaders: List[String]): JwtVerificationBuilder[F, G] =
    copy(criticalHeaders = criticalHeaders)

  override def build: F[JwtVerification[G]] =
    JwtVerification.fromHmacBuilder(this)
}

private[jots] object JwtHmacVerificationBuilder {
  def default[
    F[_]: ApplicativeThrow,
    G[_]: Clock: Crypto: MonadThrow
  ](
    algorithms: NonEmptyList[JwtHmacAlgorithm],
    secretKey: SecretKey
  ): JwtHmacVerificationBuilder[F, G] =
    JwtHmacVerificationBuilder(
      acceptedAudiences = AcceptedAudiences.none,
      acceptedIssuers = AcceptedIssuers.any,
      acceptedSubjects = AcceptedSubjects.any,
      acceptedTypes = AcceptedTypes.any,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = List.empty,
      algorithms = algorithms,
      secretKey = secretKey
    )
}

private[jots] final case class JwtAsymmetricVerificationBuilder[
  F[_]: ApplicativeThrow,
  G[_]: Clock: Crypto: MonadThrow
](
  override val acceptedAudiences: AcceptedAudiences,
  override val acceptedIssuers: AcceptedIssuers,
  override val acceptedSubjects: AcceptedSubjects,
  override val acceptedTypes: AcceptedTypes,
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: List[String],
  algorithms: NonEmptyList[JwtAsymmetricAlgorithm],
  publicKey: PublicKey
) extends JwtVerificationBuilder[F, G] {
  override def withAcceptedAudiences(audiences: AcceptedAudiences): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuers(issuers: AcceptedIssuers): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjects(subjects: AcceptedSubjects): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

  override def withAcceptedTypes(types: AcceptedTypes): JwtVerificationBuilder[F, G] =
    copy(acceptedTypes = types)

  override def withCheckExpiration(checkExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkExpiration = checkExpiration)

  override def withCheckIssuedAt(checkIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkIssuedAt = checkIssuedAt)

  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def withCheckNotBefore(checkNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkNotBefore = checkNotBefore)

  override def withRequireExpiration(requireExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireExpiration = requireExpiration)

  override def withRequireIssuedAt(requireIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireIssuedAt = requireIssuedAt)

  override def withRequireNotBefore(requireNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireNotBefore = requireNotBefore)

  override def withClockSkew(clockSkew: FiniteDuration): JwtVerificationBuilder[F, G] =
    copy(clockSkew = clockSkew)

  override def withCriticalHeaders(criticalHeaders: List[String]): JwtVerificationBuilder[F, G] =
    copy(criticalHeaders = criticalHeaders)

  override def build: F[JwtVerification[G]] =
    JwtVerification.fromAsymmetricBuilder(this)
}

private[jots] object JwtAsymmetricVerificationBuilder {
  def default[
    F[_]: ApplicativeThrow,
    G[_]: Clock: Crypto: MonadThrow
  ](
    algorithms: NonEmptyList[JwtAsymmetricAlgorithm],
    publicKey: PublicKey
  ): JwtAsymmetricVerificationBuilder[F, G] =
    JwtAsymmetricVerificationBuilder(
      acceptedAudiences = AcceptedAudiences.none,
      acceptedIssuers = AcceptedIssuers.any,
      acceptedSubjects = AcceptedSubjects.any,
      acceptedTypes = AcceptedTypes.any,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = List.empty,
      algorithms = algorithms,
      publicKey = publicKey
    )
}

private[jots] final case class JwtJwkSetVerificationBuilder[
  F[_]: MonadThrow,
  G[_]: Clock: Crypto: MonadThrow
](
  override val acceptedAudiences: AcceptedAudiences,
  override val acceptedIssuers: AcceptedIssuers,
  override val acceptedSubjects: AcceptedSubjects,
  override val acceptedTypes: AcceptedTypes,
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: List[String],
  algorithms: NonEmptyList[JwtAlgorithm],
  keySet: JwkSet
) extends JwtVerificationBuilder[F, G] {
  private val algorithmByName: NonEmptyMap[String, JwtAlgorithm] =
    algorithms.groupByNem(_.name).map(_.head)

  def algorithmWithName(name: String): Option[JwtAlgorithm] =
    algorithmByName(name)

  /**
    * Builds the specified builder using the settings from this builder.
    */
  def build(builder: JwtVerificationBuilder[F, G]): F[JwtVerification[G]] =
    builder
      .withAcceptedAudiences(acceptedAudiences)
      .withAcceptedIssuers(acceptedIssuers)
      .withAcceptedSubjects(acceptedSubjects)
      .withAcceptedTypes(acceptedTypes)
      .withCheckExpiration(checkExpiration)
      .withCheckIssuedAt(checkIssuedAt)
      .withCheckKeyRequirements(checkKeyRequirements)
      .withCheckNotBefore(checkNotBefore)
      .withRequireExpiration(requireExpiration)
      .withRequireIssuedAt(requireIssuedAt)
      .withRequireNotBefore(requireNotBefore)
      .withClockSkew(clockSkew)
      .withCriticalHeaders(criticalHeaders)
      .build

  override def withAcceptedAudiences(audiences: AcceptedAudiences): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuers(issuers: AcceptedIssuers): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjects(subjects: AcceptedSubjects): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

  override def withAcceptedTypes(types: AcceptedTypes): JwtVerificationBuilder[F, G] =
    copy(acceptedTypes = types)

  override def withCheckExpiration(checkExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkExpiration = checkExpiration)

  override def withCheckIssuedAt(checkIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkIssuedAt = checkIssuedAt)

  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def withCheckNotBefore(checkNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(checkNotBefore = checkNotBefore)

  override def withRequireExpiration(requireExpiration: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireExpiration = requireExpiration)

  override def withRequireIssuedAt(requireIssuedAt: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireIssuedAt = requireIssuedAt)

  override def withRequireNotBefore(requireNotBefore: Boolean): JwtVerificationBuilder[F, G] =
    copy(requireNotBefore = requireNotBefore)

  override def withClockSkew(clockSkew: FiniteDuration): JwtVerificationBuilder[F, G] =
    copy(clockSkew = clockSkew)

  override def withCriticalHeaders(criticalHeaders: List[String]): JwtVerificationBuilder[F, G] =
    copy(criticalHeaders = criticalHeaders)

  override def build: F[JwtVerification[G]] =
    JwtVerification.fromJwkSetBuilder(this)
}

private[jots] object JwtJwkSetVerificationBuilder {
  def default[
    F[_]: MonadThrow,
    G[_]: Clock: Crypto: MonadThrow
  ](
    algorithms: NonEmptyList[JwtAlgorithm],
    keySet: JwkSet
  ): JwtJwkSetVerificationBuilder[F, G] =
    JwtJwkSetVerificationBuilder(
      acceptedAudiences = AcceptedAudiences.none,
      acceptedIssuers = AcceptedIssuers.any,
      acceptedSubjects = AcceptedSubjects.any,
      acceptedTypes = AcceptedTypes.any,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = List.empty,
      algorithms = algorithms,
      keySet = keySet
    )
}
