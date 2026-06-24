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
  * - The expiration (exp), when present, is verified to be in the future.
  * - The not-before (nbf), when present, is verified to not be in the future.
  * - If the token contains a `crit` header, then the token is rejected. The
  *   [[JwtVerificationBuilder#withCriticalHeaders]] function can be used to
  *   specify the set of accepted critical headers.
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
    * Returns the accepted audiences; or `None` if all audiences are accepted.
    *
    * Default: `None`.
    */
  def acceptedAudiences: Option[NonEmptyList[String]]

  /**
    * Sets the specified audiences as the only accepted audiences.
    */
  def withAcceptedAudiences(audience: String, audiences: String*): JwtVerificationBuilder[F, G] =
    withAcceptedAudiencesList(NonEmptyList.of(audience, audiences: _*))

  /**
    * Sets the specified audiences as the only accepted audiences.
    */
  def withAcceptedAudiencesList(audiences: NonEmptyList[String]): JwtVerificationBuilder[F, G] =
    withAcceptedAudiencesOption(Some(audiences))

  /**
    * Sets the specified audiences as the only accepted audiences.
    *
    * If `None` is provided, all audiences will be accepted.
    */
  def withAcceptedAudiencesOption(audiences: Option[NonEmptyList[String]]): JwtVerificationBuilder[F, G]

  /**
    * Returns the accepted issuers; or `None` if all issuers are accepted.
    *
    * Default: `None`.
    */
  def acceptedIssuers: Option[NonEmptyList[String]]

  /**
    * Sets the specified issuers as the only accepted issuers.
    */
  def withAcceptedIssuers(issuer: String, issuers: String*): JwtVerificationBuilder[F, G] =
    withAcceptedIssuersList(NonEmptyList.of(issuer, issuers: _*))

  /**
    * Sets the specified issuers as the only accepted issuers.
    */
  def withAcceptedIssuersList(issuers: NonEmptyList[String]): JwtVerificationBuilder[F, G] =
    withAcceptedIssuersOption(Some(issuers))

  /**
    * Sets the specified issuers as the only accepted issuers.
    *
    * If `None` is provided, all issuers will be accepted.
    */
  def withAcceptedIssuersOption(issuers: Option[NonEmptyList[String]]): JwtVerificationBuilder[F, G]

  /**
    * Returns the accepted subjects; or `None` if all subjects are accepted.
    *
    * Default: `None`.
    */
  def acceptedSubjects: Option[NonEmptyList[String]]

  /**
    * Sets the specified subjects as the only accepted subjects.
    */
  def withAcceptedSubjects(subject: String, subjects: String*): JwtVerificationBuilder[F, G] =
    withAcceptedSubjectsList(NonEmptyList.of(subject, subjects: _*))

  /**
    * Sets the specified subjects as the only accepted subjects.
    */
  def withAcceptedSubjectsList(subjects: NonEmptyList[String]): JwtVerificationBuilder[F, G] =
    withAcceptedSubjectsOption(Some(subjects))

  /**
    * Sets the specified subjects as the only accepted subjects.
    *
    * If `None` is provided, all subjects will be accepted.
    */
  def withAcceptedSubjectsOption(subject: Option[NonEmptyList[String]]): JwtVerificationBuilder[F, G]

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
    * Returns the set of critical headers (crit) which should be accepted.
    *
    * When a token with a `crit` header is being verified:
    *
    * - every listed header name must be in this set, and also
    * - every listed header name must be present in the header.
    *
    * Intepreting the semantics of the headers are left to the application.
    *
    * Default: `Set.empty` meaning any token with a `crit` header is rejected.
    */
  def criticalHeaders: Set[String]

  /**
    * Sets the specified header names as the only accepted critical headers.
    */
  def withCriticalHeaders(criticalHeader: String, criticalHeaders: String*): JwtVerificationBuilder[F, G] =
    withCriticalHeadersSet((criticalHeader +: criticalHeaders).toSet)

  /**
    * Sets the specified header names as the only accepted critical headers.
    */
  def withCriticalHeadersSet(criticalHeaders: Set[String]): JwtVerificationBuilder[F, G]

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
      ecdsaList(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using all recognized ECDSA algorithms and a public key.
      */
    def ecdsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      ecdsaList(JwtEcdsaAlgorithm.All, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of ECDSA algorithms and a public key.
      */
    def ecdsaList(
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
      eddsaList(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using all recognized EdDSA algorithms and a public key.
      */
    def eddsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      eddsaList(JwtEddsaAlgorithm.All, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of EdDSA algorithms and a public key.
      */
    def eddsaList(
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
      hmacList(NonEmptyList.of(algorithm), secretKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using all recognized HMAC algorithms and a secret key.
      */
    def hmacAll(
      secretKey: SecretKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      hmacList(JwtHmacAlgorithm.All, secretKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of HMAC algorithms and a secret key.
      */
    def hmacList(
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
      * tokens using a list of algorithms and keys in a [[JwkSet]].
      *
      * Keys which cannot be used for signature verification are excluded
      * from the key set; a token referencing such a key is rejected. A
      * key is excluded when it has no key id (kid), since keys are
      * selected by key id, or when its `use` or `key_ops` parameters
      * indicate it is not meant for signature verification.
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
      * tokens using all recognized algorithms and keys in a [[JwkSet]].
      *
      * Keys which cannot be used for signature verification are excluded
      * from the key set; a token referencing such a key is rejected. A
      * key is excluded when it has no key id (kid), since keys are
      * selected by key id, or when its `use` or `key_ops` parameters
      * indicate it is not meant for signature verification.
      */
    def jwkSetAll(
      keySet: JwkSet
    )(implicit
      F: MonadThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      jwkSet(JwtAlgorithm.All, keySet)

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
      rsaList(NonEmptyList.of(algorithm), publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using all recognized RSA algorithms and a public key.
      */
    def rsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): JwtVerificationBuilder[F, G] =
      rsaList(JwtRsaAlgorithm.All, publicKey)

    /**
      * Returns a new [[JwtVerificationBuilder]] instance which verifies
      * tokens using a list of RSA algorithms and a public key.
      */
    def rsaList(
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
  override val acceptedAudiences: Option[NonEmptyList[String]],
  override val acceptedIssuers: Option[NonEmptyList[String]],
  override val acceptedSubjects: Option[NonEmptyList[String]],
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: Set[String],
  algorithms: NonEmptyList[JwtHmacAlgorithm],
  secretKey: SecretKey
) extends JwtVerificationBuilder[F, G] {
  private val algorithmByName: NonEmptyMap[String, JwtHmacAlgorithm] =
    algorithms.groupByNem(_.name).map(_.head)

  def algorithmWithName(name: String): Option[JwtHmacAlgorithm] =
    algorithmByName(name)

  override def withAcceptedAudiencesOption(
    audiences: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuersOption(
    issuers: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjectsOption(
    subjects: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

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

  override def withCriticalHeadersSet(criticalHeaders: Set[String]): JwtVerificationBuilder[F, G] =
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
      acceptedAudiences = None,
      acceptedIssuers = None,
      acceptedSubjects = None,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = Set.empty,
      algorithms = algorithms,
      secretKey = secretKey
    )
}

private[jots] final case class JwtAsymmetricVerificationBuilder[
  F[_]: ApplicativeThrow,
  G[_]: Clock: Crypto: MonadThrow
](
  override val acceptedAudiences: Option[NonEmptyList[String]],
  override val acceptedIssuers: Option[NonEmptyList[String]],
  override val acceptedSubjects: Option[NonEmptyList[String]],
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: Set[String],
  algorithms: NonEmptyList[JwtAsymmetricAlgorithm],
  publicKey: PublicKey
) extends JwtVerificationBuilder[F, G] {
  private val algorithmByName: NonEmptyMap[String, JwtAsymmetricAlgorithm] =
    algorithms.groupByNem(_.name).map(_.head)

  def algorithmWithName(name: String): Option[JwtAsymmetricAlgorithm] =
    algorithmByName(name)

  override def withAcceptedAudiencesOption(
    audiences: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuersOption(
    issuers: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjectsOption(
    subjects: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

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

  override def withCriticalHeadersSet(criticalHeaders: Set[String]): JwtVerificationBuilder[F, G] =
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
      acceptedAudiences = None,
      acceptedIssuers = None,
      acceptedSubjects = None,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = Set.empty,
      algorithms = algorithms,
      publicKey = publicKey
    )
}

private[jots] final case class JwtJwkSetVerificationBuilder[
  F[_]: MonadThrow,
  G[_]: Clock: Crypto: MonadThrow
](
  override val acceptedAudiences: Option[NonEmptyList[String]],
  override val acceptedIssuers: Option[NonEmptyList[String]],
  override val acceptedSubjects: Option[NonEmptyList[String]],
  override val checkExpiration: Boolean,
  override val checkIssuedAt: Boolean,
  override val checkKeyRequirements: Boolean,
  override val checkNotBefore: Boolean,
  override val requireExpiration: Boolean,
  override val requireIssuedAt: Boolean,
  override val requireNotBefore: Boolean,
  override val clockSkew: FiniteDuration,
  override val criticalHeaders: Set[String],
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
      .withAcceptedAudiencesOption(acceptedAudiences)
      .withAcceptedIssuersOption(acceptedIssuers)
      .withAcceptedSubjectsOption(acceptedSubjects)
      .withCheckExpiration(checkExpiration)
      .withCheckIssuedAt(checkIssuedAt)
      .withCheckKeyRequirements(checkKeyRequirements)
      .withCheckNotBefore(checkNotBefore)
      .withRequireExpiration(requireExpiration)
      .withRequireIssuedAt(requireIssuedAt)
      .withRequireNotBefore(requireNotBefore)
      .withClockSkew(clockSkew)
      .withCriticalHeadersSet(criticalHeaders)
      .build

  override def withAcceptedAudiencesOption(
    audiences: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedAudiences = audiences)

  override def withAcceptedIssuersOption(
    issuers: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedIssuers = issuers)

  override def withAcceptedSubjectsOption(
    subjects: Option[NonEmptyList[String]]
  ): JwtVerificationBuilder[F, G] =
    copy(acceptedSubjects = subjects)

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

  override def withCriticalHeadersSet(criticalHeaders: Set[String]): JwtVerificationBuilder[F, G] =
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
      acceptedAudiences = None,
      acceptedIssuers = None,
      acceptedSubjects = None,
      checkExpiration = true,
      checkIssuedAt = false,
      checkKeyRequirements = true,
      checkNotBefore = true,
      requireExpiration = false,
      requireIssuedAt = false,
      requireNotBefore = false,
      clockSkew = Duration.Zero,
      criticalHeaders = Set.empty,
      algorithms = algorithms,
      keySet = keySet
    )
}
