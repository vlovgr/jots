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
import cats.Functor
import cats.MonadThrow
import jots.crypto.Crypto
import jots.crypto.PrivateKey
import jots.crypto.SecretKey

/**
  * [[JwtSigning]] builder which allows customizing signing checks.
  *
  * The default instance checks that the private or secret key meets the
  * key requirements of the algorithm being used, as detailed by
  * [[checkKeyRequirements]].
  */
sealed abstract class JwtSigningBuilder[F[_], G[_]] {

  /**
    * Returns whether private and secret key requirements are checked.
    *
    * For HMAC algorithms, a [[JwtHmacAlgorithm#minKeyLength]]
    * minimum secret key length is required.
    *
    * For RSA algorithms, a minimum key length (also known as RSA
    * modulus bit length) of 2048 bits is required.
    *
    * For ECDSA and EdDSA algorithms, the private key must use the
    * exact curve bit length required by the algorithm.
    *
    * Default: `true`.
    */
  def checkKeyRequirements: Boolean

  /**
    * Sets whether private and secret key requirements are checked.
    */
  def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtSigningBuilder[F, G]

  /**
    * Returns a new [[JwtSigning]] instance using the builder settings.
    */
  def build: F[JwtSigning[G]]
}

object JwtSigningBuilder {

  /**
    * Create [[JwtSigningBuilder]] instances with the specified type.
    */
  def default[F[_]]: JwtSigningBuilderDefault[F, F] =
    new JwtSigningBuilderDefault[F, F] {}

  sealed abstract class JwtSigningBuilderDefault[F[_], G[_]] {
    private[jots] def asymmetric(
      algorithm: JwtAsymmetricAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      JwtAsymmetricSigningBuilder.default(algorithm, privateKey)

    /**
      * Returns a new [[JwtSigningBuilder]] instance which signs
      * tokens using the specified ECDSA algorithm and private key.
      */
    def ecdsa(
      algorithm: JwtEcdsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      asymmetric(algorithm, privateKey)

    /**
      * Returns a new [[JwtSigningBuilder]] instance which signs
      * tokens using the specified EdDSA algorithm and private key.
      */
    def eddsa(
      algorithm: JwtEddsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      asymmetric(algorithm, privateKey)

    /**
      * Returns a new [[JwtSigningBuilder]] instance which signs
      * tokens using the specified HMAC algorithm and secret key.
      */
    def hmac(
      algorithm: JwtHmacAlgorithm,
      secretKey: SecretKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      JwtHmacSigningBuilder.default(algorithm, secretKey)

    /**
      * Returns a new [[JwtSigningBuilder]] instance which signs
      * tokens using the specified algorithm and [[Jwk]].
      */
    def jwk(
      algorithm: JwtAlgorithm,
      key: Jwk
    )(implicit F: MonadThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      JwtJwkSigningBuilder.default(algorithm, key)

    /**
      * Returns a new [[JwtSigningBuilder]] instance which signs
      * tokens using the specified RSA algorithm and private key.
      */
    def rsa(
      algorithm: JwtRsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): JwtSigningBuilder[F, G] =
      asymmetric(algorithm, privateKey)

    /**
      * Create [[JwtSigning]] instances that sign with the specified type.
      */
    def signWith[H[_]]: JwtSigningBuilderDefault[F, H] =
      new JwtSigningBuilderDefault[F, H] {}
  }
}

private[jots] final case class JwtAsymmetricSigningBuilder[F[_]: ApplicativeThrow, G[_]: Crypto: Functor](
  override val checkKeyRequirements: Boolean,
  algorithm: JwtAsymmetricAlgorithm,
  privateKey: PrivateKey
) extends JwtSigningBuilder[F, G] {
  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtSigningBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def build: F[JwtSigning[G]] =
    JwtSigning.fromAsymmetricBuilder(this)
}

private[jots] object JwtAsymmetricSigningBuilder {
  def default[F[_]: ApplicativeThrow, G[_]: Crypto: Functor](
    algorithm: JwtAsymmetricAlgorithm,
    privateKey: PrivateKey
  ): JwtAsymmetricSigningBuilder[F, G] =
    JwtAsymmetricSigningBuilder(
      checkKeyRequirements = true,
      algorithm = algorithm,
      privateKey = privateKey
    )
}

private[jots] final case class JwtHmacSigningBuilder[F[_]: ApplicativeThrow, G[_]: Crypto: Functor](
  override val checkKeyRequirements: Boolean,
  algorithm: JwtHmacAlgorithm,
  secretKey: SecretKey
) extends JwtSigningBuilder[F, G] {
  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtSigningBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def build: F[JwtSigning[G]] =
    JwtSigning.fromHmacBuilder(this)
}

private[jots] object JwtHmacSigningBuilder {
  def default[F[_]: ApplicativeThrow, G[_]: Crypto: Functor](
    algorithm: JwtHmacAlgorithm,
    secretKey: SecretKey
  ): JwtHmacSigningBuilder[F, G] =
    JwtHmacSigningBuilder(
      checkKeyRequirements = true,
      algorithm = algorithm,
      secretKey = secretKey
    )
}

private[jots] final case class JwtJwkSigningBuilder[F[_]: MonadThrow, G[_]: Crypto: Functor](
  override val checkKeyRequirements: Boolean,
  algorithm: JwtAlgorithm,
  key: Jwk
) extends JwtSigningBuilder[F, G] {
  def algorithmMatches(name: String): Boolean =
    name == algorithm.name

  /**
    * Builds the specified builder using the settings from this builder.
    */
  def build(builder: JwtSigningBuilder[F, G]): F[JwtSigning[G]] =
    builder
      .withCheckKeyRequirements(checkKeyRequirements)
      .build

  override def withCheckKeyRequirements(checkKeyRequirements: Boolean): JwtSigningBuilder[F, G] =
    copy(checkKeyRequirements = checkKeyRequirements)

  override def build: F[JwtSigning[G]] =
    JwtSigning.fromJwkBuilder(this)
}

private[jots] object JwtJwkSigningBuilder {
  def default[F[_]: MonadThrow, G[_]: Crypto: Functor](
    algorithm: JwtAlgorithm,
    key: Jwk
  ): JwtJwkSigningBuilder[F, G] =
    JwtJwkSigningBuilder(
      checkKeyRequirements = true,
      algorithm = algorithm,
      key = key
    )
}
