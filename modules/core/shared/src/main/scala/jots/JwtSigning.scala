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
import cats.syntax.all.*
import jots.JwtException.InvalidPrivateKey
import jots.JwtException.InvalidSecretKeyLength
import jots.crypto.Crypto
import jots.crypto.PrivateKey
import jots.crypto.SecretKey
import jots.internal.KeyLength
import jots.internal.KeyRequirement

/**
  * Capability to sign [[JwtBuilder]]s and return [[SignedJwt]]s.
  *
  * Signing [[JwtBuilder]]s requires specifying the algorithm to use
  * and a [[jots.crypto.PrivateKey]] or [[jots.crypto.SecretKey]]. A
  * minimum private and secret key length is enforced by default, but
  * this can be customized using [[JwtSigningBuilder]].
  *
  * The default [[JwtSigning]] instances will set the algorithm in
  * the header of the [[JwtBuilder]] before signing, to ensure it
  * matches with the actual signing algorithm.
  *
  * It is possible to implement custom [[JwtSigning]] instances,
  * for example for testing purposes. The bytes which should be
  * signed are provided by [[JwtBuilder#signingBytes]].
  */
trait JwtSigning[F[_]] {

  /**
    * Returns a [[SignedJwt]] for the specified [[JwtBuilder]].
    */
  def sign(jwt: JwtBuilder): F[SignedJwt]
}

object JwtSigning {
  def apply[F[_]](implicit F: JwtSigning[F]): JwtSigning[F] = F

  /**
    * Create [[JwtSigning]] instances with the specified type.
    */
  def default[F[_]]: JwtSigningDefault[F, F] =
    new JwtSigningDefault[F, F] {}

  /**
    * Return a [[JwtSigning]] instance that signs
    * with the specified function.
    */
  def signWith[F[_]](f: JwtBuilder => F[SignedJwt]): JwtSigning[F] =
    new JwtSigning[F] {
      override def sign(jwt: JwtBuilder): F[SignedJwt] =
        f(jwt)
    }

  sealed abstract class JwtSigningDefault[F[_], G[_]] {

    /**
      * Returns a new [[JwtSigning]] instance which signs tokens
      * using the specified ECDSA algorithm and private key.
      */
    def ecdsa(
      algorithm: JwtEcdsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] =
      JwtSigningBuilder.default[F].signWith[G].ecdsa(algorithm, privateKey).build

    /**
      * Returns a new [[JwtSigning]] instance which signs tokens
      * using the specified EdDSA algorithm and private key.
      */
    def eddsa(
      algorithm: JwtEddsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] =
      JwtSigningBuilder.default[F].signWith[G].eddsa(algorithm, privateKey).build

    /**
      * Returns a new [[JwtSigning]] instance which signs tokens
      * using the specified HMAC algorithm and secret key.
      */
    def hmac(
      algorithm: JwtHmacAlgorithm,
      secretKey: SecretKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] =
      JwtSigningBuilder.default[F].signWith[G].hmac(algorithm, secretKey).build

    /**
      * Returns a new [[JwtSigning]] instance which signs tokens
      * using the specified RSA algorithm and private key.
      */
    def rsa(
      algorithm: JwtRsaAlgorithm,
      privateKey: PrivateKey
    )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] =
      JwtSigningBuilder.default[F].signWith[G].rsa(algorithm, privateKey).build

    /**
      * Create [[JwtSigning]] instances that sign with the specified type.
      */
    def signWith[H[_]]: JwtSigningDefault[F, H] =
      new JwtSigningDefault[F, H] {}
  }

  private[jots] def fromAsymmetricBuilder[F[_], G[_]](
    builder: JwtAsymmetricSigningBuilder[F, G]
  )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] = {
    import builder.*

    val ensureKeyRequirements: F[Unit] =
      F.whenA(checkKeyRequirements) {
        KeyLength.fromPrivateKey(privateKey) match {
          case KeyLength.Unknown =>
            F.raiseError[Unit](new InvalidPrivateKey("unable to determine private key type and length"))
          case keyLength =>
            KeyRequirement.check(algorithm.keyRequirement, keyLength)
        }
      }

    ensureKeyRequirements.as {
      new JwtSigning[G] {
        override def sign(jwt: JwtBuilder): G[SignedJwt] =
          signAsymmetric(jwt.mapHeader(_.withAlgorithm(algorithm)))

        private def signAsymmetric(jwt: JwtBuilder): G[SignedJwt] =
          Crypto[G]
            .sign(algorithm.asymmetricAlgorithm, privateKey)(jwt.signingBytes)
            .map(JwtSignature.fromSignature)
            .map(jwt.toSigned)
      }
    }
  }

  private[jots] def fromHmacBuilder[F[_], G[_]](
    builder: JwtHmacSigningBuilder[F, G]
  )(implicit F: ApplicativeThrow[F], G: Functor[G], crypto: Crypto[G]): F[JwtSigning[G]] = {
    import builder.*

    val ensureMinKeyLength: F[Unit] =
      F.whenA(checkKeyRequirements) {
        val secretKeyLength = secretKey.toByteVector.length
        val minKeyLength = algorithm.minKeyLength
        F.raiseWhen(secretKeyLength < minKeyLength)(
          new InvalidSecretKeyLength(algorithm)
        )
      }

    ensureMinKeyLength.as {
      new JwtSigning[G] {
        override def sign(jwt: JwtBuilder): G[SignedJwt] =
          signHmac(jwt.mapHeader(_.withAlgorithm(algorithm)))

        private def signHmac(jwt: JwtBuilder): G[SignedJwt] =
          Crypto[G]
            .hmac(algorithm.hashAlgorithm, secretKey)(jwt.signingBytes)
            .map(JwtSignature.fromMac)
            .map(jwt.toSigned)
      }
    }
  }
}
