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
import cats.effect.kernel.Clock
import cats.syntax.all.*
import io.circe.Decoder
import java.util.concurrent.TimeUnit
import jots.JwtException.*
import jots.crypto.Crypto
import jots.crypto.PublicKey
import jots.crypto.SecretKey
import jots.internal.KeyLength
import jots.internal.KeyRequirement
import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration
import scala.util.Try

/**
  * Capability to verify [[SignedJwt]]s and return [[VerifiedJwt]]s.
  *
  * Verifying [[SignedJwt]]s requires specifying one or more algorithms,
  * and either a [[jots.crypto.PublicKey]] or [[jots.crypto.SecretKey]].
  * Use [[JwtVerificationBuilder]] if there is a need to customize the
  * claims verification.
  *
  * It is possible to create custom [[JwtVerification]] instances, but
  * these will generally have to make use of a default implementation.
  * This stems from the fact that [[VerifiedJwt]]s can only be created
  * by the default implementations. The notable exception is that the
  * testing module allows verifying any [[SignedJwt]].
  */
trait JwtVerification[F[_]] {

  /**
    * Verifies the specified [[SignedJwt]] and returns
    * a [[VerifiedJwt]] if the signature and claims are
    * valid; otherwise raises an exception.
    */
  def verify(jwt: SignedJwt): F[VerifiedJwt]

  /**
    * Verifies the specified [[SignedJwt]] and decodes
    * the claims to the specified type if the signature
    * and claims are valid; otherwise raises an exception.
    */
  def verifyAs[A](jwt: SignedJwt)(implicit F: MonadThrow[F], A: JwtDecoder[A]): F[A] =
    verify(jwt).flatMap(_.as[A].liftTo[F])

  /**
    * Verifies the specified JWT `String` and returns
    * a [[VerifiedJwt]] if the signature and claims are
    * valid; otherwise raises an exception.
    */
  def decode(jwt: String)(implicit F: MonadThrow[F]): F[VerifiedJwt] =
    SignedJwt.fromString(jwt).liftTo[F].flatMap(verify)

  /**
    * Verifies the specified JWT `String` and decodes
    * the claims to the specified type if the signature
    * and claims are valid; otherwise raises an exception.
    */
  def decodeAs[A](jwt: String)(implicit F: MonadThrow[F], A: JwtDecoder[A]): F[A] =
    SignedJwt.fromString(jwt).liftTo[F].flatMap(verifyAs[A])
}

object JwtVerification {
  def apply[F[_]](implicit F: JwtVerification[F]): JwtVerification[F] = F

  def default[F[_]]: JwtVerificationDefault[F, F] =
    new JwtVerificationDefault[F, F] {}

  /**
    * Return a [[JwtVerification]] instance that verifies
    * with the specified function.
    */
  def verifyWith[F[_]](f: SignedJwt => F[VerifiedJwt]): JwtVerification[F] =
    new JwtVerification[F] {
      override def verify(jwt: SignedJwt): F[VerifiedJwt] =
        f(jwt)
    }

  sealed abstract class JwtVerificationDefault[F[_], G[_]] {

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].ecdsa(algorithm, publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
      * tokens using all recognized ECDSA algorithms and a public key.
      */
    def ecdsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].ecdsaAll(publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].ecdsaList(algorithms, publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].eddsa(algorithm, publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
      * tokens using all recognized EdDSA algorithms and a public key.
      */
    def eddsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].eddsaAll(publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].eddsaList(algorithms, publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].hmac(algorithm, secretKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
      * tokens using all recognized HMAC algorithms and a secret key.
      */
    def hmacAll(
      secretKey: SecretKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].hmacAll(secretKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].hmacList(algorithms, secretKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].jwkSet(algorithms, keySet).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].jwkSetAll(keySet).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].rsa(algorithm, publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
      * tokens using all recognized RSA algorithms and a public key.
      */
    def rsaAll(
      publicKey: PublicKey
    )(implicit
      F: ApplicativeThrow[F],
      G: MonadThrow[G],
      clock: Clock[G],
      crypto: Crypto[G]
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].rsaAll(publicKey).build

    /**
      * Returns a new [[JwtVerification]] instance which verifies
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
    ): F[JwtVerification[G]] =
      JwtVerificationBuilder.default[F].verifyWith[G].rsaList(algorithms, publicKey).build

    /**
      * Create [[JwtVerification]] instances that verify with the specified type.
      */
    def verifyWith[H[_]]: JwtVerificationDefault[F, H] =
      new JwtVerificationDefault[F, H] {}
  }

  private[jots] def fromHmacBuilder[F[_], G[_]](
    builder: JwtHmacVerificationBuilder[F, G]
  )(implicit
    F: ApplicativeThrow[F],
    G: MonadThrow[G],
    clock: Clock[G],
    crypto: Crypto[G]
  ): F[JwtVerification[G]] = {
    import builder.*

    val ensureMinKeyLength: F[Unit] =
      F.whenA(checkKeyRequirements) {
        val secretKeyLength = secretKey.toByteVector.length
        val algorithm = algorithms.maximumBy(_.minKeyLength)
        F.raiseWhen(secretKeyLength < algorithm.minKeyLength)(
          new InvalidSecretKeyLength(algorithm)
        )
      }

    ensureMinKeyLength.as {
      new JwtVerification[G] {
        override def verify(jwt: SignedJwt): G[VerifiedJwt] =
          for {
            _ <- verifySignature(jwt)
            _ <- verifyHeader(builder, jwt.header)
            _ <- verifyClaims(builder, jwt.claims)
          } yield VerifiedJwt.fromVerified(jwt)

        private def verifySignature(jwt: SignedJwt): G[Unit] =
          jwt.header.toJsonObject("alg") match {
            case Some(algorithm) =>
              algorithm.as[String] match {
                case Right(algorithm) =>
                  algorithmWithName(algorithm) match {
                    case Some(algorithm) => verifyHmac(jwt, algorithm, secretKey)
                    case None => G.raiseError(new RejectedAlgorithm())
                  }
                case Left(_) =>
                  G.raiseError(new InvalidAlgorithm())
              }
            case None =>
              G.raiseError(new MissingAlgorithm())
          }

        private def verifyHmac(
          jwt: SignedJwt,
          algorithm: JwtHmacAlgorithm,
          secretKey: SecretKey
        ): G[Unit] =
          Crypto[G]
            .hmac(algorithm.hashAlgorithm, secretKey)(jwt.signedBytes)
            .map(JwtSignature.fromMac)
            .flatMap(signature => G.raiseUnless(jwt.signature === signature)(new InvalidSignature()))
      }
    }
  }

  private[jots] def fromAsymmetricBuilder[F[_], G[_]](
    builder: JwtAsymmetricVerificationBuilder[F, G]
  )(implicit
    F: ApplicativeThrow[F],
    G: MonadThrow[G],
    clock: Clock[G],
    crypto: Crypto[G]
  ): F[JwtVerification[G]] = {
    import builder.*

    val ensureKeyRequirements: F[Unit] =
      F.whenA(checkKeyRequirements) {
        KeyLength.fromPublicKey(publicKey) match {
          case KeyLength.Unknown =>
            F.raiseError[Unit](new InvalidPublicKey("unable to determine public key type and length"))
          case keyLength =>
            KeyRequirement.check[F](algorithms.map(_.keyRequirement), keyLength)
        }
      }

    ensureKeyRequirements.as {
      new JwtVerification[G] {
        override def verify(jwt: SignedJwt): G[VerifiedJwt] =
          for {
            _ <- verifySignature(jwt)
            _ <- verifyHeader(builder, jwt.header)
            _ <- verifyClaims(builder, jwt.claims)
          } yield VerifiedJwt.fromVerified(jwt)

        private def verifySignature(jwt: SignedJwt): G[Unit] =
          jwt.header.toJsonObject("alg") match {
            case Some(algorithm) =>
              algorithm.as[String] match {
                case Right(algorithm) =>
                  algorithmWithName(algorithm) match {
                    case Some(algorithm) => verifyAsymmetric(jwt, algorithm, publicKey)
                    case None => G.raiseError(new RejectedAlgorithm())
                  }
                case Left(_) =>
                  G.raiseError(new InvalidAlgorithm())
              }
            case None =>
              G.raiseError(new MissingAlgorithm())
          }

        private def verifyAsymmetric(
          jwt: SignedJwt,
          algorithm: JwtAsymmetricAlgorithm,
          publicKey: PublicKey
        ): G[Unit] =
          Crypto[G]
            .verify(algorithm.asymmetricAlgorithm, publicKey)(jwt.signedBytes, jwt.signature.toSignature)
            .flatMap(verified => G.raiseUnless(verified.isValid)(new InvalidSignature()))
      }
    }
  }

  private[jots] def fromJwkSetBuilder[F[_], G[_]](
    builder: JwtJwkSetVerificationBuilder[F, G]
  )(implicit
    F: MonadThrow[F],
    G: MonadThrow[G],
    clock: Clock[G],
    crypto: Crypto[G]
  ): F[JwtVerification[G]] = {
    import builder.*

    /*
     * Returns the `JwkKeyId` and verification instance for the specified
     * key and algorithm. The algorithm has already been verified to both
     * be set on the key and to be in the list of accepted algorithms.
     */
    def verify(algorithm: JwtAlgorithm, key: Jwk): F[(JwkKeyId, JwtVerification[G])] =
      key.keyId.liftTo[F].flatMap { keyId =>
        (algorithm, key.keyType) match {
          case (algorithm: JwtEcdsaAlgorithm, JwkKeyTypes.EC) =>
            val ecdsa = JwtVerificationBuilder.default[F].verifyWith[G].ecdsa(algorithm, _)
            key.toPublicKey.liftTo[F].map(ecdsa).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtHmacAlgorithm, JwkKeyTypes.Oct) =>
            val hmac = JwtVerificationBuilder.default[F].verifyWith[G].hmac(algorithm, _)
            key.toSecretKey.liftTo[F].map(hmac).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtEddsaAlgorithm, JwkKeyTypes.OKP) =>
            val eddsa = JwtVerificationBuilder.default[F].verifyWith[G].eddsa(algorithm, _)
            key.toPublicKey.liftTo[F].map(eddsa).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtRsaAlgorithm, JwkKeyTypes.RSA) =>
            val rsa = JwtVerificationBuilder.default[F].verifyWith[G].rsa(algorithm, _)
            key.toPublicKey.liftTo[F].map(rsa).flatMap(build).tupleLeft(keyId)
          case (algorithm, keyType) =>
            F.raiseError(new UnsupportedKey(keyId, keyType, Some(algorithm)))
        }
      }

    /*
     * Returns the `JwkKeyId` and verification instance for the specified
     * key. No algorithm was specified on the key, so all of the accepted
     * algorithms for the key type are allowed.
     */
    def verifyAll(key: Jwk): F[(JwkKeyId, JwtVerification[G])] =
      key.keyId.liftTo[F].flatMap { keyId =>
        key.keyType match {
          case JwkKeyTypes.EC =>
            val ecdsaAlgorithms = algorithms.collect { case ecdsa: JwtEcdsaAlgorithm => ecdsa }
            NonEmptyList.fromList(ecdsaAlgorithms) match {
              case Some(ecdsaAlgorithms) =>
                val ecdsa = JwtVerificationBuilder.default[F].verifyWith[G].ecdsaList(ecdsaAlgorithms, _)
                key.toPublicKey.liftTo[F].map(ecdsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.OKP =>
            val eddsaAlgorithms = algorithms.collect { case eddsa: JwtEddsaAlgorithm => eddsa }
            NonEmptyList.fromList(eddsaAlgorithms) match {
              case Some(eddsaAlgorithms) =>
                val eddsa = JwtVerificationBuilder.default[F].verifyWith[G].eddsaList(eddsaAlgorithms, _)
                key.toPublicKey.liftTo[F].map(eddsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.RSA =>
            val rsaAlgorithms = algorithms.collect { case rsa: JwtRsaAlgorithm => rsa }
            NonEmptyList.fromList(rsaAlgorithms) match {
              case Some(rsaAlgorithms) =>
                val rsa = JwtVerificationBuilder.default[F].verifyWith[G].rsaList(rsaAlgorithms, _)
                key.toPublicKey.liftTo[F].map(rsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.Oct =>
            val hmacAlgorithms = algorithms.collect { case hmac: JwtHmacAlgorithm => hmac }
            NonEmptyList.fromList(hmacAlgorithms) match {
              case Some(hmacAlgorithms) =>
                val hmac = JwtVerificationBuilder.default[F].verifyWith[G].hmacList(hmacAlgorithms, _)
                key.toSecretKey.liftTo[F].map(hmac).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case keyType =>
            F.raiseError(new UnsupportedKey(keyId, keyType))
        }
      }

    def byKeyId(verifications: Map[JwkKeyId, JwtVerification[G]]): JwtVerification[G] =
      new JwtVerification[G] {
        override def verify(jwt: SignedJwt): G[VerifiedJwt] =
          jwt.header.toJsonObject("kid") match {
            case Some(keyId) =>
              keyId.asString.map(JwkKeyId.fromString) match {
                case Some(keyId) =>
                  verifications.get(keyId) match {
                    case Some(verification) => verification.verify(jwt)
                    case None => G.raiseError(new MissingKey())
                  }
                case None =>
                  G.raiseError(new InvalidKeyId())
              }
            case None =>
              G.raiseError(new MissingKeyId())
          }
      }

    def keyVerification(key: Jwk): F[(JwkKeyId, JwtVerification[G])] =
      key.toJsonObject("alg") match {
        case Some(algorithm) =>
          algorithm.asString match {
            case Some(algorithm) =>
              algorithmWithName(algorithm) match {
                case Some(algorithm) => verify(algorithm, key)
                case None => F.raiseError(new RejectedAlgorithm())
              }
            case None =>
              F.raiseError(new InvalidAlgorithm())
          }
        case None =>
          verifyAll(key)
      }

    /*
     * Returns whether the key may be used for signature verification.
     */
    def isForVerification(key: Jwk): Boolean =
      key.keyId.isRight &&
        key.toJsonObject("use").forall(_.asString.contains("sig")) &&
        key.toJsonObject("key_ops").forall(_.as[List[String]].exists(_.contains("verify")))

    NonEmptyList
      .fromList(keySet.toList.filter(isForVerification))
      .map(_.traverse(keyVerification).map(_.toList.toMap).map(byKeyId))
      .getOrElse(F.raiseError(new EmptyKeySet()))
  }

  private implicit val finiteDurationDecoder: Decoder[FiniteDuration] =
    Decoder[Long].emapTry(epochSecond => Try(Duration(epochSecond, TimeUnit.SECONDS)))

  private def verifyHeader[F[_], G[_]: ApplicativeThrow](
    builder: JwtVerificationBuilder[F, G],
    header: SignedJwtHeader
  ): G[Unit] = {
    import builder.*
    verifyCriticalHeaders(header, criticalHeaders)
  }

  private def verifyCriticalHeaders[F[_], G[_]](
    header: SignedJwtHeader,
    criticalHeaders: Set[String]
  )(implicit G: ApplicativeThrow[G]): G[Unit] =
    header.toJsonObject("crit") match {
      case Some(crit) =>
        crit.as[List[String]] match {
          case Right(names) if names.nonEmpty =>
            names.traverseVoid { name =>
              if (!header.toJsonObject.contains(name))
                G.raiseError[Unit](new MissingCriticalHeader(name))
              else if (!criticalHeaders.contains(name))
                G.raiseError[Unit](new UnsupportedCriticalHeader(name))
              else
                G.unit
            }
          case _ =>
            G.raiseError[Unit](new InvalidCriticalHeaders(crit))
        }
      case None =>
        G.unit
    }

  private def verifyClaims[F[_], G[_]: Clock: MonadThrow](
    builder: JwtVerificationBuilder[F, G],
    claims: SignedJwtClaims
  ): G[Unit] = {
    import builder.*

    for {
      _ <- acceptedAudiences.traverseVoid(verifyAudience(claims, _))
      _ <- acceptedIssuers.traverseVoid(verifyIssuer(claims, _))
      _ <- acceptedSubjects.traverseVoid(verifySubject(claims, _))
      currentTime <- Clock[G].realTime
      _ <- verifyExpiration(claims, currentTime, clockSkew, checkExpiration, requireExpiration)
      _ <- verifyIssuedAt(claims, currentTime, clockSkew, checkIssuedAt, requireIssuedAt)
      _ <- verifyNotBefore(claims, currentTime, clockSkew, checkNotBefore, requireNotBefore)
    } yield ()
  }

  private def verifyAudience[F[_]](
    claims: SignedJwtClaims,
    accepted: NonEmptyList[String]
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("aud") match {
      case Some(audience) =>
        audience.as[String].map(List(_)).orElse(audience.as[List[String]]) match {
          case Right(audiences) if audiences.exists(accepted.contains_) => F.unit
          case Right(audiences) => F.raiseError(new RejectedAudience(audiences))
          case Left(_) => F.raiseError(new InvalidAudience(audience))
        }
      case None =>
        F.raiseError(new MissingAudience())
    }

  private def verifyIssuer[F[_]](
    claims: SignedJwtClaims,
    accepted: NonEmptyList[String]
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("iss") match {
      case Some(issuer) =>
        issuer.as[String] match {
          case Right(issuer) if accepted.contains_(issuer) => F.unit
          case Right(issuer) => F.raiseError(new RejectedIssuer(issuer))
          case Left(_) => F.raiseError(new InvalidIssuer(issuer))
        }
      case None =>
        F.raiseError(new MissingIssuer())
    }

  private def verifySubject[F[_]](
    claims: SignedJwtClaims,
    accepted: NonEmptyList[String]
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("sub") match {
      case Some(subject) =>
        subject.as[String] match {
          case Right(subject) if accepted.contains_(subject) => F.unit
          case Right(subject) => F.raiseError(new RejectedSubject(subject))
          case Left(_) => F.raiseError(new InvalidSubject(subject))
        }
      case None =>
        F.raiseError(new MissingSubject())
    }

  private def verifyExpiration[F[_]](
    claims: SignedJwtClaims,
    currentTime: FiniteDuration,
    clockSkew: FiniteDuration,
    checkExpiration: Boolean,
    requireExpiration: Boolean
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("exp") match {
      case Some(expiresAt) =>
        F.whenA(checkExpiration) {
          expiresAt.as[FiniteDuration] match {
            case Right(expiresAt) =>
              val expiresAtSkewed = expiresAt.plus(clockSkew)
              F.raiseWhen(currentTime >= expiresAtSkewed)(new TokenExpired(expiresAt))
            case Left(_) =>
              F.raiseError(new InvalidExpiration(expiresAt))
          }
        }
      case None =>
        F.raiseWhen(requireExpiration)(new MissingExpiration())
    }

  private def verifyIssuedAt[F[_]](
    claims: SignedJwtClaims,
    currentTime: FiniteDuration,
    clockSkew: FiniteDuration,
    checkIssuedAt: Boolean,
    requireIssuedAt: Boolean
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("iat") match {
      case Some(issuedAt) =>
        F.whenA(checkIssuedAt) {
          issuedAt.as[FiniteDuration] match {
            case Right(issuedAt) =>
              val issuedAtSkewed = issuedAt.minus(clockSkew)
              F.raiseWhen(currentTime < issuedAtSkewed)(new TokenNotYetIssued(issuedAt))
            case Left(_) =>
              F.raiseError(new InvalidIssuedAt(issuedAt))
          }
        }
      case None =>
        F.raiseWhen(requireIssuedAt)(new MissingIssuedAt())
    }

  private def verifyNotBefore[F[_]](
    claims: SignedJwtClaims,
    currentTime: FiniteDuration,
    clockSkew: FiniteDuration,
    checkNotBefore: Boolean,
    requireNotBefore: Boolean
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("nbf") match {
      case Some(notBefore) =>
        F.whenA(checkNotBefore) {
          notBefore.as[FiniteDuration] match {
            case Right(notBefore) =>
              val notBeforeSkewed = notBefore.minus(clockSkew)
              F.raiseWhen(currentTime < notBeforeSkewed)(new TokenNotYetValid(notBefore))
            case Left(_) =>
              F.raiseError(new InvalidNotBefore(notBefore))
          }
        }
      case None =>
        F.raiseWhen(requireNotBefore)(new MissingNotBefore())
    }
}
