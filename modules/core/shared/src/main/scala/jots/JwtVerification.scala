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
import io.circe.JsonNumber
import jots.JwtException.*
import jots.crypto.Crypto
import jots.crypto.PublicKey
import jots.crypto.RsaAlgorithm
import jots.crypto.SecretKey
import jots.crypto.internal.KeyAlgorithm
import jots.internal.KeyLength
import jots.internal.KeyRequirement
import jots.internal.SkippedKeys
import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

/**
  * Capability to verify [[SignedJwt]]s and return [[VerifiedJwt]]s.
  *
  * Verifying [[SignedJwt]]s requires specifying one or more algorithms,
  * and either a [[jots.crypto.PublicKey]] or [[jots.crypto.SecretKey]].
  * Use [[JwtVerificationBuilder]] to create instances and customize the
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

  /**
    * Return a [[JwtVerification]] instance that verifies
    * with the specified function.
    */
  def verifyWith[F[_]](f: SignedJwt => F[VerifiedJwt]): JwtVerification[F] =
    new JwtVerification[F] {
      override def verify(jwt: SignedJwt): F[VerifiedJwt] =
        f(jwt)
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

    val keyLength: KeyLength =
      KeyLength.fromPublicKey(publicKey)

    val ensureKeyRequirements: F[Unit] =
      F.whenA(checkKeyRequirements) {
        keyLength match {
          case KeyLength.Unknown =>
            F.raiseError[Unit](new InvalidPublicKey("unable to determine public key type and length"))
          case keyLength =>
            KeyRequirement.check[F](algorithms.map(_.keyRequirement), keyLength)
        }
      }

    val algorithmByName: Map[String, JwtAsymmetricAlgorithm] = {
      val usable = keyAlgorithms(algorithms, keyLength, KeyAlgorithm.isRsaPss(publicKey))
      val aliases = usable.collect { case algorithm: JwtEddsaAlgorithm => algorithm.asEdDSA }
      (usable ++ aliases)
        .distinctBy(_.name)
        .map(algorithm => algorithm.name -> algorithm)
        .toMap
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
                  algorithmByName.get(algorithm) match {
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
            .adaptError { case cause => new SignatureVerificationFailed(cause) }
            .flatMap(verified => G.raiseUnless(verified.isValid)(new InvalidSignature()))
      }
    }
  }

  /*
   * Returns the algorithms which can be used with the public key.
   */
  private def keyAlgorithms(
    algorithms: NonEmptyList[JwtAsymmetricAlgorithm],
    keyLength: KeyLength,
    rsaPss: Boolean
  ): List[JwtAsymmetricAlgorithm] =
    keyLength match {
      case KeyLength.Unknown =>
        algorithms.toList
      case keyLength =>
        algorithms.filter { algorithm =>
          algorithm.asymmetricAlgorithm match {
            case _: RsaAlgorithm if rsaPss => false
            case _ => KeyRequirement.matches(algorithm.keyRequirement, keyLength)
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
            val ecdsa = JwtVerificationBuilder.default[F].verifyWith[G].ecdsa(algorithm, _: PublicKey)
            key.toPublicKey.liftTo[F].map(ecdsa).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtHmacAlgorithm, JwkKeyTypes.Oct) =>
            val hmac = JwtVerificationBuilder.default[F].verifyWith[G].hmac(algorithm, _: SecretKey)
            key.toSecretKey.liftTo[F].map(hmac).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtEddsaAlgorithm, JwkKeyTypes.OKP) =>
            val eddsa = JwtVerificationBuilder.default[F].verifyWith[G].eddsa(algorithm, _: PublicKey)
            key.toPublicKey.liftTo[F].map(eddsa).flatMap(build).tupleLeft(keyId)
          case (algorithm: JwtRsaAlgorithm, JwkKeyTypes.RSA) =>
            val rsa = JwtVerificationBuilder.default[F].verifyWith[G].rsa(algorithm, _: PublicKey)
            key.toPublicKey.liftTo[F].map(rsa).flatMap(build).tupleLeft(keyId)
          case (algorithm, keyType) =>
            F.raiseError(new UnsupportedKey(keyId.some, keyType, Some(algorithm)))
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
                val ecdsa =
                  JwtVerificationBuilder.default[F].verifyWith[G].ecdsa(ecdsaAlgorithms, _: PublicKey)
                key.toPublicKey.liftTo[F].map(ecdsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.OKP =>
            val eddsaAlgorithms = algorithms.collect { case eddsa: JwtEddsaAlgorithm => eddsa }
            NonEmptyList.fromList(eddsaAlgorithms) match {
              case Some(eddsaAlgorithms) =>
                val eddsa =
                  JwtVerificationBuilder.default[F].verifyWith[G].eddsa(eddsaAlgorithms, _: PublicKey)
                key.toPublicKey.liftTo[F].map(eddsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.RSA =>
            val rsaAlgorithms = algorithms.collect { case rsa: JwtRsaAlgorithm => rsa }
            NonEmptyList.fromList(rsaAlgorithms) match {
              case Some(rsaAlgorithms) =>
                val rsa = JwtVerificationBuilder.default[F].verifyWith[G].rsa(rsaAlgorithms, _: PublicKey)
                key.toPublicKey.liftTo[F].map(rsa).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case JwkKeyTypes.Oct =>
            val hmacAlgorithms = algorithms.collect { case hmac: JwtHmacAlgorithm => hmac }
            NonEmptyList.fromList(hmacAlgorithms) match {
              case Some(hmacAlgorithms) =>
                val hmac = JwtVerificationBuilder.default[F].verifyWith[G].hmac(hmacAlgorithms, _: SecretKey)
                key.toSecretKey.liftTo[F].map(hmac).flatMap(build).tupleLeft(keyId)
              case None =>
                F.raiseError(new NoAcceptedAlgorithms(keyId, key.keyType))
            }
          case keyType =>
            F.raiseError(new UnsupportedKey(keyId.some, keyType))
        }
      }

    def byKeyId(
      verifications: Map[JwkKeyId, JwtVerification[G]],
      skipped: List[(Jwk, JwtException)]
    ): JwtVerification[G] =
      new JwtVerification[G] with SkippedKeys {
        override val skippedKeys: List[(Jwk, JwtException)] =
          skipped

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
        case Some(algorithmJson) =>
          key.keyId.liftTo[F].flatMap { keyId =>
            algorithmJson.asString match {
              case Some(algorithmName) =>
                algorithmWithName(algorithmName).orElse(eddsaAlgorithm(algorithmName, key)) match {
                  case Some(algorithm) => verify(algorithm, key)
                  case None => F.raiseError(new RejectedKeyAlgorithm(keyId.some, algorithmName, algorithms))
                }
              case None =>
                F.raiseError(new InvalidKeyAlgorithm(keyId.some, algorithmJson))
            }
          }
        case None =>
          verifyAll(key)
      }

    /*
     * Returns the accepted EdDSA algorithm for the curve (crv) of the key,
     * when the key has the generic EdDSA algorithm, used for all curves.
     */
    def eddsaAlgorithm(algorithmName: String, key: Jwk): Option[JwtAlgorithm] =
      if (algorithmName == "EdDSA") {
        key.toJsonObject("crv").flatMap(_.asString).flatMap { curve =>
          algorithms.find {
            case algorithm: JwtEddsaAlgorithm => algorithm.asymmetricAlgorithm.name == curve
            case _ => false
          }
        }
      } else None

    /*
     * Returns whether the key may be used for signature verification.
     */
    def isForVerification(key: Jwk): Boolean =
      key.keyId.isRight &&
        key.toJsonObject("use").forall(_.asString.contains("sig")) &&
        key.toJsonObject("key_ops").forall(_.as[List[String]].exists(_.contains("verify")))

    def keyVerificationOrSkipped(key: Jwk): F[Either[(Jwk, JwtException), (JwkKeyId, JwtVerification[G])]] =
      keyVerification(key)
        .map(_.asRight[(Jwk, JwtException)])
        .recover { case e: JwtException => (key, e).asLeft }

    /*
     * Verify with the first verification, falling back to the
     * second verification in case the algorithm was rejected.
     */
    def orElseIfRejectedAlgorithm(
      first: JwtVerification[G],
      second: JwtVerification[G]
    ): JwtVerification[G] =
      JwtVerification.verifyWith { jwt =>
        first.verify(jwt).recoverWith { case _: RejectedAlgorithm => second.verify(jwt) }
      }

    keySet.toList
      .filter(isForVerification)
      .traverse(keyVerificationOrSkipped)
      .flatMap { results =>
        val (skipped, verifications) = results.partitionMap(identity)
        if (verifications.isEmpty) {
          val causes = skipped.map { case (_, cause) => cause }
          F.raiseError(new EmptyKeySet(causes))
        } else {
          val verificationByKeyId = verifications.groupMapReduce(_._1)(_._2)(orElseIfRejectedAlgorithm)
          F.pure(byKeyId(verificationByKeyId, skipped))
        }
      }
  }

  private val maxNumericDate: BigDecimal =
    BigDecimal(Long.MaxValue, 9)

  /*
   * Decode seconds with at most 9 decimals, so values are
   * exact to the nanosecond, and fit in a FiniteDuration.
   * Long numbers are rejected before parsing, since the
   * parsing time grows quadratically with digit count.
   */
  private implicit val finiteDurationDecoder: Decoder[FiniteDuration] =
    Decoder[JsonNumber].emap { numericDate =>
      val seconds =
        if (numericDate.toString.length > 32) None
        else numericDate.toBigDecimal

      seconds match {
        case Some(seconds) if seconds.scale <= 9 && seconds.abs <= maxNumericDate =>
          Right(Duration.fromNanos((seconds * 1000000000).toLongExact))
        case _ =>
          Left("invalid NumericDate")
      }
    }

  private def verifyHeader[F[_], G[_]: ApplicativeThrow](
    builder: JwtVerificationBuilder[F, G],
    header: SignedJwtHeader
  ): G[Unit] = {
    import builder.*

    verifyCriticalHeaders(header, criticalHeaders) *>
      verifyType(header, acceptedTypes)
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

  private def verifyType[F[_]](
    header: SignedJwtHeader,
    accepted: AcceptedTypes
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    accepted match {
      case AcceptedTypes.OneOf(accepted) => verifyTypeOneOf(header, accepted)
      case AcceptedTypes.AnyType => F.unit
    }

  private def verifyTypeOneOf[F[_]](
    header: SignedJwtHeader,
    accepted: NonEmptyList[String]
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    header.toJsonObject("typ") match {
      case Some(typ) =>
        typ.as[String] match {
          case Right(typ) if accepted.exists(isSameMediaType(_, typ)) => F.unit
          case Right(typ) => F.raiseError(new RejectedType(typ))
          case Left(_) => F.raiseError(new InvalidType(typ))
        }
      case None =>
        F.raiseError(new MissingType())
    }

  /*
   * Media types are case-insensitive, and types without
   * a "/" have an implied "application/" prefix.
   */
  private def isSameMediaType(first: String, second: String): Boolean = {
    def mediaType(typ: String): String =
      if (typ.contains('/')) typ else s"application/$typ"

    mediaType(first).equalsIgnoreCase(mediaType(second))
  }

  private def verifyClaims[F[_], G[_]: Clock: MonadThrow](
    builder: JwtVerificationBuilder[F, G],
    claims: SignedJwtClaims
  ): G[Unit] = {
    import builder.*

    for {
      _ <- verifyAudience(claims, acceptedAudiences)
      _ <- verifyIssuer(claims, acceptedIssuers)
      _ <- verifySubject(claims, acceptedSubjects)
      currentTime <- Clock[G].realTime
      _ <- verifyExpiration(claims, currentTime, clockSkew, checkExpiration, requireExpiration)
      _ <- verifyIssuedAt(claims, currentTime, clockSkew, checkIssuedAt, requireIssuedAt)
      _ <- verifyNotBefore(claims, currentTime, clockSkew, checkNotBefore, requireNotBefore)
    } yield ()
  }

  private def verifyAudience[F[_]](
    claims: SignedJwtClaims,
    accepted: AcceptedAudiences
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    accepted match {
      case AcceptedAudiences.OneOf(accepted) => verifyAudienceOneOf(claims, accepted)
      case AcceptedAudiences.AnyAudience => F.unit
      case AcceptedAudiences.NoAudience => verifyNoAudience(claims)
    }

  private def verifyAudienceOneOf[F[_]](
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

  private def verifyNoAudience[F[_]](
    claims: SignedJwtClaims
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    claims.toJsonObject("aud") match {
      case Some(audience) => F.raiseError(new UnexpectedAudience(audience))
      case None => F.unit
    }

  private def verifyIssuer[F[_]](
    claims: SignedJwtClaims,
    accepted: AcceptedIssuers
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    accepted match {
      case AcceptedIssuers.OneOf(accepted) => verifyIssuerOneOf(claims, accepted)
      case AcceptedIssuers.AnyIssuer => F.unit
    }

  private def verifyIssuerOneOf[F[_]](
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
    accepted: AcceptedSubjects
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    accepted match {
      case AcceptedSubjects.OneOf(accepted) => verifySubjectOneOf(claims, accepted)
      case AcceptedSubjects.AnySubject => F.unit
    }

  private def verifySubjectOneOf[F[_]](
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
              F.raiseWhen(currentTime - clockSkew >= expiresAt)(new TokenExpired(expiresAt))
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
              F.raiseWhen(currentTime + clockSkew < issuedAt)(new TokenNotYetIssued(issuedAt))
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
              F.raiseWhen(currentTime + clockSkew < notBefore)(new TokenNotYetValid(notBefore))
            case Left(_) =>
              F.raiseError(new InvalidNotBefore(notBefore))
          }
        }
      case None =>
        F.raiseWhen(requireNotBefore)(new MissingNotBefore())
    }
}
