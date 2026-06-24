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
import jots.JwtException.InvalidEcKeyLength
import jots.JwtException.InvalidPrivateKey
import jots.JwtException.InvalidRsaKeyLength
import jots.JwtException.InvalidSecretKeyLength
import jots.crypto.PrivateKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import jots.testing.*
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
}
