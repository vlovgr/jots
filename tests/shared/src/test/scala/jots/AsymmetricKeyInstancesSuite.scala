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
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object AsymmetricKeyInstancesSuite extends SimpleIOSuite with Checkers {
  test("AsymmetricKeyInstances.ecdsaKeyPairGen") {
    JwtEcdsaAlgorithm.All
      .traverse { algorithm =>
        forall(ecdsaKeyPairGen(algorithm)) { case (privateKey, publicKey) =>
          for {
            signing <- JwtSigningBuilder.default[IO].ecdsa(algorithm, privateKey).build
            verification <- JwtVerificationBuilder.default[IO].ecdsa(algorithm, publicKey).build
            signed <- JwtBuilder.default.signWith(signing)
            _ <- signed.verifyWith(verification)
          } yield success
        }
      }
      .map(_.combineAll)
  }

  test("AsymmetricKeyInstances.eddsaKeyPairGen") {
    JwtEddsaAlgorithm.All
      .flatMap(algorithm => NonEmptyList.of(algorithm, algorithm.asEdDSA))
      .traverse { algorithm =>
        forall(eddsaKeyPairGen(algorithm)) { case (privateKey, publicKey) =>
          for {
            signing <- JwtSigningBuilder.default[IO].eddsa(algorithm, privateKey).build
            verification <- JwtVerificationBuilder.default[IO].eddsa(algorithm, publicKey).build
            signed <- JwtBuilder.default.signWith(signing)
            _ <- signed.verifyWith(verification)
          } yield success
        }
      }
      .map(_.combineAll)
  }
}
