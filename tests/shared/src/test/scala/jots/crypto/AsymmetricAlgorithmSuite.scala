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

package jots.crypto

import cats.Show
import cats.kernel.laws.discipline.HashTests
import jots.testing.*
import org.scalacheck.Arbitrary
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object AsymmetricAlgorithmSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("AsymmetricAlgorithm.hash", HashTests[AsymmetricAlgorithm].hash)
  test("AsymmetricAlgorithm.show")(showTest[AsymmetricAlgorithm])

  checkAll("EcdsaAlgorithm.hash", HashTests[EcdsaAlgorithm].hash)
  test("EcdsaAlgorithm.show")(showTest[EcdsaAlgorithm])

  checkAll("EddsaAlgorithm.hash", HashTests[EddsaAlgorithm].hash)
  test("EddsaAlgorithm.show")(showTest[EddsaAlgorithm])

  checkAll("RsaAlgorithm.hash", HashTests[RsaAlgorithm].hash)
  test("RsaAlgorithm.show")(showTest[RsaAlgorithm])

  checkAll("RsaPssAlgorithm.hash", HashTests[RsaPssAlgorithm].hash)
  test("RsaPssAlgorithm.show")(showTest[RsaPssAlgorithm])

  pureTest("AsymmetricAlgorithm.familyTypes") {
    val ecdsa: List[EcdsaAlgorithm] = List(
      AsymmetricAlgorithm.SHA256withECDSAinP1363Format,
      AsymmetricAlgorithm.SHA384withECDSAinP1363Format,
      AsymmetricAlgorithm.SHA512withECDSAinP1363Format
    )
    val eddsa: List[EddsaAlgorithm] = List(AsymmetricAlgorithm.Ed25519, AsymmetricAlgorithm.Ed448)
    val rsa: List[RsaAlgorithm] =
      List(
        AsymmetricAlgorithm.SHA256withRSA,
        AsymmetricAlgorithm.SHA384withRSA,
        AsymmetricAlgorithm.SHA512withRSA
      )
    val rsaPss: List[RsaPssAlgorithm] = List(
      AsymmetricAlgorithm.SHA256withRSAandMGF1,
      AsymmetricAlgorithm.SHA384withRSAandMGF1,
      AsymmetricAlgorithm.SHA512withRSAandMGF1
    )

    expect.eql(EcdsaAlgorithm.All.toList, ecdsa) &&
    expect.eql(EddsaAlgorithm.All.toList, eddsa) &&
    expect.eql(RsaAlgorithm.All.toList, rsa) &&
    expect.eql(RsaPssAlgorithm.All.toList, rsaPss)
  }

  private def showTest[A <: AsymmetricAlgorithm: Arbitrary: Show] =
    forall { (algorithm: A) =>
      expect.eql(Show[A].show(algorithm), algorithm.show) &&
      expect.eql(algorithm.show, algorithm.toString) &&
      expect.eql(algorithm.toString, algorithm.name)
    }
}
