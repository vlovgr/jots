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

import cats.Show
import cats.kernel.laws.discipline.HashTests
import jots.testing.*
import org.scalacheck.Arbitrary
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtAlgorithmSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("JwtAlgorithm.hash", HashTests[JwtAlgorithm].hash)
  test("JwtAlgorithm.show")(showTest[JwtAlgorithm])

  checkAll("JwtHmacAlgorithm.hash", HashTests[JwtHmacAlgorithm].hash)
  test("JwtHmacAlgorithm.show")(showTest[JwtHmacAlgorithm])

  checkAll("JwtAsymmetricAlgorithm.hash", HashTests[JwtAsymmetricAlgorithm].hash)
  test("JwtAsymmetricAlgorithm.show")(showTest[JwtAsymmetricAlgorithm])

  checkAll("JwtEcdsaAlgorithm.hash", HashTests[JwtEcdsaAlgorithm].hash)
  test("JwtEcdsaAlgorithm.show")(showTest[JwtEcdsaAlgorithm])

  checkAll("JwtEddsaAlgorithm.hash", HashTests[JwtEddsaAlgorithm].hash)
  test("JwtEddsaAlgorithm.show")(showTest[JwtEddsaAlgorithm])

  checkAll("JwtRsaAlgorithm.hash", HashTests[JwtRsaAlgorithm].hash)
  test("JwtRsaAlgorithm.show")(showTest[JwtRsaAlgorithm])

  pureTest("JwtAlgorithm.familyTypes") {
    val ecdsa: List[JwtEcdsaAlgorithm] = List(JwtAlgorithm.ES256, JwtAlgorithm.ES384, JwtAlgorithm.ES512)
    val eddsa: List[JwtEddsaAlgorithm] = List(JwtAlgorithm.Ed25519, JwtAlgorithm.Ed448)
    val hmac: List[JwtHmacAlgorithm] = List(JwtAlgorithm.HS256, JwtAlgorithm.HS384, JwtAlgorithm.HS512)
    val rsa: List[JwtRsaAlgorithm] = List(
      JwtAlgorithm.PS256,
      JwtAlgorithm.PS384,
      JwtAlgorithm.PS512,
      JwtAlgorithm.RS256,
      JwtAlgorithm.RS384,
      JwtAlgorithm.RS512
    )

    expect.eql(JwtEcdsaAlgorithm.All.toList, ecdsa) &&
    expect.eql(JwtEddsaAlgorithm.All.toList, eddsa) &&
    expect.eql(JwtHmacAlgorithm.All.toList, hmac) &&
    expect.eql(JwtRsaAlgorithm.All.toList, rsa)
  }

  pureTest("JwtAsymmetricAlgorithm.familyTypes") {
    val ecdsa: List[JwtEcdsaAlgorithm] =
      List(JwtAsymmetricAlgorithm.ES256, JwtAsymmetricAlgorithm.ES384, JwtAsymmetricAlgorithm.ES512)
    val eddsa: List[JwtEddsaAlgorithm] = List(JwtAsymmetricAlgorithm.Ed25519, JwtAsymmetricAlgorithm.Ed448)
    val rsa: List[JwtRsaAlgorithm] = List(
      JwtAsymmetricAlgorithm.PS256,
      JwtAsymmetricAlgorithm.PS384,
      JwtAsymmetricAlgorithm.PS512,
      JwtAsymmetricAlgorithm.RS256,
      JwtAsymmetricAlgorithm.RS384,
      JwtAsymmetricAlgorithm.RS512
    )

    expect.eql(JwtEcdsaAlgorithm.All.toList, ecdsa) &&
    expect.eql(JwtEddsaAlgorithm.All.toList, eddsa) &&
    expect.eql(JwtRsaAlgorithm.All.toList, rsa)
  }

  private def showTest[A <: JwtAlgorithm: Arbitrary: Show] =
    forall { (algorithm: A) =>
      expect.eql(Show[A].show(algorithm), algorithm.show) &&
      expect.eql(algorithm.show, algorithm.toString) &&
      expect.eql(algorithm.toString, algorithm.name)
    }
}
