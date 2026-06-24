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

  private def showTest[A <: JwtAlgorithm: Arbitrary: Show] =
    forall { (algorithm: A) =>
      expect.eql(Show[A].show(algorithm), algorithm.show) &&
      expect.eql(algorithm.show, algorithm.toString) &&
      expect.eql(algorithm.toString, algorithm.name)
    }
}
