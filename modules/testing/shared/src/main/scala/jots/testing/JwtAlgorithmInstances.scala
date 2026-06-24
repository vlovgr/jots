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

package jots.testing

import jots.JwtAlgorithm
import jots.JwtAsymmetricAlgorithm
import jots.JwtEcdsaAlgorithm
import jots.JwtEddsaAlgorithm
import jots.JwtHmacAlgorithm
import jots.JwtRsaAlgorithm
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwtAlgorithm]]s.
  */
object JwtAlgorithmInstances extends JwtAlgorithmInstances

private[jots] trait JwtAlgorithmInstances {
  lazy val jwtAlgorithmGen: Gen[JwtAlgorithm] =
    Gen.oneOf(JwtAlgorithm.All.toList)

  implicit lazy val jwtAlgorithmArbitrary: Arbitrary[JwtAlgorithm] =
    Arbitrary(jwtAlgorithmGen)

  implicit lazy val jwtAlgorithmCogen: Cogen[JwtAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtAlgorithmFunGen: Gen[JwtAlgorithm => JwtAlgorithm] =
    Gen.function1[JwtAlgorithm, JwtAlgorithm](jwtAlgorithmGen)

  implicit lazy val jwtAlgorithmFunArbitrary: Arbitrary[JwtAlgorithm => JwtAlgorithm] =
    Arbitrary(jwtAlgorithmFunGen)

  lazy val jwtHmacAlgorithmGen: Gen[JwtHmacAlgorithm] =
    Gen.oneOf(JwtHmacAlgorithm.All.toList)

  implicit lazy val jwtHmacAlgorithmArbitrary: Arbitrary[JwtHmacAlgorithm] =
    Arbitrary(jwtHmacAlgorithmGen)

  implicit lazy val jwtHmacAlgorithmCogen: Cogen[JwtHmacAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtHmacAlgorithmFunGen: Gen[JwtHmacAlgorithm => JwtHmacAlgorithm] =
    Gen.function1[JwtHmacAlgorithm, JwtHmacAlgorithm](jwtHmacAlgorithmGen)

  implicit lazy val jwtHmacAlgorithmFunArbitrary: Arbitrary[JwtHmacAlgorithm => JwtHmacAlgorithm] =
    Arbitrary(jwtHmacAlgorithmFunGen)

  lazy val jwtAsymmetricAlgorithmGen: Gen[JwtAsymmetricAlgorithm] =
    Gen.oneOf(JwtAsymmetricAlgorithm.All.toList)

  implicit lazy val jwtAsymmetricAlgorithmArbitrary: Arbitrary[JwtAsymmetricAlgorithm] =
    Arbitrary(jwtAsymmetricAlgorithmGen)

  implicit lazy val jwtAsymmetricAlgorithmCogen: Cogen[JwtAsymmetricAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtAsymmetricAlgorithmFunGen: Gen[JwtAsymmetricAlgorithm => JwtAsymmetricAlgorithm] =
    Gen.function1[JwtAsymmetricAlgorithm, JwtAsymmetricAlgorithm](jwtAsymmetricAlgorithmGen)

  implicit lazy val jwtAsymmetricAlgorithmFunArbitrary
    : Arbitrary[JwtAsymmetricAlgorithm => JwtAsymmetricAlgorithm] =
    Arbitrary(jwtAsymmetricAlgorithmFunGen)

  lazy val jwtEcdsaAlgorithmGen: Gen[JwtEcdsaAlgorithm] =
    Gen.oneOf(JwtEcdsaAlgorithm.All.toList)

  implicit lazy val jwtEcdsaAlgorithmArbitrary: Arbitrary[JwtEcdsaAlgorithm] =
    Arbitrary(jwtEcdsaAlgorithmGen)

  implicit lazy val jwtEcdsaAlgorithmCogen: Cogen[JwtEcdsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtEcdsaAlgorithmFunGen: Gen[JwtEcdsaAlgorithm => JwtEcdsaAlgorithm] =
    Gen.function1[JwtEcdsaAlgorithm, JwtEcdsaAlgorithm](jwtEcdsaAlgorithmGen)

  implicit lazy val jwtEcdsaAlgorithmFunArbitrary: Arbitrary[JwtEcdsaAlgorithm => JwtEcdsaAlgorithm] =
    Arbitrary(jwtEcdsaAlgorithmFunGen)

  lazy val jwtEddsaAlgorithmGen: Gen[JwtEddsaAlgorithm] =
    Gen.oneOf(JwtEddsaAlgorithm.All.toList)

  implicit lazy val jwtEddsaAlgorithmArbitrary: Arbitrary[JwtEddsaAlgorithm] =
    Arbitrary(jwtEddsaAlgorithmGen)

  implicit lazy val jwtEddsaAlgorithmCogen: Cogen[JwtEddsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtEddsaAlgorithmFunGen: Gen[JwtEddsaAlgorithm => JwtEddsaAlgorithm] =
    Gen.function1[JwtEddsaAlgorithm, JwtEddsaAlgorithm](jwtEddsaAlgorithmGen)

  implicit lazy val jwtEddsaAlgorithmFunArbitrary: Arbitrary[JwtEddsaAlgorithm => JwtEddsaAlgorithm] =
    Arbitrary(jwtEddsaAlgorithmFunGen)

  lazy val jwtRsaAlgorithmGen: Gen[JwtRsaAlgorithm] =
    Gen.oneOf(JwtRsaAlgorithm.All.toList)

  implicit lazy val jwtRsaAlgorithmArbitrary: Arbitrary[JwtRsaAlgorithm] =
    Arbitrary(jwtRsaAlgorithmGen)

  implicit lazy val jwtRsaAlgorithmCogen: Cogen[JwtRsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val jwtRsaAlgorithmFunGen: Gen[JwtRsaAlgorithm => JwtRsaAlgorithm] =
    Gen.function1[JwtRsaAlgorithm, JwtRsaAlgorithm](jwtRsaAlgorithmGen)

  implicit lazy val jwtRsaAlgorithmFunArbitrary: Arbitrary[JwtRsaAlgorithm => JwtRsaAlgorithm] =
    Arbitrary(jwtRsaAlgorithmFunGen)
}
