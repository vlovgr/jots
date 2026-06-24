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

import jots.crypto.AsymmetricAlgorithm
import jots.crypto.EcdsaAlgorithm
import jots.crypto.EddsaAlgorithm
import jots.crypto.RsaAlgorithm
import jots.crypto.RsaPssAlgorithm
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.crypto.AsymmetricAlgorithm]]s.
  */
object AsymmetricAlgorithmInstances extends AsymmetricAlgorithmInstances

private[jots] trait AsymmetricAlgorithmInstances {
  lazy val asymmetricAlgorithmGen: Gen[AsymmetricAlgorithm] =
    Gen.oneOf(AsymmetricAlgorithm.All.toList)

  implicit lazy val asymmetricAlgorithmArbitrary: Arbitrary[AsymmetricAlgorithm] =
    Arbitrary(asymmetricAlgorithmGen)

  implicit lazy val asymmetricAlgorithmCogen: Cogen[AsymmetricAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val asymmetricAlgorithmFunGen: Gen[AsymmetricAlgorithm => AsymmetricAlgorithm] =
    Gen.function1(asymmetricAlgorithmGen)

  implicit lazy val asymmetricAlgorithmFunArbitrary: Arbitrary[AsymmetricAlgorithm => AsymmetricAlgorithm] =
    Arbitrary(asymmetricAlgorithmFunGen)

  lazy val ecdsaAlgorithmGen: Gen[EcdsaAlgorithm] =
    Gen.oneOf(EcdsaAlgorithm.All.toList)

  implicit lazy val ecdsaAlgorithmArbitrary: Arbitrary[EcdsaAlgorithm] =
    Arbitrary(ecdsaAlgorithmGen)

  implicit lazy val ecdsaAlgorithmCogen: Cogen[EcdsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val ecdsaAlgorithmFunGen: Gen[EcdsaAlgorithm => EcdsaAlgorithm] =
    Gen.function1[EcdsaAlgorithm, EcdsaAlgorithm](ecdsaAlgorithmGen)

  implicit lazy val ecdsaAlgorithmFunArbitrary: Arbitrary[EcdsaAlgorithm => EcdsaAlgorithm] =
    Arbitrary(ecdsaAlgorithmFunGen)

  lazy val eddsaAlgorithmGen: Gen[EddsaAlgorithm] =
    Gen.oneOf(EddsaAlgorithm.All.toList)

  implicit lazy val eddsaAlgorithmArbitrary: Arbitrary[EddsaAlgorithm] =
    Arbitrary(eddsaAlgorithmGen)

  implicit lazy val eddsaAlgorithmCogen: Cogen[EddsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val eddsaAlgorithmFunGen: Gen[EddsaAlgorithm => EddsaAlgorithm] =
    Gen.function1[EddsaAlgorithm, EddsaAlgorithm](eddsaAlgorithmGen)

  implicit lazy val eddsaAlgorithmFunArbitrary: Arbitrary[EddsaAlgorithm => EddsaAlgorithm] =
    Arbitrary(eddsaAlgorithmFunGen)

  lazy val rsaAlgorithmGen: Gen[RsaAlgorithm] =
    Gen.oneOf(RsaAlgorithm.All.toList)

  implicit lazy val rsaAlgorithmArbitrary: Arbitrary[RsaAlgorithm] =
    Arbitrary(rsaAlgorithmGen)

  implicit lazy val rsaAlgorithmCogen: Cogen[RsaAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val rsaAlgorithmFunGen: Gen[RsaAlgorithm => RsaAlgorithm] =
    Gen.function1[RsaAlgorithm, RsaAlgorithm](rsaAlgorithmGen)

  implicit lazy val rsaAlgorithmFunArbitrary: Arbitrary[RsaAlgorithm => RsaAlgorithm] =
    Arbitrary(rsaAlgorithmFunGen)

  lazy val rsaPssAlgorithmGen: Gen[RsaPssAlgorithm] =
    Gen.oneOf(RsaPssAlgorithm.All.toList)

  implicit lazy val rsaPssAlgorithmArbitrary: Arbitrary[RsaPssAlgorithm] =
    Arbitrary(rsaPssAlgorithmGen)

  implicit lazy val rsaPssAlgorithmCogen: Cogen[RsaPssAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val rsaPssAlgorithmFunGen: Gen[RsaPssAlgorithm => RsaPssAlgorithm] =
    Gen.function1[RsaPssAlgorithm, RsaPssAlgorithm](rsaPssAlgorithmGen)

  implicit lazy val rsaPssAlgorithmFunArbitrary: Arbitrary[RsaPssAlgorithm => RsaPssAlgorithm] =
    Arbitrary(rsaPssAlgorithmFunGen)
}
