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

import jots.crypto.HashAlgorithm
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.crypto.HashAlgorithm]]s.
  */
object HashAlgorithmInstances extends HashAlgorithmInstances

private[jots] trait HashAlgorithmInstances {
  lazy val hashAlgorithmGen: Gen[HashAlgorithm] =
    Gen.oneOf(HashAlgorithm.All.toList)

  implicit lazy val hashAlgorithmArbitrary: Arbitrary[HashAlgorithm] =
    Arbitrary(hashAlgorithmGen)

  implicit lazy val hashAlgorithmCogen: Cogen[HashAlgorithm] =
    Cogen[String].contramap(_.name)

  lazy val hashAlgorithmFunGen: Gen[HashAlgorithm => HashAlgorithm] =
    Gen.function1(hashAlgorithmGen)

  implicit lazy val hashAlgorithmFunArbitrary: Arbitrary[HashAlgorithm => HashAlgorithm] =
    Arbitrary(hashAlgorithmFunGen)
}
