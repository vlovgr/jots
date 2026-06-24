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

import jots.crypto.Verified
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.crypto.Verified]].
  */
object VerifiedInstances extends VerifiedInstances

private[jots] trait VerifiedInstances {
  lazy val verifiedGen: Gen[Verified] =
    arbitrary[Boolean].map(Verified.fromBoolean)

  implicit lazy val verifiedArbitrary: Arbitrary[Verified] =
    Arbitrary(verifiedGen)

  implicit lazy val verifiedCogen: Cogen[Verified] =
    Cogen[Boolean].contramap(_.isValid)

  lazy val verifiedFunGen: Gen[Verified => Verified] =
    Gen.function1(verifiedGen)

  implicit lazy val verifiedFunArbitrary: Arbitrary[Verified => Verified] =
    Arbitrary(verifiedFunGen)
}
