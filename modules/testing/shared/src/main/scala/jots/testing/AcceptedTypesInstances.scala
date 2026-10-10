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

import cats.data.NonEmptyList
import jots.AcceptedTypes
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.AcceptedTypes]].
  */
object AcceptedTypesInstances extends AcceptedTypesInstances

private[jots] trait AcceptedTypesInstances {
  lazy val acceptedTypesGen: Gen[AcceptedTypes] =
    Gen.oneOf(
      Gen.const(AcceptedTypes.any),
      for {
        typ <- arbitrary[String]
        types <- arbitrary[List[String]]
      } yield AcceptedTypes.fromList(NonEmptyList(typ, types))
    )

  implicit lazy val acceptedTypesArbitrary: Arbitrary[AcceptedTypes] =
    Arbitrary(acceptedTypesGen)

  implicit lazy val acceptedTypesCogen: Cogen[AcceptedTypes] =
    Cogen[String].contramap(_.show)

  lazy val acceptedTypesFunGen: Gen[AcceptedTypes => AcceptedTypes] =
    Gen.function1(acceptedTypesGen)

  implicit lazy val acceptedTypesFunArbitrary: Arbitrary[AcceptedTypes => AcceptedTypes] =
    Arbitrary(acceptedTypesFunGen)
}
