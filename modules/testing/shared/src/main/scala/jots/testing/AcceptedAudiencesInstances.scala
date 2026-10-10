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
import jots.AcceptedAudiences
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.AcceptedAudiences]].
  */
object AcceptedAudiencesInstances extends AcceptedAudiencesInstances

private[jots] trait AcceptedAudiencesInstances {
  lazy val acceptedAudiencesGen: Gen[AcceptedAudiences] =
    Gen.oneOf(
      Gen.const(AcceptedAudiences.none),
      Gen.const(AcceptedAudiences.any),
      for {
        audience <- arbitrary[String]
        audiences <- arbitrary[List[String]]
      } yield AcceptedAudiences.fromList(NonEmptyList(audience, audiences))
    )

  implicit lazy val acceptedAudiencesArbitrary: Arbitrary[AcceptedAudiences] =
    Arbitrary(acceptedAudiencesGen)

  implicit lazy val acceptedAudiencesCogen: Cogen[AcceptedAudiences] =
    Cogen[String].contramap(_.show)

  lazy val acceptedAudiencesFunGen: Gen[AcceptedAudiences => AcceptedAudiences] =
    Gen.function1(acceptedAudiencesGen)

  implicit lazy val acceptedAudiencesFunArbitrary: Arbitrary[AcceptedAudiences => AcceptedAudiences] =
    Arbitrary(acceptedAudiencesFunGen)
}
