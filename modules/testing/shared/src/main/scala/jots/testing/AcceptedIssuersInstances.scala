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
import jots.AcceptedIssuers
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.AcceptedIssuers]].
  */
object AcceptedIssuersInstances extends AcceptedIssuersInstances

private[jots] trait AcceptedIssuersInstances {
  lazy val acceptedIssuersGen: Gen[AcceptedIssuers] =
    Gen.oneOf(
      Gen.const(AcceptedIssuers.any),
      for {
        issuer <- arbitrary[String]
        issuers <- arbitrary[List[String]]
      } yield AcceptedIssuers.fromList(NonEmptyList(issuer, issuers))
    )

  implicit lazy val acceptedIssuersArbitrary: Arbitrary[AcceptedIssuers] =
    Arbitrary(acceptedIssuersGen)

  implicit lazy val acceptedIssuersCogen: Cogen[AcceptedIssuers] =
    Cogen[String].contramap(_.show)

  lazy val acceptedIssuersFunGen: Gen[AcceptedIssuers => AcceptedIssuers] =
    Gen.function1(acceptedIssuersGen)

  implicit lazy val acceptedIssuersFunArbitrary: Arbitrary[AcceptedIssuers => AcceptedIssuers] =
    Arbitrary(acceptedIssuersFunGen)
}
