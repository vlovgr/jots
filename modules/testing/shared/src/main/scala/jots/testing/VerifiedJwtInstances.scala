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

import cats.Show
import jots.SignedJwt
import jots.VerifiedJwt
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.VerifiedJwt]]s.
  */
object VerifiedJwtInstances extends VerifiedJwtInstances

private[jots] trait VerifiedJwtInstances {
  lazy val verifiedJwtGen: Gen[VerifiedJwt] =
    signedJwtGen.map(VerifiedJwt.fromVerified)

  implicit lazy val verifiedJwtArbitrary: Arbitrary[VerifiedJwt] =
    Arbitrary(verifiedJwtGen)

  implicit lazy val verifiedJwtCogen: Cogen[VerifiedJwt] =
    Cogen[SignedJwt].contramap(_.toSigned)

  implicit lazy val verifiedJwtShow: Show[VerifiedJwt] =
    Show.show(_.show)

  lazy val verifiedJwtFunGen: Gen[VerifiedJwt => VerifiedJwt] =
    Gen.function1(verifiedJwtGen)

  implicit lazy val verifiedJwtFunArbitrary: Arbitrary[VerifiedJwt => VerifiedJwt] =
    Arbitrary(verifiedJwtFunGen)
}
