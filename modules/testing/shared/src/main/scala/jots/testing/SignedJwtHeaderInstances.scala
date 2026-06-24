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

import jots.SignedJwtHeader
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.SignedJwtHeader]]s.
  */
object SignedJwtHeaderInstances extends SignedJwtHeaderInstances

private[jots] trait SignedJwtHeaderInstances {
  lazy val signedJwtHeaderGen: Gen[SignedJwtHeader] =
    jwtHeaderGen.map(_.toSigned)

  implicit lazy val signedJwtHeaderArbitrary: Arbitrary[SignedJwtHeader] =
    Arbitrary(signedJwtHeaderGen)

  implicit lazy val signedJwtHeaderCogen: Cogen[SignedJwtHeader] =
    Cogen[String].contramap(_.show)

  lazy val signedJwtHeaderFunGen: Gen[SignedJwtHeader => SignedJwtHeader] =
    Gen.function1(signedJwtHeaderGen)

  implicit lazy val signedJwtHeaderFunArbitrary: Arbitrary[SignedJwtHeader => SignedJwtHeader] =
    Arbitrary(signedJwtHeaderFunGen)
}
