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

import jots.JwkKeyId
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwkKeyId]]s.
  */
object JwkKeyIdInstances extends JwkKeyIdInstances

private[jots] trait JwkKeyIdInstances {
  lazy val jwkKeyIdGen: Gen[JwkKeyId] =
    arbitrary[String].map(JwkKeyId.fromString)

  implicit lazy val jwkKeyIdArbitrary: Arbitrary[JwkKeyId] =
    Arbitrary(jwkKeyIdGen)

  implicit lazy val jwkKeyIdCogen: Cogen[JwkKeyId] =
    Cogen[String].contramap(_.value)

  lazy val jwkKeyIdFunGen: Gen[JwkKeyId => JwkKeyId] =
    Gen.function1(jwkKeyIdGen)

  implicit lazy val jwkKeyIdFunArbitrary: Arbitrary[JwkKeyId => JwkKeyId] =
    Arbitrary(jwkKeyIdFunGen)
}
