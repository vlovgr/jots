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

import jots.Jwk
import jots.JwkSet
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[JwkSet]]s.
  */
object JwkSetInstances extends JwkSetInstances

private[jots] trait JwkSetInstances {
  lazy val jwkSetGen: Gen[JwkSet] =
    Gen.listOf(jwkGen).map(JwkSet.fromList)

  implicit lazy val jwkSetArbitrary: Arbitrary[JwkSet] =
    Arbitrary(jwkSetGen)

  implicit lazy val jwkSetCogen: Cogen[JwkSet] =
    Cogen[List[Jwk]].contramap(_.toList)

  lazy val jwkSetFunGen: Gen[JwkSet => JwkSet] =
    Gen.function1(jwkSetGen)

  implicit lazy val jwkSetFunArbitrary: Arbitrary[JwkSet => JwkSet] =
    Arbitrary(jwkSetFunGen)
}
