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

import jots.JwkKeyType
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwkKeyType]]s.
  */
object JwkKeyTypeInstances extends JwkKeyTypeInstances

private[jots] trait JwkKeyTypeInstances {
  lazy val jwkKeyTypeGen: Gen[JwkKeyType] =
    Gen.oneOf(JwkKeyType.All.toList)

  implicit lazy val jwkKeyTypeArbitrary: Arbitrary[JwkKeyType] =
    Arbitrary(jwkKeyTypeGen)

  implicit lazy val jwkKeyTypeCogen: Cogen[JwkKeyType] =
    Cogen[String].contramap(_.name)

  lazy val jwkKeyTypeFunGen: Gen[JwkKeyType => JwkKeyType] =
    Gen.function1(jwkKeyTypeGen)

  implicit lazy val jwkKeyTypeFunArbitrary: Arbitrary[JwkKeyType => JwkKeyType] =
    Arbitrary(jwkKeyTypeFunGen)
}
