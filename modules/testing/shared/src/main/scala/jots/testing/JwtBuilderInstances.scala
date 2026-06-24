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

import jots.JwtBuilder
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwtBuilder]]s.
  */
object JwtBuilderInstances extends JwtBuilderInstances

private[jots] trait JwtBuilderInstances {
  lazy val jwtBuilderGen: Gen[JwtBuilder] =
    for {
      header <- jwtHeaderGen
      claims <- jwtClaimsGen
    } yield JwtBuilder(header, claims)

  implicit lazy val jwtBuilderArbitrary: Arbitrary[JwtBuilder] =
    Arbitrary(jwtBuilderGen)

  implicit lazy val jwtBuilderCogen: Cogen[JwtBuilder] =
    Cogen[String].contramap(_.show)

  lazy val jwtBuilderFunGen: Gen[JwtBuilder => JwtBuilder] =
    Gen.function1(jwtBuilderGen)

  implicit lazy val jwtBuilderFunArbitrary: Arbitrary[JwtBuilder => JwtBuilder] =
    Arbitrary(jwtBuilderFunGen)
}
