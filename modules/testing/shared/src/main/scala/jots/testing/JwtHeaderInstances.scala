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

import jots.JwtHeader
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwtHeader]]s.
  */
object JwtHeaderInstances extends JwtHeaderInstances

private[jots] trait JwtHeaderInstances {
  lazy val jwtHeaderGen: Gen[JwtHeader] =
    for {
      algorithm <- Gen.option(jwtAlgorithmGen)
      contentType <- Gen.option(arbitrary[String])
      keyId <- Gen.option(arbitrary[String])
      typ <- Gen.oneOf(
        Gen.const(Some("JWT")),
        Gen.option(arbitrary[String])
      )
      header = JwtHeader.empty
        .withAlgorithmOption(algorithm)
        .withContentTypeOption(contentType)
        .withKeyIdOption(keyId)
        .withTypeOption(typ)
    } yield header

  implicit lazy val jwtHeaderArbitrary: Arbitrary[JwtHeader] =
    Arbitrary(jwtHeaderGen)

  implicit lazy val jwtHeaderCogen: Cogen[JwtHeader] =
    Cogen[String].contramap(_.show)

  lazy val jwtHeaderFunGen: Gen[JwtHeader => JwtHeader] =
    Gen.function1(jwtHeaderGen)

  implicit lazy val jwtHeaderFunArbitrary: Arbitrary[JwtHeader => JwtHeader] =
    Arbitrary(jwtHeaderFunGen)
}
