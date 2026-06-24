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

import cats.syntax.all.*
import io.circe.JsonObject
import io.circe.syntax.*
import jots.JwtClaims
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.JwtClaims]].
  */
object JwtClaimsInstances extends JwtClaimsInstances

private[jots] trait JwtClaimsInstances {
  lazy val jwtClaimsGen: Gen[JwtClaims] =
    for {
      issuer <- Gen.option(arbitrary[String])
      subject <- Gen.option(arbitrary[String])
      audience <- Gen.option(arbitrary[String])
      expiresAt <- Gen.option(arbitrary[Long])
      notBefore <- Gen.option(arbitrary[Long])
      issuedAt <- Gen.option(arbitrary[Long])
      jwtId <- Gen.option(arbitrary[String])
      claims = JwtClaims.fromJsonObject(
        JsonObject.fromFoldable(
          List(
            issuer.map(_.asJson).tupleLeft("iss"),
            subject.map(_.asJson).tupleLeft("sub"),
            audience.map(_.asJson).tupleLeft("aud"),
            expiresAt.map(_.asJson).tupleLeft("exp"),
            notBefore.map(_.asJson).tupleLeft("nbf"),
            issuedAt.map(_.asJson).tupleLeft("iat"),
            jwtId.map(_.asJson).tupleLeft("jti")
          ).flatten
        )
      )
    } yield claims

  implicit lazy val jwtClaimsArbitrary: Arbitrary[JwtClaims] =
    Arbitrary(jwtClaimsGen)

  implicit lazy val jwtClaimsCogen: Cogen[JwtClaims] =
    Cogen[String].contramap(_.show)

  lazy val jwtClaimsFunGen: Gen[JwtClaims => JwtClaims] =
    Gen.function1(jwtClaimsGen)

  implicit lazy val jwtClaimsFunArbitrary: Arbitrary[JwtClaims => JwtClaims] =
    Arbitrary(jwtClaimsFunGen)
}
