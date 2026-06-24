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
import cats.effect.SyncIO
import jots.SignedJwt
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.SignedJwt]]s.
  */
object SignedJwtInstances extends SignedJwtInstances

private[jots] trait SignedJwtInstances {

  /**
    * Generates [[jots.SignedJwt]]s with invalid signatures.
    */
  lazy val signedJwtInvalidGen: Gen[SignedJwt] =
    for {
      builder <- jwtBuilderGen
      signature <- jwtSignatureGen
      signed = builder.toSigned(signature)
    } yield signed

  /**
    * Generates [[jots.SignedJwt]]s with valid signatures.
    */
  lazy val signedJwtGen: Gen[SignedJwt] =
    for {
      builder <- jwtBuilderGen
      signing <- jwtSigningGen[SyncIO]
      signed = builder.signWith(signing).unsafeRunSync()
    } yield signed

  implicit lazy val signedJwtArbitrary: Arbitrary[SignedJwt] =
    Arbitrary(signedJwtGen)

  implicit lazy val signedJwtCogen: Cogen[SignedJwt] =
    Cogen[String].contramap(_.show)

  implicit lazy val signedJwtShow: Show[SignedJwt] =
    Show.show(_.show)

  lazy val signedJwtFunGen: Gen[SignedJwt => SignedJwt] =
    Gen.function1(signedJwtGen)

  implicit lazy val signedJwtFunArbitrary: Arbitrary[SignedJwt => SignedJwt] =
    Arbitrary(signedJwtFunGen)
}
