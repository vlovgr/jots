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

import jots.JwtSignature
import jots.testing.ScodecInstances.*
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import scodec.bits.ByteVector

/**
  * ScalaCheck generators and instances for [[jots.JwtSignature]]s.
  */
object JwtSignatureInstances extends JwtSignatureInstances

private[jots] trait JwtSignatureInstances {
  lazy val jwtSignatureGen: Gen[JwtSignature] =
    byteVectorGen.map(JwtSignature.fromByteVector)

  implicit lazy val jwtSignatureArbitrary: Arbitrary[JwtSignature] =
    Arbitrary(jwtSignatureGen)

  implicit lazy val jwtSignatureCogen: Cogen[JwtSignature] =
    Cogen[ByteVector].contramap(_.toByteVector)

  lazy val jwtSignatureFunGen: Gen[JwtSignature => JwtSignature] =
    Gen.function1(jwtSignatureGen)

  implicit lazy val jwtSignatureFunArbitrary: Arbitrary[JwtSignature => JwtSignature] =
    Arbitrary(jwtSignatureFunGen)
}
