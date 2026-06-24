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

import cats.Hash
import cats.Show
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import scodec.bits.ByteVector

/**
  * ScalaCheck generators and instances for the scodec-bits library.
  */
private[jots] object ScodecInstances extends ScodecInstances

private[jots] trait ScodecInstances {
  lazy val byteVectorGen: Gen[ByteVector] =
    arbitrary[Array[Byte]].map(ByteVector.view)

  implicit lazy val byteVectorArbitrary: Arbitrary[ByteVector] =
    Arbitrary(byteVectorGen)

  implicit lazy val byteVectorCogen: Cogen[ByteVector] =
    Cogen[Array[Byte]].contramap(_.toArrayUnsafe)

  lazy val byteVectorNonEmptyGen: Gen[ByteVector] =
    byteVectorGen.filter(_.nonEmpty)

  lazy val byteVectorFunGen: Gen[ByteVector => ByteVector] =
    Gen.function1(byteVectorGen)

  implicit lazy val byteVectorFunArbitrary: Arbitrary[ByteVector => ByteVector] =
    Arbitrary(byteVectorFunGen)

  implicit lazy val byteVectorHash: Hash[ByteVector] =
    Hash.fromUniversalHashCode

  implicit lazy val byteVectorShow: Show[ByteVector] =
    Show.fromToString
}
