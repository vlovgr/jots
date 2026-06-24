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
import jots.crypto.SecretKey
import jots.testing.ScodecInstances.*
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import scodec.bits.ByteVector

/**
  * ScalaCheck generators and instances for [[jots.crypto.SecretKey]]s.
  */
object SecretKeyInstances extends SecretKeyInstances

private[jots] trait SecretKeyInstances {

  /**
    * Generates secret keys with at least the specified length.
    */
  def secretKeyMinLengthGen(length: Int): Gen[SecretKey] =
    for {
      chosenLength <- Gen.chooseNum(length, length * 2)
      bytes <- Gen.listOfN(chosenLength, arbitrary[Byte])
      byteVector = ByteVector.view(bytes.toArray)
      secretKey <- SecretKey.fromByteVector(byteVector).map(Gen.const).getOrElse(Gen.fail)
    } yield secretKey

  /**
    * Generates secret keys with at most the specified length.
    */
  def secretKeyMaxLengthGen(length: Int): Gen[SecretKey] =
    for {
      chosenLength <- Gen.chooseNum(1, length)
      bytes <- Gen.listOfN(chosenLength, arbitrary[Byte])
      byteVector = ByteVector.view(bytes.toArray)
      secretKey <- SecretKey.fromByteVector(byteVector).map(Gen.const).getOrElse(Gen.fail)
    } yield secretKey

  lazy val secretKeyGen: Gen[SecretKey] =
    for {
      bytes <- arbitrary[Array[Byte]]
      if bytes.nonEmpty
      byteVector = ByteVector.view(bytes)
      secretKey <- SecretKey.fromByteVector(byteVector).map(Gen.const).getOrElse(Gen.fail)
    } yield secretKey

  implicit lazy val secretKeyArbitrary: Arbitrary[SecretKey] =
    Arbitrary(secretKeyGen)

  implicit lazy val secretKeyCogen: Cogen[SecretKey] =
    Cogen[ByteVector].contramap(_.toByteVector)

  implicit lazy val secretKeyShow: Show[SecretKey] =
    Show.show(_.toByteVector.decodeUtf8Lenient)

  lazy val secretKeyFunGen: Gen[SecretKey => SecretKey] =
    Gen.function1(secretKeyGen)

  implicit lazy val secretKeyFunArbitrary: Arbitrary[SecretKey => SecretKey] =
    Arbitrary(secretKeyFunGen)
}
