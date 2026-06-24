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

import jots.crypto.Mac
import jots.testing.ScodecInstances.*
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.crypto.Mac]]s.
  */
object MacInstances extends MacInstances

private[jots] trait MacInstances {
  lazy val macGen: Gen[Mac] =
    byteVectorGen.map(Mac.fromByteVector)

  implicit lazy val macArbitrary: Arbitrary[Mac] =
    Arbitrary(macGen)

  implicit lazy val macCogen: Cogen[Mac] =
    byteVectorCogen.contramap(_.toByteVector)

  lazy val macFunGen: Gen[Mac => Mac] =
    Gen.function1(macGen)

  implicit lazy val macFunArbitrary: Arbitrary[Mac => Mac] =
    Arbitrary(macFunGen)
}
