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

package jots

import cats.Eq
import cats.laws.discipline.ContravariantTests
import cats.syntax.all.*
import jots.testing.*
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import org.scalacheck.Gen.Parameters
import org.scalacheck.Prop
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtEncoderSuite extends SimpleIOSuite with Checkers with Discipline {
  private implicit def jwtEncoderArbitrary[A: Cogen]: Arbitrary[JwtEncoder[A]] =
    Arbitrary(Gen.function1[A, JwtBuilder](jwtBuilderGen).map(JwtEncoder.encodeWith))

  private implicit def jwtEncoderEq[A: Arbitrary]: Eq[JwtEncoder[A]] =
    Eq.instance { case (encoder1, encoder2) =>
      Prop
        .forAll { (a: A) =>
          encoder1.encode(a) === encoder2.encode(a)
        }
        .apply(Parameters.default)
        .success
    }

  checkAll(
    "JwtEncoder.contravariant",
    ContravariantTests[JwtEncoder].contravariant[Int, Long, String]
  )
}
