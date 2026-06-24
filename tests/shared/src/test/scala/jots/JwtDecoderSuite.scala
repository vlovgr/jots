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
import cats.laws.discipline.MonadErrorTests
import cats.syntax.all.*
import io.circe.Decoder
import io.circe.DecodingFailure
import jots.testing.*
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import org.scalacheck.Gen.Parameters
import org.scalacheck.Prop
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtDecoderSuite extends SimpleIOSuite with Checkers with Discipline {
  private implicit val decodingFailureArbitrary: Arbitrary[DecodingFailure] =
    Arbitrary(arbitrary[String].map(DecodingFailure(_, Nil)))

  private implicit val decodingFailureCogen: Cogen[DecodingFailure] =
    Cogen[String].contramap(_.message)

  private implicit def jwtDecoderArbitrary[A: Arbitrary]: Arbitrary[JwtDecoder[A]] =
    Arbitrary(
      Gen
        .function1[VerifiedJwt, Decoder.Result[A]](
          arbitrary[Either[DecodingFailure, A]]
        )
        .map(JwtDecoder.decodeWith)
    )

  private implicit def jwtDecoderEq[A: Eq]: Eq[JwtDecoder[A]] =
    Eq.instance { case (decoder1, decoder2) =>
      Prop
        .forAll { (jwt: VerifiedJwt) =>
          decoder1.decode(jwt) === decoder2.decode(jwt)
        }
        .apply(Parameters.default)
        .success
    }

  checkAll(
    "JwtDecoder.monadError",
    MonadErrorTests[JwtDecoder, DecodingFailure].monadError[Int, Long, String]
  )
}
