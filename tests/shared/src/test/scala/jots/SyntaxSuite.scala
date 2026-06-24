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

import cats.Show
import io.circe.Encoder
import jots.syntax.*
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object SyntaxSuite extends SimpleIOSuite with Checkers {
  test("Syntax.asJwt") {
    forall { (claims: Claims) =>
      expect.eql(JwtEncoder[Claims].encode(claims), claims.asJwt)
    }
  }

  private final case class Claims(id: String)

  private object Claims {
    implicit val claimsEncoder: Encoder.AsObject[Claims] =
      Encoder.forProduct1("id")(_.id)

    implicit val claimsJwtEncoder: JwtEncoder[Claims] =
      JwtEncoder.encodeClaims

    val claimsGen: Gen[Claims] =
      Gen.uuid.map(_.toString).map(apply)

    implicit val claimsArbitrary: Arbitrary[Claims] =
      Arbitrary(claimsGen)

    implicit val claimsShow: Show[Claims] =
      Show.fromToString
  }
}
