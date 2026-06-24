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
import cats.kernel.laws.discipline.HashTests
import cats.syntax.all.*
import io.circe.JsonObject
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtClaimsSuite extends SimpleIOSuite with Checkers with Discipline {
  pureTest("JwtClaims.empty") {
    expect.eql(JsonObject.empty, JwtClaims.empty.toJsonObject)
  }

  checkAll("JwtClaims.hash", HashTests[JwtClaims].hash)

  test("JwtClaims.show") {
    forall { (claims: JwtClaims) =>
      expect.eql(Show[JwtClaims].show(claims), claims.show) &&
      expect.eql(claims.show, claims.toBase64UrlNoPad)
    }
  }

  test("JwtClaims.toString") {
    forall { (claims: JwtClaims) =>
      claims.toJsonObject.toList.map { case (key, value) =>
        expect(claims.toString.contains(key)) &&
        expect(claims.toString.contains(value.show))
      }.combineAll
    }
  }
}
