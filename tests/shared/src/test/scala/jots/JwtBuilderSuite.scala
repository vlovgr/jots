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
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtBuilderSuite extends SimpleIOSuite with Checkers with Discipline {
  pureTest("JwtBuilder.default") {
    expect.eql(JwtHeader.default, JwtBuilder.default.header) &&
    expect.eql(JwtClaims.empty, JwtBuilder.default.claims)
  }

  pureTest("JwtBuilder.empty") {
    expect.eql(JwtHeader.empty, JwtBuilder.empty.header) &&
    expect.eql(JwtClaims.empty, JwtBuilder.empty.claims)
  }

  checkAll("JwtBuilder.hash", HashTests[JwtBuilder].hash)

  test("JwtBuilder.show") {
    forall { (jwt: JwtBuilder) =>
      expect.eql(Show[JwtBuilder].show(jwt), jwt.show) &&
      expect(jwt.show.contains(jwt.header.show)) &&
      expect(jwt.show.contains(jwt.claims.show))
    }
  }

  test("JwtBuilder.toString") {
    forall { (jwt: JwtBuilder) =>
      expect(jwt.toString.contains(jwt.header.toString)) &&
      expect(jwt.toString.contains(jwt.claims.toString))
    }
  }
}
