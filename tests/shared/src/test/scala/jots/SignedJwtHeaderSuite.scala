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

object SignedJwtHeaderSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("SignedJwtHeader.hash", HashTests[SignedJwtHeader].hash)

  pureTest("SignedJwtHeader.fromString: reject duplicates") {
    SignedJwtHeader.fromString(headerWithDuplicateKeys) match {
      case Left(e) => expect(e.getCause.getMessage.contains("duplicate key"))
      case Right(_) => failure("expected failure")
    }
  }

  test("SignedJwtHeader.show") {
    forall { (header: SignedJwtHeader) =>
      expect.eql(Show[SignedJwtHeader].show(header), header.show) &&
      expect.eql(header.show, header.toBase64UrlNoPad)
    }
  }

  // {"typ":"JWT","typ":"JWT"} as Base64UrlNoPad
  private val headerWithDuplicateKeys: String =
    "eyJ0eXAiOiJKV1QiLCJ0eXAiOiJKV1QifSI"
}
