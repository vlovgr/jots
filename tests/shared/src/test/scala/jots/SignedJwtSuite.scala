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

import cats.kernel.laws.discipline.HashTests
import io.circe.syntax.*
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object SignedJwtSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("SignedJwt.hash", HashTests[SignedJwt].hash)

  pureTest("SignedJwt.codec") {
    forEach(ExampleJwt.All)(example =>
      expect.eql(Right(example.signedJwt), example.signedJwt.asJson.as[SignedJwt])
    )
  }

  pureTest("SignedJwt.signedBytes") {
    forEach(ExampleJwt.All)(example => expect.same(example.signedBytes, example.signedJwt.signedBytes))
  }

  pureTest("SignedJwt.toUnsigned") {
    forEach(ExampleJwt.All)(example => expect.eql(example.builder, example.signedJwt.toBuilder))
  }
}
