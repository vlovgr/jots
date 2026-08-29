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

package jots.http4s

import cats.effect.IO
import jots.SignedJwt
import jots.testing.*
import org.http4s.Request
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object SignedJwtHeaderInstanceSuite extends SimpleIOSuite with Checkers {
  test("SignedJwtHeaderInstance.rountrip") {
    forall { (signedJwt: SignedJwt) =>
      val request = Request[IO]().withHeaders(signedJwt)
      val extracted = request.headers.get[SignedJwt]
      expect.eql(Some(signedJwt), extracted)
    }
  }
}
