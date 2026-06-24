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

package jots.crypto

import cats.effect.IO
import cats.syntax.all.*
import jots.testing.*
import scodec.bits.ByteVector
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object CryptoSuite extends SimpleIOSuite with Checkers with ScodecInstances {
  test("Crypto.hmac") {
    forall { (key: SecretKey, message: ByteVector) =>
      HashAlgorithm.All
        .traverse(Crypto[IO].hmac(_, key)(message).as(success))
        .map(_.combineAll)
    }
  }
}
