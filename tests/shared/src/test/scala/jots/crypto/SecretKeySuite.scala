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

import cats.kernel.laws.discipline.HashTests
import java.nio.charset.StandardCharsets.UTF_8
import jots.testing.*
import scodec.bits.ByteVector
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object SecretKeySuite extends SimpleIOSuite with Checkers with Discipline with ScodecInstances {
  test("SecretKey.apply") {
    forall { (s: String) =>
      expect.eql(
        SecretKey(s).toOption,
        SecretKey.fromStringUtf8(s).toOption
      )
    }
  }

  checkAll("SecretKey.hash", HashTests[SecretKey].hash)

  test("SecretKey.fromByteVector") {
    forall { (bv: ByteVector) =>
      expect.eql(
        SecretKey.fromByteVector(bv).map(_.toByteVector).toOption,
        Option.when(bv.nonEmpty)(bv)
      )
    }
  }

  test("SecretKey.fromStringUtf8") {
    forall { (s: String) =>
      expect.eql(
        SecretKey.fromStringUtf8(s).map(_.toByteVector).toOption,
        Option.when(s.nonEmpty)(ByteVector.view(s.getBytes(UTF_8)))
      )
    }
  }

  test("SecretKey.toString") {
    forall { (s: SecretKey) =>
      expect.eql(s.toString, "SecretKey(**)")
    }
  }
}
