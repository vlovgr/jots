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

import cats.Show
import cats.effect.IO
import cats.kernel.laws.discipline.HashTests
import jots.testing.*
import scodec.bits.ByteVector
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object MacSuite extends SimpleIOSuite with Checkers with Discipline with ScodecInstances {
  test("Mac.apply") {
    forall { (bv: ByteVector) =>
      expect.eql(Mac(bv), Mac.fromByteVector(bv))
    }
  }

  test("Mac.empty") {
    IO.pure(expect.eql(Mac.empty.toByteVector, ByteVector.empty))
  }

  checkAll("Mac.hash", HashTests[Mac].hash)

  test("Mac.fromByteVector") {
    forall { (bv: ByteVector) =>
      expect.eql(Mac.fromByteVector(bv).toByteVector, bv)
    }
  }

  test("Mac.show") {
    forall { (mac: Mac) =>
      expect.eql(Show[Mac].show(mac), mac.show) &&
      expect.eql(mac.show, mac.toHex)
    }
  }

  test("Mac.toHex") {
    forall { (mac: Mac) =>
      expect.eql(mac.toHex, mac.toByteVector.toHex)
    }
  }

  test("Mac.toString") {
    forall { (mac: Mac) =>
      expect(mac.toString.contains(mac.toHex))
    }
  }
}
