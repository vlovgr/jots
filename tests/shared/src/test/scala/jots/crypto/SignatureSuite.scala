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

object SignatureSuite extends SimpleIOSuite with Checkers with Discipline with ScodecInstances {
  test("Signature.apply") {
    forall { (bv: ByteVector) =>
      expect.eql(Signature(bv), Signature.fromByteVector(bv))
    }
  }

  test("Signature.empty") {
    IO.pure(expect.eql(Signature.empty.toByteVector, ByteVector.empty))
  }

  checkAll("Signature.hash", HashTests[Signature].hash)

  test("Signature.fromByteVector") {
    forall { (bv: ByteVector) =>
      expect.eql(Signature.fromByteVector(bv).toByteVector, bv)
    }
  }

  test("Signature.show") {
    forall { (signature: Signature) =>
      expect.eql(Show[Signature].show(signature), signature.show) &&
      expect.eql(signature.show, signature.toHex)
    }
  }

  test("Signature.toHex") {
    forall { (signature: Signature) =>
      expect.eql(signature.toHex, signature.toByteVector.toHex)
    }
  }

  test("Signature.toString") {
    forall { (signature: Signature) =>
      expect(signature.toString.contains(signature.toHex))
    }
  }
}
