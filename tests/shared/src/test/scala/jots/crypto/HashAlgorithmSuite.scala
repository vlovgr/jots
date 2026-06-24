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
import cats.kernel.laws.discipline.HashTests
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object HashAlgorithmSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("HashAlgorithm.hash", HashTests[HashAlgorithm].hash)

  test("HashAlgorithm.show") {
    forall { (algorithm: HashAlgorithm) =>
      expect.eql(Show[HashAlgorithm].show(algorithm), algorithm.show) &&
      expect.eql(algorithm.show, algorithm.toString) &&
      expect.eql(algorithm.toString, algorithm.name)
    }
  }
}
