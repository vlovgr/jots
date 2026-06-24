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
import jots.testing.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwkSetSuite extends SimpleIOSuite with Checkers with Discipline {
  checkAll("JwkSet.hash", HashTests[JwkSet].hash)

  test("JwkSet.show") {
    forall { (set: JwkSet) =>
      expect.eql(Show[JwkSet].show(set), set.show) &&
      expect.eql(set.show, set.toString) &&
      set.toList.map(key => expect(set.toString.contains(key.show))).combineAll
    }
  }

  test("JwkSet.toJson") {
    forall { (set: JwkSet) =>
      expect.eql(Right(set), set.toJson.as[JwkSet])
    }
  }
}
