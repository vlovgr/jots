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
import jots.crypto.Verified.Invalid
import jots.crypto.Verified.Valid
import jots.testing.*
import weaver.FunSuite
import weaver.discipline.Discipline

object VerifiedSuite extends FunSuite with Discipline {
  test("Verified.apply") {
    expect.eql(Verified(true), Valid) &&
    expect.eql(Verified(false), Invalid)
  }

  checkAll("Verified.hash", HashTests[Verified].hash)

  test("Verified.fromBoolean") {
    expect.eql(Verified.fromBoolean(true), Valid) &&
    expect.eql(Verified.fromBoolean(false), Invalid)
  }

  test("Verified.invalid") {
    expect.eql(Verified.invalid, Verified.Invalid)
  }

  test("Verified.isInvalid") {
    expect.eql(Valid.isInvalid, false) &&
    expect.eql(Invalid.isInvalid, true)
  }

  test("Verified.isValid") {
    expect.eql(Valid.isValid, true) &&
    expect.eql(Invalid.isValid, false)
  }

  test("Verified.show.invalid") {
    expect.eql(Show[Verified].show(Invalid), Invalid.show) &&
    expect.eql(Invalid.show, Invalid.toString) &&
    expect.eql(Invalid.toString, "Invalid")
  }

  test("Verified.show.valid") {
    expect.eql(Show[Verified].show(Valid), Valid.show) &&
    expect.eql(Valid.show, Valid.toString) &&
    expect.eql(Valid.toString, "Valid")
  }

  test("Verified.valid") {
    expect.eql(Verified.valid, Verified.Valid)
  }
}
