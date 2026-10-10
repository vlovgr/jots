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
import io.circe.Json
import jots.testing.*
import org.scalacheck.Gen
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

  test("JwkSet.toPublicJwkSet") {
    forall(Gen.listOf(Gen.oneOf(jwkEcdsaKeyPairGen, jwkEddsaKeyPairGen, jwkRsaKeyPairGen))) { keyPairs =>
      val (privateKeys, publicKeys) = keyPairs.unzip
      expect.eql(Some(JwkSet.fromList(publicKeys)), JwkSet.fromList(privateKeys).toPublicJwkSet.toOption)
    }
  }

  test("JwkSet.toPublicJwkSet.rejectSecretKey") {
    forall(jwkOctGen) { jwk =>
      expect(JwkSet(jwk).toPublicJwkSet.isLeft)
    }
  }

  pureTest("JwkSet.fromString.rejectNested") {
    val nested = s"""{"kty":"oct","nested":${"[" * 1000}${"]" * 1000}}"""
    expect(JwkSet.fromString(s"""{"keys":[$nested]}""").isLeft)
  }

  pureTest("JwkSet.fromString.rejectUndecodableKeys") {
    expect(JwkSet.fromString("""{"keys":[{"kid":"key-1"}]}""").isLeft)
  }

  pureTest("JwkSet.decoder.rejectNested") {
    val nested = (1 to 1000).foldLeft(Json.arr())((json, _) => Json.arr(json))
    expect(Json.obj("keys" -> Json.arr(), "nested" -> nested).as[JwkSet].isLeft)
  }
}
