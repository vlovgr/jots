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
import cats.data.NonEmptyList
import cats.kernel.laws.discipline.HashTests
import io.circe.JsonObject
import io.circe.syntax.*
import jots.testing.*
import scala.concurrent.duration.*
import weaver.SimpleIOSuite
import weaver.discipline.Discipline
import weaver.scalacheck.Checkers

object JwtClaimsSuite extends SimpleIOSuite with Checkers with Discipline {
  pureTest("JwtClaims.empty") {
    expect.eql(JsonObject.empty, JwtClaims.empty.toJsonObject)
  }

  checkAll("JwtClaims.hash", HashTests[JwtClaims].hash)

  test("JwtClaims.show") {
    forall { (claims: JwtClaims) =>
      expect.eql(Show[JwtClaims].show(claims), claims.show) &&
      expect.eql(claims.show, claims.toBase64UrlNoPad)
    }
  }

  test("JwtClaims.toString") {
    forall { (claims: JwtClaims) =>
      expect.eql(claims.toJsonObject.keys.mkString("JwtClaims(", ",", ")"), claims.toString)
    }
  }

  pureTest("JwtClaims.registeredClaims") {
    val claims =
      JwtClaims.empty
        .withIssuer("https://example.auth0.com/")
        .withSubject("8d3bbd14-dfd9-47fa-aab4-d76daf00b4f1")
        .withAudience("https://api.example.com")
        .withExpiration(3345062400L.seconds)
        .withNotBefore(1767225600L.seconds)
        .withIssuedAt(1767225600L.seconds)
        .withJwtId("a4d8e2f1-6c3b-4f5a-9e7d-1b2c3d4e5f60")

    expect.eql(
      JsonObject(
        "iss" -> "https://example.auth0.com/".asJson,
        "sub" -> "8d3bbd14-dfd9-47fa-aab4-d76daf00b4f1".asJson,
        "aud" -> "https://api.example.com".asJson,
        "exp" -> 3345062400L.asJson,
        "nbf" -> 1767225600L.asJson,
        "iat" -> 1767225600L.asJson,
        "jti" -> "a4d8e2f1-6c3b-4f5a-9e7d-1b2c3d4e5f60".asJson
      ),
      claims.toJsonObject
    )
  }

  pureTest("JwtClaims.withAudience") {
    val audiences = List("https://api.example.com", "https://admin.example.com")
    expect.eql(
      Some(audiences.asJson),
      JwtClaims.empty.withAudience(audiences.head, audiences.tail: _*).toJsonObject("aud")
    ) &&
    expect.eql(
      Some(audiences.asJson),
      JwtClaims.empty.withAudience(NonEmptyList.fromListUnsafe(audiences)).toJsonObject("aud")
    )
  }
}
