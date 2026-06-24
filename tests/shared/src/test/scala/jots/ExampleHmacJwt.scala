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
import cats.effect.IO
import io.circe.Json
import io.circe.syntax.*
import jots.crypto.SecretKey
import jots.testing.syntax.*
import org.scalacheck.Arbitrary
import org.scalacheck.Gen

final case class ExampleHmacJwt(
  override val header: JwtHeader,
  override val claims: JwtClaims,
  override val signedJwt: SignedJwt,
  secretKey: SecretKey,
  algorithm: JwtHmacAlgorithm
) extends ExampleJwt {
  override val verification: IO[JwtVerification[IO]] =
    JwtVerification.default[IO].hmac(algorithm, secretKey)
}

object ExampleHmacJwt {
  lazy val HS256: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
      secretKey"a-string-secret-at-least-256-bits-long",
      JwtHmacAlgorithm.HS256
    )

  lazy val HS256Jwk: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
      secretKey(
        "kty" -> "oct".asJson,
        "k" -> "YS1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc".asJson
      ),
      JwtHmacAlgorithm.HS256
    )

  lazy val HS384: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.owv7q9nVbW5tqUezF_G2nHTra-ANW3HqW9epyVwh08Y-Z-FKsnG8eBIpC4GTfTVU",
      secretKey"a-valid-string-secret-that-is-at-least-384-bits-long",
      JwtHmacAlgorithm.HS384
    )

  lazy val HS384Jwk: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.owv7q9nVbW5tqUezF_G2nHTra-ANW3HqW9epyVwh08Y-Z-FKsnG8eBIpC4GTfTVU",
      secretKey(
        "kty" -> "oct".asJson,
        "k" -> "YS12YWxpZC1zdHJpbmctc2VjcmV0LXRoYXQtaXMtYXQtbGVhc3QtMzg0LWJpdHMtbG9uZw".asJson
      ),
      JwtHmacAlgorithm.HS384
    )

  lazy val HS512: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
      secretKey"a-valid-string-secret-that-is-at-least-512-bits-long-which-is-very-long",
      JwtHmacAlgorithm.HS512
    )

  lazy val HS512Jwk: ExampleHmacJwt =
    ExampleHmacJwt(
      JwtHeader(
        "alg" -> "HS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
      secretKey(
        "kty" -> "oct".asJson,
        "k" -> "YS12YWxpZC1zdHJpbmctc2VjcmV0LXRoYXQtaXMtYXQtbGVhc3QtNTEyLWJpdHMtbG9uZy13aGljaC1pcy12ZXJ5LWxvbmc".asJson
      ),
      JwtHmacAlgorithm.HS512
    )

  lazy val All: List[ExampleHmacJwt] =
    List(HS256, HS256Jwk, HS384, HS384Jwk, HS512, HS512Jwk)

  val exampleHmacJwtGen: Gen[ExampleHmacJwt] =
    Gen.oneOf(All)

  implicit val exampleHmacJwtArbitrary: Arbitrary[ExampleHmacJwt] =
    Arbitrary(exampleHmacJwtGen)

  implicit val exampleHmacJwtShow: Show[ExampleHmacJwt] =
    Show.fromToString

  private def secretKey(fields: (String, Json)*): SecretKey =
    Jwk(fields: _*).flatMap(_.toSecretKey).fold(throw _, identity)
}
