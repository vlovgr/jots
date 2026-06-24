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
import io.circe.syntax.*
import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import jots.crypto.syntax.*
import jots.testing.syntax.*
import org.scalacheck.Arbitrary
import org.scalacheck.Gen

final case class ExampleEddsaJwt(
  override val header: JwtHeader,
  override val claims: JwtClaims,
  override val signedJwt: SignedJwt,
  override val privateKey: PrivateKey,
  override val publicKey: PublicKey,
  override val algorithm: JwtEddsaAlgorithm
) extends ExampleAsymmetricJwt {
  override val verification: IO[JwtVerification[IO]] =
    JwtVerification.default[IO].eddsa(algorithm, publicKey)
}

object ExampleEddsaJwt {
  lazy val Ed25519Pkcs8: ExampleEddsaJwt =
    ExampleEddsaJwt(
      JwtHeader(
        "alg" -> "Ed25519".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.IiFCYED1bkN9FL4H3UG884v2Wxmp_0SDfaaaRipa2N1QcjevsxA0WNRYnFMqPHf4tpNw93fL7PZs4az9kH0NBQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIFxEb2I7tPuKvihV4PgA55HDyMoVPHs2p0/nqJOBeuGG
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAwmK6SSAu2E9V7uynkCKEaj5nZJyTvNG4x0KohsRzLpg=
        -----END PUBLIC KEY-----
      """,
      JwtEddsaAlgorithm.Ed25519
    )

  lazy val EdDSAJwk: ExampleEddsaJwt =
    ExampleEddsaJwt(
      JwtHeader(
        "alg" -> "EdDSA".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777720149.asJson
      ),
      signedJwt"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcyMDE0OX0.TN5gnmvk1ztKPpgd-MDm65E7byPwxZcR_1xWsMQhBqil_q276svUB4FcOFDQbHJO1hRNwCkVw9a1QrWhxNxAAg",
      ExampleAsymmetricJwt.privateKey(
        "kty" -> "OKP".asJson,
        "d" -> "5h1NYZg7SoQgbivlpWgcleu6qdMsHNPCmMDWZVl3vX8".asJson,
        "crv" -> "Ed25519".asJson,
        "kid" -> "VCZXu7zoBvQNv7ijRyFjW7i2-wqoVOhyPjuBGDz-MY8".asJson,
        "x" -> "WOi-Abi-43CqPVHQx8eQ3KxQRhYx2BrYmTOPonrKhJ8".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "OKP".asJson,
        "crv" -> "Ed25519".asJson,
        "kid" -> "VCZXu7zoBvQNv7ijRyFjW7i2-wqoVOhyPjuBGDz-MY8".asJson,
        "x" -> "WOi-Abi-43CqPVHQx8eQ3KxQRhYx2BrYmTOPonrKhJ8".asJson
      ),
      JwtEddsaAlgorithm.Ed25519.asEdDSA
    )

  lazy val EdDSAPkcs8: ExampleEddsaJwt =
    ExampleEddsaJwt(
      JwtHeader(
        "alg" -> "EdDSA".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JkKWCY39IdWEQttmdqR7VdsvT-_QxheW_eb0S5wr_j83ltux_JDUIXs7a3Dtn3xuqzuhetiuJrWIvy5TzimeCg",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIFxEb2I7tPuKvihV4PgA55HDyMoVPHs2p0/nqJOBeuGG
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAwmK6SSAu2E9V7uynkCKEaj5nZJyTvNG4x0KohsRzLpg=
        -----END PUBLIC KEY-----
      """,
      JwtEddsaAlgorithm.Ed25519.asEdDSA
    )

  lazy val EdDSAPkcs8AndX509Certificate: ExampleEddsaJwt =
    ExampleEddsaJwt(
      JwtHeader(
        "alg" -> "EdDSA".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JkKWCY39IdWEQttmdqR7VdsvT-_QxheW_eb0S5wr_j83ltux_JDUIXs7a3Dtn3xuqzuhetiuJrWIvy5TzimeCg",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIFxEb2I7tPuKvihV4PgA55HDyMoVPHs2p0/nqJOBeuGG
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIBfjCCATCgAwIBAgIUFnH3GGsflOqh5rrurGfEeGbFF5IwBQYDK2VwMEUxCzAJ
        BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
        dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjYwNTA1MTgwNjMwWhcNMjYwNjA0MTgwNjMw
        WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
        SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMCowBQYDK2VwAyEAwmK6SSAu2E9V7uyn
        kCKEaj5nZJyTvNG4x0KohsRzLpijMjAwMB0GA1UdDgQWBBSVJJeQQBIjFJWvEfz4
        lejlFmweOzAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBADDB9YKzJk8OmRRTut2Q
        MW+4CCDU3Mu9YudDYzGW3OEXN4vIl4H2JtwmDnY20cWYLiLG5wMFBY17VICNQPR9
        +Ag=
        -----END CERTIFICATE-----
      """,
      JwtEddsaAlgorithm.Ed25519.asEdDSA
    )

  lazy val All: List[ExampleEddsaJwt] =
    List(Ed25519Pkcs8, EdDSAJwk, EdDSAPkcs8, EdDSAPkcs8AndX509Certificate)

  val exampleEddsaJwtGen: Gen[ExampleEddsaJwt] =
    Gen.oneOf(All)

  implicit val exampleEddsaJwtArbitrary: Arbitrary[ExampleEddsaJwt] =
    Arbitrary(exampleEddsaJwtGen)

  implicit val exampleEddsaJwtShow: Show[ExampleEddsaJwt] =
    Show.fromToString
}
