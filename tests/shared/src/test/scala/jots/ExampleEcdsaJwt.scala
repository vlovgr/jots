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

final case class ExampleEcdsaJwt(
  override val header: JwtHeader,
  override val claims: JwtClaims,
  override val signedJwt: SignedJwt,
  override val privateKey: PrivateKey,
  override val publicKey: PublicKey,
  override val algorithm: JwtEcdsaAlgorithm
) extends ExampleAsymmetricJwt {
  override val verification: IO[JwtVerification[IO]] =
    JwtVerification.default[IO].ecdsa(algorithm, publicKey)
}

object ExampleEcdsaJwt {
  lazy val ES256Jwk: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777719406.asJson
      ),
      signedJwt"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxOTQwNn0.EVAcDn9DhCdsNHfS8rstfJS2KWrQBoZQkMvLalPOGFGPTJrOLTWVT7oW4mS9kE1xwAzVCyQibUm4QdkQKcviVA",
      ExampleAsymmetricJwt.privateKey(
        "kty" -> "EC".asJson,
        "d" -> "sNdauBgjSH1WHTQiNkh9Wj4B1NEmUwUQhbVsvVcjbyw".asJson,
        "crv" -> "P-256".asJson,
        "x" -> "p9PE1rTE7gpF4uTVOtcx9W_6MnpGGg78q50ZA90wSPw".asJson,
        "y" -> "AEhWKMZsHgNPV7BHUCHab6gURnGfKfsCJJ6E5rlJwnc".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "EC".asJson,
        "crv" -> "P-256".asJson,
        "x" -> "p9PE1rTE7gpF4uTVOtcx9W_6MnpGGg78q50ZA90wSPw".asJson,
        "y" -> "AEhWKMZsHgNPV7BHUCHab6gURnGfKfsCJJ6E5rlJwnc".asJson
      ),
      JwtEcdsaAlgorithm.ES256
    )

  lazy val ES256Pkcs8: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
        OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
        1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
        q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        -----END PUBLIC KEY-----
      """,
      JwtEcdsaAlgorithm.ES256
    )

  lazy val ES256Sec1AndX509Certificate: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
      privateKey"""
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIHr2cy9YHQBa/PIW9jhf9jcQKSQsxghA3X0qelUDt9IcoAoGCCqGSM49
        AwEHoUQDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJ
        wqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        -----END EC PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIBvjCCAWSgAwIBAgIUA02+ctesTJ0HOM70SctAeQYjfRYwCgYIKoZIzj0EAwIw
        RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
        dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODAyMTNaFw0yNjA2MDQx
        ODAyMTNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
        VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnC
        qfMPWiZqB4QdbAd0E7oH50VpuZ1P087GozIwMDAdBgNVHQ4EFgQUmqhY86bNahvs
        dgzyEo2l01rEznQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA
        ztVK1oNnyBB40O4ANGZqqFI8mXbN1DRfs18i9bzqxLgCICCSPZ2t85mIVr2O40Yz
        VnaKr4ju6I+wQj3Hb8kjXvB4
        -----END CERTIFICATE-----
      """,
      JwtEcdsaAlgorithm.ES256
    )

  lazy val ES384Jwk: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777719572.asJson
      ),
      signedJwt"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxOTU3Mn0.uVoi-m1gttlMfQqOIaevVZa17I_aBGz7a8cn1A-ThE-DHRsOZjCcd1DYqwh_wYIfjtdYmM-R_7QyQ_GZYnShVfc08OCyxkjZhxdjPeCfDfF9wja2ou5GAC6OwdxgX5zN",
      ExampleAsymmetricJwt.privateKey(
        "kty" -> "EC".asJson,
        "d" -> "-3PPr5oOw8blT7XTmAccfUqmzLAB7hUNaa0wzilVagQf-7rIt8R3mQVLejH7vIT9".asJson,
        "crv" -> "P-384".asJson,
        "x" -> "R067CNQYLDplCpif64r604PNXHlomWY6Ki0B3NUosqTrcLSMg0BZQuMw1gZBE20t".asJson,
        "y" -> "cZSsvaFJdvLzf6k2IfQap5CIzqjWi53csqGDNZUKASBajAK8cDC9lQfl5bl2lwiX".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "EC".asJson,
        "crv" -> "P-384".asJson,
        "x" -> "R067CNQYLDplCpif64r604PNXHlomWY6Ki0B3NUosqTrcLSMg0BZQuMw1gZBE20t".asJson,
        "y" -> "cZSsvaFJdvLzf6k2IfQap5CIzqjWi53csqGDNZUKASBajAK8cDC9lQfl5bl2lwiX".asJson
      ),
      JwtEcdsaAlgorithm.ES384
    )

  lazy val ES384Sec1AndX509Certificate: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
      privateKey"""
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhske
        enT+rAyyPhGgBwYFK4EEACKhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+
        T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLU
        PeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
        -----END EC PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIB+jCCAYGgAwIBAgIUOMZZ3fCwXB7iH9jNK784VCWToHcwCgYIKoZIzj0EAwIw
        RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
        dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA0MjRaFw0yNjA2MDQx
        ODA0MjRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
        VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
        IgNiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GE
        tIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx8
        5ii2vMWjMjAwMB0GA1UdDgQWBBRIBAaWNI56zB3mhE3gxbtzM/hddzAPBgNVHRMB
        Af8EBTADAQH/MAoGCCqGSM49BAMCA2cAMGQCMHP8qtQn3ACDGFDAYGRlOyuk4Ztv
        YXIUuAykHaxaeBvbem+t5q5Tp6JgdQ5CLRz/iQIwegepjo3MC4aX1wJxoIU8bua0
        ymnTWAGj6KMYPE/jUf2uw3+NDrdAOThI1vsmG+9s
        -----END CERTIFICATE-----
      """,
      JwtEcdsaAlgorithm.ES384
    )

  lazy val ES384Pkcs8: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
        E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
        MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
        8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
        Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
        1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
        -----END PUBLIC KEY-----
      """,
      JwtEcdsaAlgorithm.ES384
    )

  lazy val ES512Jwk: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777719720.asJson
      ),
      signedJwt"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxOTcyMH0.AM-7eSflXleDnymAz8K5HJ2NGbAfv2OYStCdX9HqB-scZmOFfFiBe4hrdGu94dn2rXid881gte6t2_OhLQ3eaVExAO5LAnEEJ27-2Jh8MbM7G4_dvgPo3HvAMHtxn7zFr0GfP1qBKhJt-wMdoiKCll5kzoc5jZsR3PAGJn9yDKwcXqxx",
      ExampleAsymmetricJwt.privateKey(
        "kty" -> "EC".asJson,
        "d" -> "AVQ6ds0oCkRBc-Xct-b-3LAbPvg_RZDI1POtd8P_hULBWemOV84XPrF18uFjAmFPEs6xherQNmD_dVoea90yo1fC".asJson,
        "crv" -> "P-521".asJson,
        "x" -> "Aa0RijdnDNoooBlbP42Yl8v0bIOa8WXC7eNj-2ucukRPlaY_vWW7YRbQxHNSn-H-Q9hH4lhDM7iKKiDXYTZey3eA".asJson,
        "y" -> "AU2iBj8Dr_7DtzbvtjetYD_wDFgPq6cIjXAO_4nmPC0z94_z1LkUFDBnmGDeTpwO1jaulg1pOjgjzfZ7ZBiroYll".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "EC".asJson,
        "crv" -> "P-521".asJson,
        "x" -> "Aa0RijdnDNoooBlbP42Yl8v0bIOa8WXC7eNj-2ucukRPlaY_vWW7YRbQxHNSn-H-Q9hH4lhDM7iKKiDXYTZey3eA".asJson,
        "y" -> "AU2iBj8Dr_7DtzbvtjetYD_wDFgPq6cIjXAO_4nmPC0z94_z1LkUFDBnmGDeTpwO1jaulg1pOjgjzfZ7ZBiroYll".asJson
      ),
      JwtEcdsaAlgorithm.ES512
    )

  lazy val ES512Sec1AndX509Certificate: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777488635.asJson
      ),
      signedJwt"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzQ4ODYzNX0.AcoST856LERiwffqY4LKAK-HgTf-9n0QwWnBOanG4yv89zLIzVN6yLcpjbFsoS691sBGI-7M5YwWpuJ_CDy--_KHAB_aXfsNSoHkQLjrK573IgV-dLnRIqrG_gk72_PI9rSxAV2tBvOmFJj1eAWExtfYctopQNYZaMs86lq1uRAPxSHn",
      privateKey"""
        -----BEGIN EC PRIVATE KEY-----
        MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx
        0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn
        P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+
        duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv
        VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==
        -----END EC PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIICRTCCAaegAwIBAgIUBCs/PEOXJgcLlYyIQZaDRZ2j8gwwCgYIKoZIzj0EAwIw
        RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
        dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA1MDBaFw0yNjA2MDQx
        ODA1MDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
        VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZswEAYHKoZIzj0CAQYFK4EE
        ACMDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0l
        Rw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25
        pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12e6MyMDAw
        HQYDVR0OBBYEFGxBsve9A9/RL9prkrEb2LHcPbZVMA8GA1UdEwEB/wQFMAMBAf8w
        CgYIKoZIzj0EAwIDgYsAMIGHAkFLBTf/3agyv8tr7+qqUUv2JBhnaPb5MYVLTdJf
        64QK+V0Iq0Zyrtrw0FmYlh7YhZoS7bDk/1miGX64arfRpEZ6cgJCAWMz9iNlqaMx
        ql7w+gqazL1/vZBdqTyelXXvrIA120MoCMOE55xp5CSzGh3gk/TTAoFumohBg52s
        s4YrscdNUXNz
        -----END CERTIFICATE-----
      """,
      JwtEcdsaAlgorithm.ES512
    )

  lazy val ES512Pkcs8: ExampleEcdsaJwt =
    ExampleEcdsaJwt(
      JwtHeader(
        "alg" -> "ES512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777488635.asJson
      ),
      signedJwt"eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzQ4ODYzNX0.AcoST856LERiwffqY4LKAK-HgTf-9n0QwWnBOanG4yv89zLIzVN6yLcpjbFsoS691sBGI-7M5YwWpuJ_CDy--_KHAB_aXfsNSoHkQLjrK573IgV-dLnRIqrG_gk72_PI9rSxAV2tBvOmFJj1eAWExtfYctopQNYZaMs86lq1uRAPxSHn",
      privateKey"""
      -----BEGIN PRIVATE KEY-----
      MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
      9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
      Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
      v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
      jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
      ew==
      -----END PRIVATE KEY-----
    """,
      publicKey"""
      -----BEGIN PUBLIC KEY-----
      MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
      PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
      6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
      Al8G7CqwoJOsW7Kddns=
      -----END PUBLIC KEY-----
    """,
      JwtEcdsaAlgorithm.ES512
    )

  lazy val All: List[ExampleEcdsaJwt] =
    List(
      ES256Jwk,
      ES256Pkcs8,
      ES256Sec1AndX509Certificate,
      ES384Jwk,
      ES384Pkcs8,
      ES384Sec1AndX509Certificate,
      ES512Jwk,
      ES512Pkcs8,
      ES512Sec1AndX509Certificate
    )

  val exampleEcdsaJwtGen: Gen[ExampleEcdsaJwt] =
    Gen.oneOf(All)

  implicit val exampleEcdsaJwtArbitrary: Arbitrary[ExampleEcdsaJwt] =
    Arbitrary(exampleEcdsaJwtGen)

  implicit val exampleEcdsaJwtShow: Show[ExampleEcdsaJwt] =
    Show.fromToString
}
