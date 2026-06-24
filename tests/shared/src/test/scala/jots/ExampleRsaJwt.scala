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

final case class ExampleRsaJwt(
  override val header: JwtHeader,
  override val claims: JwtClaims,
  override val signedJwt: SignedJwt,
  override val privateKey: PrivateKey,
  override val publicKey: PublicKey,
  override val algorithm: JwtRsaAlgorithm
) extends ExampleAsymmetricJwt {
  override val verification: IO[JwtVerification[IO]] =
    JwtVerification.default[IO].rsa(algorithm, publicKey)
}

object ExampleRsaJwt {
  lazy val RS256Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.M2OTFHEIPKAj1vHwBvv2OQ_0M802L5okfqCWhLNWAOG4_4Ft2WOJ7-2CkZKBvbpM0O3Mnb8pbXNiMpIk7XH3N2gixI2IOphpjttRyl5lYzGECrAmwOjlDZXeyrgE8dcpD-wxdPlgUfP06PDXLga0T8nwBTfIC8vQW-oItWIawhQCCSGXIYmolNBWLnXx0HUggYe_evFlm5SPY2cY7hOz5PmsmubgbIrTrbvBAK37sVBl6JbN8tQzbZp6rgfKxp6J5EYwPbtO7ypBCiYTyMcEJifBWfRjndSJhRjMFH0xilKvtEWEL40dwmbP_Arc4TliJrJF6BtoUUST_BOt0KrwMA",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "59yWs6Ym_cvAvY0dB4jdGMh7SZTPYsfQEb7-h4nrlpEuVTTf4f8rtbJ7UFyW1jGV_A2VbykX4IXBzPiX3X7_cs-Pf-cn3jjoLmpxODX5H8NnQ2-qvc_RovDs94c-Y-DF3ruyN-5zgMYcQzu4m9aZIcINLqcuIy1FB4brORY3trk".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "4x_yct4KnGWNC1Hfj-lSp3P-m6MaNct6AOe7ku4ZSK9t2kXkSshmvCtFKlXGCZbl0-PBzXHgKoZSi00XKYcbXh6Gyeo9zm_c2c6syAgvP1YXaXEi0o-gFT6UlreziyhMRzizzHUie0bgjK3WNkEqj819LN1vUYvkyDstBaXK05E".asJson,
        "d" -> "5lWeo8wUSQOyAvePwSMs-s32S__l92D4ZvId_G5xxWk5myXZ2SxovFTb0b_MlStV8u1Z6wUG-_Fm3u_nP8ECsDQiRLx-WPW1nxgd2JhNRNUuwJ7jgLO1fjU5bLutMMk9Tj8qCv19amiST0Q9t42lo7tDvOC_nkfwdCzGWe03EV649tCYZh3obu5EtjzkFoh7zGhmK91FtDtYXedoWXaycMNUCLePD9llHUD2wlX7QNFmDkXCRdKQTgHFLkQEMjfhiraHFT4Y8YSpO-jC7BMMAy3fxjxxnAK8JEobtE7j9-K--kyni__gDi4DTqI1mSspaipaxI5kHHuQQcnKCj_h".asJson,
        "e" -> "AQAB".asJson,
        "kid" -> "nThox+srn6aa8l9uiLQ/uxwUGnk=".asJson,
        "qi" -> "VLYLrBRyuc1gECRXtUc8Aa1ZVcxf_q74RpGXDGZgrFWSOONBtuFPUqhFPsKnCrEweBQFUfqpWk4ZV1b08-DDwGBkrEjr_Z23ysHoUVmRsuoRR2RZ-pa9Bf2shMq7XU4zznpKdF4qWcdhxgj-VSlXKE2fB2DcqWxjHj3VRDcHy8o".asJson,
        "dp" -> "lZBKuhnsvvxHGT7Ewg58KLdyJ9XRLTQdOMVOZNoH2TlPfPE9lgfHB07Zks4XEpYr3MpaYblNSKyfhfu54sxANaxEMcpHgmaNBxvsaskOKXofy3Vl20kKPqRRB577FOxyVyoWXVP4t9GTe58zh3sXjpohbL202kYiaCeU5l85kyk".asJson,
        "dq" -> "pP5bSXjmKnFXQgbrKodsJPuN1ZBqBPRZH_k3-WgAdB4E5pDpZC4q-71PVI7U-7hkI0aMTmvQVfQYWNva3K8qgXgZoOsKlUIMJSoPuIzBjfhDr7ShgGcX-vboSIkQ5CGVMBQQAZKCRx3ZGDlcqTMz8R1tNr9yE8JVo-PhM_4Z1xE".asJson,
        "n" -> "zbWI7hvhh8lTkgdjdo4Gn8DlnGNOP2NMS9YhyWMdKUPTXIsDb1f5fRyHWKUOinzeTXxcYmQQnVVSIW-REVUHfrICecnvX9R4AzflVUEacoXq_951A4Tx1xy6Uxt2k65mVstqZpLZ04X-llascCpMtXQl7aQAQ7ix16VKA8CPx7rfx-wckiL2RM6zm_eMWbFx2jrucXBEG1pe6y4uKgclc6iG0dZA2t6hWF62dHjz9PVRGkMzRLnUDt3M2iUW4vLUpTTwMbu_2Q3pPELWErJpzgI2l-_rPT5RZRFXOhepWsQbNIRpFHaF_ZYf9v7fKQaYDGqrqBRr5b-8gM_97CL5yQ".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "kid" -> "nThox+srn6aa8l9uiLQ/uxwUGnk=".asJson,
        "n" -> "zbWI7hvhh8lTkgdjdo4Gn8DlnGNOP2NMS9YhyWMdKUPTXIsDb1f5fRyHWKUOinzeTXxcYmQQnVVSIW-REVUHfrICecnvX9R4AzflVUEacoXq_951A4Tx1xy6Uxt2k65mVstqZpLZ04X-llascCpMtXQl7aQAQ7ix16VKA8CPx7rfx-wckiL2RM6zm_eMWbFx2jrucXBEG1pe6y4uKgclc6iG0dZA2t6hWF62dHjz9PVRGkMzRLnUDt3M2iUW4vLUpTTwMbu_2Q3pPELWErJpzgI2l-_rPT5RZRFXOhepWsQbNIRpFHaF_ZYf9v7fKQaYDGqrqBRr5b-8gM_97CL5yQ".asJson
      ),
      JwtRsaAlgorithm.RS256
    )

  lazy val RS256Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.M2OTFHEIPKAj1vHwBvv2OQ_0M802L5okfqCWhLNWAOG4_4Ft2WOJ7-2CkZKBvbpM0O3Mnb8pbXNiMpIk7XH3N2gixI2IOphpjttRyl5lYzGECrAmwOjlDZXeyrgE8dcpD-wxdPlgUfP06PDXLga0T8nwBTfIC8vQW-oItWIawhQCCSGXIYmolNBWLnXx0HUggYe_evFlm5SPY2cY7hOz5PmsmubgbIrTrbvBAK37sVBl6JbN8tQzbZp6rgfKxp6J5EYwPbtO7ypBCiYTyMcEJifBWfRjndSJhRjMFH0xilKvtEWEL40dwmbP_Arc4TliJrJF6BtoUUST_BOt0KrwMA",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAzbWI7hvhh8lTkgdjdo4Gn8DlnGNOP2NMS9YhyWMdKUPTXIsD
        b1f5fRyHWKUOinzeTXxcYmQQnVVSIW+REVUHfrICecnvX9R4AzflVUEacoXq/951
        A4Tx1xy6Uxt2k65mVstqZpLZ04X+llascCpMtXQl7aQAQ7ix16VKA8CPx7rfx+wc
        kiL2RM6zm/eMWbFx2jrucXBEG1pe6y4uKgclc6iG0dZA2t6hWF62dHjz9PVRGkMz
        RLnUDt3M2iUW4vLUpTTwMbu/2Q3pPELWErJpzgI2l+/rPT5RZRFXOhepWsQbNIRp
        FHaF/ZYf9v7fKQaYDGqrqBRr5b+8gM/97CL5yQIDAQABAoIBAADmVZ6jzBRJA7IC
        94/BIyz6zfZL/+X3YPhm8h38bnHFaTmbJdnZLGi8VNvRv8yVK1Xy7VnrBQb78Wbe
        7+c/wQKwNCJEvH5Y9bWfGB3YmE1E1S7AnuOAs7V+NTlsu60wyT1OPyoK/X1qaJJP
        RD23jaWju0O84L+eR/B0LMZZ7TcRXrj20JhmHehu7kS2POQWiHvMaGYr3UW0O1hd
        52hZdrJww1QIt48P2WUdQPbCVftA0WYORcJF0pBOAcUuRAQyN+GKtocVPhjxhKk7
        6MLsEwwDLd/GPHGcArwkShu0TuP34r76TKeL/+AOLgNOojWZKylqKlrEjmQce5BB
        ycoKP+ECgYEA59yWs6Ym/cvAvY0dB4jdGMh7SZTPYsfQEb7+h4nrlpEuVTTf4f8r
        tbJ7UFyW1jGV/A2VbykX4IXBzPiX3X7/cs+Pf+cn3jjoLmpxODX5H8NnQ2+qvc/R
        ovDs94c+Y+DF3ruyN+5zgMYcQzu4m9aZIcINLqcuIy1FB4brORY3trkCgYEA4x/y
        ct4KnGWNC1Hfj+lSp3P+m6MaNct6AOe7ku4ZSK9t2kXkSshmvCtFKlXGCZbl0+PB
        zXHgKoZSi00XKYcbXh6Gyeo9zm/c2c6syAgvP1YXaXEi0o+gFT6UlreziyhMRziz
        zHUie0bgjK3WNkEqj819LN1vUYvkyDstBaXK05ECgYEAlZBKuhnsvvxHGT7Ewg58
        KLdyJ9XRLTQdOMVOZNoH2TlPfPE9lgfHB07Zks4XEpYr3MpaYblNSKyfhfu54sxA
        NaxEMcpHgmaNBxvsaskOKXofy3Vl20kKPqRRB577FOxyVyoWXVP4t9GTe58zh3sX
        jpohbL202kYiaCeU5l85kykCgYEApP5bSXjmKnFXQgbrKodsJPuN1ZBqBPRZH/k3
        +WgAdB4E5pDpZC4q+71PVI7U+7hkI0aMTmvQVfQYWNva3K8qgXgZoOsKlUIMJSoP
        uIzBjfhDr7ShgGcX+vboSIkQ5CGVMBQQAZKCRx3ZGDlcqTMz8R1tNr9yE8JVo+Ph
        M/4Z1xECgYBUtgusFHK5zWAQJFe1RzwBrVlVzF/+rvhGkZcMZmCsVZI440G24U9S
        qEU+wqcKsTB4FAVR+qlaThlXVvTz4MPAYGSsSOv9nbfKwehRWZGy6hFHZFn6lr0F
        /ayEyrtdTjPOekp0XipZx2HGCP5VKVcoTZ8HYNypbGMePdVENwfLyg==
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAzbWI7hvhh8lTkgdjdo4Gn8DlnGNOP2NMS9YhyWMdKUPTXIsDb1f5
        fRyHWKUOinzeTXxcYmQQnVVSIW+REVUHfrICecnvX9R4AzflVUEacoXq/951A4Tx
        1xy6Uxt2k65mVstqZpLZ04X+llascCpMtXQl7aQAQ7ix16VKA8CPx7rfx+wckiL2
        RM6zm/eMWbFx2jrucXBEG1pe6y4uKgclc6iG0dZA2t6hWF62dHjz9PVRGkMzRLnU
        Dt3M2iUW4vLUpTTwMbu/2Q3pPELWErJpzgI2l+/rPT5RZRFXOhepWsQbNIRpFHaF
        /ZYf9v7fKQaYDGqrqBRr5b+8gM/97CL5yQIDAQAB
        -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS256
    )

  lazy val RS256Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS256
    )

  lazy val RS256Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.RS256
    )

  lazy val RS384Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777717975.asJson
      ),
      signedJwt"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxNzk3NX0.UcXZ1tcS4gmJySP9D-ta3SzgsFj1ow-P3vdRrA-mgSnwrTlmqvmHvnF3NF1KuYItxVIa8pksQgJfX8-_ANBCUQ1ggmSwOoMaAY-T_7jhvLqF5cQMKelowntfwhzCOf5GSW9AxX53n8eKxqqVkec063kmx2rI_CZor3kw2Dr_43nrxVDYvjAuWDZsgrEkgVNEVIlEcqhZHJoAxBukYQpwAclryeSUWaAFKZ0xQhNKfjnw-Nq8-nV6zwZWREoxx28UpjTIXLcW69DuCftq7Zk6kKOC_0PP9JybNLfUXhjqRGIqF0pexw_03gRvmpzkkb9leFuwu8rnyNe6K9jUjkjBLHopgqkOK-B-mJhzc69_x0iEeFjfAONYetD7tQ3BDEbGPhHBj4WSy6Cg6QVv-XS5sQcOQmvSR-e9WVOhxlloghEI9Y0w2KJuSo0Y8mi0x44r2nof537x8P9PtdiAr2uufji2LtMsdwM8fPJ3FVkD16q0KAHhXjzIEuO4UJbNjji9R7OtZzeHynG-Rz0u8Hj12CxbNvWUrKK3bGOlCBCbGq2kNR3Ysr4q_DT1jQ8jz79SAanBfL-rrJtLD13ROrgGlTAQiwMDsopf906yiFfYphFKWSXQ-HO1sR1PeiuNLdrIV5bOzgfvudhlNlZq_whof9iyoS4BOwzXRDXZ88UMi-4",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "3SQBPwxh7BX3FoKv42SQd5ZOU8tNzNG1JR_AyeIZX4VdpzMYZqaOnJz-Q6LYjl4cbxntDwg_CNtbMAT73P11DupP8w82jZRLY9LZmk98ETiokbfrGpdMk-AzLK4tO1G5EajYGbXxVH0MNtbwr2e3hF6KOYQlA-HHT4naO0HvSwTkttNfHu1wMK8mR5oa6KiNQDbMV0hnBASqUEJwF8AnY5io2ePl4syZ88x_jz0kc8au3gwRm5iLqJtrtXvNufaNCVGlf76qhLrVEg6N8iHTr9f8SF6luY6OkQfvhnkZ_-kKS2qGIVYu_6wRhvLW7kYEZXz7EhzVTwLxhFYppZwOkw".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "1jtnteITp-AvLprrmXTlUDynGVtOQfn6seMEt1jfAndiuOmcVmmoEpmrZXe4iE4ASf3q6YiTglSIxoUu8D7334YHyigowevsWH5WXbRuccfMBkKoASrE6AqhaHAy0giAjkyviMvrquN1JRtn9G0lZH1Ml_VtljY7HmUTE94ayXm7SxcA4muL9HHBOfStN7zswVDC8hNIwdIV72yhvdXL89Qm99n7z3dC_RjN0cXuzp07-wvMGe8cVZrZtovoH5FXU954MRM7nx_vtQaE44cXaoqxAJ-3jVxTX4TQXlXzR33GSZaEpUg_TiN5ENXe-PXcgsjKdlgaeIXBwn4-MX8htw".asJson,
        "d" -> "D2QuIIn77rdqoDn8fVQy1BhlrG9-x8aF9qND5Nt7z9J8PlboNWombzFyIKpQpPUYAiJA5KbwJxUG_0QgDidz_ozvi3NDat1dJXTkwRE3VkXpA5ov_q-R9Qbce-yWl8MPTi2M0TdMAdurZ5bn5ZJ_6wltxJ_9U4mRcsEPJMnJ-L1t3p45YO6Md60wNiIzB6ZSlQTVxOOh6ufDC4GRKN60qtKMB8mDHLzLf3N7P70YTjs5EKDCuzyGzAKkQPI-xtXK95HYgoxXhbjaUFHcyuWOcoh5hnZBunh6eN2EyQfmEP96gupIuLIPhd4dGxDXkQ_uD2wej5apfIdjJvCVVlfyi8WhdSyCDTfVyOgnp-QGzRaVoIesLgTtlfcMxubDlhheW60Cx90v6-Lurh7iGVNVIaF_HKtD7E46z68f22TllqeGgkTVkHkCZA5xswI5rBk4QKmpEqHI56giKwUR5XSnz9j8ol3nt45s6TZfZj5cK-xcUXyGpMHCgdGo3RVXBOj4LKE9vN8Xi_F3oSEC3Evv0MvawyKy4XaG8yNnwJrG4RUNEmc0LJ7IDNJEuDSQ5uXIU5T65dylE8NpNAFmpc9bz4ILvXVzhAzQAa0uJyjoUvMjIQoIzFJbz1ZgPF47FZvqxjt00xyL1V1QjR_rIM_2cXe3WdlcVMcKOHOxbF7uF4E".asJson,
        "e" -> "AQAB".asJson,
        "kid" -> "rXsmICLsKAZBCPI6mCq2-u7uhNn8LmxwvYBCYJJISjs".asJson,
        "qi" -> "O-mWi-N4eyjKAimGZYLWEz-cjzeITkgNRO6qdYPNTrNojvFgZ8_opa1500X6uT-PcNg9oAB0cumSLL2gElQmvsV9qiHuzoNxJ1fQznx6xx3Gg_slQWJ6x6BDXpEB2mNUxcuS8ts815E2uV42a9K4HDHx-C7BpcVhocpsMzYuWh5OyuFZiOBNmVHZOIV403T1W7lLetbZbIjJR9qGjMrGV5p23cNfllTmTQdKDU5wxUq-ZS11r3_EWQ3gffenz_poKdZP_y8JpQOj0BEpFswPnuz97Ew3XqrfkatyEIqj6T5jFpLGKQvTU6LwbqKMhkvMhEQeQ6XKCumLm_7YrQ4CQg".asJson,
        "dp" -> "CaaEl2fG7jKXMdhKLLY6x707ddStdH7CVPhpxWWkjdKYH6_PJMun9ZW0UudMZAofW4naGonVlmFcPWA6TY6SCTCYhJbpXoxWLekJrf5B_85lLNbF38cyhFGIai6_spMCbI7dv2F9Qp6iZdJDdqQkEha-GXx20RCNTh9J8sQR2UhBYukegY8DElzSYtWKzxRr9Z1ulXCHbll1xULg-WhdT69dzwRvB9K99TG7b1jPum21O-Ny8UNa9OSzcpwQgkkMJpf1jPmZH2m32q3f6-0l-8qFK_NVcB-UgSfDgC7Qv6Y_2MKxT8sfCfFMYoM-de-ASZ2Gp2eyt1v9hjTsZFnHGQ".asJson,
        "dq" -> "xiVb31ajZ3prKWgQ0XbVQklXJJTW5R8ZSL749bw1SEqz_OPVvfcrhUisxsTc4PWEPuukAyxXgww9FaDJsVwMV6nYOpq6V-KmT5NKvpDMNmDdzEyKp8mvJg_vCnH8D1fdz8AN-zDhYMXQ6-lVVTY-h5t85HAUVAME2zARXSbpD8CQAvvbzZA7enRcjAZK0GrlcEgKh2xetyZhM3n-f17nrTZkdIoh5dohE4eFlqjEIEY93A0lUjdeta7r_3OX1trPMrtp37oyQxN-2qiU8P1aIyj0XedcFlt2obpuH1LQGSez5wxY06bnJpaYu4GVIiAFPNIKsTr8AM12UTYCwDUeMQ".asJson,
        "n" -> "uQ9p7ZghuUTShPnVgomGptoiSyOYY3FdjLUY7e9_x49YdiDfA139LrXqzryuDkwBl4bnxsFaVWjdYjaTJOyQEBMyvgCywurVjJ7J7H3jy8TZ3xX2JY2OfmkGpL890x1jgJqROc5F0MSBZ8-hppAJ52PblnBPkhvJuLp0ACtGwbmsJqRyLvacGMA-x0COPU7iOTWcQtI6y9oUcXAQBUEC89B6eT8iXCz5T5uOLbr-Bu3OdXCgoEc8BHN86YK-C_zUCl7wbPCxMV0vBZTnzQKxec_4r5Us3yoQWEwJ04H2JdV01yUeMtrQByc3ScxFubbQ4Kp9CwQu_clg3FsA04kvRfegSw2Re823D6ESVmZ-lbhr1z2nYL5uxBjEjc_gJUflJRrnlKylbi00dTGhdwrTrBBMXDc3QJwNudi1vtBJvjRxTcBW7sYd41wmK-USnb9S1F7S0r3dkIfmuF3dvgr4PqwRXcwPpW1NE0xR38yGMPlG8ol3IMYFI_CwfwJq6oSTrbnCtYYQXEFZ4ycRaSJ32_6Qx8cixUF5hZ6hOwiJO0qQOvqhQUWFiQLAuMYi7L9ZFc5AM_stv_AKyKzn_ITxC1bz-a0bvRNDJtZaqbXSzlWJMqmkvLyHRHwNYSMHl6CYAvj3tOwkiEiT6g0mbYgjZdSlyFJkEQCZNW7e7d5cXhU".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "kid" -> "rXsmICLsKAZBCPI6mCq2-u7uhNn8LmxwvYBCYJJISjs".asJson,
        "n" -> "uQ9p7ZghuUTShPnVgomGptoiSyOYY3FdjLUY7e9_x49YdiDfA139LrXqzryuDkwBl4bnxsFaVWjdYjaTJOyQEBMyvgCywurVjJ7J7H3jy8TZ3xX2JY2OfmkGpL890x1jgJqROc5F0MSBZ8-hppAJ52PblnBPkhvJuLp0ACtGwbmsJqRyLvacGMA-x0COPU7iOTWcQtI6y9oUcXAQBUEC89B6eT8iXCz5T5uOLbr-Bu3OdXCgoEc8BHN86YK-C_zUCl7wbPCxMV0vBZTnzQKxec_4r5Us3yoQWEwJ04H2JdV01yUeMtrQByc3ScxFubbQ4Kp9CwQu_clg3FsA04kvRfegSw2Re823D6ESVmZ-lbhr1z2nYL5uxBjEjc_gJUflJRrnlKylbi00dTGhdwrTrBBMXDc3QJwNudi1vtBJvjRxTcBW7sYd41wmK-USnb9S1F7S0r3dkIfmuF3dvgr4PqwRXcwPpW1NE0xR38yGMPlG8ol3IMYFI_CwfwJq6oSTrbnCtYYQXEFZ4ycRaSJ32_6Qx8cixUF5hZ6hOwiJO0qQOvqhQUWFiQLAuMYi7L9ZFc5AM_stv_AKyKzn_ITxC1bz-a0bvRNDJtZaqbXSzlWJMqmkvLyHRHwNYSMHl6CYAvj3tOwkiEiT6g0mbYgjZdSlyFJkEQCZNW7e7d5cXhU".asJson
      ),
      JwtRsaAlgorithm.RS384
    )

  lazy val RS384Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777717975.asJson
      ),
      signedJwt"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxNzk3NX0.UcXZ1tcS4gmJySP9D-ta3SzgsFj1ow-P3vdRrA-mgSnwrTlmqvmHvnF3NF1KuYItxVIa8pksQgJfX8-_ANBCUQ1ggmSwOoMaAY-T_7jhvLqF5cQMKelowntfwhzCOf5GSW9AxX53n8eKxqqVkec063kmx2rI_CZor3kw2Dr_43nrxVDYvjAuWDZsgrEkgVNEVIlEcqhZHJoAxBukYQpwAclryeSUWaAFKZ0xQhNKfjnw-Nq8-nV6zwZWREoxx28UpjTIXLcW69DuCftq7Zk6kKOC_0PP9JybNLfUXhjqRGIqF0pexw_03gRvmpzkkb9leFuwu8rnyNe6K9jUjkjBLHopgqkOK-B-mJhzc69_x0iEeFjfAONYetD7tQ3BDEbGPhHBj4WSy6Cg6QVv-XS5sQcOQmvSR-e9WVOhxlloghEI9Y0w2KJuSo0Y8mi0x44r2nof537x8P9PtdiAr2uufji2LtMsdwM8fPJ3FVkD16q0KAHhXjzIEuO4UJbNjji9R7OtZzeHynG-Rz0u8Hj12CxbNvWUrKK3bGOlCBCbGq2kNR3Ysr4q_DT1jQ8jz79SAanBfL-rrJtLD13ROrgGlTAQiwMDsopf906yiFfYphFKWSXQ-HO1sR1PeiuNLdrIV5bOzgfvudhlNlZq_whof9iyoS4BOwzXRDXZ88UMi-4",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN RSA PUBLIC KEY-----
        MIICCgKCAgEAuQ9p7ZghuUTShPnVgomGptoiSyOYY3FdjLUY7e9/x49YdiDfA139
        LrXqzryuDkwBl4bnxsFaVWjdYjaTJOyQEBMyvgCywurVjJ7J7H3jy8TZ3xX2JY2O
        fmkGpL890x1jgJqROc5F0MSBZ8+hppAJ52PblnBPkhvJuLp0ACtGwbmsJqRyLvac
        GMA+x0COPU7iOTWcQtI6y9oUcXAQBUEC89B6eT8iXCz5T5uOLbr+Bu3OdXCgoEc8
        BHN86YK+C/zUCl7wbPCxMV0vBZTnzQKxec/4r5Us3yoQWEwJ04H2JdV01yUeMtrQ
        Byc3ScxFubbQ4Kp9CwQu/clg3FsA04kvRfegSw2Re823D6ESVmZ+lbhr1z2nYL5u
        xBjEjc/gJUflJRrnlKylbi00dTGhdwrTrBBMXDc3QJwNudi1vtBJvjRxTcBW7sYd
        41wmK+USnb9S1F7S0r3dkIfmuF3dvgr4PqwRXcwPpW1NE0xR38yGMPlG8ol3IMYF
        I/CwfwJq6oSTrbnCtYYQXEFZ4ycRaSJ32/6Qx8cixUF5hZ6hOwiJO0qQOvqhQUWF
        iQLAuMYi7L9ZFc5AM/stv/AKyKzn/ITxC1bz+a0bvRNDJtZaqbXSzlWJMqmkvLyH
        RHwNYSMHl6CYAvj3tOwkiEiT6g0mbYgjZdSlyFJkEQCZNW7e7d5cXhUCAwEAAQ==
        -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS384
    )

  lazy val RS384Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS384
    )

  lazy val RS384Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.RS384
    )

  lazy val RS512Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718174.asJson
      ),
      signedJwt"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODE3NH0.Aa3Ap-jBWd17NDJUJzPfvRYfScsOtIlglUZWAy63PcJPj-1K0IudFs8FcPpi_ibkkP7qlhW_rAKR0H9Pjr7BQtWSDHuI7mL3ANOYx-ZM41Rx2y4togMTaj1o-VUjzGK1fsYZ_AlN5PROlkhqGfbqLF7ib_aq8PDsDV09YyhYYVlq18tsXwvziCIh_F7oVel7tBIb4k133pk8EmYk3xm-o8mGN_Rg9A0Q7xQX90kyYv8vMOuB6waYOgY5ffUJ00g_LLHY-ApocHZKkzCCl24MwJaEgP22H5ysGtviyeWXA6cFmBcTebWUfGEaEt5adO7NESafKeCmtsKihRxyW2oFig",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "5rPwnOpWocuxIX82BBuLh72YLhvehLxI8b8HEKOyRQBsS3hs9nlFz7YyVeSiebTSHl-z_GRsB3Gz9cv_1TNb2BCC1UyGU1_GYRtMC11itYgjYBlD-I-OsEDOkF74t6AaNC388SQqT0dP1nkig8qoIsvHTyBE-o2lBju3KIfOVo0".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "2bXBdy4QylVJ7A_g2FTTwtBzOgiO1bXCzsplBWbcKhB0Sj2UCQk2a34sM2ocW_NMoIuuFH7bYQqrVvLSmDq7jbEzaw-TUvNAKsIj_7ps9XRdAbLrNB_Hkqbd48oEBqmVm7f5VlDZPKRqz0pv44SCP2XY9_xcKGH7lrq7ED-CjMk".asJson,
        "d" -> "LMVsAkhDJkj9EENGzZUWrLZR6mDswSxmDEtb9FqqTsnXkYJJrf4fNw8CeFXCHCFj3ijMrLEpLsoFxYxHs93K1BsTiSKDLNRh3eC23neIzuo-6-c6lwyj-MPGvbxk5Z-WLmudnwgnXKkFsd6Nq6T81c9BElBNpKcG96gnGlFqt8EL_96GtBohqYqE_nSTyn2BCgs9l1kBZRxxZK0C2ipJqOgUmMPhGVQSPVGnz5L5JN_Skq61jvJoJyCf0FMDvIadRk1X6volc7P5dajc5FC_SYqrNEOWhozIfjeQMNtH1ql3UMspCmQtA5fl60Z5PIUz_j1bcD6UPcy83GUG_anCeQ".asJson,
        "e" -> "AQAB".asJson,
        "qi" -> "cm6468in5_O5VMvdOA5VYxtzRosI_kzraoOQzDL-rx98pKZ9OypPuH5mZyEIMBn6pBUFwjoo16HxrBvUd2SqcWt_7ofatTbwi2XPK4ITmcgK9nRd2mauvXmFvUyE37XcMmqrKWyAfwbADYz79mvI8izEWnUt3sUQLvhMN3550Xo".asJson,
        "dp" -> "unQ9iCShBbzhmOf-WQ2GFJv37XQawH6IGdHBPQKAJuJzo_9dWUqkUH65adASPHkWxPOmPNtQsCeGQaaxSrdqiFK32voxKhsi8wKj0B-Wko7HwHhLBg3ITczi5a3MKGReKUPtxVrsUwyYiwd2DLvybcTyfZHgDfwCnuoOWtR_wFU".asJson,
        "dq" -> "jJWh6KQGk6GfqqBWQVwForeYsND162sD8SUhNuvFICSf85DwFyWrzp4bTNgol_f0c3e_YdzJLVEGc486DrNeiZDz8x6Ls_UAapwTQv_PfHE33fD7kR00cq7uejnpf6PiyDt09xgeL9q8Xj9jIThgIzBRe1Gq8SjUnfDW-xcH5oE".asJson,
        "n" -> "xDJShzEjutRgjF8J7h5hO9-bXBPtZQtZO9imjPdyvC-2looZvcbSXxn2vJTYqEI-39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6_X29NVTb2yulhl0Nnj63gnTX9CGt4TaB1k9X7bYdYl1C4DKTP-PEiIsa_Nq8CFoRYRltFtoyO5Hvob7R_VhR3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q-9oQ-bHCZcbwPW3wPLkvb5TfK3Nygb_N-JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR-1qe6iQQconbgg5HuFlNAeEicTZ3ruEBYzO_0_nh78HvEQtQ".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "n" -> "xDJShzEjutRgjF8J7h5hO9-bXBPtZQtZO9imjPdyvC-2looZvcbSXxn2vJTYqEI-39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6_X29NVTb2yulhl0Nnj63gnTX9CGt4TaB1k9X7bYdYl1C4DKTP-PEiIsa_Nq8CFoRYRltFtoyO5Hvob7R_VhR3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q-9oQ-bHCZcbwPW3wPLkvb5TfK3Nygb_N-JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR-1qe6iQQconbgg5HuFlNAeEicTZ3ruEBYzO_0_nh78HvEQtQ".asJson
      ),
      JwtRsaAlgorithm.RS512
    )

  lazy val RS512Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718174.asJson
      ),
      signedJwt"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODE3NH0.Aa3Ap-jBWd17NDJUJzPfvRYfScsOtIlglUZWAy63PcJPj-1K0IudFs8FcPpi_ibkkP7qlhW_rAKR0H9Pjr7BQtWSDHuI7mL3ANOYx-ZM41Rx2y4togMTaj1o-VUjzGK1fsYZ_AlN5PROlkhqGfbqLF7ib_aq8PDsDV09YyhYYVlq18tsXwvziCIh_F7oVel7tBIb4k133pk8EmYk3xm-o8mGN_Rg9A0Q7xQX90kyYv8vMOuB6waYOgY5ffUJ00g_LLHY-ApocHZKkzCCl24MwJaEgP22H5ysGtviyeWXA6cFmBcTebWUfGEaEt5adO7NESafKeCmtsKihRxyW2oFig",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAxDJShzEjutRgjF8J7h5hO9+bXBPtZQtZO9imjPdyvC+2looZ
        vcbSXxn2vJTYqEI+39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6/X29NVTb2yulhl0
        Nnj63gnTX9CGt4TaB1k9X7bYdYl1C4DKTP+PEiIsa/Nq8CFoRYRltFtoyO5Hvob7
        R/VhR3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q+9oQ+bHCZcbwPW3wPLkvb5T
        fK3Nygb/N+JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR+1qe6iQQco
        nbgg5HuFlNAeEicTZ3ruEBYzO/0/nh78HvEQtQIDAQABAoIBACzFbAJIQyZI/RBD
        Rs2VFqy2Uepg7MEsZgxLW/Raqk7J15GCSa3+HzcPAnhVwhwhY94ozKyxKS7KBcWM
        R7PdytQbE4kigyzUYd3gtt53iM7qPuvnOpcMo/jDxr28ZOWfli5rnZ8IJ1ypBbHe
        jauk/NXPQRJQTaSnBveoJxpRarfBC//ehrQaIamKhP50k8p9gQoLPZdZAWUccWSt
        AtoqSajoFJjD4RlUEj1Rp8+S+STf0pKutY7yaCcgn9BTA7yGnUZNV+r6JXOz+XWo
        3ORQv0mKqzRDloaMyH43kDDbR9apd1DLKQpkLQOX5etGeTyFM/49W3A+lD3MvNxl
        Bv2pwnkCgYEA5rPwnOpWocuxIX82BBuLh72YLhvehLxI8b8HEKOyRQBsS3hs9nlF
        z7YyVeSiebTSHl+z/GRsB3Gz9cv/1TNb2BCC1UyGU1/GYRtMC11itYgjYBlD+I+O
        sEDOkF74t6AaNC388SQqT0dP1nkig8qoIsvHTyBE+o2lBju3KIfOVo0CgYEA2bXB
        dy4QylVJ7A/g2FTTwtBzOgiO1bXCzsplBWbcKhB0Sj2UCQk2a34sM2ocW/NMoIuu
        FH7bYQqrVvLSmDq7jbEzaw+TUvNAKsIj/7ps9XRdAbLrNB/Hkqbd48oEBqmVm7f5
        VlDZPKRqz0pv44SCP2XY9/xcKGH7lrq7ED+CjMkCgYEAunQ9iCShBbzhmOf+WQ2G
        FJv37XQawH6IGdHBPQKAJuJzo/9dWUqkUH65adASPHkWxPOmPNtQsCeGQaaxSrdq
        iFK32voxKhsi8wKj0B+Wko7HwHhLBg3ITczi5a3MKGReKUPtxVrsUwyYiwd2DLvy
        bcTyfZHgDfwCnuoOWtR/wFUCgYEAjJWh6KQGk6GfqqBWQVwForeYsND162sD8SUh
        NuvFICSf85DwFyWrzp4bTNgol/f0c3e/YdzJLVEGc486DrNeiZDz8x6Ls/UAapwT
        Qv/PfHE33fD7kR00cq7uejnpf6PiyDt09xgeL9q8Xj9jIThgIzBRe1Gq8SjUnfDW
        +xcH5oECgYBybrjryKfn87lUy904DlVjG3NGiwj+TOtqg5DMMv6vH3ykpn07Kk+4
        fmZnIQgwGfqkFQXCOijXofGsG9R3ZKpxa3/uh9q1NvCLZc8rghOZyAr2dF3aZq69
        eYW9TITftdwyaqspbIB/BsANjPv2a8jyLMRadS3exRAu+Ew3fnnReg==
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxDJShzEjutRgjF8J7h5hO9+bXBPtZQtZO9imjPdyvC+2looZvcbS
        Xxn2vJTYqEI+39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6/X29NVTb2yulhl0Nnj6
        3gnTX9CGt4TaB1k9X7bYdYl1C4DKTP+PEiIsa/Nq8CFoRYRltFtoyO5Hvob7R/Vh
        R3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q+9oQ+bHCZcbwPW3wPLkvb5TfK3N
        ygb/N+JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR+1qe6iQQconbgg
        5HuFlNAeEicTZ3ruEBYzO/0/nh78HvEQtQIDAQAB
        -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS512
    )

  lazy val RS512Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.RS512
    )

  lazy val RS512Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "RS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.RS512
    )

  lazy val PS256Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718393.asJson
      ),
      signedJwt"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODM5M30.WRXfVDvQ5kl1i_ZcrGwvBS0PXlWvwHf6sqTHpo-taWGeXpkIOGrpMUcZ9nyMG2ZVI360e0pdS9vRlT01MY40bt3--yY0B19c1vLOFxWG4yBJ-eRCxc9ZYYIP72OIOqy1hio1aTnbTDPfyxaUU_P4vZ07C8o8PMJ6ZiAMzWrRXykWIMEHn4Od9qzrph3_NEaAt3Dfu9rx-iYLm_dfJj-aiqTxOTA09ZRXkyOTSuN-pxe_IK7LSolvd19eBGE2VM-fn6R1jbdotBvDUEuZr-OkoVJUUxBgipg75SY7s5uNssOhujoxJYAT322LbB6cqH_b52UQ7alymw4SRDyBw1CKDP8oCOBhj2R4x4kpAR4LFY8yTStHIBIyIGFY_yoQtwaP8IjlhnUV-Z8V8-BmXJ38d5qfcnpELuT9EvWDFHyGyTMcg9LuavRcDdaLoMTVJkt89SfOTyBiU1bu83V3cvJVgFHn6J0TRoKDyHV3GJRNbOxcrGTNNmGBBuKPQEfYP84r",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "uoFLCQhD-RMFotVmZzlvA71jLaVxzsKNo_a6gNjBoFXc1bPT79Zc11C_podOKSXAPLtNTSVYTWR6r8khOQJkBe54P5WYQCeR5WsBVQJ_hHPxXJKVGepQbSW82DSk-fupfp5SxEsZfq6JyvI3j8NZtmiY--FhaJMQmCW9MyaIlspfKfU6wUHEsMMRVWQGLCVhoYjQyWcBCHn2XJziOPSuqT6Q3DC6kv1iEGdUFEORPZVVRjaDNRDI1AKXiQPHB0Nv".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "tsPaWZnHRglD1LT6zE7eKWOoSpBuwcCiFV6M-b3A_uyU-APe_VrVVFjm8_kmt6TUnJXSEYxrmBQRJxujD3iRZVpsQA8pGOwn5S2mZDW4VfVIfuWL0noXV2tCTLEo9wbn0atYmbmqaVAzSrIQl1s6oJ4lVQDhXyxRrPQlymOm3dLo0zzOpmRs3Woy5HkEtAd5IxMXWNgbwRO56XHUgN4n5MHkYhtxOnnmci2knrXMsAbGwtWExMRjiW4rmjWADfmv".asJson,
        "d" -> "PY8lJCOG3OO0NlwbpdHixgm8KNJgDlnEzE42mKE5qONY-mubt1wxSf3DHW-J0OUyPl2EZptj_UqInaQBIIUiT9NawSDFMJ4WEdytktWE-0D_wYCjc2_w-63vvwfst7qHnXEAv-coCpkT0IDPOA0ODpnW19EY_bmJMAVZrIiiUNzYTIviDvVOMt19rgHVjLhKiw_fiuXZYHedXSLIKVJo7Cbf1Jtxh0sHiEakh-nb-23q9CsMVySB0pA_qOZWkUrPajRnA4vdIb7to_SnNDtmVOpyai7lgq5UAoPrv4HPjx8B0D5YqEhaO93iUSAPzlQ5m11BHxW2_jVyoeuNNuPrBxSd7H6etI_8cOhsBGfOn8DMmhkUtmBVGSGnH0gecyFIMyLj4t1l_I_Anj8oU8a69B3OtGrPT4QxBf0dBf3zb12xF0p1-u5cXoM3kz_k3Zt8LZfVDJLcktVA0L8Rpr3OuDaezDoJ2G0NskReefnp8I7PSPiohZrbQOAAg1i-CS0P".asJson,
        "e" -> "AQAB".asJson,
        "qi" -> "rzsru9vUlY75x7L3k3RrGe0xZ07jQONmeWG-M9ySzBLFzGtcGyHnZ0cKRmhaqVhbp9hUgZ1aqPAhaJ0yd5xDjaoiBOUne6WMFUV2HsTtl1NbMj2ThR1QpENDxJKP0HFMl2YCGw9e_3_0bjH-sAWc-m1C_AM5woS4gbCOT1ObeyB3ohwdS59zFrIr3YSvsYW0T-Ka8rr3mzeQ6E6k2RoT7AOT7clQHFz3G0xkhR_gBIAZH5i-ktaqAWSflnUtgHk5".asJson,
        "dp" -> "A81O8kgw2osAumkPRVtuX-0kcHHG-CgPKyCEfMvuZo5ZiiG4WFNOYTVMMuDfPwd9-771vHTeb_V0atD21GqwD07lNKagC-7CkqKzzD_YyaJzcSer0nNsYE08pEuucUooEmS32ziMtIBqXrDBYTTiR02qkLfvfGpDFFbwnHJUpn5JollVcUsd71yKper8FTpN2zUmzHRFGR8jXo_0LKUQSnL0EQkNRKHVte_lTuRxuYepzVyfIB3PekLzQ9_H1uYR".asJson,
        "dq" -> "I2-4D3VsmNzFBSIOGr0UAExtXf_BKdoS0zfg969eE0-F1szRWKhbAp62MQnXAvZ3ruCxuWtTlUoWxVFrfV1wO4mbwZPu8QEg_yOpxnZQBoKnissxIB9CFVYbpckX20XAfvvNEwlXzFGbkFkUNHSg2nGvZVrlV9G9CF7SUPqfaRUyxXpdyw9fuFKWCYyZZ9qnFzDlbvl_8CDGBEho3o-0hns9r_QIMUFfeDX3XDp9tIer1C0YMBqv_f6Zf63t5UfL".asJson,
        "n" -> "hSaa5_Si2WfVq87-9uJCp0TSp5-5CN_KHO3uVx2wHaXFrLkrScEv8gAegs3jEN5WEOvZ9rZ6Tgfh0lr6CQRr73iRU5yB6Ap_26imTkFZ8RZeZ5z8Z9U3x_2ycCP9lKY4QvR5FOOqdd1FC7hECdqUko4h78kwl8PeKqEyEmm2YTcinVR_yh-4BB7X6Nh-NzIkiVEAVPDiA1QuFkxQUSHJC0pUbSNJz_SRKiHg-Ll4of_-qnD-GKt0dzLpRxgN0cU3EpBbRKv-fmPBh7-ImieYTZepsvNPLeProvFWoao8JgekrmcbgleYxLeQSAjRf8jaY5ZqsPTgTAdD4Nkbt4oChOuQrEaUkeO_i1RDpNKASFgnUtaKST4hmDCygLo9PfT2nK4V9SO5ratmO7LCgqxSUXtWgD6nBZKzpdjtQKiGakcyyC2zUk0ujPpQzmi0hdmfLqTTbK1W0iCyqz_-7vrizk9UT-h3Gpd2VOYYsbFxuDxGjHzEEcWZwptGzzwLMQ_h".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "n" -> "hSaa5_Si2WfVq87-9uJCp0TSp5-5CN_KHO3uVx2wHaXFrLkrScEv8gAegs3jEN5WEOvZ9rZ6Tgfh0lr6CQRr73iRU5yB6Ap_26imTkFZ8RZeZ5z8Z9U3x_2ycCP9lKY4QvR5FOOqdd1FC7hECdqUko4h78kwl8PeKqEyEmm2YTcinVR_yh-4BB7X6Nh-NzIkiVEAVPDiA1QuFkxQUSHJC0pUbSNJz_SRKiHg-Ll4of_-qnD-GKt0dzLpRxgN0cU3EpBbRKv-fmPBh7-ImieYTZepsvNPLeProvFWoao8JgekrmcbgleYxLeQSAjRf8jaY5ZqsPTgTAdD4Nkbt4oChOuQrEaUkeO_i1RDpNKASFgnUtaKST4hmDCygLo9PfT2nK4V9SO5ratmO7LCgqxSUXtWgD6nBZKzpdjtQKiGakcyyC2zUk0ujPpQzmi0hdmfLqTTbK1W0iCyqz_-7vrizk9UT-h3Gpd2VOYYsbFxuDxGjHzEEcWZwptGzzwLMQ_h".asJson
      ),
      JwtRsaAlgorithm.PS256
    )

  lazy val PS256Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718393.asJson
      ),
      signedJwt"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODM5M30.WRXfVDvQ5kl1i_ZcrGwvBS0PXlWvwHf6sqTHpo-taWGeXpkIOGrpMUcZ9nyMG2ZVI360e0pdS9vRlT01MY40bt3--yY0B19c1vLOFxWG4yBJ-eRCxc9ZYYIP72OIOqy1hio1aTnbTDPfyxaUU_P4vZ07C8o8PMJ6ZiAMzWrRXykWIMEHn4Od9qzrph3_NEaAt3Dfu9rx-iYLm_dfJj-aiqTxOTA09ZRXkyOTSuN-pxe_IK7LSolvd19eBGE2VM-fn6R1jbdotBvDUEuZr-OkoVJUUxBgipg75SY7s5uNssOhujoxJYAT322LbB6cqH_b52UQ7alymw4SRDyBw1CKDP8oCOBhj2R4x4kpAR4LFY8yTStHIBIyIGFY_yoQtwaP8IjlhnUV-Z8V8-BmXJ38d5qfcnpELuT9EvWDFHyGyTMcg9LuavRcDdaLoMTVJkt89SfOTyBiU1bu83V3cvJVgFHn6J0TRoKDyHV3GJRNbOxcrGTNNmGBBuKPQEfYP84r",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN RSA PUBLIC KEY-----
        MIIBigKCAYEAhSaa5/Si2WfVq87+9uJCp0TSp5+5CN/KHO3uVx2wHaXFrLkrScEv
        8gAegs3jEN5WEOvZ9rZ6Tgfh0lr6CQRr73iRU5yB6Ap/26imTkFZ8RZeZ5z8Z9U3
        x/2ycCP9lKY4QvR5FOOqdd1FC7hECdqUko4h78kwl8PeKqEyEmm2YTcinVR/yh+4
        BB7X6Nh+NzIkiVEAVPDiA1QuFkxQUSHJC0pUbSNJz/SRKiHg+Ll4of/+qnD+GKt0
        dzLpRxgN0cU3EpBbRKv+fmPBh7+ImieYTZepsvNPLeProvFWoao8JgekrmcbgleY
        xLeQSAjRf8jaY5ZqsPTgTAdD4Nkbt4oChOuQrEaUkeO/i1RDpNKASFgnUtaKST4h
        mDCygLo9PfT2nK4V9SO5ratmO7LCgqxSUXtWgD6nBZKzpdjtQKiGakcyyC2zUk0u
        jPpQzmi0hdmfLqTTbK1W0iCyqz/+7vrizk9UT+h3Gpd2VOYYsbFxuDxGjHzEEcWZ
        wptGzzwLMQ/hAgMBAAE=
        -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS256
    )

  lazy val PS256Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS256
    )

  lazy val PS256Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS256".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iOeNU4dAFFeBwNj6qdhdvm-IvDQrTa6R22lQVJVuWJxorJfeQww5Nwsra0PjaOYhAMj9jNMO5YLmud8U7iQ5gJK2zYyepeSuXhfSi8yjFZfRiSkelqSkU19I-Ja8aQBDbqXf2SAWA8mHF8VS3F08rgEaLCyv98fLLH4vSvsJGf6ueZSLKDVXz24rZRXGWtYYk_OYYTVgR1cg0BLCsuCvqZvHleImJKiWmtS0-CymMO4MMjCy_FIl6I56NqLE9C87tUVpo1mT-kbg5cHDD8I7MjCW5Iii5dethB4Vid3mZ6emKjVYgXrtkOQ-JyGMh6fnQxEFN1ft33GX2eRHluK9eg",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.PS256
    )

  lazy val PS384Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718554.asJson
      ),
      signedJwt"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODU1NH0.eXPtULWYq48f-5wMiieHza1ZIRmajviyozcA20SQEk_aywcXk9f9e0y2ZeOCNTtcV86ZLTptzdKwtuCPW0uaW8Lg0RS3_S58Vf6eSWN4pR01RwRiSwcP5VVicmm1EvnJr7J4s7hkidFflzLWBteZ1zO2S0FH4q4Q1VZQd9MMt6AHGnbiYrgIQgR2wJITW3RnqFcm1VGDdmF4PZu76EArBy1OpL_mEOfJVD57D8PoXLiKKgGByryBYIdHRO7iFI27ZLyqbd-UpFjfdYL5416_bWXi5c37C_LHCJ4CcjprAQJ4txxEtSq8Ck5IdPcXMF5NhaJz7WFsk_3CA8PwWUmPzfLuYQOaO1tIPdpjQj0fLhDK5-1JIxjyrNoKWBVr-vzyj0FG_ZVNQP4aJUEQyGwrQMKK20ruhjjH6FXvYG7vD_lHoHKmPG-EU4sfuabARfWNYokEWwSZ4OauYBr2pWAK__uRP1A26Qav17GnMnCy63xwyEsp9-zumvpCJf3yp2pvYYtdBG9EW1JC24ShxipIkajy6q_mGNB-nOdCAnu99FMc-mSZBpT69roz3ZXm0CplNot13aSWI_Y6aRRX1dbasforYCqzKZJWfJkDLWFFAx_5UK_TBcHhkzlOmGVz4eYlCDBNWt6G-CrzmlH2WOtQNn83u4ZGBZKzQn9MyaGXypY",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "57JaO_HQ031LEx7dhBKMm5ZNSNJKy7o1j-4vfNRnNPriPCSWWYu2igzQLFQAccj-Kr7sMYmyLBBRe52k5kvplJ8iQoCBha4TDZeeTayFbXUxEETPI4A1Z4i-C3T16xB0FJZY7NQ_4fUr8rUwOhtd3jhU80-xoJUIWOaKO7JtiV65aMXrxzNShLEzuk2Zn-MNXYg-TP_-ouqRXmya5hl3XmA3g1Kwhti0XJv_ecAyStwC4NZVt7nBd4eaHyGBIdWk7y-4w7SFT8wkF0jaNslmQEDe1gjeC-DBRAiurj2gZkVjJnrXycheIj3FXI5A9KZXyJF9gm1SAt6_tUDY53IdFw".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "7eDzHyGnHp84F1RCcPz7mWnrmAFgS29NEPdjUu-KOgi3RciWdOB98He1Vikl44JeCvATZyUMUiNrqWP07YHk1rkYvWG2nQ64RcsIGFyUe8TXY6SlJtg81Moj2cB7arGoI7OaJqWkjXH9-y46PHpHfhk6s9-8N0Lu2KSn5ocXG78gM8gwpb-eiVxmFdI7A4Ps3JyLKduAToxlt_HL19clGagWtbb7uP4azCRDl0xwFkeGFisDYARYe-nuOjGe4OgUMt2uUKrZ7g4jgs4A0OO9PocPBfx4Q4JEX_wsn2Fh5zOkaciEj5787tQhT0CqzEZit4_pGdCSut9m9EsO7mEhZQ".asJson,
        "d" -> "C_Ju2ylwKZ1zLN8yTzRvKwET47vY9_wqzPWtd8cRjA8Tgyy-Sz3PkXCqwnZQfpO05j9rHB3PDqhZs_dDutF97lXCSjrjvF8eQIaxYHZXqLcWRKPwoHWmOpjRv_ganNqbga_TWffzneaHhm2bydD4eR6LfD7HhjB4FWNT4JYZHCNPJRQ_j25lMkUhgqUxXEUnde7Q6PUmSr_uQhtKJ-leiueW9vIJaaKfhJx_w0oge3e5fQteAgCNYEmxtDYQZXHOxBWI2K0uFAacbiIp2YVUnPZw7WEvBtKmomWv3PR4PwdV9lG9NotXZRLfAU3-hwdtWNDZbhx_w0fQX9WPw8yM52bhl0fJxc0Ep6csg7lwaJdzo08YnvA7ZWQaYA4Rr1yoKkNTQTwaG_awhLc2mywvnuk163R5LSIdZXNPtX7_UBOFIh9U-FBgNF6JaDvp8QC69z_7hjRqT5IdW9qlWTdT8DXxvnYDKVC9LhPFKz1R_FafLZE3tZK95ycaJBEUupqRJych_Xr9PRWsvmuvffR57JlRY6k90_Nm9Ssc3XY_yKYpSGZI0o2obdPTuWUsDlJtFrFsL227I4awDIwDECpTYGx2H_vHIYPzetLtjC8QBPeEjred5B53g1dhIh49txAdYI8FJrkrZTq_JBgoqbT8HdglAiBGK8QB0ZUVQ_ojV90".asJson,
        "e" -> "AQAB".asJson,
        "qi" -> "GPs-w_ICj3dPLfqLrqG3r8nfAFilCvHqDgvtwAvmk2MtF5o9hmYuKcdP08GshfPe1bcuoKUwCpLZHq6mNmL8L6VreLYvIMbneBHp5JF1bIAjql3WaXDMUt7TdlxvIa7b0AZst68lQc_CLr7xUM6IYnNnsxTsV1MCg4NNe631l40PNf9RPh3un9Ht02AlHzVI54jah0EDrg-7E1H74fSJA6vRNIPGSpq09jEvuzUgB_JsopNF1gf2Q6QqE9jPCRjBnryA2eJYAzxSXWb1HjKuRRezsJnzTlA_H_Q3BK6B126mjhOOnRMl3BfW-qvoBvJ2uFIJ7RChH58KMDz-Evfgvw".asJson,
        "dp" -> "NYPDRa8vnXmF-o-ZeGTUZydLCHPR5MZIksrf2wQwJlOAJ4YH1_zmF3KoLmTkiWN0GSlp4nM8XOMT_upFaQ_FjpdG0Xde8yJmsi__107urn5v66MI-Nkm_Jff1UOZfUaamRq0xVasvqLjGLbywakKgEYgkOYqT728ZNQyv2ER3bWsO1_jemoHODC5kuFTh1NpBd5vDVffV3-4Pcf16wmcwYaVq9ZQgYTR-8XoNxXGR_YTEB1RRRM5dUMzvNb_PXJcGwa5tTIfzHOJLnucMyVHYbXaAjOgHbw2x2D9_66qOpTyNrQO3UNTQrNjv2H37Mny4peAFrzrQVBzlQi6UJLR1w".asJson,
        "dq" -> "AT63JwePD1r3-S9ItbytOG1UfVQsg9iOR7NzwqBcUddv1h6pouz128dUnKHUf-9TvKzq_RQ1j0x-KMHMK14Nq44Gch9LzGCiWEMqxK3fXRJ3qh7Xem-RSe_Q5jfarYFGhwFOojsltFPPZ3wjc-OT8jYBl6VpH8Tq6Rlbg5pbZZrHeV3n20Y4dzGTmzOheXA8Uh9DnzF153NWqPLMBVIr8IlvrP3LLXmu_DiIXgdZYtR3ADCzcNI1AFkGFSnjUfwE9wsv-V4bi-JpDysy1-UJPYWJb5eVrYzF_NaeCSuCTqp3htI012eWnU1g60BEZJNNuvY22xq7Wd0Hdenapya8_Q".asJson,
        "n" -> "10u1ouwG_QElj8vR-b2NPkWqf46jbt3tKMOM_H-hPIf0HQkcGvXIlEesl-PU93Aca4E3StN1E7Ibq8y_gZj1TL_neJ2RjFd82y04gFiMIBbUY1DXflL6s-GRU8TpKY0i1oDSbfGqVj3ly48Kzc_1Im9phiMQHykB7P3VI-USpLXMWdtmyVgwIhPf3o7b9MX5J4-SO8SVFd1qArqpaUFKTbMlIYLXx1AJNOrPhv6QeQcuUGj1sKDT7TXCmk8IFoZFIE3fkEu_xuOs6Q73FLRPPH2y2CtUAbqz7ZRjKJri_3lSYO0FBZKc220SX4v6_PNKCxDGV2ZUttnzpAvoRYoMGoTwjJVshKMQjr7Cl2g4qc9UkUfwnTFxOtraWF2j08h7TCIVaqz4mMpIkT0YnNNEi_WjMB35KDZqPUlJGU7da1FNX2HqmjeyRKdGM_BHwsTJyzcKjlvk3h-XMljc-O6or3dQmVHLWjMcarj5WA__pUU6Fy4C6AjC3h1Ji_CHR8Cahhg66xcfvYJkmQSeo1Fhxg43tKEbrTUpJo-LgUzG4Wk9vvlH_ZZQ06Ssf0bSgj5mv81F7oICcppKxDb2Ce5Fe2UM5_FgLcHU2_bku1thUdAFKwgUMegqKIdN_K8jk5z7PtWbdIpDztWLIVNjpekfVD_f7Ex94DOeM-mo8218cRM".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "n" -> "10u1ouwG_QElj8vR-b2NPkWqf46jbt3tKMOM_H-hPIf0HQkcGvXIlEesl-PU93Aca4E3StN1E7Ibq8y_gZj1TL_neJ2RjFd82y04gFiMIBbUY1DXflL6s-GRU8TpKY0i1oDSbfGqVj3ly48Kzc_1Im9phiMQHykB7P3VI-USpLXMWdtmyVgwIhPf3o7b9MX5J4-SO8SVFd1qArqpaUFKTbMlIYLXx1AJNOrPhv6QeQcuUGj1sKDT7TXCmk8IFoZFIE3fkEu_xuOs6Q73FLRPPH2y2CtUAbqz7ZRjKJri_3lSYO0FBZKc220SX4v6_PNKCxDGV2ZUttnzpAvoRYoMGoTwjJVshKMQjr7Cl2g4qc9UkUfwnTFxOtraWF2j08h7TCIVaqz4mMpIkT0YnNNEi_WjMB35KDZqPUlJGU7da1FNX2HqmjeyRKdGM_BHwsTJyzcKjlvk3h-XMljc-O6or3dQmVHLWjMcarj5WA__pUU6Fy4C6AjC3h1Ji_CHR8Cahhg66xcfvYJkmQSeo1Fhxg43tKEbrTUpJo-LgUzG4Wk9vvlH_ZZQ06Ssf0bSgj5mv81F7oICcppKxDb2Ce5Fe2UM5_FgLcHU2_bku1thUdAFKwgUMegqKIdN_K8jk5z7PtWbdIpDztWLIVNjpekfVD_f7Ex94DOeM-mo8218cRM".asJson
      ),
      JwtRsaAlgorithm.PS384
    )

  lazy val PS384Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718554.asJson
      ),
      signedJwt"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODU1NH0.eXPtULWYq48f-5wMiieHza1ZIRmajviyozcA20SQEk_aywcXk9f9e0y2ZeOCNTtcV86ZLTptzdKwtuCPW0uaW8Lg0RS3_S58Vf6eSWN4pR01RwRiSwcP5VVicmm1EvnJr7J4s7hkidFflzLWBteZ1zO2S0FH4q4Q1VZQd9MMt6AHGnbiYrgIQgR2wJITW3RnqFcm1VGDdmF4PZu76EArBy1OpL_mEOfJVD57D8PoXLiKKgGByryBYIdHRO7iFI27ZLyqbd-UpFjfdYL5416_bWXi5c37C_LHCJ4CcjprAQJ4txxEtSq8Ck5IdPcXMF5NhaJz7WFsk_3CA8PwWUmPzfLuYQOaO1tIPdpjQj0fLhDK5-1JIxjyrNoKWBVr-vzyj0FG_ZVNQP4aJUEQyGwrQMKK20ruhjjH6FXvYG7vD_lHoHKmPG-EU4sfuabARfWNYokEWwSZ4OauYBr2pWAK__uRP1A26Qav17GnMnCy63xwyEsp9-zumvpCJf3yp2pvYYtdBG9EW1JC24ShxipIkajy6q_mGNB-nOdCAnu99FMc-mSZBpT69roz3ZXm0CplNot13aSWI_Y6aRRX1dbasforYCqzKZJWfJkDLWFFAx_5UK_TBcHhkzlOmGVz4eYlCDBNWt6G-CrzmlH2WOtQNn83u4ZGBZKzQn9MyaGXypY",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
      -----BEGIN RSA PUBLIC KEY-----
      MIICCgKCAgEA10u1ouwG/QElj8vR+b2NPkWqf46jbt3tKMOM/H+hPIf0HQkcGvXI
      lEesl+PU93Aca4E3StN1E7Ibq8y/gZj1TL/neJ2RjFd82y04gFiMIBbUY1DXflL6
      s+GRU8TpKY0i1oDSbfGqVj3ly48Kzc/1Im9phiMQHykB7P3VI+USpLXMWdtmyVgw
      IhPf3o7b9MX5J4+SO8SVFd1qArqpaUFKTbMlIYLXx1AJNOrPhv6QeQcuUGj1sKDT
      7TXCmk8IFoZFIE3fkEu/xuOs6Q73FLRPPH2y2CtUAbqz7ZRjKJri/3lSYO0FBZKc
      220SX4v6/PNKCxDGV2ZUttnzpAvoRYoMGoTwjJVshKMQjr7Cl2g4qc9UkUfwnTFx
      OtraWF2j08h7TCIVaqz4mMpIkT0YnNNEi/WjMB35KDZqPUlJGU7da1FNX2Hqmjey
      RKdGM/BHwsTJyzcKjlvk3h+XMljc+O6or3dQmVHLWjMcarj5WA//pUU6Fy4C6AjC
      3h1Ji/CHR8Cahhg66xcfvYJkmQSeo1Fhxg43tKEbrTUpJo+LgUzG4Wk9vvlH/ZZQ
      06Ssf0bSgj5mv81F7oICcppKxDb2Ce5Fe2UM5/FgLcHU2/bku1thUdAFKwgUMegq
      KIdN/K8jk5z7PtWbdIpDztWLIVNjpekfVD/f7Ex94DOeM+mo8218cRMCAwEAAQ==
      -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS384
    )

  lazy val PS384Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS384
    )

  lazy val PS384Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS384".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Lfe_aCQme_gQpUk9-6l9qesu0QYZtfdzfy08w8uqqPH_gnw-IVyQwyGLBHPFBJHMbifdSMxPjJjkCD0laIclhnBhowILu6k66_5Y2z78GHg8YjKocAvB-wSUiBhuV6hXVxE5emSjhfVz2OwiCk2bfk2hziRpkdMvfcITkCx9dmxHU6qcEIsTTHuH020UcGayB1-IoimnjTdCsV1y4CMr_ECDjBrqMdnontkqKRIM1dtmgYFsJM6xm7ewi_ksG_qZHhaoBkxQ9wq9OVQRGiSZYowCp73d2BF3jYMhdmv2JiaUz5jRvv6lVU7Quq6ylVAlSPxeov9voYHO1mgZFCY1kQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.PS384
    )

  lazy val PS512Jwk: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718702.asJson
      ),
      signedJwt"eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODcwMn0.Isrkad-3uu93J25Bn5jEugjhIdY2e667yuy60wSKpsoemhXewCRJAAH_1uyrtw977h_DWzbTC8j1z85-iQU4DL2zwIcjjpipmQFyqERqgr4VPtI5dpSdTAkZiJ0i0cyc5Pl-_ZKYMJRYPKyttSWHrKLXM_kAUvOnZclCu9vFZxm8b9ixTK6Xu5i8dVqFstlQxjdWc0ZSi07rgmdc3SqrEgkjnsUIn-6pPX06o7JpZemwzvMYoYToJgJW7M_hcwehOhU7eyUL4Mx3w9s0Jlr0jprVPRIdyWRxNQZxYu7ee-22zlc5EGWeC9AaLEuqUhIaEnMeBbqZcFt42lQsfQjXcA",
      ExampleAsymmetricJwt.privateKey(
        "p" -> "7IGEM0YWF8LKLdlWBgoJ5S46VxJSub6pXT0rdAnfTl--heBalhoPQJYtwS-8ew6JPp5ax4pa7REP_6WsDb6rfdqu2ma-ENYxOvsYCjyCG8ypuM8PJ-FBPYqLxHht_xRQtoo4Xyr4NP3sUlPA4gIHhNLzdtqHNstKbix8OhO68m8".asJson,
        "kty" -> "RSA".asJson,
        "q" -> "2ZnpzxwleJU_vigi2of1jGdwJTWa4f-tO5pq0ROelCme_vQYZVwmbpbTppKPSupV6sejKPgE2zU1afWEoceZU92ch99HTB47rwcp0x5KVeEQUPJPW5xASfgDPxIJm9u43ejyARG86Noid9FGRjVzgqpPhTq94aVMg6bjXlUqF98".asJson,
        "d" -> "Pi1XjOjKPAWz7YWCxiZ8cZfV3KnGGEBXH8CJl0MPZpntqli9p9XaaCcvdFydfCGZQn9-wdd9QGpomIJIEUF6PnP5M0dtKEJJOYCuWH_hTxxPObqjboIzSj6UEIqZyPfqep0wbl3u-AGNaY65kKAhIITiG8TYSBLrlUqhSHu4buwEJZCLu0WnlkuFQ_kP1KxBgCFHp2f-jQCZ1aGr4Dp35TkWBzMuUCcqfn_-uG1krG-OqmyZThflwNEprI10OYDcl3-1QOC5wvAPA9cGJkQzR3t0RAjKz3EwtvBRddkxPS7Yavjy1RG_vG2KFnVIUBbAFZbsi2IN1GYxphhE6Joj-Q".asJson,
        "e" -> "AQAB".asJson,
        "qi" -> "zoWYocJq9TWQ1OPHkbRi9wwduTbhyqxHGL4CyXPnmnC1qlI94L6bzjizYShulNeDzLUaJv9aMav0sh4vPUbmXu8_h8jTrnsh0z-Hv_4qRygzMBLtBBF4_NcrDqQ0tgu0S487u4XBxBaw3DfA58JnJVXFD-gTMHZsHbi0-2VkzCA".asJson,
        "dp" -> "IeAPOnTgdzjMUrLdknHfpvbvHkeel8JKafN4BN_hH02xcWWINBW5d4vLM--NdKbJW7G82PXlPi2CeCCXu0RDNfybrOaodKrpVERg1h6CmE7BRJpL1m96M8FjcZm6T53uTacQmfkCojx4m_YpG3Yk845vlueIFH4bxBoVFRB8Z3s".asJson,
        "dq" -> "1FT5750Ze1a3wohLqk5s7rqolcZ_AfSJR9XgUXABl7Ydbc8mVxHadqM6mBn_NS0A9X4k2f9aTcTYADMRXwPzvABNk8_uNHpz5tDooRe3laFuWG55vXz0xrj6AftJ4QpAlFmQfDagzd69L4nINw5FTsV9nxW434x64yRgTVZxIqU".asJson,
        "n" -> "yQf6eLEa9ixnmkZgFLpxt4-KP7LX45bQSXLrkBxfzZmNh5hwKEGzpGFkzY8DuPXJpNMUgH7jyNR906GJ4g_1FlTqmJ9wuhnvObC8PriQq7ssZ-N41AtwlcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZhMd7_AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm-5UASGETzDtuN3_tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl668XAELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQ".asJson
      ),
      ExampleAsymmetricJwt.publicKey(
        "kty" -> "RSA".asJson,
        "e" -> "AQAB".asJson,
        "n" -> "yQf6eLEa9ixnmkZgFLpxt4-KP7LX45bQSXLrkBxfzZmNh5hwKEGzpGFkzY8DuPXJpNMUgH7jyNR906GJ4g_1FlTqmJ9wuhnvObC8PriQq7ssZ-N41AtwlcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZhMd7_AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm-5UASGETzDtuN3_tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl668XAELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQ".asJson
      ),
      JwtRsaAlgorithm.PS512
    )

  lazy val PS512Pkcs1: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1777718702.asJson
      ),
      signedJwt"eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc3NzcxODcwMn0.Isrkad-3uu93J25Bn5jEugjhIdY2e667yuy60wSKpsoemhXewCRJAAH_1uyrtw977h_DWzbTC8j1z85-iQU4DL2zwIcjjpipmQFyqERqgr4VPtI5dpSdTAkZiJ0i0cyc5Pl-_ZKYMJRYPKyttSWHrKLXM_kAUvOnZclCu9vFZxm8b9ixTK6Xu5i8dVqFstlQxjdWc0ZSi07rgmdc3SqrEgkjnsUIn-6pPX06o7JpZemwzvMYoYToJgJW7M_hcwehOhU7eyUL4Mx3w9s0Jlr0jprVPRIdyWRxNQZxYu7ee-22zlc5EGWeC9AaLEuqUhIaEnMeBbqZcFt42lQsfQjXcA",
      privateKey"""
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAyQf6eLEa9ixnmkZgFLpxt4+KP7LX45bQSXLrkBxfzZmNh5hw
        KEGzpGFkzY8DuPXJpNMUgH7jyNR906GJ4g/1FlTqmJ9wuhnvObC8PriQq7ssZ+N4
        1AtwlcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZ
        hMd7/AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm
        +5UASGETzDtuN3/tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl
        668XAELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQIDAQABAoIBAD4tV4zoyjwFs+2F
        gsYmfHGX1dypxhhAVx/AiZdDD2aZ7apYvafV2mgnL3RcnXwhmUJ/fsHXfUBqaJiC
        SBFBej5z+TNHbShCSTmArlh/4U8cTzm6o26CM0o+lBCKmcj36nqdMG5d7vgBjWmO
        uZCgISCE4hvE2EgS65VKoUh7uG7sBCWQi7tFp5ZLhUP5D9SsQYAhR6dn/o0AmdWh
        q+A6d+U5FgczLlAnKn5//rhtZKxvjqpsmU4X5cDRKayNdDmA3Jd/tUDgucLwDwPX
        BiZEM0d7dEQIys9xMLbwUXXZMT0u2Gr48tURv7xtihZ1SFAWwBWW7ItiDdRmMaYY
        ROiaI/kCgYEA7IGEM0YWF8LKLdlWBgoJ5S46VxJSub6pXT0rdAnfTl++heBalhoP
        QJYtwS+8ew6JPp5ax4pa7REP/6WsDb6rfdqu2ma+ENYxOvsYCjyCG8ypuM8PJ+FB
        PYqLxHht/xRQtoo4Xyr4NP3sUlPA4gIHhNLzdtqHNstKbix8OhO68m8CgYEA2Znp
        zxwleJU/vigi2of1jGdwJTWa4f+tO5pq0ROelCme/vQYZVwmbpbTppKPSupV6sej
        KPgE2zU1afWEoceZU92ch99HTB47rwcp0x5KVeEQUPJPW5xASfgDPxIJm9u43ejy
        ARG86Noid9FGRjVzgqpPhTq94aVMg6bjXlUqF98CgYAh4A86dOB3OMxSst2Scd+m
        9u8eR56Xwkpp83gE3+EfTbFxZYg0Fbl3i8sz7410pslbsbzY9eU+LYJ4IJe7REM1
        /Jus5qh0qulURGDWHoKYTsFEmkvWb3ozwWNxmbpPne5NpxCZ+QKiPHib9ikbdiTz
        jm+W54gUfhvEGhUVEHxnewKBgQDUVPnvnRl7VrfCiEuqTmzuuqiVxn8B9IlH1eBR
        cAGXth1tzyZXEdp2ozqYGf81LQD1fiTZ/1pNxNgAMxFfA/O8AE2Tz+40enPm0Oih
        F7eVoW5Ybnm9fPTGuPoB+0nhCkCUWZB8NqDN3r0vicg3DkVOxX2fFbjfjHrjJGBN
        VnEipQKBgQDOhZihwmr1NZDU48eRtGL3DB25NuHKrEcYvgLJc+eacLWqUj3gvpvO
        OLNhKG6U14PMtRom/1oxq/SyHi89RuZe7z+HyNOueyHTP4e//ipHKDMwEu0EEXj8
        1ysOpDS2C7RLjzu7hcHEFrDcN8DnwmclVcUP6BMwdmwduLT7ZWTMIA==
        -----END RSA PRIVATE KEY-----
      """,
      publicKey"""
      -----BEGIN RSA PUBLIC KEY-----
      MIIBCgKCAQEAyQf6eLEa9ixnmkZgFLpxt4+KP7LX45bQSXLrkBxfzZmNh5hwKEGz
      pGFkzY8DuPXJpNMUgH7jyNR906GJ4g/1FlTqmJ9wuhnvObC8PriQq7ssZ+N41Atw
      lcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZhMd7
      /AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm+5UA
      SGETzDtuN3/tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl668X
      AELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQIDAQAB
      -----END RSA PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS512
    )

  lazy val PS512Pkcs8: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
        4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
        +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
        kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
        0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
        cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
        mwIDAQAB
        -----END PUBLIC KEY-----
      """,
      JwtRsaAlgorithm.PS512
    )

  lazy val PS512Pkcs8AndX509Certificate: ExampleRsaJwt =
    ExampleRsaJwt(
      JwtHeader(
        "alg" -> "PS512".asJson,
        "typ" -> "JWT".asJson
      ),
      JwtClaims(
        "sub" -> "1234567890".asJson,
        "name" -> "John Doe".asJson,
        "admin" -> true.asJson,
        "iat" -> 1516239022.asJson
      ),
      signedJwt"eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ",
      privateKey"""
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
        MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
        NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
        qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
        p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
        ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
        VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
        laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
        sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
        mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
        dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
        ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
        DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
        N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
        0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
        t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
        AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
        48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
        DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
        xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
        mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
        2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
        et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
        VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
        TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
        dn/RsYEONbwQSjIfMPkvxF+8HQ==
        -----END PRIVATE KEY-----
      """,
      publicKey"""
        -----BEGIN CERTIFICATE-----
        MIIDSjCCAjKgAwIBAgIUPCHZk3CxOF3JI5JFd/09zZO+aWMwDQYJKoZIhvcNAQEL
        BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
        GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA5MzRaFw0yNjA2
        MDQxODA5MzRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
        HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9
        8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSn
        XyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODS
        ctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV
        //eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71o
        ZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAGjMjAwMB0GA1Ud
        DgQWBBRlwyVtF+aY3C93+6truraspq7S1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
        SIb3DQEBCwUAA4IBAQBZ9HpUj3/MEANHNWrDgr3a+8cb4VCtN4rYEI+hsSfdxMF2
        lLSa2yrG94+6TT09LR9gZMGBEbkQPaPaVtco51a6gfUAliROEUscjsZN1tetxeOC
        5zNERSDpyFgAjIwYNLRJum9BaBHVzu5kXagLV8tF2H2/2hJOM0PTFMdOLfx89VtS
        yrW36zr8C8dPXn6OJ3+plrnojpWvFC4Ww6biXGqF0pSaGK2Fb4AfER7sUZANgnMk
        I++dvVM4oHAdTEi3FZQOx/ouIliXgPC0cdIOCGQ3QXfq/nOyx8wE5U8DjyzgJLPr
        sKfGVGthXZEZj5eL1WXiYYf0UHXBLGYl8m6WhlWw
        -----END CERTIFICATE-----
      """,
      JwtRsaAlgorithm.PS512
    )

  lazy val All: List[ExampleRsaJwt] =
    List(
      PS256Jwk,
      PS256Pkcs1,
      PS256Pkcs8,
      PS256Pkcs8AndX509Certificate,
      PS384Jwk,
      PS384Pkcs1,
      PS384Pkcs8,
      PS384Pkcs8AndX509Certificate,
      PS512Jwk,
      PS512Pkcs1,
      PS512Pkcs8,
      PS512Pkcs8AndX509Certificate,
      RS256Jwk,
      RS256Pkcs1,
      RS256Pkcs8,
      RS256Pkcs8AndX509Certificate,
      RS384Jwk,
      RS384Pkcs1,
      RS384Pkcs8,
      RS384Pkcs8AndX509Certificate,
      RS512Jwk,
      RS512Pkcs1,
      RS512Pkcs8,
      RS512Pkcs8AndX509Certificate
    )

  val exampleRsaJwtGen: Gen[ExampleRsaJwt] =
    Gen.oneOf(All)

  implicit val exampleRsaJwtArbitrary: Arbitrary[ExampleRsaJwt] =
    Arbitrary(exampleRsaJwtGen)

  implicit val exampleRsaJwtShow: Show[ExampleRsaJwt] =
    Show.fromToString
}
