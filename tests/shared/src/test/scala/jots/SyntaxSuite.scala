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
import io.circe.Encoder
import io.circe.syntax.*
import jots.syntax.*
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object SyntaxSuite extends SimpleIOSuite with Checkers {
  test("Syntax.asJwt") {
    forall { (claims: Claims) =>
      expect.eql(JwtEncoder[Claims].encode(claims), claims.asJwt)
    }
  }

  pureTest("Syntax.jwk") {
    val expected =
      Jwk(
        "kty" -> "RSA".asJson,
        "kid" -> "5e41c292-56cf-4ddf-93e9-60caecb07fd7".asJson,
        "d" -> "WnaPS21C9yJkrULLn8--OF20W7pt1vlIIwcVN22ZKyME4kuxAw39LLkPiEN8m0y7i90oW39HHALKGvsC84tXdf8f_-EOtaFBVjs0diOPbAlPCg-Nb_P6FN6wci75DsTQBe1JdYAWWeqqb4TO-4rrgbnAvkeT2yJf90vjweQaUlw0B87XfZng2LkUEkZn5rORgwMPMMydEYw6e20se4VperG_PTO1kofF2SjY--MVpQD1EsX4Ej8-y5jboZDQEy3FrJcyjmTONRJAp4Eo3rNIO3mjbCC5vMd6BTQeHmsWbiCs0hdFLBPUfVp7354hkWbrulOT9dHspBbaZfsku5drsQ".asJson,
        "n" -> "wqNlxygo6pAvdyu-iMknGTZ3jqFg_9MUPZTUDIeNXoj1lupYIq9rf8RDYZ42hJmfuTTql0b9PMNwOzXfPnszeu26iYGEi0_mpddpiapSOdQwK0m4QV1w7fQk2j4EwTex0_AgkMWA8Ps6rnhoFXbUxdoIVmaNa2TpyuqLOf1YkfaRztdAJ2pc2KrEn8j0RL-dq0_QH018PwdaMdDX5AS0klqQzYeQpfcBHjrXD5nZ8NrSQ92gN9zc8c0cuZSO4XJbQjOyHMZbdilopWa_rqzpEDQmiyA1nVdBrIg2vcAj-c0ZfSJuFW_GDMe_eyX_WUhps1aqDdJ07o6N796MneQlSQ".asJson,
        "e" -> "AQAB".asJson,
        "p" -> "43LknPAsuJdC0QwiqxZLiKidPUKJhSaSGAez8R_PMGzvuT9QujLGRVqVTSBndd3fpGZ_62oFNuxDLQyA2PSnf971p8UdEtSR0ioRd1BQ2mWrQrsSr4270beBzBQHhydqxOHHR0v58PUZ_J-uzzUNlmnEKkVzK-o2SkILBsmr-A8".asJson,
        "q" -> "2xIh6QCzfDp28DhsaUb3H2kPI4VtjTb430N_TTpTh04rL-l-24HnV60Q_0EoF0pLVx23-tyj1ar5p6VxJ42sBbFUTXbDXbo67CivaLXMYi7wk56IUGTrSjLUkSrwJGR2ErFOyU0ZchyP3VSbhNzJqHs7Tw8FZ2yZF6HyOggF9Sc".asJson,
        "dp" -> "1grHTVFQJJ5kSKos7ehbSM20u3OkSuOTVH3bPqz6o83AgwoshC1IHPgzzJMUCf20etfixb3ODnOke_5qOsFx54oAj9OVmqTkXW0tZqT0kbJfyrqVyROOjrsssMqgkvXrKkB28odzPOjLfcsgDOsWUFhUPJuC2O7eDF--VLLw3M0".asJson,
        "dq" -> "BmC8w__VOeSp2cyKu3Xpc-ynGC2mRto23KkmZ6UvEV1hPH_bxaA-j_rl58iJ1kO_dcXTuWX7DxlvM0ZJyREC1ReYkLjIb04gsQduM-o3DRS4xFN1PIHzp7FbJu7NFwIlvd2ToaCxAPV76sGv1WpoJJOR4ndZfO1Yd6urVa0uHzk".asJson,
        "qi" -> "SKY0hJdh_QJSTyitji0CKABna9AqCTmzJ4xuecR6LTXWnILbddduapkWYHF6FGFoDeUO6EmnWqF47UskEBGr7vYGEhc0mcQ4hHSlQusSpY0LhlFOIN1SCQUD0TXsCOfVBUjYSXOKO1Mvxm35X_BH5miXY89uWMN_1LM6pWWEjpM".asJson
      )

    val found =
      jwk"""
        {
          "kty": "RSA",
          "kid": "5e41c292-56cf-4ddf-93e9-60caecb07fd7",
          "d": "WnaPS21C9yJkrULLn8--OF20W7pt1vlIIwcVN22ZKyME4kuxAw39LLkPiEN8m0y7i90oW39HHALKGvsC84tXdf8f_-EOtaFBVjs0diOPbAlPCg-Nb_P6FN6wci75DsTQBe1JdYAWWeqqb4TO-4rrgbnAvkeT2yJf90vjweQaUlw0B87XfZng2LkUEkZn5rORgwMPMMydEYw6e20se4VperG_PTO1kofF2SjY--MVpQD1EsX4Ej8-y5jboZDQEy3FrJcyjmTONRJAp4Eo3rNIO3mjbCC5vMd6BTQeHmsWbiCs0hdFLBPUfVp7354hkWbrulOT9dHspBbaZfsku5drsQ",
          "n": "wqNlxygo6pAvdyu-iMknGTZ3jqFg_9MUPZTUDIeNXoj1lupYIq9rf8RDYZ42hJmfuTTql0b9PMNwOzXfPnszeu26iYGEi0_mpddpiapSOdQwK0m4QV1w7fQk2j4EwTex0_AgkMWA8Ps6rnhoFXbUxdoIVmaNa2TpyuqLOf1YkfaRztdAJ2pc2KrEn8j0RL-dq0_QH018PwdaMdDX5AS0klqQzYeQpfcBHjrXD5nZ8NrSQ92gN9zc8c0cuZSO4XJbQjOyHMZbdilopWa_rqzpEDQmiyA1nVdBrIg2vcAj-c0ZfSJuFW_GDMe_eyX_WUhps1aqDdJ07o6N796MneQlSQ",
          "e": "AQAB",
          "p": "43LknPAsuJdC0QwiqxZLiKidPUKJhSaSGAez8R_PMGzvuT9QujLGRVqVTSBndd3fpGZ_62oFNuxDLQyA2PSnf971p8UdEtSR0ioRd1BQ2mWrQrsSr4270beBzBQHhydqxOHHR0v58PUZ_J-uzzUNlmnEKkVzK-o2SkILBsmr-A8",
          "q": "2xIh6QCzfDp28DhsaUb3H2kPI4VtjTb430N_TTpTh04rL-l-24HnV60Q_0EoF0pLVx23-tyj1ar5p6VxJ42sBbFUTXbDXbo67CivaLXMYi7wk56IUGTrSjLUkSrwJGR2ErFOyU0ZchyP3VSbhNzJqHs7Tw8FZ2yZF6HyOggF9Sc",
          "dp": "1grHTVFQJJ5kSKos7ehbSM20u3OkSuOTVH3bPqz6o83AgwoshC1IHPgzzJMUCf20etfixb3ODnOke_5qOsFx54oAj9OVmqTkXW0tZqT0kbJfyrqVyROOjrsssMqgkvXrKkB28odzPOjLfcsgDOsWUFhUPJuC2O7eDF--VLLw3M0",
          "dq": "BmC8w__VOeSp2cyKu3Xpc-ynGC2mRto23KkmZ6UvEV1hPH_bxaA-j_rl58iJ1kO_dcXTuWX7DxlvM0ZJyREC1ReYkLjIb04gsQduM-o3DRS4xFN1PIHzp7FbJu7NFwIlvd2ToaCxAPV76sGv1WpoJJOR4ndZfO1Yd6urVa0uHzk",
          "qi": "SKY0hJdh_QJSTyitji0CKABna9AqCTmzJ4xuecR6LTXWnILbddduapkWYHF6FGFoDeUO6EmnWqF47UskEBGr7vYGEhc0mcQ4hHSlQusSpY0LhlFOIN1SCQUD0TXsCOfVBUjYSXOKO1Mvxm35X_BH5miXY89uWMN_1LM6pWWEjpM"
        }
      """

    expect.same(expected, Right(found))
  }

  pureTest("Syntax.jwkSet") {
    val expected =
      Jwk(
        "kty" -> "OKP".asJson,
        "alg" -> "EdDSA".asJson,
        "kid" -> "b1da5c18-4ab3-403d-ba7e-dc3da64cf35c".asJson,
        "crv" -> "Ed25519".asJson,
        "x" -> "CQQsdHb50GMb0AoEKHa5DZn_Jw6hRoI-bpwWsJCGxxg".asJson,
        "d" -> "gh2rgbLrxM3XctI8OsFwssBTytBAdaYFpjKUIOrdbl4".asJson
      ).map(JwkSet(_))

    val found =
      jwkSet"""
        {
          "keys": [
            {
              "kty": "OKP",
              "alg": "EdDSA",
              "kid": "b1da5c18-4ab3-403d-ba7e-dc3da64cf35c",
              "crv": "Ed25519",
              "x": "CQQsdHb50GMb0AoEKHa5DZn_Jw6hRoI-bpwWsJCGxxg",
              "d": "gh2rgbLrxM3XctI8OsFwssBTytBAdaYFpjKUIOrdbl4"
            }
          ]
        }
      """

    expect.same(expected, Right(found))
  }

  private final case class Claims(id: String)

  private object Claims {
    implicit val claimsEncoder: Encoder.AsObject[Claims] =
      Encoder.forProduct1("id")(_.id)

    implicit val claimsJwtEncoder: JwtEncoder[Claims] =
      JwtEncoder.encodeClaims

    val claimsGen: Gen[Claims] =
      Gen.uuid.map(_.toString).map(apply)

    implicit val claimsArbitrary: Arbitrary[Claims] =
      Arbitrary(claimsGen)

    implicit val claimsShow: Show[Claims] =
      Show.fromToString
  }
}
