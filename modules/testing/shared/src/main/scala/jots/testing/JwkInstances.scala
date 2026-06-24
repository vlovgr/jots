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

package jots.testing

import io.circe.Json
import io.circe.syntax.*
import jots.Jwk
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[Jwk]]s.
  */
object JwkInstances extends JwkInstances

private[jots] trait JwkInstances {
  lazy val jwkEcdsaKeyPairGen: Gen[(Jwk, Jwk)] =
    Gen.oneOf(
      List(
        jwk(
          "kty" -> "EC".asJson,
          "d" -> "sNdauBgjSH1WHTQiNkh9Wj4B1NEmUwUQhbVsvVcjbyw".asJson,
          "crv" -> "P-256".asJson,
          "x" -> "p9PE1rTE7gpF4uTVOtcx9W_6MnpGGg78q50ZA90wSPw".asJson,
          "y" -> "AEhWKMZsHgNPV7BHUCHab6gURnGfKfsCJJ6E5rlJwnc".asJson
        ) -> jwk(
          "kty" -> "EC".asJson,
          "crv" -> "P-256".asJson,
          "x" -> "p9PE1rTE7gpF4uTVOtcx9W_6MnpGGg78q50ZA90wSPw".asJson,
          "y" -> "AEhWKMZsHgNPV7BHUCHab6gURnGfKfsCJJ6E5rlJwnc".asJson
        ),
        jwk(
          "kty" -> "EC".asJson,
          "d" -> "-3PPr5oOw8blT7XTmAccfUqmzLAB7hUNaa0wzilVagQf-7rIt8R3mQVLejH7vIT9".asJson,
          "crv" -> "P-384".asJson,
          "x" -> "R067CNQYLDplCpif64r604PNXHlomWY6Ki0B3NUosqTrcLSMg0BZQuMw1gZBE20t".asJson,
          "y" -> "cZSsvaFJdvLzf6k2IfQap5CIzqjWi53csqGDNZUKASBajAK8cDC9lQfl5bl2lwiX".asJson
        ) -> jwk(
          "kty" -> "EC".asJson,
          "crv" -> "P-384".asJson,
          "x" -> "R067CNQYLDplCpif64r604PNXHlomWY6Ki0B3NUosqTrcLSMg0BZQuMw1gZBE20t".asJson,
          "y" -> "cZSsvaFJdvLzf6k2IfQap5CIzqjWi53csqGDNZUKASBajAK8cDC9lQfl5bl2lwiX".asJson
        ),
        jwk(
          "kty" -> "EC".asJson,
          "d" -> "AVQ6ds0oCkRBc-Xct-b-3LAbPvg_RZDI1POtd8P_hULBWemOV84XPrF18uFjAmFPEs6xherQNmD_dVoea90yo1fC".asJson,
          "crv" -> "P-521".asJson,
          "x" -> "Aa0RijdnDNoooBlbP42Yl8v0bIOa8WXC7eNj-2ucukRPlaY_vWW7YRbQxHNSn-H-Q9hH4lhDM7iKKiDXYTZey3eA".asJson,
          "y" -> "AU2iBj8Dr_7DtzbvtjetYD_wDFgPq6cIjXAO_4nmPC0z94_z1LkUFDBnmGDeTpwO1jaulg1pOjgjzfZ7ZBiroYll".asJson
        ) -> jwk(
          "kty" -> "EC".asJson,
          "crv" -> "P-521".asJson,
          "x" -> "Aa0RijdnDNoooBlbP42Yl8v0bIOa8WXC7eNj-2ucukRPlaY_vWW7YRbQxHNSn-H-Q9hH4lhDM7iKKiDXYTZey3eA".asJson,
          "y" -> "AU2iBj8Dr_7DtzbvtjetYD_wDFgPq6cIjXAO_4nmPC0z94_z1LkUFDBnmGDeTpwO1jaulg1pOjgjzfZ7ZBiroYll".asJson
        )
      )
    )

  lazy val jwkEcdsaPrivateKeyGen: Gen[Jwk] =
    jwkEcdsaKeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val jwkEcdsaPublicKeyGen: Gen[Jwk] =
    jwkEcdsaKeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val jwkEddsaKeyPairGen: Gen[(Jwk, Jwk)] =
    Gen.oneOf(
      List(
        jwk(
          "kty" -> "OKP".asJson,
          "d" -> "5h1NYZg7SoQgbivlpWgcleu6qdMsHNPCmMDWZVl3vX8".asJson,
          "crv" -> "Ed25519".asJson,
          "kid" -> "VCZXu7zoBvQNv7ijRyFjW7i2-wqoVOhyPjuBGDz-MY8".asJson,
          "x" -> "WOi-Abi-43CqPVHQx8eQ3KxQRhYx2BrYmTOPonrKhJ8".asJson
        ) -> jwk(
          "kty" -> "OKP".asJson,
          "crv" -> "Ed25519".asJson,
          "kid" -> "VCZXu7zoBvQNv7ijRyFjW7i2-wqoVOhyPjuBGDz-MY8".asJson,
          "x" -> "WOi-Abi-43CqPVHQx8eQ3KxQRhYx2BrYmTOPonrKhJ8".asJson
        )
      )
    )

  lazy val jwkEddsaPrivateKeyGen: Gen[Jwk] =
    jwkEddsaKeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val jwkEddsaPublicKeyGen: Gen[Jwk] =
    jwkEddsaKeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val jwkOctGen: Gen[Jwk] =
    for {
      secretKey <- secretKeyGen
      key = secretKey.toByteVector.toBase64UrlNoPad.asJson
    } yield jwk("kty" -> "oct".asJson, "k" -> key)

  lazy val jwkRsaKeyPairGen: Gen[(Jwk, Jwk)] =
    Gen.oneOf(
      List(
        jwk(
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
        ) ->
          jwk(
            "kty" -> "RSA".asJson,
            "e" -> "AQAB".asJson,
            "kid" -> "nThox+srn6aa8l9uiLQ/uxwUGnk=".asJson,
            "n" -> "zbWI7hvhh8lTkgdjdo4Gn8DlnGNOP2NMS9YhyWMdKUPTXIsDb1f5fRyHWKUOinzeTXxcYmQQnVVSIW-REVUHfrICecnvX9R4AzflVUEacoXq_951A4Tx1xy6Uxt2k65mVstqZpLZ04X-llascCpMtXQl7aQAQ7ix16VKA8CPx7rfx-wckiL2RM6zm_eMWbFx2jrucXBEG1pe6y4uKgclc6iG0dZA2t6hWF62dHjz9PVRGkMzRLnUDt3M2iUW4vLUpTTwMbu_2Q3pPELWErJpzgI2l-_rPT5RZRFXOhepWsQbNIRpFHaF_ZYf9v7fKQaYDGqrqBRr5b-8gM_97CL5yQ".asJson
          ),
        jwk(
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
        ) -> jwk(
          "kty" -> "RSA".asJson,
          "e" -> "AQAB".asJson,
          "kid" -> "rXsmICLsKAZBCPI6mCq2-u7uhNn8LmxwvYBCYJJISjs".asJson,
          "n" -> "uQ9p7ZghuUTShPnVgomGptoiSyOYY3FdjLUY7e9_x49YdiDfA139LrXqzryuDkwBl4bnxsFaVWjdYjaTJOyQEBMyvgCywurVjJ7J7H3jy8TZ3xX2JY2OfmkGpL890x1jgJqROc5F0MSBZ8-hppAJ52PblnBPkhvJuLp0ACtGwbmsJqRyLvacGMA-x0COPU7iOTWcQtI6y9oUcXAQBUEC89B6eT8iXCz5T5uOLbr-Bu3OdXCgoEc8BHN86YK-C_zUCl7wbPCxMV0vBZTnzQKxec_4r5Us3yoQWEwJ04H2JdV01yUeMtrQByc3ScxFubbQ4Kp9CwQu_clg3FsA04kvRfegSw2Re823D6ESVmZ-lbhr1z2nYL5uxBjEjc_gJUflJRrnlKylbi00dTGhdwrTrBBMXDc3QJwNudi1vtBJvjRxTcBW7sYd41wmK-USnb9S1F7S0r3dkIfmuF3dvgr4PqwRXcwPpW1NE0xR38yGMPlG8ol3IMYFI_CwfwJq6oSTrbnCtYYQXEFZ4ycRaSJ32_6Qx8cixUF5hZ6hOwiJO0qQOvqhQUWFiQLAuMYi7L9ZFc5AM_stv_AKyKzn_ITxC1bz-a0bvRNDJtZaqbXSzlWJMqmkvLyHRHwNYSMHl6CYAvj3tOwkiEiT6g0mbYgjZdSlyFJkEQCZNW7e7d5cXhU".asJson
        ),
        jwk(
          "p" -> "5rPwnOpWocuxIX82BBuLh72YLhvehLxI8b8HEKOyRQBsS3hs9nlFz7YyVeSiebTSHl-z_GRsB3Gz9cv_1TNb2BCC1UyGU1_GYRtMC11itYgjYBlD-I-OsEDOkF74t6AaNC388SQqT0dP1nkig8qoIsvHTyBE-o2lBju3KIfOVo0".asJson,
          "kty" -> "RSA".asJson,
          "q" -> "2bXBdy4QylVJ7A_g2FTTwtBzOgiO1bXCzsplBWbcKhB0Sj2UCQk2a34sM2ocW_NMoIuuFH7bYQqrVvLSmDq7jbEzaw-TUvNAKsIj_7ps9XRdAbLrNB_Hkqbd48oEBqmVm7f5VlDZPKRqz0pv44SCP2XY9_xcKGH7lrq7ED-CjMk".asJson,
          "d" -> "LMVsAkhDJkj9EENGzZUWrLZR6mDswSxmDEtb9FqqTsnXkYJJrf4fNw8CeFXCHCFj3ijMrLEpLsoFxYxHs93K1BsTiSKDLNRh3eC23neIzuo-6-c6lwyj-MPGvbxk5Z-WLmudnwgnXKkFsd6Nq6T81c9BElBNpKcG96gnGlFqt8EL_96GtBohqYqE_nSTyn2BCgs9l1kBZRxxZK0C2ipJqOgUmMPhGVQSPVGnz5L5JN_Skq61jvJoJyCf0FMDvIadRk1X6volc7P5dajc5FC_SYqrNEOWhozIfjeQMNtH1ql3UMspCmQtA5fl60Z5PIUz_j1bcD6UPcy83GUG_anCeQ".asJson,
          "e" -> "AQAB".asJson,
          "qi" -> "cm6468in5_O5VMvdOA5VYxtzRosI_kzraoOQzDL-rx98pKZ9OypPuH5mZyEIMBn6pBUFwjoo16HxrBvUd2SqcWt_7ofatTbwi2XPK4ITmcgK9nRd2mauvXmFvUyE37XcMmqrKWyAfwbADYz79mvI8izEWnUt3sUQLvhMN3550Xo".asJson,
          "dp" -> "unQ9iCShBbzhmOf-WQ2GFJv37XQawH6IGdHBPQKAJuJzo_9dWUqkUH65adASPHkWxPOmPNtQsCeGQaaxSrdqiFK32voxKhsi8wKj0B-Wko7HwHhLBg3ITczi5a3MKGReKUPtxVrsUwyYiwd2DLvybcTyfZHgDfwCnuoOWtR_wFU".asJson,
          "dq" -> "jJWh6KQGk6GfqqBWQVwForeYsND162sD8SUhNuvFICSf85DwFyWrzp4bTNgol_f0c3e_YdzJLVEGc486DrNeiZDz8x6Ls_UAapwTQv_PfHE33fD7kR00cq7uejnpf6PiyDt09xgeL9q8Xj9jIThgIzBRe1Gq8SjUnfDW-xcH5oE".asJson,
          "n" -> "xDJShzEjutRgjF8J7h5hO9-bXBPtZQtZO9imjPdyvC-2looZvcbSXxn2vJTYqEI-39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6_X29NVTb2yulhl0Nnj63gnTX9CGt4TaB1k9X7bYdYl1C4DKTP-PEiIsa_Nq8CFoRYRltFtoyO5Hvob7R_VhR3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q-9oQ-bHCZcbwPW3wPLkvb5TfK3Nygb_N-JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR-1qe6iQQconbgg5HuFlNAeEicTZ3ruEBYzO_0_nh78HvEQtQ".asJson
        ) -> jwk(
          "kty" -> "RSA".asJson,
          "e" -> "AQAB".asJson,
          "n" -> "xDJShzEjutRgjF8J7h5hO9-bXBPtZQtZO9imjPdyvC-2looZvcbSXxn2vJTYqEI-39E24jMRkPPEIcYwa4Zj8K2RVDLcsj1I6_X29NVTb2yulhl0Nnj63gnTX9CGt4TaB1k9X7bYdYl1C4DKTP-PEiIsa_Nq8CFoRYRltFtoyO5Hvob7R_VhR3XOCfP70AkUCSOBsShyG8UOUUqhRXcWJ8w6Q-9oQ-bHCZcbwPW3wPLkvb5TfK3Nygb_N-JcX3dM6txWfWvEPCevTiaP4ws8MCzGT9DrsyWLhc7pAR-1qe6iQQconbgg5HuFlNAeEicTZ3ruEBYzO_0_nh78HvEQtQ".asJson
        ),
        jwk(
          "p" -> "uoFLCQhD-RMFotVmZzlvA71jLaVxzsKNo_a6gNjBoFXc1bPT79Zc11C_podOKSXAPLtNTSVYTWR6r8khOQJkBe54P5WYQCeR5WsBVQJ_hHPxXJKVGepQbSW82DSk-fupfp5SxEsZfq6JyvI3j8NZtmiY--FhaJMQmCW9MyaIlspfKfU6wUHEsMMRVWQGLCVhoYjQyWcBCHn2XJziOPSuqT6Q3DC6kv1iEGdUFEORPZVVRjaDNRDI1AKXiQPHB0Nv".asJson,
          "kty" -> "RSA".asJson,
          "q" -> "tsPaWZnHRglD1LT6zE7eKWOoSpBuwcCiFV6M-b3A_uyU-APe_VrVVFjm8_kmt6TUnJXSEYxrmBQRJxujD3iRZVpsQA8pGOwn5S2mZDW4VfVIfuWL0noXV2tCTLEo9wbn0atYmbmqaVAzSrIQl1s6oJ4lVQDhXyxRrPQlymOm3dLo0zzOpmRs3Woy5HkEtAd5IxMXWNgbwRO56XHUgN4n5MHkYhtxOnnmci2knrXMsAbGwtWExMRjiW4rmjWADfmv".asJson,
          "d" -> "PY8lJCOG3OO0NlwbpdHixgm8KNJgDlnEzE42mKE5qONY-mubt1wxSf3DHW-J0OUyPl2EZptj_UqInaQBIIUiT9NawSDFMJ4WEdytktWE-0D_wYCjc2_w-63vvwfst7qHnXEAv-coCpkT0IDPOA0ODpnW19EY_bmJMAVZrIiiUNzYTIviDvVOMt19rgHVjLhKiw_fiuXZYHedXSLIKVJo7Cbf1Jtxh0sHiEakh-nb-23q9CsMVySB0pA_qOZWkUrPajRnA4vdIb7to_SnNDtmVOpyai7lgq5UAoPrv4HPjx8B0D5YqEhaO93iUSAPzlQ5m11BHxW2_jVyoeuNNuPrBxSd7H6etI_8cOhsBGfOn8DMmhkUtmBVGSGnH0gecyFIMyLj4t1l_I_Anj8oU8a69B3OtGrPT4QxBf0dBf3zb12xF0p1-u5cXoM3kz_k3Zt8LZfVDJLcktVA0L8Rpr3OuDaezDoJ2G0NskReefnp8I7PSPiohZrbQOAAg1i-CS0P".asJson,
          "e" -> "AQAB".asJson,
          "qi" -> "rzsru9vUlY75x7L3k3RrGe0xZ07jQONmeWG-M9ySzBLFzGtcGyHnZ0cKRmhaqVhbp9hUgZ1aqPAhaJ0yd5xDjaoiBOUne6WMFUV2HsTtl1NbMj2ThR1QpENDxJKP0HFMl2YCGw9e_3_0bjH-sAWc-m1C_AM5woS4gbCOT1ObeyB3ohwdS59zFrIr3YSvsYW0T-Ka8rr3mzeQ6E6k2RoT7AOT7clQHFz3G0xkhR_gBIAZH5i-ktaqAWSflnUtgHk5".asJson,
          "dp" -> "A81O8kgw2osAumkPRVtuX-0kcHHG-CgPKyCEfMvuZo5ZiiG4WFNOYTVMMuDfPwd9-771vHTeb_V0atD21GqwD07lNKagC-7CkqKzzD_YyaJzcSer0nNsYE08pEuucUooEmS32ziMtIBqXrDBYTTiR02qkLfvfGpDFFbwnHJUpn5JollVcUsd71yKper8FTpN2zUmzHRFGR8jXo_0LKUQSnL0EQkNRKHVte_lTuRxuYepzVyfIB3PekLzQ9_H1uYR".asJson,
          "dq" -> "I2-4D3VsmNzFBSIOGr0UAExtXf_BKdoS0zfg969eE0-F1szRWKhbAp62MQnXAvZ3ruCxuWtTlUoWxVFrfV1wO4mbwZPu8QEg_yOpxnZQBoKnissxIB9CFVYbpckX20XAfvvNEwlXzFGbkFkUNHSg2nGvZVrlV9G9CF7SUPqfaRUyxXpdyw9fuFKWCYyZZ9qnFzDlbvl_8CDGBEho3o-0hns9r_QIMUFfeDX3XDp9tIer1C0YMBqv_f6Zf63t5UfL".asJson,
          "n" -> "hSaa5_Si2WfVq87-9uJCp0TSp5-5CN_KHO3uVx2wHaXFrLkrScEv8gAegs3jEN5WEOvZ9rZ6Tgfh0lr6CQRr73iRU5yB6Ap_26imTkFZ8RZeZ5z8Z9U3x_2ycCP9lKY4QvR5FOOqdd1FC7hECdqUko4h78kwl8PeKqEyEmm2YTcinVR_yh-4BB7X6Nh-NzIkiVEAVPDiA1QuFkxQUSHJC0pUbSNJz_SRKiHg-Ll4of_-qnD-GKt0dzLpRxgN0cU3EpBbRKv-fmPBh7-ImieYTZepsvNPLeProvFWoao8JgekrmcbgleYxLeQSAjRf8jaY5ZqsPTgTAdD4Nkbt4oChOuQrEaUkeO_i1RDpNKASFgnUtaKST4hmDCygLo9PfT2nK4V9SO5ratmO7LCgqxSUXtWgD6nBZKzpdjtQKiGakcyyC2zUk0ujPpQzmi0hdmfLqTTbK1W0iCyqz_-7vrizk9UT-h3Gpd2VOYYsbFxuDxGjHzEEcWZwptGzzwLMQ_h".asJson
        ) -> jwk(
          "kty" -> "RSA".asJson,
          "e" -> "AQAB".asJson,
          "n" -> "hSaa5_Si2WfVq87-9uJCp0TSp5-5CN_KHO3uVx2wHaXFrLkrScEv8gAegs3jEN5WEOvZ9rZ6Tgfh0lr6CQRr73iRU5yB6Ap_26imTkFZ8RZeZ5z8Z9U3x_2ycCP9lKY4QvR5FOOqdd1FC7hECdqUko4h78kwl8PeKqEyEmm2YTcinVR_yh-4BB7X6Nh-NzIkiVEAVPDiA1QuFkxQUSHJC0pUbSNJz_SRKiHg-Ll4of_-qnD-GKt0dzLpRxgN0cU3EpBbRKv-fmPBh7-ImieYTZepsvNPLeProvFWoao8JgekrmcbgleYxLeQSAjRf8jaY5ZqsPTgTAdD4Nkbt4oChOuQrEaUkeO_i1RDpNKASFgnUtaKST4hmDCygLo9PfT2nK4V9SO5ratmO7LCgqxSUXtWgD6nBZKzpdjtQKiGakcyyC2zUk0ujPpQzmi0hdmfLqTTbK1W0iCyqz_-7vrizk9UT-h3Gpd2VOYYsbFxuDxGjHzEEcWZwptGzzwLMQ_h".asJson
        ),
        jwk(
          "p" -> "57JaO_HQ031LEx7dhBKMm5ZNSNJKy7o1j-4vfNRnNPriPCSWWYu2igzQLFQAccj-Kr7sMYmyLBBRe52k5kvplJ8iQoCBha4TDZeeTayFbXUxEETPI4A1Z4i-C3T16xB0FJZY7NQ_4fUr8rUwOhtd3jhU80-xoJUIWOaKO7JtiV65aMXrxzNShLEzuk2Zn-MNXYg-TP_-ouqRXmya5hl3XmA3g1Kwhti0XJv_ecAyStwC4NZVt7nBd4eaHyGBIdWk7y-4w7SFT8wkF0jaNslmQEDe1gjeC-DBRAiurj2gZkVjJnrXycheIj3FXI5A9KZXyJF9gm1SAt6_tUDY53IdFw".asJson,
          "kty" -> "RSA".asJson,
          "q" -> "7eDzHyGnHp84F1RCcPz7mWnrmAFgS29NEPdjUu-KOgi3RciWdOB98He1Vikl44JeCvATZyUMUiNrqWP07YHk1rkYvWG2nQ64RcsIGFyUe8TXY6SlJtg81Moj2cB7arGoI7OaJqWkjXH9-y46PHpHfhk6s9-8N0Lu2KSn5ocXG78gM8gwpb-eiVxmFdI7A4Ps3JyLKduAToxlt_HL19clGagWtbb7uP4azCRDl0xwFkeGFisDYARYe-nuOjGe4OgUMt2uUKrZ7g4jgs4A0OO9PocPBfx4Q4JEX_wsn2Fh5zOkaciEj5787tQhT0CqzEZit4_pGdCSut9m9EsO7mEhZQ".asJson,
          "d" -> "C_Ju2ylwKZ1zLN8yTzRvKwET47vY9_wqzPWtd8cRjA8Tgyy-Sz3PkXCqwnZQfpO05j9rHB3PDqhZs_dDutF97lXCSjrjvF8eQIaxYHZXqLcWRKPwoHWmOpjRv_ganNqbga_TWffzneaHhm2bydD4eR6LfD7HhjB4FWNT4JYZHCNPJRQ_j25lMkUhgqUxXEUnde7Q6PUmSr_uQhtKJ-leiueW9vIJaaKfhJx_w0oge3e5fQteAgCNYEmxtDYQZXHOxBWI2K0uFAacbiIp2YVUnPZw7WEvBtKmomWv3PR4PwdV9lG9NotXZRLfAU3-hwdtWNDZbhx_w0fQX9WPw8yM52bhl0fJxc0Ep6csg7lwaJdzo08YnvA7ZWQaYA4Rr1yoKkNTQTwaG_awhLc2mywvnuk163R5LSIdZXNPtX7_UBOFIh9U-FBgNF6JaDvp8QC69z_7hjRqT5IdW9qlWTdT8DXxvnYDKVC9LhPFKz1R_FafLZE3tZK95ycaJBEUupqRJych_Xr9PRWsvmuvffR57JlRY6k90_Nm9Ssc3XY_yKYpSGZI0o2obdPTuWUsDlJtFrFsL227I4awDIwDECpTYGx2H_vHIYPzetLtjC8QBPeEjred5B53g1dhIh49txAdYI8FJrkrZTq_JBgoqbT8HdglAiBGK8QB0ZUVQ_ojV90".asJson,
          "e" -> "AQAB".asJson,
          "qi" -> "GPs-w_ICj3dPLfqLrqG3r8nfAFilCvHqDgvtwAvmk2MtF5o9hmYuKcdP08GshfPe1bcuoKUwCpLZHq6mNmL8L6VreLYvIMbneBHp5JF1bIAjql3WaXDMUt7TdlxvIa7b0AZst68lQc_CLr7xUM6IYnNnsxTsV1MCg4NNe631l40PNf9RPh3un9Ht02AlHzVI54jah0EDrg-7E1H74fSJA6vRNIPGSpq09jEvuzUgB_JsopNF1gf2Q6QqE9jPCRjBnryA2eJYAzxSXWb1HjKuRRezsJnzTlA_H_Q3BK6B126mjhOOnRMl3BfW-qvoBvJ2uFIJ7RChH58KMDz-Evfgvw".asJson,
          "dp" -> "NYPDRa8vnXmF-o-ZeGTUZydLCHPR5MZIksrf2wQwJlOAJ4YH1_zmF3KoLmTkiWN0GSlp4nM8XOMT_upFaQ_FjpdG0Xde8yJmsi__107urn5v66MI-Nkm_Jff1UOZfUaamRq0xVasvqLjGLbywakKgEYgkOYqT728ZNQyv2ER3bWsO1_jemoHODC5kuFTh1NpBd5vDVffV3-4Pcf16wmcwYaVq9ZQgYTR-8XoNxXGR_YTEB1RRRM5dUMzvNb_PXJcGwa5tTIfzHOJLnucMyVHYbXaAjOgHbw2x2D9_66qOpTyNrQO3UNTQrNjv2H37Mny4peAFrzrQVBzlQi6UJLR1w".asJson,
          "dq" -> "AT63JwePD1r3-S9ItbytOG1UfVQsg9iOR7NzwqBcUddv1h6pouz128dUnKHUf-9TvKzq_RQ1j0x-KMHMK14Nq44Gch9LzGCiWEMqxK3fXRJ3qh7Xem-RSe_Q5jfarYFGhwFOojsltFPPZ3wjc-OT8jYBl6VpH8Tq6Rlbg5pbZZrHeV3n20Y4dzGTmzOheXA8Uh9DnzF153NWqPLMBVIr8IlvrP3LLXmu_DiIXgdZYtR3ADCzcNI1AFkGFSnjUfwE9wsv-V4bi-JpDysy1-UJPYWJb5eVrYzF_NaeCSuCTqp3htI012eWnU1g60BEZJNNuvY22xq7Wd0Hdenapya8_Q".asJson,
          "n" -> "10u1ouwG_QElj8vR-b2NPkWqf46jbt3tKMOM_H-hPIf0HQkcGvXIlEesl-PU93Aca4E3StN1E7Ibq8y_gZj1TL_neJ2RjFd82y04gFiMIBbUY1DXflL6s-GRU8TpKY0i1oDSbfGqVj3ly48Kzc_1Im9phiMQHykB7P3VI-USpLXMWdtmyVgwIhPf3o7b9MX5J4-SO8SVFd1qArqpaUFKTbMlIYLXx1AJNOrPhv6QeQcuUGj1sKDT7TXCmk8IFoZFIE3fkEu_xuOs6Q73FLRPPH2y2CtUAbqz7ZRjKJri_3lSYO0FBZKc220SX4v6_PNKCxDGV2ZUttnzpAvoRYoMGoTwjJVshKMQjr7Cl2g4qc9UkUfwnTFxOtraWF2j08h7TCIVaqz4mMpIkT0YnNNEi_WjMB35KDZqPUlJGU7da1FNX2HqmjeyRKdGM_BHwsTJyzcKjlvk3h-XMljc-O6or3dQmVHLWjMcarj5WA__pUU6Fy4C6AjC3h1Ji_CHR8Cahhg66xcfvYJkmQSeo1Fhxg43tKEbrTUpJo-LgUzG4Wk9vvlH_ZZQ06Ssf0bSgj5mv81F7oICcppKxDb2Ce5Fe2UM5_FgLcHU2_bku1thUdAFKwgUMegqKIdN_K8jk5z7PtWbdIpDztWLIVNjpekfVD_f7Ex94DOeM-mo8218cRM".asJson
        ) ->
          jwk(
            "kty" -> "RSA".asJson,
            "e" -> "AQAB".asJson,
            "n" -> "10u1ouwG_QElj8vR-b2NPkWqf46jbt3tKMOM_H-hPIf0HQkcGvXIlEesl-PU93Aca4E3StN1E7Ibq8y_gZj1TL_neJ2RjFd82y04gFiMIBbUY1DXflL6s-GRU8TpKY0i1oDSbfGqVj3ly48Kzc_1Im9phiMQHykB7P3VI-USpLXMWdtmyVgwIhPf3o7b9MX5J4-SO8SVFd1qArqpaUFKTbMlIYLXx1AJNOrPhv6QeQcuUGj1sKDT7TXCmk8IFoZFIE3fkEu_xuOs6Q73FLRPPH2y2CtUAbqz7ZRjKJri_3lSYO0FBZKc220SX4v6_PNKCxDGV2ZUttnzpAvoRYoMGoTwjJVshKMQjr7Cl2g4qc9UkUfwnTFxOtraWF2j08h7TCIVaqz4mMpIkT0YnNNEi_WjMB35KDZqPUlJGU7da1FNX2HqmjeyRKdGM_BHwsTJyzcKjlvk3h-XMljc-O6or3dQmVHLWjMcarj5WA__pUU6Fy4C6AjC3h1Ji_CHR8Cahhg66xcfvYJkmQSeo1Fhxg43tKEbrTUpJo-LgUzG4Wk9vvlH_ZZQ06Ssf0bSgj5mv81F7oICcppKxDb2Ce5Fe2UM5_FgLcHU2_bku1thUdAFKwgUMegqKIdN_K8jk5z7PtWbdIpDztWLIVNjpekfVD_f7Ex94DOeM-mo8218cRM".asJson
          ),
        jwk(
          "p" -> "7IGEM0YWF8LKLdlWBgoJ5S46VxJSub6pXT0rdAnfTl--heBalhoPQJYtwS-8ew6JPp5ax4pa7REP_6WsDb6rfdqu2ma-ENYxOvsYCjyCG8ypuM8PJ-FBPYqLxHht_xRQtoo4Xyr4NP3sUlPA4gIHhNLzdtqHNstKbix8OhO68m8".asJson,
          "kty" -> "RSA".asJson,
          "q" -> "2ZnpzxwleJU_vigi2of1jGdwJTWa4f-tO5pq0ROelCme_vQYZVwmbpbTppKPSupV6sejKPgE2zU1afWEoceZU92ch99HTB47rwcp0x5KVeEQUPJPW5xASfgDPxIJm9u43ejyARG86Noid9FGRjVzgqpPhTq94aVMg6bjXlUqF98".asJson,
          "d" -> "Pi1XjOjKPAWz7YWCxiZ8cZfV3KnGGEBXH8CJl0MPZpntqli9p9XaaCcvdFydfCGZQn9-wdd9QGpomIJIEUF6PnP5M0dtKEJJOYCuWH_hTxxPObqjboIzSj6UEIqZyPfqep0wbl3u-AGNaY65kKAhIITiG8TYSBLrlUqhSHu4buwEJZCLu0WnlkuFQ_kP1KxBgCFHp2f-jQCZ1aGr4Dp35TkWBzMuUCcqfn_-uG1krG-OqmyZThflwNEprI10OYDcl3-1QOC5wvAPA9cGJkQzR3t0RAjKz3EwtvBRddkxPS7Yavjy1RG_vG2KFnVIUBbAFZbsi2IN1GYxphhE6Joj-Q".asJson,
          "e" -> "AQAB".asJson,
          "qi" -> "zoWYocJq9TWQ1OPHkbRi9wwduTbhyqxHGL4CyXPnmnC1qlI94L6bzjizYShulNeDzLUaJv9aMav0sh4vPUbmXu8_h8jTrnsh0z-Hv_4qRygzMBLtBBF4_NcrDqQ0tgu0S487u4XBxBaw3DfA58JnJVXFD-gTMHZsHbi0-2VkzCA".asJson,
          "dp" -> "IeAPOnTgdzjMUrLdknHfpvbvHkeel8JKafN4BN_hH02xcWWINBW5d4vLM--NdKbJW7G82PXlPi2CeCCXu0RDNfybrOaodKrpVERg1h6CmE7BRJpL1m96M8FjcZm6T53uTacQmfkCojx4m_YpG3Yk845vlueIFH4bxBoVFRB8Z3s".asJson,
          "dq" -> "1FT5750Ze1a3wohLqk5s7rqolcZ_AfSJR9XgUXABl7Ydbc8mVxHadqM6mBn_NS0A9X4k2f9aTcTYADMRXwPzvABNk8_uNHpz5tDooRe3laFuWG55vXz0xrj6AftJ4QpAlFmQfDagzd69L4nINw5FTsV9nxW434x64yRgTVZxIqU".asJson,
          "n" -> "yQf6eLEa9ixnmkZgFLpxt4-KP7LX45bQSXLrkBxfzZmNh5hwKEGzpGFkzY8DuPXJpNMUgH7jyNR906GJ4g_1FlTqmJ9wuhnvObC8PriQq7ssZ-N41AtwlcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZhMd7_AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm-5UASGETzDtuN3_tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl668XAELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQ".asJson
        ) -> jwk(
          "kty" -> "RSA".asJson,
          "e" -> "AQAB".asJson,
          "n" -> "yQf6eLEa9ixnmkZgFLpxt4-KP7LX45bQSXLrkBxfzZmNh5hwKEGzpGFkzY8DuPXJpNMUgH7jyNR906GJ4g_1FlTqmJ9wuhnvObC8PriQq7ssZ-N41AtwlcJL0QBblW2xYBs3lubiWFzRykAlk8LlNVjefVJrt0tkz7UdQ5ScPC33ISwZhMd7_AjBIoPcxzHDBkfLuqzk7nIqSVJxfnckbvTv6ApHDbTllFij2wAv4YkK3Ctm-5UASGETzDtuN3_tLlVlXM3nBCjXKhDjJ8EsPNQGxLEFLEXlEitL3Alp9xXzphRl668XAELN7vc6eJYiZPmo1VJYtFWmlS9JnNcnsQ".asJson
        )
      )
    )

  lazy val jwkRsaPrivateKeyGen: Gen[Jwk] =
    jwkRsaKeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val jwkRsaPublicKeyGen: Gen[Jwk] =
    jwkRsaKeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val jwkGen: Gen[Jwk] =
    Gen.oneOf(
      jwkEcdsaPublicKeyGen,
      jwkEddsaPublicKeyGen,
      jwkOctGen,
      jwkRsaPublicKeyGen
    )

  implicit lazy val jwkArbitrary: Arbitrary[Jwk] =
    Arbitrary(jwkGen)

  implicit lazy val jwkCogen: Cogen[Jwk] =
    Cogen[String].contramap(_.toJson.noSpaces)

  lazy val jwkFunGen: Gen[Jwk => Jwk] =
    Gen.function1(jwkGen)

  implicit lazy val jwkFunArbitrary: Arbitrary[Jwk => Jwk] =
    Arbitrary(jwkFunGen)

  private def jwk(fields: (String, Json)*): Jwk =
    Jwk(fields: _*).fold(throw _, identity)
}
