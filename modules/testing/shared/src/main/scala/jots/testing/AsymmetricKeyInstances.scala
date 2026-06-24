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

import cats.Show
import jots.JwtEcdsaAlgorithm
import jots.JwtEcdsaAlgorithms
import jots.JwtEddsaAlgorithm
import jots.JwtEddsaAlgorithms
import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import jots.testing.ScodecInstances.*
import org.scalacheck.Arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen
import scodec.bits.ByteVector

/**
  * ScalaCheck generators and instances for [[jots.crypto.PrivateKey]]s
  * and [[jots.crypto.PublicKey]]s.
  */
object AsymmetricKeyInstances extends AsymmetricKeyInstances

private[jots] trait AsymmetricKeyInstances {
  lazy val ecdsaP256KeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
            |OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
            |1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
            |q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN EC PRIVATE KEY-----
            |MHcCAQEEIHr2cy9YHQBa/PIW9jhf9jcQKSQsxghA3X0qelUDt9IcoAoGCCqGSM49
            |AwEHoUQDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJ
            |wqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
            |-----END EC PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN CERTIFICATE-----
            |MIIBvjCCAWSgAwIBAgIUA02+ctesTJ0HOM70SctAeQYjfRYwCgYIKoZIzj0EAwIw
            |RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
            |dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODAyMTNaFw0yNjA2MDQx
            |ODAyMTNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
            |VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
            |PQMBBwNCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnC
            |qfMPWiZqB4QdbAd0E7oH50VpuZ1P087GozIwMDAdBgNVHQ4EFgQUmqhY86bNahvs
            |dgzyEo2l01rEznQwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA
            |ztVK1oNnyBB40O4ANGZqqFI8mXbN1DRfs18i9bzqxLgCICCSPZ2t85mIVr2O40Yz
            |VnaKr4ju6I+wQj3Hb8kjXvB4
            |-----END CERTIFICATE-----
          """.stripMargin
        )
      )
    )

  lazy val ecdsaP384KeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN EC PRIVATE KEY-----
            |MIGkAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhske
            |enT+rAyyPhGgBwYFK4EEACKhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+
            |T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLU
            |PeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
            |-----END EC PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN CERTIFICATE-----
            |MIIB+jCCAYGgAwIBAgIUOMZZ3fCwXB7iH9jNK784VCWToHcwCgYIKoZIzj0EAwIw
            |RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
            |dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA0MjRaFw0yNjA2MDQx
            |ODA0MjRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
            |VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwdjAQBgcqhkjOPQIBBgUrgQQA
            |IgNiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GE
            |tIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx8
            |5ii2vMWjMjAwMB0GA1UdDgQWBBRIBAaWNI56zB3mhE3gxbtzM/hddzAPBgNVHRMB
            |Af8EBTADAQH/MAoGCCqGSM49BAMCA2cAMGQCMHP8qtQn3ACDGFDAYGRlOyuk4Ztv
            |YXIUuAykHaxaeBvbem+t5q5Tp6JgdQ5CLRz/iQIwegepjo3MC4aX1wJxoIU8bua0
            |ymnTWAGj6KMYPE/jUf2uw3+NDrdAOThI1vsmG+9s
            |-----END CERTIFICATE-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
            |E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
            |MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
            |8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
            |Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
            |1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
            |-----END PUBLIC KEY-----
          """.stripMargin
        )
      )
    )

  lazy val ecdsaP521KeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN EC PRIVATE KEY-----
            |MIHcAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx
            |0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdn
            |P798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+
            |duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcv
            |VtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==
            |-----END EC PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN CERTIFICATE-----
            |MIICRTCCAaegAwIBAgIUBCs/PEOXJgcLlYyIQZaDRZ2j8gwwCgYIKoZIzj0EAwIw
            |RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
            |dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA1MDUxODA1MDBaFw0yNjA2MDQx
            |ODA1MDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
            |VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZswEAYHKoZIzj0CAQYFK4EE
            |ACMDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0l
            |Rw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25
            |pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12e6MyMDAw
            |HQYDVR0OBBYEFGxBsve9A9/RL9prkrEb2LHcPbZVMA8GA1UdEwEB/wQFMAMBAf8w
            |CgYIKoZIzj0EAwIDgYsAMIGHAkFLBTf/3agyv8tr7+qqUUv2JBhnaPb5MYVLTdJf
            |64QK+V0Iq0Zyrtrw0FmYlh7YhZoS7bDk/1miGX64arfRpEZ6cgJCAWMz9iNlqaMx
            |ql7w+gqazL1/vZBdqTyelXXvrIA120MoCMOE55xp5CSzGh3gk/TTAoFumohBg52s
            |s4YrscdNUXNz
            |-----END CERTIFICATE-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
            |9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
            |Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
            |v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
            |jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
            |ew==
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
            |PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
            |6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
            |Al8G7CqwoJOsW7Kddns=
            |-----END PUBLIC KEY-----
          """.stripMargin
        )
      )
    )

  def ecdsaKeyPairGen(algorithm: JwtEcdsaAlgorithm): Gen[(PrivateKey, PublicKey)] =
    algorithm match {
      case JwtEcdsaAlgorithms.ES256 => ecdsaP256KeyPairGen
      case JwtEcdsaAlgorithms.ES384 => ecdsaP384KeyPairGen
      case JwtEcdsaAlgorithms.ES512 => ecdsaP521KeyPairGen
    }

  lazy val ecdsaP256PrivateKeyGen: Gen[PrivateKey] =
    ecdsaP256KeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val ecdsaP384PrivateKeyGen: Gen[PrivateKey] =
    ecdsaP384KeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val ecdsaP521PrivateKeyGen: Gen[PrivateKey] =
    ecdsaP521KeyPairGen.map { case (privateKey, _) => privateKey }

  def ecdsaPrivateKeyGen(algorithm: JwtEcdsaAlgorithm): Gen[PrivateKey] =
    ecdsaKeyPairGen(algorithm).map { case (privateKey, _) => privateKey }

  lazy val ecdsaP256PublicKeyGen: Gen[PublicKey] =
    ecdsaP256KeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val ecdsaP384PublicKeyGen: Gen[PublicKey] =
    ecdsaP384KeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val ecdsaP521PublicKeyGen: Gen[PublicKey] =
    ecdsaP521KeyPairGen.map { case (_, publicKey) => publicKey }

  def ecdsaPublicKeyGen(algorithm: JwtEcdsaAlgorithm): Gen[PublicKey] =
    ecdsaKeyPairGen(algorithm).map { case (_, publicKey) => publicKey }

  lazy val ed25519KeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MC4CAQAwBQYDK2VwBCIEIFxEb2I7tPuKvihV4PgA55HDyMoVPHs2p0/nqJOBeuGG
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MCowBQYDK2VwAyEAwmK6SSAu2E9V7uynkCKEaj5nZJyTvNG4x0KohsRzLpg=
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MC4CAQAwBQYDK2VwBCIEIFxEb2I7tPuKvihV4PgA55HDyMoVPHs2p0/nqJOBeuGG
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN CERTIFICATE-----
            |MIIBfjCCATCgAwIBAgIUFnH3GGsflOqh5rrurGfEeGbFF5IwBQYDK2VwMEUxCzAJ
            |BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
            |dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjYwNTA1MTgwNjMwWhcNMjYwNjA0MTgwNjMw
            |WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY
            |SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMCowBQYDK2VwAyEAwmK6SSAu2E9V7uyn
            |kCKEaj5nZJyTvNG4x0KohsRzLpijMjAwMB0GA1UdDgQWBBSVJJeQQBIjFJWvEfz4
            |lejlFmweOzAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBADDB9YKzJk8OmRRTut2Q
            |MW+4CCDU3Mu9YudDYzGW3OEXN4vIl4H2JtwmDnY20cWYLiLG5wMFBY17VICNQPR9
            |+Ag=
            |-----END CERTIFICATE-----
          """.stripMargin
        )
      )
    )

  lazy val ed448KeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MEcCAQAwBQYDK2VxBDsEOTH4JoDjxx0Dl8YdTH1OPghgrIHa24LHa9DsAkohUMaf
            |d8Emxcv/pc2hvsMvC2xNPxaxOU0slOiA9A==
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MEMwBQYDK2VxAzoAf3M0tGtHWy5tm+OOpZDApkBZaaQo0TUVpvGf8yO5B2c2e2GN
            |4VWN2wrPiwn7Z7E896ODjy3rc/KA
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MEcCAQAwBQYDK2VxBDsEOSxXuPqZdeVSZqME35+g9okZrvYttyJCUmpjtzOsqhic
            |FDVv9j9yyqcfICw/UgjzJ31vnYK0BObtQQ==
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MEMwBQYDK2VxAzoAO7oKc10tnqjaSqYoNU9a5Ffg4VK3t1rQ9wNVbez0i8ydDx9O
            |tc2V1cbdv3g/bOo+euoSvEMyd2qA
            |-----END PUBLIC KEY-----
          """.stripMargin
        )
      )
    )

  def eddsaKeyPairGen(algorithm: JwtEddsaAlgorithm): Gen[(PrivateKey, PublicKey)] =
    algorithm match {
      case JwtEddsaAlgorithms.EdDSA(algorithm) => eddsaKeyPairGen(algorithm)
      case JwtEddsaAlgorithms.Ed25519 => ed25519KeyPairGen
      case JwtEddsaAlgorithms.Ed448 => ed448KeyPairGen
    }

  lazy val ed25519PrivateKeyGen: Gen[PrivateKey] =
    ed25519KeyPairGen.map { case (privateKey, _) => privateKey }

  lazy val ed448PrivateKeyGen: Gen[PrivateKey] =
    ed448KeyPairGen.map { case (privateKey, _) => privateKey }

  def eddsaPrivateKeyGen(algorithm: JwtEddsaAlgorithm): Gen[PrivateKey] =
    eddsaKeyPairGen(algorithm).map { case (privateKey, _) => privateKey }

  lazy val ed25519PublicKeyGen: Gen[PublicKey] =
    ed25519KeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val ed448PublicKeyGen: Gen[PublicKey] =
    ed448KeyPairGen.map { case (_, publicKey) => publicKey }

  def eddsaPublicKeyGen(algorithm: JwtEddsaAlgorithm): Gen[PublicKey] =
    eddsaKeyPairGen(algorithm).map { case (_, publicKey) => publicKey }

  /**
    * Generates RSA key-pairs of less than 2048 bits.
    */
  lazy val rsaInsecureKeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN RSA PRIVATE KEY-----
            |MIICXgIBAAKBgQC3fJ9/iS28tDDcqZ+go6Snbem6tEN27veQwg6arattdZhYA4MP
            |WEKG8+aE2pp9tv3xNeSiY6F0CrXPpEAh37xDa9Edn0ehGDORXUYarSJrVVsrrfWl
            |IpXVw3oVrqG35ylkfhLjuQtX/rBtho3HMCXd3KBCug6k1iY1tF9z2thvgwIDAQAB
            |AoGAVjCrN5x3qJm4Dh97xVi5YpCl5zcALeEI163gcFY+HZfMrSNRMCcUcRIm6adK
            |RN1toh3fvUwxrjHNv7D3EzJm2zTdGnocLe2R6vhvQT+5X2tU2//9UC+wVBp2/gaU
            |X8F42rsUtTgYqWzTqcAh6rOLFIi2+09DCMzpnPT0syeLF0ECQQDlRHifx0Pnq+uC
            |YC7hAMLQn9OzzhPexiJp+wjb8q4LRrdS19vVK2M5uMg1z48IKE0QZ8pKqBOxgUGK
            |a80YmWajAkEAzOGexq7OnkpjwBYYxwMa5UZ0c5Yws9hRQkUG8GJdV4bvfuiAwLEi
            |WiroUSc9fbgg6UNfRyywXGGdL1F6GerBoQJBANfVgv1gOVQjbD470EYwUjbXEBUI
            |n3os6v78vlVZ/HFPLIyH/EONagdQJuNJuCyEzC/yleV8n7WOqqXmYJmU6KMCQQCF
            |JQKoH6YK3FEi3blQa8Yoxbab/zi7R5LXPECcK3B5lylBEhvKHdMzQbskMhoV/3jz
            |3mKmwHYEMzORMqPk/9jBAkEAjmH1pw0jVWlxmhM5wMACd1fzJZgFLyFX59p0wE7M
            |dqdiPVYzotnOvRWkCogXQNhjRgHpsKoBh7Oy2wwzk6Osfw==
            |-----END RSA PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3fJ9/iS28tDDcqZ+go6Snbem6
            |tEN27veQwg6arattdZhYA4MPWEKG8+aE2pp9tv3xNeSiY6F0CrXPpEAh37xDa9Ed
            |n0ehGDORXUYarSJrVVsrrfWlIpXVw3oVrqG35ylkfhLjuQtX/rBtho3HMCXd3KBC
            |ug6k1iY1tF9z2thvgwIDAQAB
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN RSA PRIVATE KEY-----
            |MIICWgIBAAKBgHWvJW4uf4z4XS226fnAQ/i0WDaLWHRolX0GCq0Tq7PZmBrksgMb
            |7jsLtjX5Ft0M7cEaKHGxXxSQST1Ezs1OaMuRys1qmuxKPBGJ91IVe/FCTgcPmMhT
            |vU53RLnDEPv5eir4SnywDfNPZaSf0apn9s2+gNbFYIkZa0DsRyc0KEqnAgMBAAEC
            |gYBh2yy1rMZ1EwRwAdwWx6/9ewCrAj2gNmKvXjm8Z1HsL/BR1H7NJQl4Yam2wZQo
            |ZRrB6h1dRI76S2wLHU8U2rE6BTwhVk1RfDWvNPyi+4zb29Q82jPYXE4+lOEXv3/5
            |R4F5DYjJAf3QWSF6GECROhYRYALoZolaqr6TNakkFV+0YQJBANgJ2kbrbkBKrG0w
            |/acWgfbKSI1XT1dt8s5V7t5k3bPyQTyf9xviukbVJzmMSdrST2/2vJn4HKqcmo+9
            |O1kgyZcCQQCLc+LoKbB5r5Lm998l6p8Uy60w6+unvB6GEqWg5A32tbB0SR9NTiEw
            |NEmV2vooXKNLwwWl5EIT/smEjn+ATwlxAkB1OXtoag1L83j2UtQAGzVwHTkbAJo7
            |vZw3m+deY2rtXnFJnR8v0Wn0T2rWTioxA1c5UK/r9/ZOGWXAwxR1+1WHAkAD9Bsg
            |vd3U9VdS2QAokQhFjKiyVF3v+XNcFbdAYnbK4cfI5DHQ/UAPn8veRcEF1+qBQVwt
            |odUFwBlyep++wX7hAkAN/5+TfaqelouclXxqJm1BHDZ+9um8soLUjte/+uzIF3Ed
            |aBhBWJnzJp2QB3WKVemphJhJFdS4h/8AEmgEIybn
            |-----END RSA PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHWvJW4uf4z4XS226fnAQ/i0WDaL
            |WHRolX0GCq0Tq7PZmBrksgMb7jsLtjX5Ft0M7cEaKHGxXxSQST1Ezs1OaMuRys1q
            |muxKPBGJ91IVe/FCTgcPmMhTvU53RLnDEPv5eir4SnywDfNPZaSf0apn9s2+gNbF
            |YIkZa0DsRyc0KEqnAgMBAAE=
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN RSA PRIVATE KEY-----
            |MIICXgIBAAKBgQC0l+apSB4Od/Bulesv2eId92acEjRjJcDHrv8Th74xriXuMY+r
            |N4bs8A8+ZGi5TwGQ4OmJ7pvm0GRfEXTst8Qu/qljLnxCGpDXgbpagLqOq1ubYKQv
            |7Gi24oddcyTrDy9oaJQ+NNU/COAt7/7Fh7+cfSYpx2RF31nLrrnrEAnv2wIDAQAB
            |AoGANpluTWPWYn10nZqJ3o+7Q2AXD7yZRhiV7klEKT1zDUYfhaJKU3OYQW5azXxC
            |BTSTvp+hO+h+DgyXK/71INR2ZVR6VQPwsUnodfaD6UmtwYNk/lOuFSMIJpqXu4Uy
            |dWrfdyH91PnIDzDaeXM433qIpBZTQcVGr9a1gcsHniycRJECQQDpTY1LDM+RAVqj
            |17aeFD2C4afNIF9UKRsMQUQACUoWjTJs1IwtbQU2rRtH23zjaoHxWdMIKi8jkmpf
            |VeAPPcaVAkEAximbxSDggYcDiKpja0efad8lT2UAq01PDkqRfeI0I/TZHs05JybJ
            |HqO09rbMDC7gupPgZDYe7sUtXTkUsLZwrwJBANT1U1oEUZu9Lq2MBEf7lcJYlMEr
            |IZlDBEuFb7rQv+4h6LtqsKHud+nWzaYj9bXozMAwC+/SAcForuxjCOkgrJkCQQCW
            |maKvw1e8OO7fm5bpPkqR/KvvVfSXO67cTqGaCSLVPM0R0qgf8CMjbQkoAy66B5p1
            |UdNUdak2j5X1Zl8qGc0zAkEAgVfHpFwA6E7iU/cJI5TiG9Mx6j/JmCbHpaoTJrmF
            |HA5WQImjDCGxxqjs9IKwooXiWPjSOncHbajKLDy7Hwlivg==
            |-----END RSA PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0l+apSB4Od/Bulesv2eId92ac
            |EjRjJcDHrv8Th74xriXuMY+rN4bs8A8+ZGi5TwGQ4OmJ7pvm0GRfEXTst8Qu/qlj
            |LnxCGpDXgbpagLqOq1ubYKQv7Gi24oddcyTrDy9oaJQ+NNU/COAt7/7Fh7+cfSYp
            |x2RF31nLrrnrEAnv2wIDAQAB
            |-----END PUBLIC KEY-----
          """.stripMargin
        )
      )
    )

  /**
    * Generates RSA private keys of less than 2048 bits.
    */
  lazy val rsaInsecurePrivateKeyGen: Gen[PrivateKey] =
    rsaInsecureKeyPairGen.map { case (privateKey, _) => privateKey }

  /**
    * Generates RSA public keys of less than 2048 bits.
    */
  lazy val rsaInsecurePublicKeyGen: Gen[PublicKey] =
    rsaInsecureKeyPairGen.map { case (_, publicKey) => publicKey }

  /**
    * Generates RSA key-pairs of at least 2048 bits.
    */
  lazy val rsaKeyPairGen: Gen[(PrivateKey, PublicKey)] =
    Gen.oneOf(
      List(
        privateKey(
          """
            |-----BEGIN PRIVATE KEY-----
            |MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfnVYjPfHAnO1D
            |FATbTf8phYcQOkBKZPdAhbbmHfJT5k2ADe2brrVAKmOIP86hoScaYmNUGC+q7mfd
            |ymbasjRiKKO9us5OyR4An2O3v2JpvSjGV+t30H272W5tNunLOYncjT5LIVTbZ580
            |BJ/bTUN7FWic9EI1frqf3ffrdsu8weNGMeP7IKs4BNG4l2rU1557Gbv9lU/WNdrz
            |4eXnacWmvKaHfUyhwraNczFg1C+nEFxbPQa+I+RAMy7+AQVW8jMyMEdu1DL2h36x
            |OheLzLhZvZ/qHMNO53hLFBr5gBoMK5DaGKixTWk7B7q5qipOrckjz9dPQU1AEORW
            |4X93o+3bAgMBAAECggEAM2vzV7g5nbWQxIb7B5IJrd1MRYCWvMDpXRqW8WzdaIUu
            |G56hGYI/91OQrFDuJ2ktGVVwLaP7G2TiBnSSDUvTD3qLQfEgTQaDCW1QKV7ZfDpK
            |HBgwDnIXR8EFT98ck/HOBcVlN7wdw++OvSnuPC8YmdssUEBq4iQZSK6wk+W6Pm1v
            |tBjUDzwyRBhyCkRYiICdYbCDZjg2U1w6CrCX1+1e3bpoC12U5FfU06wCMSqeFUor
            |alfXTEibiTetGLp8nyMqkr9KVWhA9BSBS+Y4MB385Xsci7UJ8UhTzRpSawEcvgOI
            |3Hp2zWTnZDOtw3jD89LOkYDb1cptTHdJvqQxn2qlnQKBgQDbfzgnGNBmJonFOzPW
            |0/Ta+gde8ql9frGv4LZL3H8Xk1lCB4Spkwk48ftEan7+HW6w8A7p+WeddH9/QZjF
            |Lw0BCDotn+lOTtOQPtloQbwijI84gbwbVdNCAo//0AxuF/K+5nBeaYDgi+/81yHp
            |B79hR7RHCjUwCYZMnKkmRpHBlwKBgQC6KLVQm4ZoXEbhK72xcdV7crFc4di5bJnW
            |M4e4eE4seJRpEVRgkLOF6z2OzDy/ILYY/2kXqx9mcBhqrGa7Ein1w7m3tYI4YT0/
            |d4Ge/tC0aUoxqPjgftzAZK5IT65xwkBvpIB2XlSmsSD+VUzw0Jtbcjchrq7GdE4G
            |qlr5WtN2XQKBgHnNz0ti6cLGAA4DHHFKjcY2mYCHCKcrd08yU/clFSHwEsghg+zW
            |O3fuUJFWx8IccyCdFqmgTW+DBn2H2U8THRRFjINlCgL6m0ygk+TXFZ/WgGPLGqfQ
            |qLso0OAUg9FUWNC28AR0Z6A0B6k3eQnn0rwZHmGNuJY/stcw2Gz1HE1hAoGAVgrI
            |uygXOJcl/58q/yABLxy005xjgliqxfFtUprwbueQmPt0h2l6QHSZMC5ACYsB/43V
            |siXazosTDgL/PInJsRk09q9DL/Hp0DLZS3a1Wh2sOEXEOmcIezhNwYhqtZO2GqPq
            |6ErzT1RhTox4knmoxNyGlN/bUkihY71LbSNIx9UCgYEAhzeD5L5Dm9fFT1pQxV6Y
            |hIWWRt30wlqZR7/0qFIzvAsxTEObEuK080jvEC5hZkpyFo/a/5YFeClp1NSlQbMw
            |CURqMNlx+OESdLB3t/vTkRfx00WYuWgcGWMKhXaytBWzNGdeWMAbUX5C6+n/yWgD
            |u97GT0DP+RVmY5UPLF5oeFs=
            |-----END PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn51WIz3xwJztQxQE203/
            |KYWHEDpASmT3QIW25h3yU+ZNgA3tm661QCpjiD/OoaEnGmJjVBgvqu5n3cpm2rI0
            |YiijvbrOTskeAJ9jt79iab0oxlfrd9B9u9lubTbpyzmJ3I0+SyFU22efNASf201D
            |exVonPRCNX66n93363bLvMHjRjHj+yCrOATRuJdq1Neeexm7/ZVP1jXa8+Hl52nF
            |prymh31MocK2jXMxYNQvpxBcWz0GviPkQDMu/gEFVvIzMjBHbtQy9od+sToXi8y4
            |Wb2f6hzDTud4SxQa+YAaDCuQ2hiosU1pOwe6uaoqTq3JI8/XT0FNQBDkVuF/d6Pt
            |2wIDAQAB
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN RSA PRIVATE KEY-----
            |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
            |-----END RSA PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmTZoSk2SCHDBu5S1DjE9
            |RDGw6YZwXZFJjG70gHfqjkuQF2DEqo48NWF4Syjgcl78y3pvgLiswqw6CgpoOyEs
            |anRnvOSimxZxCNm8x/aRzOSIxq/iRpca9bLbGyv2TXeyBNLJOs6q8zPSwO9wYe3+
            |+z+i0aemuenWN4iIBoLzB2lZXGwyn56T+s+HHsHRfCrXNrW0yYmKmhaefXfWrLtj
            |kcXfUmMa5xYbysQXaFIUxiebBxmbDiaNw4DgYa2dutgZ1N7+FLpVcPAnCxGVabyJ
            |bljpJoATC22Wq3h7fdd2q5AScBjMzxGnpqSqxwAx+4qqTQ32AjgTIMCvyzf+uc+j
            |jG4qvZj5UqhRfc/Bedmh70l5kt69MZgzbtqjwOjJQmuqYb0m1Xj60xETxOZvSdG+
            |fIeQrEPcwiWsRm8wxSVer31lLnenbYWZRj3FifAJ/wrz0eBLdto6cPVeXkDcKBu0
            |eZQwiMoaaGsOMXu4Hdft+RzJC2HQe+vWLwzEPAbauPOcH1TRj/RbTuuaRJW7ZgxS
            |5xFzaNb4GDZdqyr0VGpePf00f258bPSk5FfZihqs1/D1dIEvfodmJO1UniA/XPpc
            |vYZAnwKk/gEuHuYrDbtH88YnMSRFWWxQNNavrMrlqrCcUEU+jnqJip/9FwUIjjR/
            |eEzqpgzqyimf1UJ9u/ldackCAwEAAQ==
            |-----END PUBLIC KEY-----
          """.stripMargin
        ),
        privateKey(
          """
            |-----BEGIN RSA PRIVATE KEY-----
            |MIIEogIBAAKCAQEAwUC8SFKv+YdGfrkeZiJnn9Oqdk0H37ZhWf5xOe1aAI+LLz9S
            |Wr+WAY+MSZyJifQDUMC+gvoYNTXMl8lrW8gYZ6cf6/C9qTR6sKwYl/+LtEuubzkj
            |Qn8CTdwKu8IUxWlscdZLLBnHdi7/np9UkBclq7DI98ModCMz7ojl07ss2ZRHbpDK
            |jhbdIpc959+SQIU6en5PKrVsG9zFj6Wg046xqksl1a1LHkX8V872Bty0VhsTxrOa
            |QtsHNklXOb8DPHcJ0cXe961YbA48y7R0e+9hr5bfTPRO72LFxy6T+a8NrBr4Y376
            |q5tLuSqRuRpU63Lc864P074WmwSD0d/Y/kHIZwIDAQABAoIBAGsj5r76CNIAq5aq
            |Ly5UuLqlcQYxYsImrQZlyIRjENjqvDGvm4rwWMv4t8A/5wjynbvxgC3BVhZ6AznL
            |05eI8e7Vex8l0yCyFatJXkE2zk9g/g5v0RqWq8Ja0iCSU023SwY51mdWy3y8Rb+9
            |efaAvsPXOTQToKPyuGHwx+qBBTaCxSHJbewx+orTwpYOYbjlhs+Bu9QbkHxIaBen
            |MwrncwWW91JMh9RAmVO5N2fjEpUj6o3dnWM4eGkeflbd9l9wc/jHv8Gd9n+HbCXt
            |8I61xIT5aPVgUZWqEJ1BpUsrTXRUJ3L8G3IENmbrOm2sclQ2em96goItWafmy0pU
            |j2nkYyECgYEA8oYsKq6+yDe2dQjFwZwFxzB/VYG2y7XN65P7bQBoahMA80vy2wW6
            |TM6dXwegmAA+j+6yCB2Ap7fq6i5vZjhdvWVNNmQojJFJKYUyPu42rOTNApO5hPcr
            |VMpt7cc91InPKVnAZqwJd7AE1XWUIqt/m4e7rvcgl5D3/PbDZWcRLi8CgYEAy/2y
            |B/Rs9ciiNWCRC2xZPH57ohjFxv8Om/rord7T8ZG5SctMB7qUowGdnwywVX0sUTbw
            |dHo6HsY6oyyQlJfw3DDA6nVZ0QQAh5AbmwzL1XNzMzYn3xQplmQRyLrCVFGsqTyW
            |8yhBESgYS/Zd/kaYgHefOX/aGtqkWqg2uEiL80kCgYAtKHSS4gTeLRmJQz/nZBDj
            |XRFor4WE+u5D3kMjsb6/eZhktRCcXb2pzZMZ/caWZv0/ObfmsO+iyykvv8O4aehy
            |eqlc5ltyiR7xXz7S3vJJUTUnNLCHpKpp2GONsdq+d4aecXrU41XD9n9/66vQpNRW
            |9ngpBRUJg9HZRW1utTlKuwKBgAedCl39o2tw94zic8dnXdVCKz8biZYpwtPTg4ep
            |v2NOuwmkCsxnDFEhKE7dXF90coj9cfAG99BaOaoJacQB/71YHHsjshx498QXftBE
            |o/7tdik9JjPPPtYcGgXR4prfCYCvgDrHD9aiFnYPVea9n8d7r3en6+4Apw2zJYev
            |PXnxAoGAeUH7AssQ0fCNDdEP384MPKVcXT8Teg/QhwqTMy0JTx8OFSf5TS8ph5nh
            |/1L7xQ9apwmCEZe3i3/5SKM73Z0hML3uymNp7vFdUw30O/j4bTflW4Gtl1P3vHtj
            |CCpiqEb7LeqR28Ma+9XHo35FzBSs7YMUbhjmICvoas4bNO277AA=
            |-----END RSA PRIVATE KEY-----
          """.stripMargin
        ) -> publicKey(
          """
            |-----BEGIN PUBLIC KEY-----
            |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwUC8SFKv+YdGfrkeZiJn
            |n9Oqdk0H37ZhWf5xOe1aAI+LLz9SWr+WAY+MSZyJifQDUMC+gvoYNTXMl8lrW8gY
            |Z6cf6/C9qTR6sKwYl/+LtEuubzkjQn8CTdwKu8IUxWlscdZLLBnHdi7/np9UkBcl
            |q7DI98ModCMz7ojl07ss2ZRHbpDKjhbdIpc959+SQIU6en5PKrVsG9zFj6Wg046x
            |qksl1a1LHkX8V872Bty0VhsTxrOaQtsHNklXOb8DPHcJ0cXe961YbA48y7R0e+9h
            |r5bfTPRO72LFxy6T+a8NrBr4Y376q5tLuSqRuRpU63Lc864P074WmwSD0d/Y/kHI
            |ZwIDAQAB
            |-----END PUBLIC KEY-----
          """.stripMargin
        )
      )
    )

  /**
    * Generates RSA private keys of at least 2048 bits.
    */
  lazy val rsaPrivateKeyGen =
    rsaKeyPairGen.map { case (privateKey, _) => privateKey }

  /**
    * Generates RSA public keys of at least 2048 bits.
    */
  lazy val rsaPublicKeyGen: Gen[PublicKey] =
    rsaKeyPairGen.map { case (_, publicKey) => publicKey }

  lazy val privateKeyGen: Gen[PrivateKey] =
    Gen.oneOf(
      Gen.oneOf(
        ecdsaP256PrivateKeyGen,
        ecdsaP384PrivateKeyGen,
        ecdsaP521PrivateKeyGen
      ),
      Gen.oneOf(
        ed25519PrivateKeyGen,
        ed448PrivateKeyGen
      ),
      rsaPrivateKeyGen
    )

  implicit lazy val privateKeyArbitrary: Arbitrary[PrivateKey] =
    Arbitrary(privateKeyGen)

  implicit lazy val privateKeyCogen: Cogen[PrivateKey] =
    Cogen[ByteVector].contramap(_.toPkcs8)

  lazy val privateKeyFunGen: Gen[PrivateKey => PrivateKey] =
    Gen.function1(privateKeyGen)

  implicit lazy val privateKeyFunArbitrary: Arbitrary[PrivateKey => PrivateKey] =
    Arbitrary(privateKeyFunGen)

  implicit lazy val privateKeyShow: Show[PrivateKey] =
    Show.show(_.toPkcs8Pem)

  lazy val publicKeyGen: Gen[PublicKey] =
    Gen.oneOf(
      Gen.oneOf(
        ecdsaP256PublicKeyGen,
        ecdsaP384PublicKeyGen,
        ecdsaP521PublicKeyGen
      ),
      Gen.oneOf(
        ed25519PublicKeyGen,
        ed448PublicKeyGen
      ),
      rsaPublicKeyGen
    )

  implicit lazy val publicKeyArbitrary: Arbitrary[PublicKey] =
    Arbitrary(publicKeyGen)

  implicit lazy val publicKeyCogen: Cogen[PublicKey] =
    Cogen[ByteVector].contramap(_.toX509Spki)

  lazy val publicKeyFunGen: Gen[PublicKey => PublicKey] =
    Gen.function1(publicKeyGen)

  implicit lazy val publicKeyFunArbitrary: Arbitrary[PublicKey => PublicKey] =
    Arbitrary(publicKeyFunGen)

  private def privateKey(privateKey: String): PrivateKey =
    PrivateKey(privateKey).fold(throw _, identity)

  private def publicKey(publicKey: String): PublicKey =
    PublicKey(publicKey).fold(throw _, identity)
}
