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

import cats.Functor
import jots.JwtSigning
import jots.crypto.Crypto
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import scala.util.Try

/**
  * ScalaCheck generators and instances for [[jots.JwtSigning]].
  */
object JwtSigningInstances extends JwtSigningInstances

private[jots] trait JwtSigningInstances {

  /**
    * Generates [[jots.JwtSigning]] instances that signs with ECDSA.
    */
  def ecdsaJwtSigningGen[F[_]: Crypto: Functor]: Gen[JwtSigning[F]] =
    for {
      algorithm <- jwtEcdsaAlgorithmGen
      privateKey <- ecdsaPrivateKeyGen(algorithm)
      signing <- JwtSigning
        .default[Try]
        .signWith[F]
        .ecdsa(algorithm, privateKey)
        .fold(throw _, Gen.const)
    } yield signing

  /**
    * Generates [[jots.JwtSigning]] instances that signs with EdDSA.
    */
  def eddsaJwtSigningGen[F[_]: Crypto: Functor]: Gen[JwtSigning[F]] =
    for {
      algorithm <- jwtEddsaAlgorithmGen
      privateKey <- eddsaPrivateKeyGen(algorithm)
      signing <- JwtSigning
        .default[Try]
        .signWith[F]
        .eddsa(algorithm, privateKey)
        .fold(throw _, Gen.const)
    } yield signing

  /**
    * Generates [[jots.JwtSigning]] instances that signs with HMAC.
    */
  def hmacJwtSigningGen[F[_]: Crypto: Functor]: Gen[JwtSigning[F]] =
    for {
      algorithm <- jwtHmacAlgorithmGen
      secretKey <- secretKeyMinLengthGen(algorithm.minKeyLength)
      signing <- JwtSigning
        .default[Try]
        .signWith[F]
        .hmac(algorithm, secretKey)
        .fold(throw _, Gen.const)
    } yield signing

  /**
    * Generates [[jots.JwtSigning]] instances that signs with RSA.
    */
  def rsaJwtSigningGen[F[_]: Crypto: Functor]: Gen[JwtSigning[F]] =
    for {
      algorithm <- jwtRsaAlgorithmGen
      privateKey <- rsaPrivateKeyGen
      signing <- JwtSigning
        .default[Try]
        .signWith[F]
        .rsa(algorithm, privateKey)
        .fold(throw _, Gen.const)
    } yield signing

  /**
    * Generates [[jots.JwtSigning]] instances that signs tokens.
    */
  def jwtSigningGen[F[_]: Crypto: Functor]: Gen[JwtSigning[F]] =
    Gen.oneOf(
      ecdsaJwtSigningGen,
      eddsaJwtSigningGen,
      hmacJwtSigningGen,
      rsaJwtSigningGen
    )

  implicit def jwtSigningArbitrary[F[_]: Crypto: Functor]: Arbitrary[JwtSigning[F]] =
    Arbitrary(jwtSigningGen[F])
}
