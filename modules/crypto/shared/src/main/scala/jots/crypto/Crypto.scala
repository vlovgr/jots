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

package jots.crypto

import cats.effect.kernel.Sync
import scodec.bits.ByteVector

/**
  * Cryptographic functions to support working with JSON
  * Web Tokens (JWTs).
  */
sealed abstract class Crypto[F[_]] {

  /**
    * Returns the Hash-based Message Authentication Code
    * (HMAC) using the specified hash algorithm, secret
    * key, and message.
    */
  def hmac(
    algorithm: HashAlgorithm,
    secretKey: SecretKey
  )(
    message: ByteVector
  ): F[Mac]

  /**
    * Generates a signature using the specified asymmetric
    * algorithm, private key, and message.
    */
  def sign(
    algorithm: AsymmetricAlgorithm,
    privateKey: PrivateKey
  )(
    message: ByteVector
  ): F[Signature]

  /**
    * Verifies a signature using the specified asymmetric
    * algorithm, public key, and message.
    */
  def verify(
    algorithm: AsymmetricAlgorithm,
    publicKey: PublicKey
  )(
    message: ByteVector,
    signature: Signature
  ): F[Verified]
}

object Crypto extends CryptoCompanionPlatform {
  def apply[F[_]](implicit F: Crypto[F]): Crypto[F] = F

  implicit def cryptoSync[F[_]: Sync]: Crypto[F] =
    new Crypto[F] {
      override def hmac(
        algorithm: HashAlgorithm,
        secretKey: SecretKey
      )(
        message: ByteVector
      ): F[Mac] =
        Crypto.hmac(
          algorithm = algorithm,
          secretKey = secretKey,
          message = message
        )

      override def sign(
        algorithm: AsymmetricAlgorithm,
        privateKey: PrivateKey
      )(
        message: ByteVector
      ): F[Signature] =
        Crypto.sign(
          algorithm = algorithm,
          privateKey = privateKey,
          message = message
        )

      override def verify(
        algorithm: AsymmetricAlgorithm,
        publicKey: PublicKey
      )(
        message: ByteVector,
        signature: Signature
      ): F[Verified] =
        Crypto.verify(
          algorithm = algorithm,
          publicKey = publicKey,
          message = message,
          signature = signature
        )
    }
}
