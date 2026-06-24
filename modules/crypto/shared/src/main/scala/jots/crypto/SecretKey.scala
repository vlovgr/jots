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

import cats.Hash
import cats.syntax.all.*
import jots.crypto.CryptoException.InvalidSecretKey
import scodec.bits.ByteVector

/**
  * A non-empty secret key used for cryptographic operations.
  */
sealed abstract class SecretKey {

  /**
    * Returns the non-empty bytes for the secret key.
    */
  def toByteVector: ByteVector
}

object SecretKey {
  private final case class SecretKeyImpl(
    override val toByteVector: ByteVector
  ) extends SecretKey {
    override def equals(any: Any): Boolean =
      any match {
        case SecretKeyImpl(byteVector) =>
          toByteVector.equalsConstantTime(byteVector)
        case _ => false
      }

    override def toString: String =
      "SecretKey(**)"
  }

  /**
    * Alias for [[SecretKey.fromStringUtf8]].
    */
  def apply(secretKey: String): Either[CryptoException, SecretKey] =
    fromStringUtf8(secretKey)

  /**
    * Returns a new [[SecretKey]] from the specified bytes.
    *
    * Returns an exception if the specified bytes are empty.
    */
  def fromByteVector(secretKey: ByteVector): Either[CryptoException, SecretKey] =
    if (secretKey.nonEmpty) Right(SecretKeyImpl(secretKey))
    else Left(new InvalidSecretKey("the secret key is empty"))

  /**
    * Returns a new [[SecretKey]] from the specified `String`.
    *
    * Returns an exception if UTF-8 encoding fails, or if the
    * secret key is empty.
    */
  def fromStringUtf8(secretKey: String): Either[CryptoException, SecretKey] =
    for {
      utf8 <- ByteVector
        .encodeUtf8(secretKey)
        .leftMap(e => new InvalidSecretKey("failed to UTF-8 encode secret key", Some(e)))
      secretKey <- fromByteVector(utf8)
    } yield secretKey

  implicit val secretKeyHash: Hash[SecretKey] =
    Hash.fromUniversalHashCode
}
