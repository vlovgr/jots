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
import cats.Show
import scodec.bits.ByteVector

/**
  * The bytes output from an asymmetric signing operation.
  */
sealed abstract class Signature {

  /**
    * Returns the bytes (possibly empty) for the signature.
    */
  def toByteVector: ByteVector

  /**
    * Returns the hexadecimal representation of the signature.
    */
  def toHex: String

  /**
    * Alias for [[Signature#toHex]].
    */
  def show: String
}

object Signature {
  private final case class SignatureImpl(
    override val toByteVector: ByteVector
  ) extends Signature {
    override def toHex: String =
      toByteVector.toHex

    override def show: String =
      toHex

    override def toString: String =
      s"Signature($toHex)"

    override def equals(any: Any): Boolean =
      any match {
        case SignatureImpl(byteVector) =>
          toByteVector.equalsConstantTime(byteVector)
        case _ => false
      }
  }

  /**
    * The empty signature without any bytes.
    */
  val empty: Signature =
    SignatureImpl(ByteVector.empty)

  /**
    * Alias for [[Signature.fromByteVector]].
    */
  def apply(signature: ByteVector): Signature =
    fromByteVector(signature)

  /**
    * Returns a new [[Signature]] from the specified bytes.
    */
  def fromByteVector(signature: ByteVector): Signature =
    if (signature.isEmpty) empty else SignatureImpl(signature)

  implicit val signatureHash: Hash[Signature] =
    Hash.fromUniversalHashCode

  implicit val signatureShow: Show[Signature] =
    Show.show(_.show)
}
