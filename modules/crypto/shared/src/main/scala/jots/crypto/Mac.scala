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
  * Represents a Message Authentication Code (MAC).
  */
sealed abstract class Mac {

  /**
    * Returns the bytes (possibly empty) for the MAC.
    */
  def toByteVector: ByteVector

  /**
    * Returns the hexadecimal representation of the MAC.
    */
  def toHex: String

  /**
    * Alias for [[Mac#toHex]].
    */
  def show: String
}

object Mac {
  private final case class MacImpl(
    override val toByteVector: ByteVector
  ) extends Mac {
    override def toHex: String =
      toByteVector.toHex

    override def show: String =
      toHex

    override def toString: String =
      s"Mac($toHex)"

    override def equals(any: Any): Boolean =
      any match {
        case MacImpl(byteVector) =>
          toByteVector.equalsConstantTime(byteVector)
        case _ => false
      }
  }

  /**
    * The empty mac without any bytes.
    */
  val empty: Mac =
    MacImpl(ByteVector.empty)

  /**
    * Alias for [[Mac.fromByteVector]].
    */
  def apply(mac: ByteVector): Mac =
    fromByteVector(mac)

  /**
    * Returns a new [[Mac]] from the specified bytes.
    */
  def fromByteVector(mac: ByteVector): Mac =
    if (mac.isEmpty) empty else MacImpl(mac)

  implicit val macHash: Hash[Mac] =
    Hash.fromUniversalHashCode

  implicit val macShow: Show[Mac] =
    Show.show(_.show)
}
