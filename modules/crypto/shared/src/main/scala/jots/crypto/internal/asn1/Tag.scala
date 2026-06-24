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

package jots.crypto.internal.asn1

import scodec.bits.ByteVector

private[jots] sealed abstract class Tag(val value: Int) {
  require((value & 0xff) == value, s"Tag $value out of range 0..255")

  def tlv(contents: ByteVector): ByteVector =
    ByteVector(value) ++ Tag.writeTlvLength(contents.size) ++ contents
}

private[jots] object Tag {
  case object BitString extends Tag(0x03)
  case object Context0 extends Tag(0xa0)
  case object Context1 extends Tag(0xa1)
  case object Int extends Tag(0x02)
  case object Null extends Tag(0x05)
  case object OctetString extends Tag(0x04)
  case object Oid extends Tag(0x06)
  case object Seq extends Tag(0x30)
  final case class Unknown(override val value: Int) extends Tag(value)

  def apply(value: Int): Tag =
    value match {
      case BitString.value => BitString
      case Context0.value => Context0
      case Context1.value => Context1
      case Int.value => Int
      case Null.value => Null
      case OctetString.value => OctetString
      case Oid.value => Oid
      case Seq.value => Seq
      case value => Unknown(value)
    }

  private def writeTlvLength(length: Long): ByteVector =
    if (length < 128L) ByteVector(length)
    else {
      var bytes = ByteVector.empty
      var remaining = length
      while (remaining > 0L) {
        bytes = ByteVector(remaining & 0xffL) ++ bytes
        remaining = remaining >>> 8
      }
      ByteVector(0x80 | bytes.size.toInt) ++ bytes
    }
}
