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

import scala.annotation.tailrec
import scodec.bits.ByteVector

private[jots] object Asn1 {
  def bitString(contents: ByteVector): ByteVector =
    Tag.BitString.tlv(contents)

  def context0(contents: ByteVector): ByteVector =
    Tag.Context0.tlv(contents)

  def context1(contents: ByteVector): ByteVector =
    Tag.Context1.tlv(contents)

  val emptySeq: ByteVector =
    Asn1.seq(ByteVector.empty)

  @tailrec
  def findTlv(
    contents: ByteVector,
    start: Long,
    p: Tlv => Boolean
  ): Option[ByteVector] =
    if (start >= contents.size) None
    else
      readTlv(contents, start) match {
        case Some(tlv) if p(tlv) => Some(tlv.contents)
        case Some(tlv) => findTlv(contents, tlv.end, p)
        case None => None
      }

  def int(contents: ByteVector): ByteVector =
    Tag.Int.tlv(contents)

  val intZero: ByteVector =
    Tag.Int.tlv(ByteVector(0))

  val Null: ByteVector =
    Tag.Null.tlv(ByteVector.empty)

  def octetString(contents: ByteVector): ByteVector =
    Tag.OctetString.tlv(contents)

  def oid(oid: Oid): ByteVector =
    Tag.Oid.tlv(oid.contents)

  def padLeft(contents: ByteVector, length: Int): Option[ByteVector] = {
    val trimmed = contents.dropWhile(_ == 0)
    Option.when(trimmed.size <= length.toLong) {
      ByteVector.fill(length.toLong - trimmed.size)(0) ++ trimmed
    }
  }

  def readTlv(contents: ByteVector, offset: Long): Option[Tlv] =
    if (offset < 0L || offset >= contents.size) None
    else {
      val tag = Tag(contents(offset) & 0xff)
      readTlvLength(contents, offset + 1L).flatMap { case (length, bytes) =>
        val start = offset + 1L + bytes
        if (length < 0L || length > contents.size - start) None
        else {
          val end = start + length
          Some(Tlv(tag, contents.slice(start, end), end))
        }
      }
    }

  private[this] def readTlvLength(bytes: ByteVector, offset: Long): Option[(Long, Long)] =
    if (offset >= bytes.size) None
    else {
      val first = bytes(offset) & 0xff
      if (first < 0x80) Some((first.toLong, 1L))
      else {
        val length = first & 0x7f
        if (length == 0 || length > 8) None
        else if (offset + 1L + length > bytes.size) None
        else {
          @tailrec
          def loop(i: Int, acc: Long): Long =
            if (i == length) acc
            else loop(i + 1, (acc << 8) | (bytes(offset + 1L + i) & 0xffL))
          Some((loop(0, 0L), 1L + length))
        }
      }
    }

  def seq(contents: ByteVector*): ByteVector =
    Tag.Seq.tlv(ByteVector.concat(contents))

  @tailrec
  def skipTlv(
    contents: ByteVector,
    start: Long,
    count: Int
  ): Option[Long] =
    if (count <= 0) Some(start)
    else
      readTlv(contents, start) match {
        case Some(tlv) => skipTlv(contents, tlv.end, count - 1)
        case None => None
      }

  def uint(contents: ByteVector): ByteVector = {
    val stripped =
      contents.dropWhile(_ == 0)

    val padded =
      if (stripped.isEmpty) ByteVector(0)
      else if ((stripped.head & 0x80) != 0) ByteVector(0) ++ stripped
      else stripped

    Tag.Int.tlv(padded)
  }
}
