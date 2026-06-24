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

private[jots] final case class Tlv(
  tag: Tag,
  contents: ByteVector,
  end: Long
) {
  def isBitString: Boolean = tag == Tag.BitString
  def isContext0: Boolean = tag == Tag.Context0
  def isInt: Boolean = tag == Tag.Int
  def isOctetString: Boolean = tag == Tag.OctetString
  def isOid: Boolean = tag == Tag.Oid
  def isSeq: Boolean = tag == Tag.Seq
}
