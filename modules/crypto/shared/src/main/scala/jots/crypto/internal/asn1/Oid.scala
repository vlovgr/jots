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

private[jots] sealed abstract class Oid(val contents: ByteVector)

private[jots] object Oid {
  case object Ec extends Oid(ByteVector(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01))
  case object Ed25519 extends Oid(ByteVector(0x2b, 0x65, 0x70))
  case object Ed448 extends Oid(ByteVector(0x2b, 0x65, 0x71))
  case object P256 extends Oid(ByteVector(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07))
  case object P384 extends Oid(ByteVector(0x2b, 0x81, 0x04, 0x00, 0x22))
  case object P521 extends Oid(ByteVector(0x2b, 0x81, 0x04, 0x00, 0x23))
  case object Rsa extends Oid(ByteVector(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01))
}
