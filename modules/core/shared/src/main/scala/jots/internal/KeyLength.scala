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

package jots.internal

import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import jots.crypto.internal.asn1.Tlv
import scodec.bits.ByteVector

/**
  * Used to determine the bit length of an asymmetric key.
  */
private[jots] sealed abstract class KeyLength

private[jots] object KeyLength {

  /**
    * The key is of type RSA with the specified modulus bit length.
    */
  final case class Rsa(bits: Int) extends KeyLength

  /**
    * The key is of type ECDSA with the specified curve bit length.
    */
  final case class Ecdsa(bits: Int) extends KeyLength

  /**
    * The key is of type EdDSA with the specified curve bit length.
    */
  final case class Eddsa(bits: Int) extends KeyLength

  /**
    * The key is of an unknown type or an has an unknown bit length.
    */
  case object Unknown extends KeyLength

  def fromPrivateKey(privateKey: PrivateKey): KeyLength = {
    val pkcs8 =
      privateKey.toPkcs8

    val parsed =
      for {
        outer <- Asn1.readTlv(pkcs8, 0L) if outer.isSeq && outer.end == pkcs8.size
        version <- Asn1.readTlv(outer.contents, 0L) if version.isInt
        algorithmId <- Asn1.readTlv(outer.contents, version.end) if algorithmId.isSeq
      } yield (outer, algorithmId)

    parsed match {
      case Some((outer, algorithmId)) =>
        keyLength(algorithmId, rsaPrivateModulus(outer, algorithmId))
      case None =>
        Unknown
    }
  }

  def fromPublicKey(publicKey: PublicKey): KeyLength = {
    val spki =
      publicKey.toX509Spki

    val parsed =
      for {
        outer <- Asn1.readTlv(spki, 0L) if outer.isSeq && outer.end == spki.size
        algorithmId <- Asn1.readTlv(outer.contents, 0L) if algorithmId.isSeq
      } yield (outer, algorithmId)

    parsed match {
      case Some((outer, algorithmId)) =>
        keyLength(algorithmId, rsaPublicModulus(outer, algorithmId))
      case None =>
        Unknown
    }
  }

  private def keyLength(algorithmId: Tlv, rsaModulus: => Option[ByteVector]): KeyLength =
    Asn1.readTlv(algorithmId.contents, 0L) match {
      case Some(oid) if oid.isOid =>
        oid.contents match {
          case Oid.Rsa.contents =>
            rsaModulus.map(modulus => Rsa(rsaModulusBits(modulus))).getOrElse(Unknown)
          case Oid.Ec.contents =>
            ecdsaCurveBits(algorithmId, oid.end).map(Ecdsa(_)).getOrElse(Unknown)
          case Oid.Ed25519.contents =>
            Eddsa(256)
          case Oid.Ed448.contents =>
            Eddsa(456)
          case _ =>
            Unknown
        }
      case _ =>
        Unknown
    }

  private def ecdsaCurveBits(algorithmId: Tlv, curveOffset: Long): Option[Int] =
    for {
      curve <- Asn1.readTlv(algorithmId.contents, curveOffset) if curve.isOid
      bits <- curve.contents match {
        case Oid.P256.contents => Some(256)
        case Oid.P384.contents => Some(384)
        case Oid.P521.contents => Some(521)
        case _ => None
      }
    } yield bits

  private def rsaPrivateModulus(outer: Tlv, algorithmId: Tlv): Option[ByteVector] =
    for {
      keyOctets <- Asn1.readTlv(outer.contents, algorithmId.end) if keyOctets.isOctetString
      rsaKey <- Asn1.readTlv(keyOctets.contents, 0L) if rsaKey.isSeq
      rsaVersion <- Asn1.readTlv(rsaKey.contents, 0L) if rsaVersion.isInt
      modulus <- Asn1.readTlv(rsaKey.contents, rsaVersion.end) if modulus.isInt
    } yield modulus.contents

  private def rsaPublicModulus(outer: Tlv, algorithmId: Tlv): Option[ByteVector] =
    for {
      keyBits <- Asn1.readTlv(outer.contents, algorithmId.end) if keyBits.isBitString
      rsaKey <- Asn1.readTlv(keyBits.contents.drop(1), 0L) if rsaKey.isSeq
      modulus <- Asn1.readTlv(rsaKey.contents, 0L) if modulus.isInt
    } yield modulus.contents

  private def rsaModulusBits(modulus: ByteVector): Int = {
    val stripped = modulus.dropWhile(_ == 0)
    if (stripped.isEmpty) 0
    else
      (stripped.size.toInt - 1) * 8 +
        (32 - Integer.numberOfLeadingZeros(stripped.head & 0xff))
  }
}
