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
import java.util.regex.Pattern
import jots.crypto.CryptoException.InvalidPrivateKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import scodec.bits.Bases.Alphabets.Base64
import scodec.bits.ByteVector

/**
  * A private key of an asymmetric public-private key pair.
  *
  * Private keys are represented using PKCS #8 in DER using
  * [[PrivateKey#toPkcs8]] or alternatively in PEM-encoding
  * using [[PrivateKey#toPkcs8Pem]].
  *
  * Functions are provided to convert from various formats.
  *
  * - [[PrivateKey.fromPem]] accepts some PEM-encoded formats.
  * - [[PrivateKey.fromPkcs1]] accepts PKCS #1 RSA private key DER.
  * - [[PrivateKey.fromPkcs8]] accepts unmodified PKCS #8 DER.
  * - [[PrivateKey.fromSec1]] accepts SEC1 EC private key DER.
  *
  * Note there are no checks for whether the key can be used, or
  * if it belongs to a certain public-key cryptosystem (e.g. RSA).
  */
sealed abstract class PrivateKey {

  /**
    * Returns the private key as bytes in the PKCS #8 DER format.
    */
  def toPkcs8: ByteVector

  /**
    * Returns the private key as PEM-encoded in the PKCS #8 DER format.
    */
  def toPkcs8Pem: String
}

object PrivateKey {
  private final case class PrivateKeyImpl(
    override val toPkcs8: ByteVector
  ) extends PrivateKey {
    override def toPkcs8Pem: String =
      toPkcs8.toBase64
        .grouped(64)
        .mkString(
          start = s"-----BEGIN PRIVATE KEY-----\n",
          sep = "\n",
          end = s"\n-----END PRIVATE KEY-----"
        )

    override def toString: String =
      s"PrivateKey(**)"

    override def equals(any: Any): Boolean =
      any match {
        case PrivateKeyImpl(pkcs8) =>
          toPkcs8.equalsConstantTime(pkcs8)
        case _ => false
      }
  }

  /**
    * Alias for [[PrivateKey.fromPem]].
    */
  def apply(privateKey: String): Either[CryptoException, PrivateKey] =
    fromPem(privateKey)

  /**
    * Returns a new [[PrivateKey]] from the specified PEM-encoded key.
    *
    * The following PEM labels are recognized by the function.
    *
    * - `EC PRIVATE KEY` for EC keys in the SEC1 DER format.
    * - `PRIVATE KEY` for keys in the PKCS #8 DER format.
    * - `RSA PRIVATE KEY` for RSA keys in PKCS #1 DER.
    */
  def fromPem(privateKey: String): Either[CryptoException, PrivateKey] = {
    val matcher = pemPattern.matcher(privateKey)
    if (matcher.matches()) {
      val beginLabel = matcher.group(1)
      val endLabel = matcher.group(3)
      if (beginLabel == endLabel) {
        val contents = matcher.group(2)
        ByteVector
          .fromBase64Descriptive(contents, Base64)
          .leftMap(details => new InvalidPrivateKey(s"failed to decode PEM as Base64: $details"))
          .flatMap { privateKey =>
            beginLabel match {
              case "EC PRIVATE KEY" => fromSec1(privateKey)
              case "PRIVATE KEY" => Right(fromPkcs8(privateKey))
              case "RSA PRIVATE KEY" => fromPkcs1(privateKey)
              case label => Left(new InvalidPrivateKey(s"unsupported PEM label: $label"))
            }
          }
      } else Left(new InvalidPrivateKey("the PEM labels do not match"))
    } else Left(new InvalidPrivateKey("unrecognized PEM string format"))
  }

  /**
    * Returns a new [[PrivateKey]] from the specified PKCS #1 RSA private key DER.
    */
  def fromPkcs1(privateKey: ByteVector): Either[CryptoException, PrivateKey] = {
    val pkcs8 = Asn1
      .readTlv(privateKey, 0L)
      .filter(tlv => tlv.isSeq && tlv.end == privateKey.size)
      .as(
        PrivateKey.fromPkcs8(
          Asn1.seq(
            Asn1.intZero ++
              Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null) ++
              Asn1.octetString(privateKey)
          )
        )
      )

    pkcs8.toRight(new InvalidPrivateKey("failed to extract private key from PKCS#1"))
  }

  /**
    * Returns a new [[PrivateKey]] from the specified PKCS #8 private key DER.
    */
  def fromPkcs8(privateKey: ByteVector): PrivateKey =
    PrivateKeyImpl(privateKey)

  /**
    * Returns a new [[PrivateKey]] from the specified SEC1 EC private key DER.
    */
  def fromSec1(privateKey: ByteVector): Either[CryptoException, PrivateKey] = {
    val pkcs8 =
      for {
        outer <- Asn1.readTlv(privateKey, 0L) if outer.isSeq && outer.end == privateKey.size
        version <- Asn1.readTlv(outer.contents, 0L) if version.isInt
        key <- Asn1.readTlv(outer.contents, version.end) if key.isOctetString
        params <- Asn1.findTlv(outer.contents, key.end, _.isContext0)
      } yield PrivateKey.fromPkcs8(
        Asn1.seq(
          Asn1.intZero ++
            Asn1.seq(Asn1.oid(Oid.Ec) ++ params) ++
            Asn1.octetString(privateKey)
        )
      )

    pkcs8.toRight(new InvalidPrivateKey("failed to extract private key from SEC1"))
  }

  implicit val privateKeyHash: Hash[PrivateKey] =
    Hash.fromUniversalHashCode

  private val pemPattern: Pattern =
    Pattern.compile(
      raw"\A\s*-----BEGIN (EC PRIVATE KEY|PRIVATE KEY|RSA PRIVATE KEY)-----(.+)-----END (EC PRIVATE KEY|PRIVATE KEY|RSA PRIVATE KEY)-----\s*\z",
      Pattern.DOTALL
    )
}
