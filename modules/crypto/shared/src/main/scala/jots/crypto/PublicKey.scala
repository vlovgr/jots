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
import cats.syntax.all.*
import java.util.regex.Pattern
import jots.crypto.CryptoException.InvalidPublicKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import scodec.bits.Bases.Alphabets.Base64
import scodec.bits.ByteVector

/**
  * A public key of an asymmetric public-private key pair.
  *
  * Public keys are represented using X.509 Subject Public
  * Key Info (SPKI) in DER using [[PublicKey#toX509Spki]]
  * or PEM-encoded using [[PublicKey#toX509SpkiPem]].
  *
  * Functions are provided to convert from various formats.
  *
  * - [[PublicKey.fromPem]] accepts some PEM-encoded formats.
  * - [[PublicKey.fromPkcs1]] accepts PKCS#1 RSA public key DER.
  * - [[PublicKey.fromX509Certificate]] accepts X.509 certificate DER.
  * - [[PublicKey.fromX509Spki]] accepts unmodified X.509 SPKI DER.
  *
  * Note there are no checks for whether the key can be used, or
  * if it belongs to a certain public-key cryptosystem (e.g. RSA).
  */
sealed abstract class PublicKey {

  /**
    * Returns the public key as bytes in the X.509 Subject
    * Public Key Info (SPKI) DER format.
    */
  def toX509Spki: ByteVector

  /**
    * Returns the public key as PEM-encoded in the X.509
    * Subject Public Key Info (SPKI) DER format.
    */
  def toX509SpkiPem: String

  /**
    * Alias for [[PublicKey#toX509SpkiPem]].
    */
  def show: String
}

object PublicKey {
  private final case class PublicKeyImpl(
    override val toX509Spki: ByteVector
  ) extends PublicKey {
    override def toX509SpkiPem: String =
      toX509Spki.toBase64
        .grouped(64)
        .mkString(
          start = s"-----BEGIN PUBLIC KEY-----\n",
          sep = "\n",
          end = s"\n-----END PUBLIC KEY-----"
        )

    override def show: String =
      toX509SpkiPem

    override def toString: String =
      s"PublicKey($show)"
  }

  /**
    * Alias for [[PublicKey.fromPem]].
    */
  def apply(publicKey: String): Either[CryptoException, PublicKey] =
    fromPem(publicKey)

  /**
    * Returns a new [[PublicKey]] from the specified PEM-encoded
    * key or certificate.
    *
    * The following PEM labels are recognized by the function.
    *
    * - `CERTIFICATE` for X.509 certificates (DER format).
    * - `PUBLIC KEY` for keys in the X.509 SPKI DER format.
    * - `RSA PUBLIC KEY` for RSA keys in PKCS#1 DER format.
    */
  def fromPem(publicKey: String): Either[CryptoException, PublicKey] = {
    val matcher = pemPattern.matcher(publicKey)
    if (matcher.matches()) {
      val beginLabel = matcher.group(1)
      val endLabel = matcher.group(3)
      if (beginLabel == endLabel) {
        val contents = matcher.group(2)
        ByteVector
          .fromBase64Descriptive(contents, Base64)
          .leftMap(details => new InvalidPublicKey(s"failed to decode PEM as Base64: $details"))
          .flatMap { publicKey =>
            beginLabel match {
              case "CERTIFICATE" => fromX509Certificate(publicKey)
              case "PUBLIC KEY" => Right(fromX509Spki(publicKey))
              case "RSA PUBLIC KEY" => fromPkcs1(publicKey)
              case label => Left(new InvalidPublicKey(s"unsupported PEM label: $label"))
            }
          }
      } else Left(new InvalidPublicKey("the PEM labels do not match"))
    } else Left(new InvalidPublicKey("unrecognized PEM string format"))
  }

  /**
    * Returns a new [[PublicKey]] from the specified PKCS#1 RSA public key DER.
    */
  def fromPkcs1(publicKey: ByteVector): Either[CryptoException, PublicKey] = {
    val x509Spki = Asn1
      .readTlv(publicKey, 0L)
      .filter(tlv => tlv.isSeq && tlv.end == publicKey.size)
      .as(
        PublicKey.fromX509Spki(
          Asn1.seq(
            Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null),
            Asn1.bitString(ByteVector(0) ++ publicKey)
          )
        )
      )

    x509Spki.toRight(new InvalidPublicKey("failed to extract public key from PKCS#1"))
  }

  /**
    * Returns a new [[PublicKey]] from the specified X.509 certificate DER.
    *
    * Note this function does not check the signing chain, expiry,
    * name constraints, key usage etc. It only extracts the public
    * key contained within the certificate.
    */
  def fromX509Certificate(certificate: ByteVector): Either[CryptoException, PublicKey] = {
    val x509Spki =
      for {
        cert <- Asn1.readTlv(certificate, 0L) if cert.isSeq && cert.end == certificate.size
        tbs <- Asn1.readTlv(cert.contents, 0L) if tbs.isSeq
        version = Asn1.readTlv(tbs.contents, 0L).filter(_.isContext0)
        versionEnd = version.map(_.end).getOrElse(0L)
        offset <- Asn1.skipTlv(tbs.contents, versionEnd, 5)
        spki <- Asn1.readTlv(tbs.contents, offset) if spki.isSeq
      } yield PublicKey.fromX509Spki(Asn1.seq(spki.contents))

    x509Spki.toRight(new InvalidPublicKey("failed to extract public key from X.509 certificate"))
  }

  /**
    * Returns a new [[PublicKey]] from the specified X.509 SPKI DER.
    */
  def fromX509Spki(publicKey: ByteVector): PublicKey =
    PublicKeyImpl(publicKey)

  implicit val publicKeyHash: Hash[PublicKey] =
    Hash.fromUniversalHashCode

  implicit val publicKeyShow: Show[PublicKey] =
    Show.show(_.show)

  private val pemPattern: Pattern =
    Pattern.compile(
      raw"\A\s*-----BEGIN (CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----(.+)-----END (CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY)-----\s*\z",
      Pattern.DOTALL
    )
}
