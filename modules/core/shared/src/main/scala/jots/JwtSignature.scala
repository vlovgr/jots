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

package jots

import cats.Hash
import cats.Show
import jots.JwtException.InvalidJwtSignature
import jots.crypto.Mac
import jots.crypto.Signature
import scodec.bits.Bases.Alphabets.Base64UrlNoPad
import scodec.bits.ByteVector

/**
  * The bytes constituting the signature part of a [[SignedJwt]].
  *
  * [[JwtSignature]]s are usually created with [[JwtSignature.fromMac]]
  * from [[jots.crypto.Mac]]s, or using [[JwtSignature.fromSignature]]
  * from [[jots.crypto.Signature]]s when creating tokens. When parsing
  * existing signatures, [[JwtSignature.fromString]] is available.
  *
  * The [[JwtSignature]] should generally not be trusted unless
  * it is part of a [[VerifiedJwt]], so the signature is verified.
  *
  * Note it is possible for signatures to be empty. However, no default
  * [[JwtSigning]] will emit empty signatures. Similarly, all default
  * [[JwtVerification]]s will reject empty signatures.
  */
sealed abstract class JwtSignature {

  /**
    * Returns `true` if the signature is empty; `false` otherwise.
    */
  def isEmpty: Boolean

  /**
    * Returns the bytes (possibly empty) representing the signature.
    */
  def toByteVector: ByteVector

  /**
    * Returns the signature in its `String` representation.
    */
  def toBase64UrlNoPad: String

  /**
    * Returns a new [[jots.crypto.Signature]] with the signature.
    */
  def toSignature: Signature

  /**
    * Alias for [[JwtSignature#toBase64UrlNoPad]].
    */
  def show: String
}

object JwtSignature {
  private final case class JwtSignatureImpl(
    override val toByteVector: ByteVector
  ) extends JwtSignature {
    override def isEmpty: Boolean =
      toByteVector.isEmpty

    override def toBase64UrlNoPad: String =
      toByteVector.toBase64UrlNoPad

    override def toSignature: Signature =
      Signature(toByteVector)

    override def toString: String =
      s"JwtSignature($toBase64UrlNoPad)"

    override def equals(any: Any): Boolean =
      any match {
        case JwtSignatureImpl(byteVector) =>
          toByteVector.equalsConstantTime(byteVector)
        case _ => false
      }

    override def show: String =
      toBase64UrlNoPad
  }

  /**
    * The empty signature without any bytes.
    */
  val empty: JwtSignature =
    JwtSignatureImpl(ByteVector.empty)

  /**
    * Alias for [[JwtSignature.fromByteVector]].
    */
  def apply(signature: ByteVector): JwtSignature =
    fromByteVector(signature)

  /**
    * Returns a new [[JwtSignature]] by parsing the specified
    * signature in its `String` representation.
    */
  def fromBase64UrlNoPad(signature: String): Either[JwtException, JwtSignature] =
    ByteVector.fromBase64Descriptive(signature, Base64UrlNoPad) match {
      case Right(signature) => Right(JwtSignature.fromByteVector(signature))
      case Left(details) => Left(new InvalidJwtSignature(s"failed to decode as Base64UrlNoPad: $details"))
    }

  /**
    * Returns a new [[JwtSignature]] from the specified bytes.
    */
  def fromByteVector(signature: ByteVector): JwtSignature =
    if (signature.isEmpty) empty else JwtSignatureImpl(signature)

  /**
    * Returns a new [[JwtSignature]] from the specified [[jots.crypto.Mac]].
    */
  def fromMac(mac: Mac): JwtSignature =
    fromByteVector(mac.toByteVector)

  /**
    * Returns a new [[JwtSignature]] from the specified [[jots.crypto.Signature]].
    */
  def fromSignature(signature: Signature): JwtSignature =
    fromByteVector(signature.toByteVector)

  /**
    * Alias for [[JwtSignature.fromBase64UrlNoPad]].
    */
  def fromString(signature: String): Either[JwtException, JwtSignature] =
    fromBase64UrlNoPad(signature)

  implicit val jwtSignatureHash: Hash[JwtSignature] =
    Hash.fromUniversalHashCode

  implicit val jwtSignatureShow: Show[JwtSignature] =
    Show.show(_.show)
}
