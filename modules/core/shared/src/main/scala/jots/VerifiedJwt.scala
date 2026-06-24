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
import cats.syntax.all.*
import io.circe.Decoder

/**
  * A [[SignedJwt]] for which the signature has been verified as valid.
  *
  * Token verification typically also includes verifying that claims
  * are valid, although this is optional and depends on the use case.
  *
  * [[VerifiedJwt]]s can only be created by the default implementations
  * of [[JwtVerification]]. The notable exception is the testing module
  * which allows to create a [[VerifiedJwt]] from any [[SignedJwt]].
  */
sealed abstract class VerifiedJwt {

  /**
    * Decodes this [[VerifiedJwt]] to the specified type.
    */
  def as[A: JwtDecoder]: Decoder.Result[A]

  /**
    * Returns the [[SignedJwtHeader]] which has been verified.
    */
  def header: SignedJwtHeader

  /**
    * Returns the [[SignedJwtClaims]] which have been verified.
    */
  def claims: SignedJwtClaims

  /**
    * Returns the [[JwtSignature]] which has been verified.
    */
  def signature: JwtSignature

  /**
    * Returns a new [[JwtBuilder]] using the verified header and claims.
    *
    * This enables using a verified token as the basis of a new token.
    */
  def toBuilder: JwtBuilder

  /**
    * Returns the [[SignedJwt]] which has been verified.
    */
  def toSigned: SignedJwt

  /**
    * Returns the verified token in its `String` representation.
    *
    * Note that tokens are generally considered sensitive details.
    */
  def show: String
}

object VerifiedJwt {
  private final case class VerifiedJwtImpl(
    override val toSigned: SignedJwt
  ) extends VerifiedJwt {
    override def as[A: JwtDecoder]: Decoder.Result[A] =
      JwtDecoder[A].decode(this)

    override def header: SignedJwtHeader =
      toSigned.header

    override def claims: SignedJwtClaims =
      toSigned.claims

    override def signature: JwtSignature =
      toSigned.signature

    override def toBuilder: JwtBuilder =
      toSigned.toBuilder

    override def show: String =
      show"$header.$claims.$signature"

    override def toString: String =
      s"VerifiedJwt($header,$claims)"
  }

  /**
    * Returns a new [[VerifiedJwt]] from a verified [[SignedJwt]].
    *
    * This should only be done from the default [[JwtVerification]]
    * instances after verifying the signature (and claims). The one
    * exception to this is the testing module, which allows creating
    * a [[VerifiedJwt]] from any [[SignedJwt]].
    */
  private[jots] def fromVerified(jwt: SignedJwt): VerifiedJwt =
    VerifiedJwtImpl(jwt)

  implicit val verifiedJwtHash: Hash[VerifiedJwt] =
    Hash.fromUniversalHashCode
}
