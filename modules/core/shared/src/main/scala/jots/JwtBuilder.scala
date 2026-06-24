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
import cats.syntax.all.*
import java.nio.charset.StandardCharsets.UTF_8
import scodec.bits.ByteVector

/**
  * Represents a JWT being constructed, prior to signing.
  */
sealed abstract class JwtBuilder {

  /**
    * Returns the [[JwtHeader]] of the JWT being constructed.
    */
  def header: JwtHeader

  /**
    * Returns a new [[JwtBuilder]] with the specified
    * function applied on the existing [[JwtHeader]].
    */
  def mapHeader(f: JwtHeader => JwtHeader): JwtBuilder

  /**
    * Returns a new [[JwtBuilder]] with the specified [[JwtHeader]].
    */
  def withHeader(header: JwtHeader): JwtBuilder

  /**
    * Returns the [[JwtClaims]] of the JWT being constructed.
    */
  def claims: JwtClaims

  /**
    * Returns a new [[JwtBuilder]] with the specified
    * function applied on the existing [[JwtClaims]].
    */
  def mapClaims(f: JwtClaims => JwtClaims): JwtBuilder

  /**
    * Returns a new [[JwtBuilder]] with the specified [[JwtClaims]].
    */
  def withClaims(claims: JwtClaims): JwtBuilder

  /**
    * Returns a [[SignedJwt]] by signing the contents of
    * the JWT with the specified [[JwtSigning]] instance.
    */
  def signWith[F[_]](signing: JwtSigning[F]): F[SignedJwt]

  /**
    * Returns a [[SignedJwt]] using the specified signature.
    */
  def toSigned(signature: JwtSignature): SignedJwt

  /**
    * Returns the bytes which should be signed during signing.
    */
  def signingBytes: ByteVector

  /**
    * Returns a `String` representation of the JWT being constructed.
    *
    * This is the Base64UrlNoPad header and claims separated by a dot.
    */
  def show: String
}

object JwtBuilder {
  private final case class JwtBuilderImpl(
    override val header: JwtHeader,
    override val claims: JwtClaims
  ) extends JwtBuilder {
    override def mapHeader(f: JwtHeader => JwtHeader): JwtBuilder =
      withHeader(f(header))

    override def withHeader(header: JwtHeader): JwtBuilder =
      copy(header = header)

    override def mapClaims(f: JwtClaims => JwtClaims): JwtBuilder =
      withClaims(f(claims))

    override def withClaims(claims: JwtClaims): JwtBuilder =
      copy(claims = claims)

    override def signWith[F[_]](signing: JwtSigning[F]): F[SignedJwt] =
      signing.sign(this)

    override def toSigned(signature: JwtSignature): SignedJwt =
      SignedJwt(header.toSigned, claims.toSigned, signature)

    override def signingBytes: ByteVector =
      ByteVector.view(show.getBytes(UTF_8))

    override def show: String =
      show"$header.$claims"

    override def toString: String =
      s"JwtBuilder($header,$claims)"
  }

  /**
    * Returns a new [[JwtBuilder]] with the specified header and claims.
    */
  def apply(header: JwtHeader, claims: JwtClaims): JwtBuilder =
    JwtBuilderImpl(header, claims)

  /**
    * The default [[JwtBuilder]] with the [[JwtHeader.default]]
    * header and [[JwtClaims.empty]] claims.
    */
  val default: JwtBuilder =
    JwtBuilder(JwtHeader.default, JwtClaims.empty)

  /**
    * The empty [[JwtBuilder]] with the [[JwtHeader.empty]]
    * header and [[JwtClaims.empty]] claims.
    */
  val empty: JwtBuilder =
    JwtBuilder(JwtHeader.empty, JwtClaims.empty)

  implicit val jwtBuilderHash: Hash[JwtBuilder] =
    Hash.fromUniversalHashCode

  implicit val jwtBuilderShow: Show[JwtBuilder] =
    Show.show(_.show)
}
