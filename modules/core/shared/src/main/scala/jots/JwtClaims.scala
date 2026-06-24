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
import io.circe.Json
import io.circe.JsonObject
import java.nio.charset.StandardCharsets.UTF_8
import scodec.bits.ByteVector

/**
  * The claims of a JWT being constructed, prior to signing.
  */
sealed abstract class JwtClaims {

  /**
    * Returns a new [[JwtClaims]] with the specified value
    * set for the specified key.
    */
  def add(name: String, value: Json): JwtClaims

  /**
    * Returns a new [[JwtClaims]] with the specified key set to
    * the specified value, or removed if `None`.
    */
  def addOption(name: String, value: Option[Json]): JwtClaims

  /**
    * Returns a new [[JwtClaims]] with the specified key-value pairs set.
    */
  def addAll(keys: (String, Json)*): JwtClaims

  /**
    * Returns a new [[JwtClaims]] with the specified key removed.
    */
  def remove(name: String): JwtClaims

  /**
    * Returns a new [[JwtClaims]] by applying the specified
    * function on the claims `JsonObject` representation.
    */
  def mapJsonObject(f: JsonObject => JsonObject): JwtClaims

  /**
    * Returns the header `JsonObject` rendered without spaces in UTF-8.
    */
  def toByteVector: ByteVector

  /**
    * Returns [[JwtClaims#toByteVector]] in Base64UrlNoPad encoding.
    */
  def toBase64UrlNoPad: String

  /**
    * Returns the claims represented as a `JsonObject`.
    */
  def toJsonObject: JsonObject

  /**
    * Returns the claims represented as `Json`.
    */
  def toJson: Json

  /**
    * Returns a new [[SignedJwtClaims]] for these claims.
    */
  def toSigned: SignedJwtClaims

  /**
    * Alias for [[JwtClaims#toBase64UrlNoPad]].
    */
  def show: String
}

object JwtClaims {
  private final case class JwtClaimsImpl(
    override val toJsonObject: JsonObject
  ) extends JwtClaims {
    override def add(name: String, value: Json): JwtClaims =
      mapJsonObject(_.add(name, value))

    override def addOption(name: String, value: Option[Json]): JwtClaims =
      value.fold(remove(name))(add(name, _))

    override def addAll(keys: (String, Json)*): JwtClaims =
      keys.foldLeft(this: JwtClaims) { case (header, (name, value)) => header.add(name, value) }

    override def remove(name: String): JwtClaims =
      mapJsonObject(_.remove(name))

    override def mapJsonObject(f: JsonObject => JsonObject): JwtClaims =
      copy(f(toJsonObject))

    override def toByteVector: ByteVector =
      ByteVector.view(toJson.noSpaces.getBytes(UTF_8))

    override def toBase64UrlNoPad: String =
      toByteVector.toBase64UrlNoPad

    override def toJson: Json =
      toJsonObject.toJson

    override def toSigned: SignedJwtClaims =
      SignedJwtClaims.fromClaims(this)

    override def toString: String =
      toJsonObject.toIterable
        .map { case (key, value) => show"$key -> $value" }
        .mkString("JwtClaims(", ",", ")")

    override def show: String =
      toBase64UrlNoPad
  }

  /**
    * The empty [[JwtClaims]] without any claims.
    */
  val empty: JwtClaims =
    new JwtClaimsImpl(JsonObject.empty)

  /**
    * Returns a new [[JwtClaims]] with the specified key-value pairs.
    */
  def apply(fields: (String, Json)*): JwtClaims =
    fromJsonObject(JsonObject(fields: _*))

  /**
    * Returns a new [[JwtClaims]] from the specified `JsonObject`.
    */
  def fromJsonObject(jsonObject: JsonObject): JwtClaims =
    if (jsonObject.isEmpty) empty else JwtClaimsImpl(jsonObject)

  implicit val jwtClaimsHash: Hash[JwtClaims] =
    Hash.fromUniversalHashCode

  implicit val jwtClaimsShow: Show[JwtClaims] =
    Show.show(_.show)
}
