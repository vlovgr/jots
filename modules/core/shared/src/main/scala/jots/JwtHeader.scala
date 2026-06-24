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
import cats.data.NonEmptyList
import cats.syntax.all.*
import io.circe.Json
import io.circe.JsonObject
import io.circe.syntax.*
import java.nio.charset.StandardCharsets.UTF_8
import scodec.bits.ByteVector

/**
  * The header of a JWT being constructed, prior to signing.
  */
sealed abstract class JwtHeader {

  /**
    * Returns a new [[JwtHeader]] with the specified algorithm's
    * name set for the `alg` key.
    *
    * Note the algorithm is normally set by [[JwtSigning]] when
    * signing and not set manually.
    */
  def withAlgorithm(algorithm: JwtAlgorithm): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified algorithm's
    * name set for the `alg` key, or with the `alg` key removed
    * when `None` is provided.
    *
    * Note the algorithm is normally set by [[JwtSigning]] when
    * signing and not set manually.
    */
  def withAlgorithmOption(algorithm: Option[JwtAlgorithm]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `alg` key removed.
    */
  def withoutAlgorithm: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified content type
    * set for the `cty` key.
    */
  def withContentType(contentType: String): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `cty` key set to the
    * specified content type, or removed if `None`.
    */
  def withContentTypeOption(contentType: Option[String]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `cty` key removed.
    */
  def withoutContentType: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified header names
    * set for the `crit` key, marking them as critical.
    */
  def withCriticalHeaders(criticalHeader: String, criticalHeaders: String*): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified header names
    * set for the `crit` key, marking them as critical.
    */
  def withCriticalHeadersList(criticalHeaders: NonEmptyList[String]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `crit` key removed.
    */
  def withoutCriticalHeaders: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified key id
    * set for the `kid` key.
    */
  def withKeyId(keyId: String): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `kid` key set to the
    * specified key id, or removed if `None`.
    */
  def withKeyIdOption(keyId: Option[String]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `kid` key removed.
    */
  def withoutKeyId: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified type
    * set for the `typ` key.
    */
  def withType(`type`: String): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `typ` key set to the
    * specified type, or removed if `None`.
    */
  def withTypeOption(`type`: Option[String]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the default type `JWT`
    * set for the `typ` key.
    */
  def withDefaultType: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the `typ` key removed.
    */
  def withoutType: JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified value
    * set for the specified key.
    */
  def add(name: String, value: Json): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified key set to
    * the specified value, or removed if `None`.
    */
  def addOption(name: String, value: Option[Json]): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified key-value pairs set.
    */
  def addAll(keys: (String, Json)*): JwtHeader

  /**
    * Returns a new [[JwtHeader]] with the specified key removed.
    */
  def remove(name: String): JwtHeader

  /**
    * Returns a new [[JwtHeader]] by applying the specified
    * function on the header `JsonObject` representation.
    */
  def mapJsonObject(f: JsonObject => JsonObject): JwtHeader

  /**
    * Returns the header `JsonObject` rendered without spaces in UTF-8.
    */
  def toByteVector: ByteVector

  /**
    * Returns [[JwtHeader#toByteVector]] in Base64UrlNoPad encoding.
    */
  def toBase64UrlNoPad: String

  /**
    * Returns the header represented as a `JsonObject`.
    */
  def toJsonObject: JsonObject

  /**
    * Returns the header represented as `Json`.
    */
  def toJson: Json

  /**
    * Returns a new [[SignedJwtHeader]] for this header.
    */
  def toSigned: SignedJwtHeader

  /**
    * Alias for [[JwtHeader#toBase64UrlNoPad]].
    */
  def show: String
}

object JwtHeader {
  private final case class JwtHeaderImpl(
    override val toJsonObject: JsonObject
  ) extends JwtHeader {
    override def withAlgorithm(algorithm: JwtAlgorithm): JwtHeader =
      add("alg", algorithm.name.asJson)

    override def withAlgorithmOption(algorithm: Option[JwtAlgorithm]): JwtHeader =
      algorithm.fold(withoutAlgorithm)(withAlgorithm)

    override def withoutAlgorithm: JwtHeader =
      remove("alg")

    override def withContentType(contentType: String): JwtHeader =
      add("cty", contentType.asJson)

    override def withContentTypeOption(contentType: Option[String]): JwtHeader =
      contentType.fold(withoutContentType)(withContentType)

    override def withoutContentType: JwtHeader =
      remove("cty")

    override def withCriticalHeaders(criticalHeader: String, criticalHeaders: String*): JwtHeader =
      withCriticalHeadersList(NonEmptyList.of(criticalHeader, criticalHeaders: _*))

    override def withCriticalHeadersList(criticalHeaders: NonEmptyList[String]): JwtHeader =
      add("crit", criticalHeaders.asJson)

    override def withoutCriticalHeaders: JwtHeader =
      remove("crit")

    override def withKeyId(keyId: String): JwtHeader =
      add("kid", keyId.asJson)

    override def withKeyIdOption(keyId: Option[String]): JwtHeader =
      keyId.fold(withoutKeyId)(withKeyId)

    override def withoutKeyId: JwtHeader =
      remove("kid")

    override def withType(`type`: String): JwtHeader =
      add("typ", `type`.asJson)

    override def withTypeOption(`type`: Option[String]): JwtHeader =
      `type`.fold(withoutType)(withType)

    override def withDefaultType: JwtHeader =
      withType("JWT")

    override def withoutType: JwtHeader =
      remove("typ")

    override def add(name: String, value: Json): JwtHeader =
      mapJsonObject(_.add(name, value))

    override def addOption(name: String, value: Option[Json]): JwtHeader =
      value.fold(remove(name))(add(name, _))

    override def addAll(keys: (String, Json)*): JwtHeader =
      keys.foldLeft(this: JwtHeader) { case (header, (name, value)) => header.add(name, value) }

    override def remove(name: String): JwtHeader =
      mapJsonObject(_.remove(name))

    override def mapJsonObject(f: JsonObject => JsonObject): JwtHeader =
      copy(f(toJsonObject))

    override def toByteVector: ByteVector =
      ByteVector.view(toJson.noSpaces.getBytes(UTF_8))

    override def toBase64UrlNoPad: String =
      toByteVector.toBase64UrlNoPad

    override def toJson: Json =
      toJsonObject.toJson

    override def toSigned: SignedJwtHeader =
      SignedJwtHeader.fromHeader(this)

    override def toString: String =
      toJsonObject.toIterable
        .map { case (key, value) => show"$key -> $value" }
        .mkString("JwtHeader(", ",", ")")

    override def show: String =
      toBase64UrlNoPad
  }

  /**
    * The empty [[JwtHeader]] without any keys: `{}`.
    */
  val empty: JwtHeader =
    new JwtHeaderImpl(JsonObject.empty)

  /**
    * A [[JwtHeader]] with the default type: `{"typ":"JWT"}`.
    */
  val default: JwtHeader =
    empty.withDefaultType

  /**
    * Returns a new [[JwtHeader]] with the specified key-value pairs.
    */
  def apply(fields: (String, Json)*): JwtHeader =
    fromJsonObject(JsonObject(fields: _*))

  /**
    * Returns a new [[JwtHeader]] from the specified `JsonObject`.
    */
  def fromJsonObject(jsonObject: JsonObject): JwtHeader =
    if (jsonObject.isEmpty) empty else JwtHeaderImpl(jsonObject)

  implicit val jwtHeaderHash: Hash[JwtHeader] =
    Hash.fromUniversalHashCode

  implicit val jwtHeaderShow: Show[JwtHeader] =
    Show.show(_.show)
}
