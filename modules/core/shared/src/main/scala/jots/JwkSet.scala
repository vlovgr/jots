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
import io.circe.Decoder
import io.circe.Encoder
import io.circe.Json
import io.circe.JsonObject
import io.circe.syntax.*

/**
  * Represents a set of keys known as a JSON Web Key Set (JWK Set).
  */
sealed abstract class JwkSet {

  /**
    * Returns `true` if the key set is empty; otherwise `false`.
    */
  def isEmpty: Boolean

  /**
    * Returns the number of keys contained in the key set.
    */
  def size: Int

  /**
    * Returns the key set as a `JsonObject`.
    */
  def toJsonObject: JsonObject

  /**
    * Returns the key set as `Json`.
    */
  def toJson: Json

  /**
    * Returns the set of keys as a `List`.
    */
  def toList: List[Jwk]

  /**
    * Returns a `String` representation of the key set.
    */
  def show: String
}

object JwkSet {
  private final case class JwkSetImpl(
    override val toList: List[Jwk]
  ) extends JwkSet {
    override def isEmpty: Boolean =
      toList.isEmpty

    override def size: Int =
      toList.size

    override def toJsonObject: JsonObject =
      JsonObject("keys" -> toList.asJson)

    override def toJson: Json =
      toJsonObject.toJson

    override def show: String =
      toList.map(_.show).mkString("JwkSet(", ",", ")")

    override def toString: String =
      show
  }

  /**
    * The empty key set without any keys.
    */
  val empty: JwkSet =
    JwkSetImpl(List.empty)

  /**
    * Returns a new [[JwkSet]] with the specified keys.
    */
  def apply(keys: Jwk*): JwkSet =
    fromList(keys.toList)

  /**
    * Returns a new [[JwkSet]] from the specified list of keys.
    */
  def fromList(keys: List[Jwk]): JwkSet =
    if (keys.isEmpty) empty else JwkSetImpl(keys)

  implicit val jwkSetDecoder: Decoder[JwkSet] =
    Decoder[List[Jwk]].at("keys").map(fromList)

  implicit val jwkSetEncoder: Encoder[JwkSet] =
    Encoder.instance(_.toJson)

  implicit val jwkSetHash: Hash[JwkSet] =
    Hash.fromUniversalHashCode

  implicit val jwkSetShow: Show[JwkSet] =
    Show.show(_.show)
}
