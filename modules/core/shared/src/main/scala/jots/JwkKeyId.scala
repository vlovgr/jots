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

/**
  * The key identifier used to identify a specific key in a [[JwkSet]].
  *
  * Usually set as the `kid` parameter in a [[Jwk]] or [[JwtHeader]].
  */
sealed abstract class JwkKeyId {

  /**
    * Returns the `String` key identifier value.
    */
  def value: String

  /**
    * Alias for [[JwkKeyId#value]].
    */
  def show: String
}

object JwkKeyId {
  private final case class JwkKeyIdImpl(override val value: String) extends JwkKeyId {
    override val show: String = value
    override val toString: String = s"JwkKeyId($value)"
  }

  /**
    * Alias for [[JwkKeyId.fromString]].
    */
  def apply(value: String): JwkKeyId =
    fromString(value)

  /**
    * Returns a new [[JwkKeyId]] from the specified `String`.
    */
  def fromString(value: String): JwkKeyId =
    JwkKeyIdImpl(value)

  def unapply(keyId: JwkKeyId): Some[String] =
    Some(keyId.value)

  implicit val jwkKeyIdHash: Hash[JwkKeyId] =
    Hash.fromUniversalHashCode

  implicit val jwkKeyIdShow: Show[JwkKeyId] =
    Show.show(_.show)
}
