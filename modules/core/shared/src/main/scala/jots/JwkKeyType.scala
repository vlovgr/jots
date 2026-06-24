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
import cats.data.NonEmptyMap
import jots.JwkKeyTypes.Unknown
import jots.JwtException.UnsupportedKeyType

/**
  * The key type used to identify the type of key for a [[Jwk]].
  *
  * Required to be set as the `kty` parameter for a [[Jwk]].
  */
sealed abstract class JwkKeyType {

  /**
    * Returns the `String` name for the key type.
    */
  def name: String

  /**
    * Alias for [[JwkKeyType#name]].
    */
  def show: String
}

object JwkKeyType {

  /**
    * The Elliptic Curve (EC) key type.
    */
  val EC: JwkKeyType = JwkKeyTypes.EC

  /**
    * The Octet sequence (oct) key type.
    */
  val Oct: JwkKeyType = JwkKeyTypes.Oct

  /**
    * The Octet Key Pair (OKP) key type.
    */
  val OKP: JwkKeyType = JwkKeyTypes.OKP

  /**
    * The Rivest–Shamir–Adleman (RSA) key type.
    */
  val RSA: JwkKeyType = JwkKeyTypes.RSA

  /**
    * The list of all recognized [[JwkKeyType]]s.
    */
  val All: NonEmptyList[JwkKeyType] =
    NonEmptyList.of(EC, Oct, OKP, RSA)

  private val byName: NonEmptyMap[String, JwkKeyType] =
    All.groupByNem(_.name).map(_.head)

  /**
    * Alias for [[JwkKeyType.withName]].
    */
  def apply(name: String): JwkKeyType =
    withName(name)

  /**
    * Returns the [[JwkKeyType]] with the specified name
    * if it is recognized; otherwise a [[JwtException]].
    */
  def fromName(name: String): Either[JwtException, JwkKeyType] =
    byName(name).toRight(new UnsupportedKeyType(name))

  /**
    * Returns a [[JwkKeyType]] with the specified name.
    */
  def withName(name: String): JwkKeyType =
    fromName(name).getOrElse(Unknown(name))

  def unapply(keyType: JwkKeyType): Some[String] =
    Some(keyType.name)

  implicit val jwkKeyTypeHash: Hash[JwkKeyType] =
    Hash.fromUniversalHashCode

  implicit val jwkKeyTypeShow: Show[JwkKeyType] =
    Show.show(_.show)
}

private[jots] object JwkKeyTypes {
  case object EC extends JwkKeyType {
    override val name: String = "EC"
    override val show: String = name
    override val toString: String = s"JwkKeyType($name)"
  }

  case object Oct extends JwkKeyType {
    override val name: String = "oct"
    override val show: String = name
    override val toString: String = s"JwkKeyType($name)"
  }

  case object OKP extends JwkKeyType {
    override val name: String = "OKP"
    override val show: String = name
    override val toString: String = s"JwkKeyType($name)"
  }

  case object RSA extends JwkKeyType {
    override val name: String = "RSA"
    override val show: String = name
    override val toString: String = s"JwkKeyType($name)"
  }

  final case class Unknown(override val name: String) extends JwkKeyType {
    override val show: String = name
    override val toString: String = s"JwkKeyType($name)"
  }
}
