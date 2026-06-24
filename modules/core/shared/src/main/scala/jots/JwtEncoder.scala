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

import cats.Contravariant
import io.circe.Encoder
import io.circe.syntax.*

/**
  * Encodes instances of type `A` to [[JwtBuilder]]s.
  *
  * A common approach is to encode instances of type `A`
  * as the claims of a [[JwtBuilder]]. This can be done
  * by defining an `Encoder.AsObject` instance and then
  * using [[JwtEncoder.encodeClaims]].
  */
trait JwtEncoder[A] { self =>

  /**
    * Encodes the specified value to a [[JwtBuilder]].
    */
  def encode(a: A): JwtBuilder

  /**
    * Returns a new [[JwtEncoder]] which applies the
    * function to encode values using this encoder.
    */
  final def contramap[B](f: B => A): JwtEncoder[B] =
    new JwtEncoder[B] {
      override def encode(b: B): JwtBuilder =
        self.encode(f(b))
    }

  /**
    * Returns a new [[JwtEncoder]] which applies the
    * function on the [[JwtBuilder]] after encoding.
    */
  final def mapJwt(f: JwtBuilder => JwtBuilder): JwtEncoder[A] =
    new JwtEncoder[A] {
      override def encode(a: A): JwtBuilder =
        f(self.encode(a))
    }

  /**
    * Returns a new [[JwtEncoder]] which applies the
    * function on the [[JwtClaims]] after encoding.
    */
  final def mapClaims(f: JwtClaims => JwtClaims): JwtEncoder[A] =
    mapJwt(_.mapClaims(f))

  /**
    * Returns a new [[JwtEncoder]] which applies the
    * function on the [[JwtHeader]] after encoding.
    */
  final def mapHeader(f: JwtHeader => JwtHeader): JwtEncoder[A] =
    mapJwt(_.mapHeader(f))
}

object JwtEncoder {
  def apply[A](implicit encoder: JwtEncoder[A]): JwtEncoder[A] =
    encoder

  /**
    * Returns a [[JwtEncoder]] which encodes as [[JwtClaims]]
    * using an `Encoder.AsObject`.
    *
    * Uses [[JwtBuilder.default]] with [[JwtHeader.default]]
    * for `{"typ":"JWT"}` header value.
    */
  def encodeClaims[A: Encoder.AsObject]: JwtEncoder[A] =
    encodeClaimsWith(a => JwtClaims.fromJsonObject(a.asJsonObject))

  /**
    * Returns a [[JwtEncoder]] which encodes as [[JwtClaims]]
    * using the specified function.
    *
    * Uses [[JwtBuilder.default]] with [[JwtHeader.default]]
    * for `{"typ":"JWT"}` header value.
    */
  def encodeClaimsWith[A](f: A => JwtClaims): JwtEncoder[A] =
    encodeWith(a => JwtBuilder.default.withClaims(f(a)))

  /**
    * Returns a [[JwtEncoder]] which encodes using
    * the specified function.
    */
  def encodeWith[A](f: A => JwtBuilder): JwtEncoder[A] =
    new JwtEncoder[A] {
      override def encode(a: A): JwtBuilder =
        f(a)
    }

  implicit val jwtEncoderContravariant: Contravariant[JwtEncoder] =
    new Contravariant[JwtEncoder] {
      override def contramap[A, B](encoder: JwtEncoder[A])(f: B => A): JwtEncoder[B] =
        encoder.contramap(f)
    }
}
