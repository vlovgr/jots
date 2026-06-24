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

import cats.MonadError
import cats.syntax.all.*
import io.circe.Decoder
import io.circe.DecodingFailure
import scala.annotation.tailrec

/**
  * Decodes [[VerifiedJwt]]s to instances of type `A`.
  *
  * A common approach is to decode [[VerifiedJwt]] claims
  * to type `A`. This can be done by defining a `Decoder`
  * instance and using [[JwtDecoder.decodeClaims]].
  */
trait JwtDecoder[A] { self =>

  /**
    * Decodes the specified [[VerifiedJwt]] to type `A`.
    */
  def decode(jwt: VerifiedJwt): Decoder.Result[A]

  /**
    * Returns a new [[JwtDecoder]] based on the result of this decoder.
    */
  final def flatMap[B](f: A => JwtDecoder[B]): JwtDecoder[B] =
    JwtDecoder.decodeWith(jwt => self.decode(jwt).flatMap(f(_).decode(jwt)))

  /**
    * Returns a new [[JwtDecoder]] which handles decoding failures.
    */
  final def handleErrorWith(f: DecodingFailure => JwtDecoder[A]): JwtDecoder[A] =
    JwtDecoder.decodeWith(jwt => self.decode(jwt).handleErrorWith(f(_).decode(jwt)))

  /**
    * Returns a new [[JwtDecoder]] which applies the function on the result.
    */
  final def map[B](f: A => B): JwtDecoder[B] =
    JwtDecoder.decodeWith(self.decode(_).map(f))
}

object JwtDecoder {
  def apply[A](implicit decoder: JwtDecoder[A]): JwtDecoder[A] =
    decoder

  /**
    * Returns a [[JwtDecoder]] which always decodes
    * to the specified value.
    */
  def const[A](a: A): JwtDecoder[A] =
    decodeWith(_ => Right(a))

  /**
    * Returns a [[JwtDecoder]] which decodes the
    * verified claims using a `Decoder` instance.
    */
  def decodeClaims[A: Decoder]: JwtDecoder[A] =
    decodeWith(_.claims.toJson.as[A])

  /**
    * Returns a [[JwtDecoder]] which decodes using
    * the specified function.
    */
  def decodeWith[A](f: VerifiedJwt => Decoder.Result[A]): JwtDecoder[A] =
    new JwtDecoder[A] {
      override def decode(jwt: VerifiedJwt): Decoder.Result[A] =
        f(jwt)
    }

  /**
    * Returns a [[JwtDecoder]] which always fails with
    * the specified `DecodingFailure`.
    */
  def failed[A](failure: DecodingFailure): JwtDecoder[A] =
    decodeWith(_ => Left(failure))

  implicit val jwtDecoderMonadError: MonadError[JwtDecoder, DecodingFailure] =
    new MonadError[JwtDecoder, DecodingFailure] {
      override def pure[A](a: A): JwtDecoder[A] =
        JwtDecoder.const(a)

      override def map[A, B](decoder: JwtDecoder[A])(f: A => B): JwtDecoder[B] =
        decoder.map(f)

      override def flatMap[A, B](decoder: JwtDecoder[A])(f: A => JwtDecoder[B]): JwtDecoder[B] =
        decoder.flatMap(f)

      override def handleErrorWith[A](decoder: JwtDecoder[A])(
        f: DecodingFailure => JwtDecoder[A]
      ): JwtDecoder[A] =
        decoder.handleErrorWith(f)

      override def raiseError[A](e: DecodingFailure): JwtDecoder[A] =
        JwtDecoder.failed(e)

      override def tailRecM[A, B](a: A)(f: A => JwtDecoder[Either[A, B]]): JwtDecoder[B] =
        new JwtDecoder[B] {
          @tailrec
          private def step(jwt: VerifiedJwt, a1: A): Decoder.Result[B] =
            f(a1).decode(jwt) match {
              case left @ Left(_) => left.rightCast
              case Right(Left(a2)) => step(jwt, a2)
              case Right(right @ Right(_)) => right.leftCast
            }

          override def decode(jwt: VerifiedJwt): Decoder.Result[B] =
            step(jwt, a)
        }
    }
}
