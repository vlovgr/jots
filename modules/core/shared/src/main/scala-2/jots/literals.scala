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

import java.lang.StringBuilder
import org.typelevel.literally.Literally

object literals {
  object JwkLiteral extends Literally[Jwk] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[Jwk]] = {
      import c.universe._
      Jwk.fromString(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.Jwk.fromString($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[Jwk] =
      apply(c)(args: _*)
  }

  object JwkSetLiteral extends Literally[JwkSet] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[JwkSet]] = {
      import c.universe._
      JwkSet.fromString(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.JwkSet.fromString($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[JwkSet] =
      apply(c)(args: _*)
  }

  private def message(e: Throwable): String = {
    def go(builder: StringBuilder, e: Throwable): String = {
      val cause = e.getCause
      if (cause != null) {
        go(builder.append(": ").append(cause.getMessage), cause)
      } else builder.toString
    }

    go(new StringBuilder(e.getMessage), e)
  }
}
