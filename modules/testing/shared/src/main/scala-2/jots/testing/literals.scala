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

package jots.testing

import java.lang.StringBuilder
import jots.SignedJwt
import jots.crypto.PrivateKey
import jots.crypto.SecretKey
import org.typelevel.literally.Literally

object literals {
  object PrivateKeyLiteral extends Literally[PrivateKey] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[PrivateKey]] = {
      import c.universe._
      PrivateKey(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.crypto.PrivateKey($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[PrivateKey] =
      apply(c)(args: _*)
  }

  object SecretKeyLiteral extends Literally[SecretKey] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[SecretKey]] = {
      import c.universe._
      SecretKey(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.crypto.SecretKey($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[SecretKey] =
      apply(c)(args: _*)
  }

  object SignedJwtLiteral extends Literally[SignedJwt] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[SignedJwt]] = {
      import c.universe._
      SignedJwt.fromString(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.SignedJwt.fromString($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[SignedJwt] =
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
