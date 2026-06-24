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
    override def validate(s: String)(using Quotes): Either[String, Expr[PrivateKey]] =
      PrivateKey(s) match {
        case Right(_) => Right('{ _root_.jots.crypto.PrivateKey(${ Expr(s) }).toOption.get })
        case Left(e) => Left(message(e))
      }
  }

  object SecretKeyLiteral extends Literally[SecretKey] {
    override def validate(s: String)(using Quotes): Either[String, Expr[SecretKey]] =
      SecretKey(s) match {
        case Right(_) => Right('{ _root_.jots.crypto.SecretKey(${ Expr(s) }).toOption.get })
        case Left(e) => Left(message(e))
      }
  }

  object SignedJwtLiteral extends Literally[SignedJwt] {
    override def validate(s: String)(using Quotes): Either[String, Expr[SignedJwt]] =
      SignedJwt.fromString(s) match {
        case Right(_) => Right('{ _root_.jots.SignedJwt.fromString(${ Expr(s) }).toOption.get })
        case Left(e) => Left(message(e))
      }
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
