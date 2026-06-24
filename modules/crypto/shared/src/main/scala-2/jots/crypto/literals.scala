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

package jots.crypto

import java.lang.StringBuilder
import org.typelevel.literally.Literally

object literals {
  object PublicKeyLiteral extends Literally[PublicKey] {
    override def validate(c: Context)(s: String): Either[String, c.Expr[PublicKey]] = {
      import c.universe._
      PublicKey(s) match {
        case Right(_) => Right(c.Expr(q"_root_.jots.crypto.PublicKey($s).toOption.get"))
        case Left(e) => Left(message(e))
      }
    }

    def make(c: Context)(args: c.Expr[Any]*): c.Expr[PublicKey] =
      apply(c)(args: _*)
  }

  private def message(e: CryptoException): String = {
    def go(builder: StringBuilder, e: Throwable): String = {
      val cause = e.getCause
      if (cause != null) {
        go(builder.append(": ").append(cause.getMessage), cause)
      } else builder.toString
    }

    go(new StringBuilder(e.getMessage), e)
  }
}
