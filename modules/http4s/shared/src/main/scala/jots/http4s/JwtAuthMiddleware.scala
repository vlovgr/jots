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

package jots.http4s

import cats.MonadThrow
import cats.data.Kleisli
import cats.data.OptionT
import cats.syntax.all.*
import io.circe.DecodingFailure
import jots.JwtDecoder
import jots.JwtException
import jots.JwtVerification
import jots.SignedJwt
import org.http4s.AuthScheme
import org.http4s.AuthedRoutes
import org.http4s.Challenge
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.headers.Authorization
import org.http4s.headers.`WWW-Authenticate`
import org.http4s.server.AuthMiddleware

/**
  * Provides support for creating `AuthMiddleware`s that
  * parse, verify and decode JSON Web Tokens (JWTs) from
  * incoming request headers.
  */
object JwtAuthMiddleware {

  /**
    * Alias for [[JwtAuthMiddleware.verifyWith]] but where
    * the `JwtVerification` instance is passed implicitly.
    */
  def apply[F[_]: JwtVerification: MonadThrow, A: JwtDecoder]: AuthMiddleware[F, A] =
    verifyWith[F, A](JwtVerification[F])

  /**
    * Returns an `AuthMiddleware` that reads tokens from the
    * `Authorization: Bearer <token>` header and proceeds to
    * verify them using the provided `JwtVerification`, then
    * finally decoding using the `JwtDecoder` instance.
    *
    * Requests with a missing or invalid token will receive
    * a 401 Unauthorized response with a `WWW-Authenticate`
    * header set detailing the issue.
    */
  def verifyWith[F[_]: MonadThrow, A: JwtDecoder](
    verification: JwtVerification[F]
  ): AuthMiddleware[F, A] = {
    val onFailure: AuthedRoutes[JwtAuthFailure, F] =
      Kleisli { request =>
        val authenticate = `WWW-Authenticate`(request.context.challenge)
        OptionT.pure[F](Response[F](Status.Unauthorized).withHeaders(authenticate))
      }

    def reject(failure: JwtAuthFailure): F[Either[JwtAuthFailure, A]] =
      failure.asLeft[A].pure[F]

    val authUser: Kleisli[F, Request[F], Either[JwtAuthFailure, A]] =
      Kleisli { request =>
        request.headers.get[SignedJwt] match {
          case Some(jwt) =>
            verification.verifyAs[A](jwt).map(_.asRight[JwtAuthFailure]).recover {
              case _: JwtException | _: DecodingFailure => Invalid.asLeft
            }
          case None if hasBearerCredentials(request) =>
            reject(Invalid)
          case None =>
            reject(Missing)
        }
      }

    AuthMiddleware(authUser, onFailure)
  }

  private def hasBearerCredentials[F[_]](request: Request[F]): Boolean =
    request.headers.get[Authorization].exists(_.credentials.authScheme == AuthScheme.Bearer)

  private sealed abstract class JwtAuthFailure {
    def challenge: Challenge
  }

  private object Invalid extends JwtAuthFailure {
    override val challenge: Challenge =
      Challenge("Bearer", "", Map("error" -> "invalid_token"))
  }

  private object Missing extends JwtAuthFailure {
    override val challenge: Challenge =
      Challenge("Bearer", "")
  }
}
