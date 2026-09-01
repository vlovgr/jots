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

import cats.data.Kleisli
import cats.data.OptionT
import cats.effect.IO
import cats.syntax.all.*
import io.circe.DecodingFailure
import jots.ExampleHmacJwt
import jots.ExampleJwt
import jots.JwtDecoder
import jots.JwtVerification
import jots.SignedJwt
import org.http4s.AuthScheme
import org.http4s.AuthedRoutes
import org.http4s.Credentials
import org.http4s.Header
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.headers.Authorization
import org.http4s.headers.`WWW-Authenticate`
import weaver.SimpleIOSuite

object JwtAuthMiddlewareSuite extends SimpleIOSuite {
  test("JwtAuthMiddleware.verifyExamples") {
    ExampleJwt.All
      .traverse { example =>
        for {
          verification <- example.verification
          response <- respondTo(verification, requestWith(example.signedJwt))
          subject <- response.as[String]
        } yield expect.eql(Status.Ok, response.status) && expect.eql("1234567890", subject)
      }
      .map(_.combineAll)
  }

  test("JwtAuthMiddleware.apply") {
    val example = ExampleHmacJwt.HS256
    for {
      verification <- example.verification
      response <- {
        implicit val jwtVerification: JwtVerification[IO] = verification
        implicit val jwtDecoder: JwtDecoder[String] = subjectDecoder
        JwtAuthMiddleware[IO, String]
          .apply(routes)
          .run(requestWith(example.signedJwt))
          .getOrElse(Response[IO](Status.NotFound))
      }
      subject <- response.as[String]
    } yield expect.eql(Status.Ok, response.status) && expect.eql("1234567890", subject)
  }

  test("JwtAuthMiddleware.rejectMissingToken") {
    for {
      verification <- ExampleHmacJwt.HS256.verification
      response <- respondTo(verification, Request[IO]())
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(missingChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.rejectMalformedToken") {
    val credentials = Credentials.Token(AuthScheme.Bearer, "not-a-token")
    for {
      verification <- ExampleHmacJwt.HS256.verification
      response <- respondTo(verification, Request[IO]().putHeaders(Authorization(credentials)))
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(invalidChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.rejectOtherAuthScheme") {
    val credentials = Credentials.Token(AuthScheme.Basic, "dXNlcjpwYXNzd29yZA==")
    for {
      verification <- ExampleHmacJwt.HS256.verification
      response <- respondTo(verification, Request[IO]().putHeaders(Authorization(credentials)))
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(missingChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.rejectUnparseableCredentials") {
    val authorization = Header.Raw(Authorization.name, "?")
    for {
      verification <- ExampleHmacJwt.HS256.verification
      response <- respondTo(verification, Request[IO]().putHeaders(authorization))
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(missingChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.rejectInvalidToken") {
    for {
      verification <- ExampleHmacJwt.HS384.verification
      response <- respondTo(verification, requestWith(ExampleHmacJwt.HS256.signedJwt))
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(invalidChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.rejectDecodeFailure") {
    val example = ExampleHmacJwt.HS256
    val decoder = JwtDecoder.failed[String](DecodingFailure("the claims are missing", Nil))
    for {
      verification <- example.verification
      response <- respondTo(verification, requestWith(example.signedJwt), decoder)
    } yield expect.eql(Status.Unauthorized, response.status) &&
      expect.eql(invalidChallenge, challengeOf(response))
  }

  test("JwtAuthMiddleware.raiseOtherErrors") {
    val error = new RuntimeException("the key set could not be fetched")
    val verification = JwtVerification.verifyWith[IO](_ => IO.raiseError(error))
    for {
      result <- respondTo(verification, requestWith(ExampleHmacJwt.HS256.signedJwt)).attempt
      _ <- matchOrFailFast[IO](result) { case Left(`error`) => () }
    } yield success
  }

  /**
    * The challenge for requests where no token was provided.
    */
  private val missingChallenge: String =
    "Bearer realm=\"\""

  /**
    * The challenge for requests where the token was not accepted.
    */
  private val invalidChallenge: String =
    "Bearer realm=\"\",error=\"invalid_token\""

  private val subjectDecoder: JwtDecoder[String] =
    JwtDecoder.decodeWith(_.claims.toJson.hcursor.get[String]("sub"))

  /**
    * Routes which respond with the decoded token as the response body.
    */
  private val routes: AuthedRoutes[String, IO] =
    Kleisli(request => OptionT.pure[IO](Response[IO](Status.Ok).withEntity(request.context)))

  private def requestWith(signedJwt: SignedJwt): Request[IO] =
    Request[IO]().withHeaders(signedJwt)

  /**
    * Returns the rendered `WWW-Authenticate` challenge of the
    * response, or an empty `String` if no such header exists.
    */
  private def challengeOf(response: Response[IO]): String =
    response.headers.get[`WWW-Authenticate`].foldMap(_.values.head.value)

  private def respondTo(
    verification: JwtVerification[IO],
    request: Request[IO],
    decoder: JwtDecoder[String] = subjectDecoder
  ): IO[Response[IO]] = {
    implicit val jwtDecoder: JwtDecoder[String] = decoder
    JwtAuthMiddleware
      .verifyWith[IO, String](verification)
      .apply(routes)
      .run(request)
      .getOrElse(Response[IO](Status.NotFound))
  }
}
