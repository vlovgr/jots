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

import cats.syntax.all.*
import org.http4s.AuthScheme
import org.http4s.Credentials
import org.http4s.Header
import org.http4s.ParseFailure
import org.http4s.headers.Authorization

package object http4s {

  /**
    * Instance for reading and writing [[SignedJwt]]s
    * as `Authorization: Bearer <token>` credentials.
    */
  implicit val signedJwtHeaderInstance: Header[SignedJwt, Header.Single] =
    Header.createRendered(
      Authorization.name,
      signedJwt => Credentials.Token(AuthScheme.Bearer, signedJwt.show),
      Authorization.parse(_).flatMap {
        case Authorization(Credentials.Token(AuthScheme.Bearer, token)) =>
          SignedJwt.fromString(token).leftMap(e => ParseFailure("Invalid Authorization header", e.message))
        case _ =>
          Left(ParseFailure("Invalid Authorization header", "credentials are not a bearer token"))
      }
    )
}
