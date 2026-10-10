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

import cats.effect.IO
import jots.Jwk
import jots.JwkSet
import org.http4s.MediaType
import org.http4s.Request
import org.http4s.headers.`Content-Type`
import weaver.SimpleIOSuite

object JwkEntityDecoderSuite extends SimpleIOSuite {
  test("JwkEntityDecoder.redactDecodeFailure") {
    for {
      result <- jsonRequest("""{"kid":"key-1","d":"secret"}""").attemptAs[Jwk].value
      _ <- matchOrFailFast[IO](result) { case Left(failure) if !failure.getMessage.contains("secret") => () }
    } yield success
  }

  test("JwkEntityDecoder.redactNested") {
    for {
      result <- jsonRequest(nested).attemptAs[Jwk].value
      _ <- matchOrFailFast[IO](result) { case Left(failure) if failure.getMessage.length < 100 => () }
    } yield success
  }

  test("JwkSetEntityDecoder.redactDecodeFailure") {
    for {
      result <- jsonRequest("""{"keys":[{"kid":"key-1","d":"secret"}]}""").attemptAs[JwkSet].value
      _ <- matchOrFailFast[IO](result) { case Left(failure) if !failure.getMessage.contains("secret") => () }
    } yield success
  }

  test("JwkSetEntityDecoder.redactNested") {
    for {
      result <- jsonRequest(nested).attemptAs[JwkSet].value
      _ <- matchOrFailFast[IO](result) { case Left(failure) if failure.getMessage.length < 100 => () }
    } yield success
  }

  private val nested: String =
    "[" * 4000 + "]" * 4000

  private def jsonRequest(json: String): Request[IO] =
    Request[IO]()
      .withEntity(json)
      .withContentType(`Content-Type`(MediaType.application.json))
}
