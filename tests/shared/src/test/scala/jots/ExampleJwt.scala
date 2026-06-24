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

import cats.effect.IO
import java.nio.charset.StandardCharsets.UTF_8
import scodec.bits.ByteVector

trait ExampleJwt {
  def header: JwtHeader

  def claims: JwtClaims

  def signedJwt: SignedJwt

  def verification: IO[JwtVerification[IO]]

  final def builder: JwtBuilder =
    JwtBuilder(header, claims)

  final def signedBytes: ByteVector =
    ByteVector.view(show.take(show.lastIndexOf(".")).getBytes(UTF_8))

  final def show: String =
    signedJwt.show

  final def verifiedJwt: IO[VerifiedJwt] =
    verification.flatMap(signedJwt.verifyWith)
}

object ExampleJwt {
  lazy val All: List[ExampleJwt] =
    ExampleHmacJwt.All ::: ExampleAsymmetricJwt.All
}
