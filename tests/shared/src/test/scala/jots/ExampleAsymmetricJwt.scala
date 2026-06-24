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

import cats.Show
import io.circe.Json
import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import org.scalacheck.Arbitrary
import org.scalacheck.Gen

trait ExampleAsymmetricJwt extends ExampleJwt {
  def algorithm: JwtAsymmetricAlgorithm

  def privateKey: PrivateKey

  def publicKey: PublicKey
}

object ExampleAsymmetricJwt {
  def privateKey(fields: (String, Json)*): PrivateKey =
    Jwk(fields: _*).flatMap(_.toPrivateKey).fold(throw _, identity)

  def publicKey(fields: (String, Json)*): PublicKey =
    Jwk(fields: _*).flatMap(_.toPublicKey).fold(throw _, identity)

  lazy val All: List[ExampleAsymmetricJwt] =
    ExampleEcdsaJwt.All ::: ExampleEddsaJwt.All ::: ExampleRsaJwt.All

  val exampleAsymmetricJwtGen: Gen[ExampleAsymmetricJwt] =
    Gen.oneOf(All)

  implicit val exampleAsymmetricJwtArbitrary: Arbitrary[ExampleAsymmetricJwt] =
    Arbitrary(exampleAsymmetricJwtGen)

  implicit val exampleAsymmetricJwtShow: Show[ExampleAsymmetricJwt] =
    Show.fromToString
}
