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

package jots.internal

import cats.ApplicativeThrow
import cats.data.NonEmptyList
import jots.JwtException.InvalidEcKeyLength
import jots.JwtException.InvalidEddsaKeyLength
import jots.JwtException.InvalidRsaKeyLength

/**
  * Describes the key length requirement of a [[jots.JwtAsymmetricAlgorithm]].
  */
private[jots] sealed abstract class KeyRequirement

private[jots] object KeyRequirement {

  /**
    * The key must be of type RSA with at least the specified modulus bit length.
    */
  final case class Rsa(minBits: Int) extends KeyRequirement

  /**
    * The key must be of type ECDSA with exactly the specified curve bit length.
    */
  final case class Ecdsa(bits: Int) extends KeyRequirement

  /**
    * The key must be of type EdDSA with exactly the specified curve bit length.
    */
  final case class Eddsa(bits: Int) extends KeyRequirement

  /**
    * Checks the specified key length against a single requirement.
    */
  def check[F[_]: ApplicativeThrow](requirement: KeyRequirement, keyLength: KeyLength): F[Unit] =
    check(NonEmptyList.one(requirement), keyLength)

  /**
    * Checks the specified key length against mutiple requirements.
    */
  def check[F[_]](
    requirements: NonEmptyList[KeyRequirement],
    keyLength: KeyLength
  )(implicit F: ApplicativeThrow[F]): F[Unit] =
    keyLength match {
      case KeyLength.Rsa(bits) =>
        requirements
          .collectFirst { case Rsa(minBits) if bits >= minBits => F.unit }
          .getOrElse(F.raiseError(new InvalidRsaKeyLength(bits)))
      case KeyLength.Ecdsa(bits) =>
        requirements
          .collectFirst { case Ecdsa(`bits`) => F.unit }
          .getOrElse(F.raiseError(new InvalidEcKeyLength(bits)))
      case KeyLength.Eddsa(bits) =>
        requirements
          .collectFirst { case Eddsa(`bits`) => F.unit }
          .getOrElse(F.raiseError(new InvalidEddsaKeyLength(bits)))
      case KeyLength.Unknown =>
        F.unit
    }
}
