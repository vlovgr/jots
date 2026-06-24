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

import cats.Hash
import cats.Show

/**
  * The output from signature verification:
  * [[Verified.Valid]] or [[Verified.Invalid]].
  */
sealed abstract class Verified {

  /**
    * Returns `true` if valid; `false` otherwise.
    */
  def isValid: Boolean

  /**
    * Returns `true` if invalid; `false` otherwise.
    */
  def isInvalid: Boolean

  /**
    * Returns `"Valid"` if valid; `"Invalid"` otherwise.
    */
  def show: String
}

object Verified {
  case object Valid extends Verified {
    override val isValid: Boolean = true
    override val isInvalid: Boolean = false
    override val show: String = toString
  }

  case object Invalid extends Verified {
    override val isValid: Boolean = false
    override val isInvalid: Boolean = true
    override val show: String = toString
  }

  /**
    * Alias for [[Verified.fromBoolean]].
    */
  def apply(valid: Boolean): Verified =
    fromBoolean(valid)

  /**
    * Returns [[Verified.Valid]] if the specified
    * value is `true`; [[Verified.Invalid]] otherwise.
    */
  def fromBoolean(valid: Boolean): Verified =
    if (valid) Valid else Invalid

  /**
    * Alias for [[Verified.Valid]].
    */
  val valid: Verified = Valid

  /**
    * Alias for [[Verified.Invalid]].
    */
  val invalid: Verified = Invalid

  implicit val verifiedHash: Hash[Verified] =
    Hash.fromUniversalHashCode

  implicit val verifiedShow: Show[Verified] =
    Show.show(_.show)
}
