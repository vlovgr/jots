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
import cats.data.NonEmptyList

/**
  * Represents a cryptographic hash algorithm.
  */
sealed abstract class HashAlgorithm {

  /**
    * Returns a name for the hash algorithm.
    */
  def name: String

  /**
    * Alias for [[HashAlgorithm#name]].
    */
  def show: String
}

object HashAlgorithm {
  val SHA224: HashAlgorithm = HashAlgorithms.SHA224
  val SHA256: HashAlgorithm = HashAlgorithms.SHA256
  val SHA384: HashAlgorithm = HashAlgorithms.SHA384
  val SHA512: HashAlgorithm = HashAlgorithms.SHA512
  val SHA512_224: HashAlgorithm = HashAlgorithms.SHA512_224
  val SHA512_256: HashAlgorithm = HashAlgorithms.SHA512_256
  val SHA3_224: HashAlgorithm = HashAlgorithms.SHA3_224
  val SHA3_256: HashAlgorithm = HashAlgorithms.SHA3_256
  val SHA3_384: HashAlgorithm = HashAlgorithms.SHA3_384
  val SHA3_512: HashAlgorithm = HashAlgorithms.SHA3_512

  /**
    * The list of all recognized [[HashAlgorithm]]s.
    */
  val All: NonEmptyList[HashAlgorithm] =
    NonEmptyList.of(
      SHA224,
      SHA256,
      SHA384,
      SHA512,
      SHA512_224,
      SHA512_256,
      SHA3_224,
      SHA3_256,
      SHA3_384,
      SHA3_512
    )

  implicit val hashAlgorithmHash: Hash[HashAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val hashAlgorithmShow: Show[HashAlgorithm] =
    Show.show(_.show)
}

private[jots] object HashAlgorithms {
  case object SHA224 extends HashAlgorithm {
    override val name: String = "SHA-224"
    override val show: String = name
    override val toString = name
  }

  case object SHA256 extends HashAlgorithm {
    override val name: String = "SHA-256"
    override val show: String = name
    override val toString = name
  }

  case object SHA384 extends HashAlgorithm {
    override val name: String = "SHA-384"
    override val show: String = name
    override val toString = name
  }

  case object SHA512 extends HashAlgorithm {
    override val name: String = "SHA-512"
    override val show: String = name
    override val toString = name
  }

  case object SHA512_224 extends HashAlgorithm {
    override val name: String = "SHA-512/224"
    override val show: String = name
    override val toString = name
  }

  case object SHA512_256 extends HashAlgorithm {
    override val name: String = "SHA-512/256"
    override val show: String = name
    override val toString = name
  }

  case object SHA3_224 extends HashAlgorithm {
    override val name: String = "SHA3-224"
    override val show: String = name
    override val toString = name
  }

  case object SHA3_256 extends HashAlgorithm {
    override val name: String = "SHA3-256"
    override val show: String = name
    override val toString = name
  }

  case object SHA3_384 extends HashAlgorithm {
    override val name: String = "SHA3-384"
    override val show: String = name
    override val toString = name
  }

  case object SHA3_512 extends HashAlgorithm {
    override val name: String = "SHA3-512"
    override val show: String = name
    override val toString = name
  }
}
