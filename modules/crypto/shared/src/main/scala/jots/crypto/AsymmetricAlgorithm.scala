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
  * Represents a cryptographic asymmetric algorithm for signatures.
  */
sealed abstract class AsymmetricAlgorithm {

  /**
    * Returns a name for the asymmetric algorithm.
    */
  def name: String

  /**
    * Alias for [[AsymmetricAlgorithm#name]].
    */
  def show: String
}

object AsymmetricAlgorithm {
  val Ed25519: AsymmetricAlgorithm = EddsaAlgorithms.Ed25519
  val Ed448: AsymmetricAlgorithm = EddsaAlgorithms.Ed448
  val SHA256withECDSAinP1363Format: AsymmetricAlgorithm = EcdsaAlgorithms.SHA256withECDSAinP1363Format
  val SHA256withRSA: AsymmetricAlgorithm = RsaAlgorithms.SHA256withRSA
  val SHA256withRSAandMGF1: AsymmetricAlgorithm = RsaPssAlgorithms.SHA256withRSAandMGF1
  val SHA384withECDSAinP1363Format: AsymmetricAlgorithm = EcdsaAlgorithms.SHA384withECDSAinP1363Format
  val SHA384withRSA: AsymmetricAlgorithm = RsaAlgorithms.SHA384withRSA
  val SHA384withRSAandMGF1: AsymmetricAlgorithm = RsaPssAlgorithms.SHA384withRSAandMGF1
  val SHA512withECDSAinP1363Format: AsymmetricAlgorithm = EcdsaAlgorithms.SHA512withECDSAinP1363Format
  val SHA512withRSA: AsymmetricAlgorithm = RsaAlgorithms.SHA512withRSA
  val SHA512withRSAandMGF1: AsymmetricAlgorithm = RsaPssAlgorithms.SHA512withRSAandMGF1

  /**
    * The list of all recognized [[AsymmetricAlgorithm]]s.
    */
  val All: NonEmptyList[AsymmetricAlgorithm] =
    NonEmptyList.of(
      Ed25519,
      Ed448,
      SHA256withECDSAinP1363Format,
      SHA256withRSA,
      SHA256withRSAandMGF1,
      SHA384withECDSAinP1363Format,
      SHA384withRSA,
      SHA384withRSAandMGF1,
      SHA512withECDSAinP1363Format,
      SHA512withRSA,
      SHA512withRSAandMGF1
    )

  implicit val asymmetricAlgorithmHash: Hash[AsymmetricAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val asymmetricAlgorithmShow: Show[AsymmetricAlgorithm] =
    Show.show(_.show)
}

/**
  * Represents an Elliptic Curve Digital Signature Algorithm (ECDSA).
  */
sealed abstract class EcdsaAlgorithm extends AsymmetricAlgorithm {

  /**
    * Returns the [[HashAlgorithm]] used by the algorithm.
    */
  def hashAlgorithm: HashAlgorithm

  /**
    * Returns the field size in bytes for the elliptic curve.
    */
  def fieldSize: Int
}

object EcdsaAlgorithm {
  val SHA256withECDSAinP1363Format: EcdsaAlgorithm = EcdsaAlgorithms.SHA256withECDSAinP1363Format
  val SHA384withECDSAinP1363Format: EcdsaAlgorithm = EcdsaAlgorithms.SHA384withECDSAinP1363Format
  val SHA512withECDSAinP1363Format: EcdsaAlgorithm = EcdsaAlgorithms.SHA512withECDSAinP1363Format

  /**
    * The list of all recognized [[EcdsaAlgorithm]]s.
    */
  val All: NonEmptyList[EcdsaAlgorithm] =
    NonEmptyList.of(
      SHA256withECDSAinP1363Format,
      SHA384withECDSAinP1363Format,
      SHA512withECDSAinP1363Format
    )

  implicit val ecdsaAlgorithmHash: Hash[EcdsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val ecdsaAlgorithmShow: Show[EcdsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object EcdsaAlgorithms {
  case object SHA256withECDSAinP1363Format extends EcdsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
    override val fieldSize: Int = 32
    override val name: String = "SHA256withECDSAinP1363Format"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA384withECDSAinP1363Format extends EcdsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA384
    override val fieldSize: Int = 48
    override val name: String = "SHA384withECDSAinP1363Format"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA512withECDSAinP1363Format extends EcdsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512
    override val fieldSize: Int = 66
    override val name: String = "SHA512withECDSAinP1363Format"
    override val show: String = name
    override val toString: String = name
  }
}

/**
  * Represents an Edwards-curve Digital Signature Algorithm (EdDSA).
  */
sealed abstract class EddsaAlgorithm extends AsymmetricAlgorithm

object EddsaAlgorithm {
  val Ed25519: EddsaAlgorithm = EddsaAlgorithms.Ed25519
  val Ed448: EddsaAlgorithm = EddsaAlgorithms.Ed448

  /**
    * The list of all recognized [[EddsaAlgorithm]]s.
    */
  val All: NonEmptyList[EddsaAlgorithm] =
    NonEmptyList.of(Ed25519, Ed448)

  implicit val eddsaAlgorithmHash: Hash[EddsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val eddsaAlgorithmShow: Show[EddsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object EddsaAlgorithms {
  case object Ed25519 extends EddsaAlgorithm {
    override val name: String = "Ed25519"
    override val show: String = name
    override val toString: String = name
  }

  case object Ed448 extends EddsaAlgorithm {
    override val name: String = "Ed448"
    override val show: String = name
    override val toString: String = name
  }
}

/**
  * Represents an RSA (Rivest–Shamir–Adleman) algorithm.
  */
sealed abstract class RsaAlgorithm extends AsymmetricAlgorithm {

  /**
    * Returns the [[HashAlgorithm]] used by the algorithm.
    */
  def hashAlgorithm: HashAlgorithm
}

object RsaAlgorithm {
  val SHA256withRSA: RsaAlgorithm = RsaAlgorithms.SHA256withRSA
  val SHA384withRSA: RsaAlgorithm = RsaAlgorithms.SHA384withRSA
  val SHA512withRSA: RsaAlgorithm = RsaAlgorithms.SHA512withRSA

  /**
    * The list of all recognized [[RsaAlgorithm]]s.
    */
  val All: NonEmptyList[RsaAlgorithm] =
    NonEmptyList.of(
      SHA256withRSA,
      SHA384withRSA,
      SHA512withRSA
    )

  implicit val rsaAlgorithmHash: Hash[RsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val rsaAlgorithmShow: Show[RsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object RsaAlgorithms {
  case object SHA256withRSA extends RsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
    override val name: String = "SHA256withRSA"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA384withRSA extends RsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA384
    override val name: String = "SHA384withRSA"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA512withRSA extends RsaAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512
    override val name: String = "SHA512withRSA"
    override val show: String = name
    override val toString: String = name
  }
}

/**
  * Represents an RSA-PSS (Rivest–Shamir–Adleman Probabilistic Signature Scheme) algorithm.
  */
sealed abstract class RsaPssAlgorithm extends AsymmetricAlgorithm {

  /**
    * Returns the [[HashAlgorithm]] used by the algorithm.
    */
  def hashAlgorithm: HashAlgorithm

  /**
    * Returns the salt length in bytes used by the algorithm.
    */
  def saltLength: Int
}

object RsaPssAlgorithm {
  val SHA256withRSAandMGF1: RsaPssAlgorithm = RsaPssAlgorithms.SHA256withRSAandMGF1
  val SHA384withRSAandMGF1: RsaPssAlgorithm = RsaPssAlgorithms.SHA384withRSAandMGF1
  val SHA512withRSAandMGF1: RsaPssAlgorithm = RsaPssAlgorithms.SHA512withRSAandMGF1

  /**
    * The list of all recognized [[RsaPssAlgorithm]]s.
    */
  val All: NonEmptyList[RsaPssAlgorithm] =
    NonEmptyList.of(
      SHA256withRSAandMGF1,
      SHA384withRSAandMGF1,
      SHA512withRSAandMGF1
    )

  implicit val rsaPssAlgorithmHash: Hash[RsaPssAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val rsaPssAlgorithmShow: Show[RsaPssAlgorithm] =
    Show.show(_.show)
}

private[jots] object RsaPssAlgorithms {
  case object SHA256withRSAandMGF1 extends RsaPssAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
    override val saltLength: Int = 32
    override val name: String = "SHA256withRSAandMGF1"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA384withRSAandMGF1 extends RsaPssAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA384
    override val saltLength: Int = 48
    override val name: String = "SHA384withRSAandMGF1"
    override val show: String = name
    override val toString: String = name
  }

  case object SHA512withRSAandMGF1 extends RsaPssAlgorithm {
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512
    override val saltLength: Int = 64
    override val name: String = "SHA512withRSAandMGF1"
    override val show: String = name
    override val toString: String = name
  }
}
