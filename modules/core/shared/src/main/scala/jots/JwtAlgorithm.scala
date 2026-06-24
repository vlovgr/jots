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

import cats.Hash
import cats.Show
import cats.data.NonEmptyList
import jots.crypto.AsymmetricAlgorithm
import jots.crypto.EcdsaAlgorithm
import jots.crypto.EddsaAlgorithm
import jots.crypto.HashAlgorithm
import jots.crypto.RsaAlgorithm
import jots.crypto.RsaPssAlgorithm
import jots.internal.KeyRequirement

/**
  * Represents a cryptographic algorithm for JWT signatures.
  */
sealed abstract class JwtAlgorithm {

  /**
    * Returns the name of the algorithm.
    */
  def name: String

  /**
    * Alias for [[JwtAlgorithm#name]].
    */
  def show: String
}

object JwtAlgorithm {
  val Ed25519: JwtAlgorithm = JwtEddsaAlgorithms.Ed25519
  val Ed448: JwtAlgorithm = JwtEddsaAlgorithms.Ed448
  val ES256: JwtAlgorithm = JwtEcdsaAlgorithms.ES256
  val ES384: JwtAlgorithm = JwtEcdsaAlgorithms.ES384
  val ES512: JwtAlgorithm = JwtEcdsaAlgorithms.ES512
  val HS256: JwtAlgorithm = JwtHmacAlgorithms.HS256
  val HS384: JwtAlgorithm = JwtHmacAlgorithms.HS384
  val HS512: JwtAlgorithm = JwtHmacAlgorithms.HS512
  val PS256: JwtAlgorithm = JwtRsaAlgorithms.PS256
  val PS384: JwtAlgorithm = JwtRsaAlgorithms.PS384
  val PS512: JwtAlgorithm = JwtRsaAlgorithms.PS512
  val RS256: JwtAlgorithm = JwtRsaAlgorithms.RS256
  val RS384: JwtAlgorithm = JwtRsaAlgorithms.RS384
  val RS512: JwtAlgorithm = JwtRsaAlgorithms.RS512

  /**
    * The list of all recognized [[JwtAlgorithm]]s.
    */
  val All: NonEmptyList[JwtAlgorithm] =
    NonEmptyList.of(
      Ed25519,
      Ed448,
      ES256,
      ES384,
      ES512,
      HS256,
      HS384,
      HS512,
      PS256,
      PS384,
      PS512,
      RS256,
      RS384,
      RS512
    )

  implicit val jwtAlgorithmHash: Hash[JwtAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtAlgorithmShow: Show[JwtAlgorithm] =
    Show.show(_.show)
}

/**
  * Represents a Hash-based Message Authentication Code (HMAC)
  * algorithm for JWT signatures.
  */
sealed abstract class JwtHmacAlgorithm extends JwtAlgorithm {

  /**
    * Returns the cryptograhic hash algorithm being used.
    */
  def hashAlgorithm: HashAlgorithm

  /**
    * Returns the minimum required secret key length in bytes.
    */
  def minKeyLength: Int
}

object JwtHmacAlgorithm {
  val HS256: JwtHmacAlgorithm = JwtHmacAlgorithms.HS256
  val HS384: JwtHmacAlgorithm = JwtHmacAlgorithms.HS384
  val HS512: JwtHmacAlgorithm = JwtHmacAlgorithms.HS512

  /**
    * The list of all recognized [[JwtHmacAlgorithm]]s.
    */
  val All: NonEmptyList[JwtHmacAlgorithm] =
    NonEmptyList.of(HS256, HS384, HS512)

  implicit val jwtHmacAlgorithmHash: Hash[JwtHmacAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtHmacAlgorithmShow: Show[JwtHmacAlgorithm] =
    Show.show(_.show)
}

private[jots] object JwtHmacAlgorithms {
  case object HS256 extends JwtHmacAlgorithm {
    override val name: String = "HS256"
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
    override val minKeyLength: Int = 32
    override val show: String = name
    override val toString: String = name
  }

  case object HS384 extends JwtHmacAlgorithm {
    override val name: String = "HS384"
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA384
    override val minKeyLength: Int = 48
    override val show: String = name
    override val toString: String = name
  }

  case object HS512 extends JwtHmacAlgorithm {
    override val name: String = "HS512"
    override val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA512
    override val minKeyLength: Int = 64
    override val show: String = name
    override val toString: String = name
  }
}

/**
  * Represents a cryptographic asymmetric algorithm for JWT signatures.
  */
sealed abstract class JwtAsymmetricAlgorithm extends JwtAlgorithm {

  /**
    * Returns the cryptograhic asymmetric algorithm being used.
    */
  def asymmetricAlgorithm: AsymmetricAlgorithm

  /**
    * Returns the private and public key length requirement.
    */
  private[jots] def keyRequirement: KeyRequirement
}

object JwtAsymmetricAlgorithm {
  val Ed25519: JwtAsymmetricAlgorithm = JwtEddsaAlgorithms.Ed25519
  val Ed448: JwtAsymmetricAlgorithm = JwtEddsaAlgorithms.Ed448
  val ES256: JwtAsymmetricAlgorithm = JwtEcdsaAlgorithms.ES256
  val ES384: JwtAsymmetricAlgorithm = JwtEcdsaAlgorithms.ES384
  val ES512: JwtAsymmetricAlgorithm = JwtEcdsaAlgorithms.ES512
  val PS256: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.PS256
  val PS384: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.PS384
  val PS512: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.PS512
  val RS256: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.RS256
  val RS384: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.RS384
  val RS512: JwtAsymmetricAlgorithm = JwtRsaAlgorithms.RS512

  /**
    * The list of all recognized [[JwtAsymmetricAlgorithm]]s.
    */
  val All: NonEmptyList[JwtAsymmetricAlgorithm] =
    NonEmptyList.of(
      Ed25519,
      Ed448,
      ES256,
      ES384,
      ES512,
      PS256,
      PS384,
      PS512,
      RS256,
      RS384,
      RS512
    )

  implicit val jwtAsymmetricAlgorithmHash: Hash[JwtAsymmetricAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtAsymmetricAlgorithmShow: Show[JwtAsymmetricAlgorithm] =
    Show.show(_.show)
}

/**
  * Represents an Elliptic Curve Digital Signature Algorithm (ECDSA)
  * for JWT signatures.
  */
sealed abstract class JwtEcdsaAlgorithm extends JwtAsymmetricAlgorithm

object JwtEcdsaAlgorithm {
  val ES256: JwtEcdsaAlgorithm = JwtEcdsaAlgorithms.ES256
  val ES384: JwtEcdsaAlgorithm = JwtEcdsaAlgorithms.ES384
  val ES512: JwtEcdsaAlgorithm = JwtEcdsaAlgorithms.ES512

  /**
    * The list of all recognized [[JwtEcdsaAlgorithm]]s.
    */
  val All: NonEmptyList[JwtEcdsaAlgorithm] =
    NonEmptyList.of(ES256, ES384, ES512)

  implicit val jwtEcdsaAlgorithmHash: Hash[JwtEcdsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtEcdsaAlgorithmShow: Show[JwtEcdsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object JwtEcdsaAlgorithms {
  case object ES256 extends JwtEcdsaAlgorithm {
    override val name: String = "ES256"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = EcdsaAlgorithm.SHA256withECDSAinP1363Format
    override val keyRequirement: KeyRequirement = KeyRequirement.Ecdsa(256)
    override val show: String = name
    override val toString: String = name
  }

  case object ES384 extends JwtEcdsaAlgorithm {
    override val name: String = "ES384"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = EcdsaAlgorithm.SHA384withECDSAinP1363Format
    override val keyRequirement: KeyRequirement = KeyRequirement.Ecdsa(384)
    override val show: String = name
    override val toString: String = name
  }

  case object ES512 extends JwtEcdsaAlgorithm {
    override val name: String = "ES512"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = EcdsaAlgorithm.SHA512withECDSAinP1363Format
    override val keyRequirement: KeyRequirement = KeyRequirement.Ecdsa(521)
    override val show: String = name
    override val toString: String = name
  }
}

/**
  * Represents an Edwards-curve Digital Signature Algorithm (EdDSA)
  * for JWT signatures.
  */
sealed abstract class JwtEddsaAlgorithm extends JwtAsymmetricAlgorithm {

  /**
    * Returns the algorithm but with the `EdDSA` alternative name.
    *
    * The generic `EdDSA` name was historically used for both the
    * Ed25519 and Ed448 curves. However, because of ambiguity
    * regarding which curve was used to sign the token, the
    * name was deprecated in favour of Ed25519 and Ed448.
    */
  def asEdDSA: JwtEddsaAlgorithm
}

object JwtEddsaAlgorithm {
  val Ed25519: JwtEddsaAlgorithm = JwtEddsaAlgorithms.Ed25519
  val Ed448: JwtEddsaAlgorithm = JwtEddsaAlgorithms.Ed448

  /**
    * The list of all recognized [[JwtEddsaAlgorithm]]s.
    */
  val All: NonEmptyList[JwtEddsaAlgorithm] =
    NonEmptyList.of(Ed25519, Ed448)

  implicit val jwtEddsaAlgorithmHash: Hash[JwtEddsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtEddsaAlgorithmShow: Show[JwtEddsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object JwtEddsaAlgorithms {
  case object Ed25519 extends JwtEddsaAlgorithm {
    override val name: String = "Ed25519"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = EddsaAlgorithm.Ed25519
    override val keyRequirement: KeyRequirement = KeyRequirement.Eddsa(256)
    override val show: String = name
    override val toString: String = name
    override def asEdDSA: JwtEddsaAlgorithm = EdDSA(this)
  }

  case object Ed448 extends JwtEddsaAlgorithm {
    override val name: String = "Ed448"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = EddsaAlgorithm.Ed448
    override val keyRequirement: KeyRequirement = KeyRequirement.Eddsa(456)
    override val show: String = name
    override val toString: String = name
    override def asEdDSA: JwtEddsaAlgorithm = EdDSA(this)
  }

  final case class EdDSA(algorithm: JwtEddsaAlgorithm) extends JwtEddsaAlgorithm {
    override val name: String = "EdDSA"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = algorithm.asymmetricAlgorithm
    override val keyRequirement: KeyRequirement = algorithm.keyRequirement
    override val show: String = name
    override val toString: String = name
    override def asEdDSA: JwtEddsaAlgorithm = this
  }
}

/**
  * Represents an RSA (Rivest–Shamir–Adleman) algorithm for JWT signatures.
  */
sealed abstract class JwtRsaAlgorithm extends JwtAsymmetricAlgorithm

object JwtRsaAlgorithm {
  val PS256: JwtRsaAlgorithm = JwtRsaAlgorithms.PS256
  val PS384: JwtRsaAlgorithm = JwtRsaAlgorithms.PS384
  val PS512: JwtRsaAlgorithm = JwtRsaAlgorithms.PS512
  val RS256: JwtRsaAlgorithm = JwtRsaAlgorithms.RS256
  val RS384: JwtRsaAlgorithm = JwtRsaAlgorithms.RS384
  val RS512: JwtRsaAlgorithm = JwtRsaAlgorithms.RS512

  /**
    * The list of all recognized [[JwtRsaAlgorithm]]s.
    */
  val All: NonEmptyList[JwtRsaAlgorithm] =
    NonEmptyList.of(PS256, PS384, PS512, RS256, RS384, RS512)

  implicit val jwtRsaAlgorithmHash: Hash[JwtRsaAlgorithm] =
    Hash.fromUniversalHashCode

  implicit val jwtRsaAlgorithmShow: Show[JwtRsaAlgorithm] =
    Show.show(_.show)
}

private[jots] object JwtRsaAlgorithms {
  case object RS256 extends JwtRsaAlgorithm {
    override val name: String = "RS256"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaAlgorithm.SHA256withRSA
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }

  case object RS384 extends JwtRsaAlgorithm {
    override val name: String = "RS384"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaAlgorithm.SHA384withRSA
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }

  case object RS512 extends JwtRsaAlgorithm {
    override val name: String = "RS512"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaAlgorithm.SHA512withRSA
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }

  case object PS256 extends JwtRsaAlgorithm {
    override val name: String = "PS256"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaPssAlgorithm.SHA256withRSAandMGF1
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }

  case object PS384 extends JwtRsaAlgorithm {
    override val name: String = "PS384"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaPssAlgorithm.SHA384withRSAandMGF1
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }

  case object PS512 extends JwtRsaAlgorithm {
    override val name: String = "PS512"
    override val asymmetricAlgorithm: AsymmetricAlgorithm = RsaPssAlgorithm.SHA512withRSAandMGF1
    override val keyRequirement: KeyRequirement = KeyRequirement.Rsa(2048)
    override val show: String = name
    override val toString: String = name
  }
}
