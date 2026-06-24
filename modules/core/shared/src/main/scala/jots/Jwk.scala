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
import cats.syntax.all.*
import io.circe.Decoder
import io.circe.Encoder
import io.circe.Json
import io.circe.JsonObject
import jots.JwtException.InvalidKeyId
import jots.JwtException.InvalidKeyType
import jots.JwtException.InvalidPrivateKey
import jots.JwtException.InvalidPublicKey
import jots.JwtException.InvalidSecretKey
import jots.JwtException.MissingKeyId
import jots.JwtException.MissingKeyType
import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import jots.crypto.SecretKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid
import scodec.bits.Bases.Alphabets.Base64UrlNoPad
import scodec.bits.ByteVector

/**
  * Represents a key known as a JSON Web Key (JWK).
  */
sealed abstract class Jwk {

  /**
    * Returns the [[JwkKeyId]] if present or a
    * [[JwtException]] if missing or invalid.
    */
  def keyId: Either[JwtException, JwkKeyId]

  /**
    * Returns the [[JwkKeyType]] for the key.
    */
  def keyType: JwkKeyType

  /**
    * Returns the key as a `JsonObject`.
    */
  def toJsonObject: JsonObject

  /**
    * Returns the key as `Json`.
    */
  def toJson: Json

  /**
    * Returns the key as a [[jots.crypto.PrivateKey]]
    * or a [[JwtException]] if it was not possible.
    */
  def toPrivateKey: Either[JwtException, PrivateKey]

  /**
    * Returns the key as a [[jots.crypto.PublicKey]]
    * or a [[JwtException]] if it was not possible.
    */
  def toPublicKey: Either[JwtException, PublicKey]

  /**
    * Returns the key as a [[jots.crypto.SecretKey]]
    * or a [[JwtException]] if it was not possible.
    */
  def toSecretKey: Either[JwtException, SecretKey]

  /**
    * Returns a `String` representation of the key.
    */
  def show: String
}

object Jwk {
  private final case class JwkImpl(
    override val keyType: JwkKeyType,
    override val toJsonObject: JsonObject
  ) extends Jwk {
    override def keyId: Either[JwtException, JwkKeyId] =
      toJsonObject("kid") match {
        case Some(keyId) =>
          keyId.asString match {
            case Some(keyId) => Right(JwkKeyId.fromString(keyId))
            case None => Left(new InvalidKeyId())
          }
        case None => Left(new MissingKeyId())
      }

    override def toJson: Json =
      toJsonObject.toJson

    override def toPrivateKey: Either[InvalidPrivateKey, PrivateKey] =
      keyType match {
        case JwkKeyTypes.EC => JwkEc.toPrivateKey(toJsonObject)
        case JwkKeyTypes.OKP => JwkOkp.toPrivateKey(toJsonObject)
        case JwkKeyTypes.RSA => JwkRsa.toPrivateKey(toJsonObject)
        case keyType =>
          Left(new InvalidPrivateKey(s"unsupported key type [${keyType.name}]"))
      }

    override def toPublicKey: Either[InvalidPublicKey, PublicKey] =
      keyType match {
        case JwkKeyTypes.EC => JwkEc.toPublicKey(toJsonObject)
        case JwkKeyTypes.OKP => JwkOkp.toPublicKey(toJsonObject)
        case JwkKeyTypes.RSA => JwkRsa.toPublicKey(toJsonObject)
        case keyType =>
          Left(new InvalidPublicKey(s"unsupported key type [${keyType.name}]"))
      }

    override def toSecretKey: Either[InvalidSecretKey, SecretKey] =
      keyType match {
        case JwkKeyTypes.Oct => JwkOct.toSecretKey(toJsonObject)
        case keyType =>
          Left(new InvalidSecretKey(s"unsupported key type [${keyType.name}]"))
      }

    override def show: String =
      keyId match {
        case Right(keyId) => show"Jwk($keyId, $keyType)"
        case Left(_) => show"Jwk($keyType)"
      }

    override def toString: String =
      show
  }

  /**
    * Returns a new [[Jwk]] with the specified key-value pairs.
    */
  def apply(fields: (String, Json)*): Either[JwtException, Jwk] =
    fromJsonObject(JsonObject(fields: _*))

  /**
    * Returns a new [[Jwk]] from the specified JSON object, or
    * a [[JwtException]] if the key type is missing or invalid.
    */
  def fromJsonObject(jsonObject: JsonObject): Either[JwtException, Jwk] =
    jsonObject("kty") match {
      case Some(keyType) =>
        keyType.asString.map(JwkKeyType.withName) match {
          case Some(keyType) => Right(new JwkImpl(keyType, jsonObject))
          case None => Left(new InvalidKeyType(keyType))
        }
      case None => Left(new MissingKeyType())
    }

  implicit val jwkDecoder: Decoder[Jwk] =
    Decoder[JsonObject].emap(fromJsonObject(_).leftMap(_.message))

  implicit val jwkEncoder: Encoder[Jwk] =
    Encoder.instance(_.toJson)

  implicit val jwkHash: Hash[Jwk] =
    Hash.fromUniversalHashCode

  implicit val jwkShow: Show[Jwk] =
    Show.show(_.show)

  private[jots] def base64UrlNoPad(jsonObject: JsonObject, name: String): Either[String, ByteVector] =
    jsonObject(name) match {
      case Some(value) =>
        value.asString match {
          case Some(value) =>
            ByteVector
              .fromBase64Descriptive(value, Base64UrlNoPad)
              .leftMap(details => s"failed to decode $name as Base64UrlNoPad: $details")
          case None => Left(s"property $name is not a string")
        }
      case None => Left(s"missing property $name")
    }
}

private[jots] object JwkEc {
  def toPrivateKey(jsonObject: JsonObject): Either[InvalidPrivateKey, PrivateKey] =
    for {
      curve <- jsonObject("crv").toRight(new InvalidPrivateKey("missing curve (crv)"))
      curveString <- curve.asString.toRight(
        new InvalidPrivateKey(s"invalid curve [${curve.noSpaces}]")
      )
      x <- Jwk.base64UrlNoPad(jsonObject, "x").leftMap(new InvalidPrivateKey(_))
      y <- Jwk.base64UrlNoPad(jsonObject, "y").leftMap(new InvalidPrivateKey(_))
      d <- Jwk.base64UrlNoPad(jsonObject, "d").leftMap(new InvalidPrivateKey(_))
      privateKey <- encodePrivateKey(curveString, x, y, d)
    } yield privateKey

  def toPublicKey(jsonObject: JsonObject): Either[InvalidPublicKey, PublicKey] =
    for {
      curve <- jsonObject("crv").toRight(new InvalidPublicKey("missing curve (crv)"))
      curveString <- curve.asString.toRight(
        new InvalidPublicKey(s"invalid curve [${curve.noSpaces}]")
      )
      x <- Jwk.base64UrlNoPad(jsonObject, "x").leftMap(new InvalidPublicKey(_))
      y <- Jwk.base64UrlNoPad(jsonObject, "y").leftMap(new InvalidPublicKey(_))
      publicKey <- encodePublicKey(curveString, x, y)
    } yield publicKey

  private def encodePrivateKey(
    curve: String,
    x: ByteVector,
    y: ByteVector,
    d: ByteVector
  ): Either[InvalidPrivateKey, PrivateKey] =
    for {
      oid <- oid(curve).leftMap(new InvalidPrivateKey(_))
      length <- length(curve).leftMap(new InvalidPrivateKey(_))
      xLeftPadded <- Asn1
        .padLeft(x, length)
        .toRight(new InvalidPrivateKey(s"x is ${x.length} bytes, expected at most $length bytes"))
      yLeftPadded <- Asn1
        .padLeft(y, length)
        .toRight(new InvalidPrivateKey(s"y is ${y.length} bytes, expected at most $length bytes"))
      dLeftPadded <- Asn1
        .padLeft(d, length)
        .toRight(new InvalidPrivateKey(s"d is ${d.length} bytes, expected at most $length bytes"))
    } yield PrivateKey.fromPkcs8 {
      val point =
        ByteVector(0x04) ++ xLeftPadded ++ yLeftPadded

      val privateKey =
        Asn1.seq(
          Asn1.uint(ByteVector(1)),
          Asn1.octetString(dLeftPadded),
          Asn1.context0(Asn1.oid(oid)),
          Asn1.context1(Asn1.bitString(ByteVector(0) ++ point))
        )

      Asn1.seq(
        Asn1.uint(ByteVector(0)),
        Asn1.seq(Asn1.oid(Oid.Ec), Asn1.oid(oid)),
        Asn1.octetString(privateKey)
      )
    }

  private def encodePublicKey(
    curve: String,
    x: ByteVector,
    y: ByteVector
  ): Either[InvalidPublicKey, PublicKey] =
    for {
      oid <- oid(curve).leftMap(new InvalidPublicKey(_))
      length <- length(curve).leftMap(new InvalidPublicKey(_))
      xLeftPadded <- Asn1
        .padLeft(x, length)
        .toRight(new InvalidPublicKey(s"x is ${x.length} bytes, expected at most $length bytes"))
      yLeftPadded <- Asn1
        .padLeft(y, length)
        .toRight(new InvalidPublicKey(s"y is ${y.length} bytes, expected at most $length bytes"))
    } yield PublicKey.fromX509Spki {
      val point =
        ByteVector(0x04) ++ xLeftPadded ++ yLeftPadded

      Asn1.seq(
        Asn1.seq(Asn1.oid(Oid.Ec), Asn1.oid(oid)),
        Asn1.bitString(ByteVector(0) ++ point)
      )
    }

  private def oid(curve: String): Either[String, Oid] =
    curve match {
      case "P-256" => Right(Oid.P256)
      case "P-384" => Right(Oid.P384)
      case "P-521" => Right(Oid.P521)
      case curve => Left(s"unsupported curve [$curve]")
    }

  private def length(curve: String): Either[String, Int] =
    curve match {
      case "P-256" => Right(32)
      case "P-384" => Right(48)
      case "P-521" => Right(66)
      case curve => Left(s"unsupported curve [$curve]")
    }
}

private[jots] object JwkOct {
  def toSecretKey(jsonObject: JsonObject): Either[InvalidSecretKey, SecretKey] =
    for {
      k <- Jwk.base64UrlNoPad(jsonObject, "k").leftMap(new InvalidSecretKey(_))
      secretKey <- SecretKey.fromByteVector(k).leftMap(_ => new InvalidSecretKey("the secret key is empty"))
    } yield secretKey
}

private[jots] object JwkOkp {
  def toPrivateKey(jsonObject: JsonObject): Either[InvalidPrivateKey, PrivateKey] =
    for {
      curve <- jsonObject("crv").toRight(new InvalidPrivateKey("missing curve (crv)"))
      curveString <- curve.asString.toRight(
        new InvalidPrivateKey(s"invalid curve [${curve.noSpaces}]")
      )
      d <- Jwk.base64UrlNoPad(jsonObject, "d").leftMap(new InvalidPrivateKey(_))
      privateKey <- encodePrivateKey(curveString, d)
    } yield privateKey

  def toPublicKey(jsonObject: JsonObject): Either[InvalidPublicKey, PublicKey] =
    for {
      curve <- jsonObject("crv").toRight(new InvalidPublicKey("missing curve (crv)"))
      curveString <- curve.asString.toRight(
        new InvalidPublicKey(s"invalid curve [${curve.noSpaces}]")
      )
      x <- Jwk.base64UrlNoPad(jsonObject, "x").leftMap(new InvalidPublicKey(_))
      publicKey <- encodePublicKey(curveString, x)
    } yield publicKey

  private def encodePrivateKey(curve: String, d: ByteVector): Either[InvalidPrivateKey, PrivateKey] =
    oid(curve) match {
      case Right(oid) =>
        Right(
          PrivateKey.fromPkcs8(
            Asn1.seq(
              Asn1.uint(ByteVector(0)),
              Asn1.seq(Asn1.oid(oid)),
              Asn1.octetString(Asn1.octetString(d))
            )
          )
        )
      case Left(message) =>
        Left(new InvalidPrivateKey(message))
    }

  private def encodePublicKey(curve: String, x: ByteVector): Either[InvalidPublicKey, PublicKey] =
    oid(curve) match {
      case Right(oid) =>
        Right(
          PublicKey.fromX509Spki(
            Asn1.seq(
              Asn1.seq(Asn1.oid(oid)),
              Asn1.bitString(ByteVector(0) ++ x)
            )
          )
        )
      case Left(message) =>
        Left(new InvalidPublicKey(message))
    }

  private def oid(curve: String): Either[String, Oid] =
    curve match {
      case "Ed25519" => Right(Oid.Ed25519)
      case curve => Left(s"unsupported curve [$curve]")
    }
}

private[jots] object JwkRsa {
  def toPrivateKey(jsonObject: JsonObject): Either[InvalidPrivateKey, PrivateKey] =
    for {
      n <- Jwk.base64UrlNoPad(jsonObject, "n").leftMap(new InvalidPrivateKey(_))
      e <- Jwk.base64UrlNoPad(jsonObject, "e").leftMap(new InvalidPrivateKey(_))
      d <- Jwk.base64UrlNoPad(jsonObject, "d").leftMap(new InvalidPrivateKey(_))
      p <- Jwk.base64UrlNoPad(jsonObject, "p").leftMap(new InvalidPrivateKey(_))
      q <- Jwk.base64UrlNoPad(jsonObject, "q").leftMap(new InvalidPrivateKey(_))
      dp <- Jwk.base64UrlNoPad(jsonObject, "dp").leftMap(new InvalidPrivateKey(_))
      dq <- Jwk.base64UrlNoPad(jsonObject, "dq").leftMap(new InvalidPrivateKey(_))
      qi <- Jwk.base64UrlNoPad(jsonObject, "qi").leftMap(new InvalidPrivateKey(_))
      privateKey = encodePrivateKey(n, e, d, p, q, dp, dq, qi)
    } yield privateKey

  def toPublicKey(jsonObject: JsonObject): Either[InvalidPublicKey, PublicKey] =
    for {
      n <- Jwk.base64UrlNoPad(jsonObject, "n").leftMap(new InvalidPublicKey(_))
      e <- Jwk.base64UrlNoPad(jsonObject, "e").leftMap(new InvalidPublicKey(_))
      publicKey = encodePublicKey(n, e)
    } yield publicKey

  private def encodePrivateKey(
    n: ByteVector,
    e: ByteVector,
    d: ByteVector,
    p: ByteVector,
    q: ByteVector,
    dp: ByteVector,
    dq: ByteVector,
    qi: ByteVector
  ): PrivateKey =
    PrivateKey.fromPkcs8 {
      val privateKey =
        Asn1.seq(
          Asn1.uint(ByteVector(0)),
          Asn1.uint(n),
          Asn1.uint(e),
          Asn1.uint(d),
          Asn1.uint(p),
          Asn1.uint(q),
          Asn1.uint(dp),
          Asn1.uint(dq),
          Asn1.uint(qi)
        )

      Asn1.seq(
        Asn1.uint(ByteVector(0)),
        Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null),
        Asn1.octetString(privateKey)
      )
    }

  private def encodePublicKey(n: ByteVector, e: ByteVector): PublicKey =
    PublicKey.fromX509Spki {
      val publicKey =
        Asn1.seq(
          Asn1.uint(n),
          Asn1.uint(e)
        )

      Asn1.seq(
        Asn1.seq(Asn1.oid(Oid.Rsa), Asn1.Null),
        Asn1.bitString(ByteVector(0) ++ publicKey)
      )
    }
}
