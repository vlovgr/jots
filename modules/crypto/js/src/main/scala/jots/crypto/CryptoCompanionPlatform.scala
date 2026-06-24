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

import cats.effect.kernel.Sync
import jots.crypto.CryptoException.WrongKeyType
import jots.crypto.JsCrypto.KeyObject
import scala.scalajs.js
import scala.scalajs.js.JavaScriptException
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Uint8Array
import scodec.bits.ByteVector

private[crypto] trait CryptoCompanionPlatform {
  private[crypto] def hmac[F[_]: Sync](
    algorithm: HashAlgorithm,
    secretKey: SecretKey,
    message: ByteVector
  ): F[Mac] =
    Sync[F].delay {
      val hmac = JsCrypto.createHmac(nameOf(algorithm), secretKey.toByteVector.toUint8Array)
      hmac.update(message.toUint8Array)
      Mac(ByteVector.view(hmac.digest()))
    }

  private[crypto] def sign[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    algorithm match {
      case algorithm: EcdsaAlgorithm => signEcdsa(algorithm, privateKey, message)
      case algorithm: EddsaAlgorithm => signEddsa(algorithm, privateKey, message)
      case algorithm: RsaAlgorithm => signRsa(algorithm, privateKey, message)
      case algorithm: RsaPssAlgorithm => signRsaPss(algorithm, privateKey, message)
    }

  private[this] def signEcdsa[F[_]: Sync](
    algorithm: EcdsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val key = createPrivateKey(privateKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val sign = JsCrypto.createSign(nameOf(algorithm.hashAlgorithm))
      sign.update(message.toUint8Array)
      sign.end()
      val signOptions = js.Dynamic.literal(
        key = key,
        dsaEncoding = "ieee-p1363"
      )
      Signature(ByteVector.view(sign.sign(signOptions)))
    }

  private[this] def signEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val key = createPrivateKey(privateKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      Signature(ByteVector.view(JsCrypto.sign(null, message.toUint8Array, key)))
    }

  private[this] def signRsa[F[_]: Sync](
    algorithm: RsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val key = createPrivateKey(privateKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val sign = JsCrypto.createSign(nameOf(algorithm.hashAlgorithm))
      sign.update(message.toUint8Array)
      sign.end()
      Signature(ByteVector.view(sign.sign(key)))
    }

  private[this] def signRsaPss[F[_]: Sync](
    algorithm: RsaPssAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val key = createPrivateKey(privateKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val sign = JsCrypto.createSign(nameOf(algorithm.hashAlgorithm))
      sign.update(message.toUint8Array)
      sign.end()
      val signOptions = js.Dynamic.literal(
        key = key,
        padding = JsCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength = algorithm.saltLength
      )
      Signature(ByteVector.view(sign.sign(signOptions)))
    }

  private[crypto] def verify[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    algorithm match {
      case algorithm: EcdsaAlgorithm => verifyEcdsa(algorithm, publicKey, message, signature)
      case algorithm: EddsaAlgorithm => verifyEddsa(algorithm, publicKey, message, signature)
      case algorithm: RsaAlgorithm => verifyRsa(algorithm, publicKey, message, signature)
      case algorithm: RsaPssAlgorithm => verifyRsaPss(algorithm, publicKey, message, signature)
    }

  private[this] def verifyEcdsa[F[_]: Sync](
    algorithm: EcdsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val key = createPublicKey(publicKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val verify = JsCrypto.createVerify(nameOf(algorithm.hashAlgorithm))
      verify.update(message.toUint8Array)
      val verifyOptions = js.Dynamic.literal(
        key = key,
        dsaEncoding = "ieee-p1363"
      )

      try Verified(verify.verify(verifyOptions, signature.toByteVector.toUint8Array))
      catch { case _: JavaScriptException => Verified.Invalid }
    }

  private[this] def verifyEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val key = createPublicKey(publicKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      try Verified(JsCrypto.verify(null, message.toUint8Array, key, signature.toByteVector.toUint8Array))
      catch { case _: JavaScriptException => Verified.Invalid }
    }

  private[this] def verifyRsa[F[_]: Sync](
    algorithm: RsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val key = createPublicKey(publicKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val verify = JsCrypto.createVerify(nameOf(algorithm.hashAlgorithm))
      verify.update(message.toUint8Array)

      try Verified(verify.verify(key, signature.toByteVector.toUint8Array))
      catch { case _: JavaScriptException => Verified.Invalid }
    }

  private[this] def verifyRsaPss[F[_]: Sync](
    algorithm: RsaPssAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val key = createPublicKey(publicKey)
      if (key.asymmetricKeyType != keyType(algorithm))
        throw new WrongKeyType(key.asymmetricKeyType, keyType(algorithm), algorithm)

      val verify = JsCrypto.createVerify(nameOf(algorithm.hashAlgorithm))
      verify.update(message.toUint8Array)
      val verifyOptions = js.Dynamic.literal(
        key = key,
        padding = JsCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength = algorithm.saltLength
      )

      try Verified(verify.verify(verifyOptions, signature.toByteVector.toUint8Array))
      catch { case _: JavaScriptException => Verified.Invalid }
    }

  private[this] def keyType(algorithm: AsymmetricAlgorithm): String =
    algorithm match {
      case _: EcdsaAlgorithm => "ec"
      case EddsaAlgorithms.Ed25519 => "ed25519"
      case EddsaAlgorithms.Ed448 => "ed448"
      case _: RsaAlgorithm => "rsa"
      case _: RsaPssAlgorithm => "rsa"
    }

  private[this] def nameOf(algorithm: HashAlgorithm): String =
    algorithm match {
      case HashAlgorithms.SHA224 => "SHA224"
      case HashAlgorithms.SHA256 => "SHA256"
      case HashAlgorithms.SHA384 => "SHA384"
      case HashAlgorithms.SHA512 => "SHA512"
      case HashAlgorithms.SHA512_224 => "SHA512-224"
      case HashAlgorithms.SHA512_256 => "SHA512-256"
      case HashAlgorithms.SHA3_224 => "SHA3-224"
      case HashAlgorithms.SHA3_256 => "SHA3-256"
      case HashAlgorithms.SHA3_384 => "SHA3-384"
      case HashAlgorithms.SHA3_512 => "SHA3-512"
    }

  private[this] def createPrivateKey(privateKey: PrivateKey): KeyObject =
    JsCrypto.createPrivateKey(
      js.Dynamic.literal(
        key = privateKey.toPkcs8.toUint8Array,
        format = "der",
        `type` = "pkcs8"
      )
    )

  private[this] def createPublicKey(publicKey: PublicKey): KeyObject =
    JsCrypto.createPublicKey(
      js.Dynamic.literal(
        key = publicKey.toX509Spki.toUint8Array,
        format = "der",
        `type` = "spki"
      )
    )
}

private object JsCrypto {
  @js.native
  @JSImport("crypto", "createHmac")
  def createHmac(algorithm: String, key: Uint8Array): Hmac = js.native

  @js.native
  trait Hmac extends js.Object {
    def update(data: Uint8Array): Unit = js.native
    def digest(): Uint8Array = js.native
  }

  @js.native
  @JSImport("crypto", "createPublicKey")
  def createPublicKey(publicKey: js.Object): KeyObject = js.native

  @js.native
  @JSImport("crypto", "createPrivateKey")
  def createPrivateKey(privateKey: js.Object): KeyObject = js.native

  @js.native
  trait KeyObject extends js.Object {
    def asymmetricKeyType: String = js.native
  }

  @js.native
  @JSImport("crypto", "createVerify")
  def createVerify(algorithm: String): Verify = js.native

  @js.native
  trait Verify extends js.Object {
    def update(data: Uint8Array): Unit = js.native
    def verify(publicKey: KeyObject, signature: Uint8Array): Boolean = js.native
    def verify(options: js.Object, signature: Uint8Array): Boolean = js.native
  }

  @js.native
  @JSImport("crypto", "createSign")
  def createSign(algorithm: String): Sign = js.native

  @js.native
  @JSImport("crypto", "sign")
  def sign(
    algorithm: String,
    data: Uint8Array,
    key: KeyObject
  ): Uint8Array = js.native

  @js.native
  @JSImport("crypto", "verify")
  def verify(
    algorithm: String,
    data: Uint8Array,
    key: KeyObject,
    signature: Uint8Array
  ): Boolean =
    js.native

  @js.native
  trait Sign extends js.Object {
    def update(data: Uint8Array): Unit = js.native
    def end(): Unit = js.native
    def sign(privateKey: KeyObject): Uint8Array = js.native
    def sign(options: js.Object): Uint8Array = js.native
  }

  @js.native
  @JSImport("crypto", "constants")
  def constants: Constants = js.native

  @js.native
  trait Constants extends js.Object {
    def RSA_PKCS1_PSS_PADDING: Int = js.native
  }
}
