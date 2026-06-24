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
import java.security.KeyFactory
import java.security.SignatureException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.spec.SecretKeySpec
import scodec.bits.ByteVector

private[crypto] trait CryptoCompanionPlatform {
  private[crypto] def hmac[F[_]: Sync](
    algorithm: HashAlgorithm,
    secretKey: SecretKey,
    message: ByteVector
  ): F[Mac] =
    Sync[F].delay {
      val name = hmacNameOf(algorithm)
      val mac = javax.crypto.Mac.getInstance(name)
      mac.init(new SecretKeySpec(secretKey.toByteVector.toArrayUnsafe, name))
      Mac(ByteVector.view(mac.doFinal(message.toArrayUnsafe)))
    }

  private[crypto] def sign[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[jots.crypto.Signature] =
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
      val keySpec = new PKCS8EncodedKeySpec(privateKey.toPkcs8.toArrayUnsafe)
      val key = KeyFactory.getInstance("EC").generatePrivate(keySpec)
      val signing = java.security.Signature.getInstance(nameOf(algorithm))
      signing.initSign(key)
      signing.update(message.toArrayUnsafe)
      Signature(ByteVector.view(signing.sign()))
    }

  private[this] def signEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val name = nameOf(algorithm)
      val keySpec = new PKCS8EncodedKeySpec(privateKey.toPkcs8.toArrayUnsafe)
      val key = KeyFactory.getInstance(name).generatePrivate(keySpec)
      val signing = java.security.Signature.getInstance(name)
      signing.initSign(key)
      signing.update(message.toArrayUnsafe)
      Signature(ByteVector.view(signing.sign()))
    }

  private[this] def signRsa[F[_]: Sync](
    algorithm: RsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val keySpec = new PKCS8EncodedKeySpec(privateKey.toPkcs8.toArrayUnsafe)
      val key = KeyFactory.getInstance("RSA").generatePrivate(keySpec)
      val signing = java.security.Signature.getInstance(nameOf(algorithm))
      signing.initSign(key)
      signing.update(message.toArrayUnsafe)
      Signature(ByteVector.view(signing.sign()))
    }

  private[this] def signRsaPss[F[_]: Sync](
    algorithm: RsaPssAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val keySpec = new PKCS8EncodedKeySpec(privateKey.toPkcs8.toArrayUnsafe)
      val key = KeyFactory.getInstance("RSA").generatePrivate(keySpec)
      val signing = java.security.Signature.getInstance("RSASSA-PSS")
      signing.setParameter(pssParameterSpec(algorithm))
      signing.initSign(key)
      signing.update(message.toArrayUnsafe)
      Signature(ByteVector.view(signing.sign()))
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
      val keySpec = new X509EncodedKeySpec(publicKey.toX509Spki.toArrayUnsafe)
      val key = KeyFactory.getInstance("EC").generatePublic(keySpec)
      val signing = java.security.Signature.getInstance(nameOf(algorithm))
      signing.initVerify(key)
      signing.update(message.toArrayUnsafe)
      try Verified(signing.verify(signature.toByteVector.toArrayUnsafe))
      catch { case _: SignatureException => Verified.Invalid }
    }

  private[this] def verifyEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val name = nameOf(algorithm)
      val keySpec = new X509EncodedKeySpec(publicKey.toX509Spki.toArrayUnsafe)
      val key = KeyFactory.getInstance(name).generatePublic(keySpec)
      val signing = java.security.Signature.getInstance(name)
      signing.initVerify(key)
      signing.update(message.toArrayUnsafe)
      try Verified(signing.verify(signature.toByteVector.toArrayUnsafe))
      catch { case _: SignatureException => Verified.Invalid }
    }

  private[this] def verifyRsa[F[_]: Sync](
    algorithm: RsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val keySpec = new X509EncodedKeySpec(publicKey.toX509Spki.toArrayUnsafe)
      val key = KeyFactory.getInstance("RSA").generatePublic(keySpec)
      val signing = java.security.Signature.getInstance(nameOf(algorithm))
      signing.initVerify(key)
      signing.update(message.toArrayUnsafe)
      try Verified(signing.verify(signature.toByteVector.toArrayUnsafe))
      catch { case _: SignatureException => Verified.Invalid }
    }

  private[this] def verifyRsaPss[F[_]: Sync](
    algorithm: RsaPssAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val keySpec = new X509EncodedKeySpec(publicKey.toX509Spki.toArrayUnsafe)
      val key = KeyFactory.getInstance("RSA").generatePublic(keySpec)
      val signing = java.security.Signature.getInstance("RSASSA-PSS")
      signing.setParameter(pssParameterSpec(algorithm))
      signing.initVerify(key)
      signing.update(message.toArrayUnsafe)
      try Verified(signing.verify(signature.toByteVector.toArrayUnsafe))
      catch { case _: SignatureException => Verified.Invalid }
    }

  private[this] def hmacNameOf(algorithm: HashAlgorithm): String =
    algorithm match {
      case HashAlgorithms.SHA224 => "HmacSHA224"
      case HashAlgorithms.SHA256 => "HmacSHA256"
      case HashAlgorithms.SHA384 => "HmacSHA384"
      case HashAlgorithms.SHA512 => "HmacSHA512"
      case HashAlgorithms.SHA512_224 => "HmacSHA512/224"
      case HashAlgorithms.SHA512_256 => "HmacSHA512/256"
      case HashAlgorithms.SHA3_224 => "HmacSHA3-224"
      case HashAlgorithms.SHA3_256 => "HmacSHA3-256"
      case HashAlgorithms.SHA3_384 => "HmacSHA3-384"
      case HashAlgorithms.SHA3_512 => "HmacSHA3-512"
    }

  private[this] def nameOf(algorithm: RsaAlgorithm): String =
    algorithm match {
      case RsaAlgorithms.SHA256withRSA => "SHA256withRSA"
      case RsaAlgorithms.SHA384withRSA => "SHA384withRSA"
      case RsaAlgorithms.SHA512withRSA => "SHA512withRSA"
    }

  private[this] def nameOf(algorithm: EcdsaAlgorithm): String =
    algorithm match {
      case EcdsaAlgorithms.SHA256withECDSAinP1363Format => "SHA256withECDSAinP1363Format"
      case EcdsaAlgorithms.SHA384withECDSAinP1363Format => "SHA384withECDSAinP1363Format"
      case EcdsaAlgorithms.SHA512withECDSAinP1363Format => "SHA512withECDSAinP1363Format"
    }

  private[this] def nameOf(algorithm: EddsaAlgorithm): String =
    algorithm match {
      case EddsaAlgorithms.Ed25519 => "Ed25519"
      case EddsaAlgorithms.Ed448 => "Ed448"
    }

  private[this] def pssParameterSpec(algorithm: RsaPssAlgorithm): PSSParameterSpec =
    algorithm match {
      case RsaPssAlgorithms.SHA256withRSAandMGF1 =>
        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
      case RsaPssAlgorithms.SHA384withRSAandMGF1 =>
        new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
      case RsaPssAlgorithms.SHA512withRSAandMGF1 =>
        new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
    }
}
