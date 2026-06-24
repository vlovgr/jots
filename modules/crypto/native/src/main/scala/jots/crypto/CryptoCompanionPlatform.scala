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
import jots.crypto.CryptoException.*
import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*
import scodec.bits.ByteVector

private[crypto] trait CryptoCompanionPlatform {
  import openssl.*

  private[crypto] def hmac[F[_]: Sync](
    algorithm: HashAlgorithm,
    secretKey: SecretKey,
    message: ByteVector
  ): F[Mac] =
    Sync[F].delay {
      Zone.acquire { implicit zone =>
        val name = nameOf(algorithm)
        val evpMd = EVP_get_digestbyname(toCString(name))
        if (evpMd == null) throw opensslError("EVP_get_digestbyname")

        val key = secretKey.toByteVector.toArrayUnsafe
        val data = message.toArrayUnsafe
        val md = new Array[Byte](EVP_MAX_MD_SIZE)
        val mdLen = stackalloc[CUnsignedInt]()

        val hmac = HMAC(
          evpMd,
          if (key.isEmpty) null else key.atUnsafe(0),
          key.length,
          if (data.isEmpty) null else data.atUnsafe(0),
          data.length.toCSize,
          md.atUnsafe(0),
          mdLen
        )

        if (hmac == null) throw opensslError("HMAC")
        Mac(ByteVector(md, 0, (!mdLen).toInt))
      }
    }

  private[crypto] def sign[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    algorithm match {
      case algorithm: EcdsaAlgorithm =>
        signEcdsa(algorithm, privateKey, message)
      case algorithm: EddsaAlgorithm =>
        signEddsa(algorithm, privateKey, message)
      case algorithm: RsaAlgorithm =>
        signRsa(
          algorithm = algorithm,
          hashAlgorithm = algorithm.hashAlgorithm,
          privateKey = privateKey,
          message = message,
          pss = None
        )
      case algorithm: RsaPssAlgorithm =>
        signRsa(
          algorithm = algorithm,
          hashAlgorithm = algorithm.hashAlgorithm,
          privateKey = privateKey,
          message = message,
          pss = Some(algorithm.saltLength)
        )
    }

  private[this] def signEcdsa[F[_]: Sync](
    algorithm: EcdsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      Zone.acquire { implicit zone =>
        val evpMd = EVP_get_digestbyname(toCString(nameOf(algorithm.hashAlgorithm)))
        if (evpMd == null) throw opensslError("EVP_get_digestbyname")

        val pkey = loadPrivateKey(privateKey)
        try {
          val id = EVP_PKEY_get_base_id(pkey)
          if (id != EVP_PKEY_EC) throw new WrongKeyType(id, EVP_PKEY_EC, algorithm)

          val ctx = EVP_MD_CTX_new()
          if (ctx == null) throw opensslError("EVP_MD_CTX_new")
          try {
            if (EVP_DigestSignInit(ctx, null, evpMd, null, pkey) != 1)
              throw opensslError("EVP_DigestSignInit")

            val data = message.toArrayUnsafe
            val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)
            if (EVP_DigestSignUpdate(ctx, dataPtr, data.length.toCSize) != 1)
              throw opensslError("EVP_DigestSignUpdate")

            val sigLen = stackalloc[CSize]()
            if (EVP_DigestSignFinal(ctx, null, sigLen) != 1)
              throw opensslError("EVP_DigestSignFinal")

            val derSig = new Array[Byte]((!sigLen).toInt)
            val derPtr = if (derSig.isEmpty) null else derSig.atUnsafe(0)
            if (EVP_DigestSignFinal(ctx, derPtr, sigLen) != 1)
              throw opensslError("EVP_DigestSignFinal")

            Signature(derToP1363(derSig, (!sigLen).toInt, algorithm.fieldSize))
          } finally EVP_MD_CTX_free(ctx)
        } finally EVP_PKEY_free(pkey)
      }
    }

  private[this] def signEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector
  ): F[Signature] =
    Sync[F].delay {
      val pkey = loadPrivateKey(privateKey)
      try {
        val id = EVP_PKEY_get_base_id(pkey)
        if (id != pkeyBaseId(algorithm))
          throw new WrongKeyType(id, pkeyBaseId(algorithm), algorithm)

        val ctx = EVP_MD_CTX_new()
        if (ctx == null) throw opensslError("EVP_MD_CTX_new")
        try {
          if (EVP_DigestSignInit(ctx, null, null, null, pkey) != 1)
            throw opensslError("EVP_DigestSignInit")

          val data = message.toArrayUnsafe
          val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)

          val sigLen = stackalloc[CSize]()
          if (EVP_DigestSign(ctx, null, sigLen, dataPtr, data.length.toCSize) != 1)
            throw opensslError("EVP_DigestSign")

          val sig = new Array[Byte]((!sigLen).toInt)
          val sigPtr = if (sig.isEmpty) null else sig.atUnsafe(0)
          if (EVP_DigestSign(ctx, sigPtr, sigLen, dataPtr, data.length.toCSize) != 1)
            throw opensslError("EVP_DigestSign")

          Signature(ByteVector.view(sig))
        } finally EVP_MD_CTX_free(ctx)
      } finally EVP_PKEY_free(pkey)
    }

  private[this] def signRsa[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    hashAlgorithm: HashAlgorithm,
    privateKey: PrivateKey,
    message: ByteVector,
    pss: Option[Int]
  ): F[Signature] =
    Sync[F].delay {
      Zone.acquire { implicit zone =>
        val name = nameOf(hashAlgorithm)
        val evpMd = EVP_get_digestbyname(toCString(name))
        if (evpMd == null) throw opensslError("EVP_get_digestbyname")

        val pkey = loadPrivateKey(privateKey)
        try {
          val id = EVP_PKEY_get_base_id(pkey)
          if (id != EVP_PKEY_RSA) throw new WrongKeyType(id, EVP_PKEY_RSA, algorithm)

          val ctx = EVP_MD_CTX_new()
          if (ctx == null) throw opensslError("EVP_MD_CTX_new")
          try {
            val pctxPtr = stackalloc[Ptr[EVP_PKEY_CTX]]()
            !pctxPtr = null

            if (EVP_DigestSignInit(ctx, pctxPtr, evpMd, null, pkey) != 1)
              throw opensslError("EVP_DigestSignInit")

            pss.foreach(saltLength => rsaSetPss(!pctxPtr, evpMd, saltLength))

            val data = message.toArrayUnsafe
            val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)
            if (EVP_DigestSignUpdate(ctx, dataPtr, data.length.toCSize) != 1)
              throw opensslError("EVP_DigestSignUpdate")

            val sigLen = stackalloc[CSize]()
            if (EVP_DigestSignFinal(ctx, null, sigLen) != 1)
              throw opensslError("EVP_DigestSignFinal")

            val sig = new Array[Byte]((!sigLen).toInt)
            val sigPtr = if (sig.isEmpty) null else sig.atUnsafe(0)
            if (EVP_DigestSignFinal(ctx, sigPtr, sigLen) != 1)
              throw opensslError("EVP_DigestSignFinal")

            Signature(ByteVector.view(sig))
          } finally EVP_MD_CTX_free(ctx)
        } finally EVP_PKEY_free(pkey)
      }
    }

  private[crypto] def verify[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    algorithm match {
      case algorithm: EcdsaAlgorithm =>
        verifyEcdsa(algorithm, publicKey, message, signature)
      case algorithm: EddsaAlgorithm =>
        verifyEddsa(algorithm, publicKey, message, signature)
      case algorithm: RsaAlgorithm =>
        verifyRsa(
          algorithm = algorithm,
          hashAlgorithm = algorithm.hashAlgorithm,
          publicKey = publicKey,
          message = message,
          signature = signature,
          pss = None
        )
      case algorithm: RsaPssAlgorithm =>
        verifyRsa(
          algorithm = algorithm,
          hashAlgorithm = algorithm.hashAlgorithm,
          publicKey = publicKey,
          message = message,
          signature = signature,
          pss = Some(algorithm.saltLength)
        )
    }

  private[this] def verifyEcdsa[F[_]: Sync](
    algorithm: EcdsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      Zone.acquire { implicit zone =>
        val evpMd = EVP_get_digestbyname(toCString(nameOf(algorithm.hashAlgorithm)))
        if (evpMd == null) throw opensslError("EVP_get_digestbyname")

        val pkey = loadPublicKey(publicKey)
        try {
          val id = EVP_PKEY_get_base_id(pkey)
          if (id != EVP_PKEY_EC) throw new WrongKeyType(id, EVP_PKEY_EC, algorithm)

          val fieldSize = algorithm.fieldSize
          val rawSig = signature.toByteVector.toArrayUnsafe
          if (rawSig.length != fieldSize * 2) Verified.Invalid
          else {
            val ctx = EVP_MD_CTX_new()
            if (ctx == null) throw opensslError("EVP_MD_CTX_new")
            try {
              if (EVP_DigestVerifyInit(ctx, null, evpMd, null, pkey) != 1)
                throw opensslError("EVP_DigestVerifyInit")

              val data = message.toArrayUnsafe
              val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)
              if (EVP_DigestVerifyUpdate(ctx, dataPtr, data.length.toCSize) != 1)
                throw opensslError("EVP_DigestVerifyUpdate")

              val derSig = p1363ToDer(rawSig, fieldSize)
              val sigPtr = if (derSig.isEmpty) null else derSig.atUnsafe(0)
              EVP_DigestVerifyFinal(ctx, sigPtr, derSig.length.toCSize) match {
                case 1 => Verified.Valid
                case 0 => Verified.Invalid
                case _ => throw opensslError("EVP_DigestVerifyFinal")
              }
            } finally EVP_MD_CTX_free(ctx)
          }
        } finally EVP_PKEY_free(pkey)
      }
    }

  private[this] def verifyEddsa[F[_]: Sync](
    algorithm: EddsaAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature
  ): F[Verified] =
    Sync[F].delay {
      val pkey = loadPublicKey(publicKey)
      try {
        val id = EVP_PKEY_get_base_id(pkey)
        if (id != pkeyBaseId(algorithm))
          throw new WrongKeyType(id, pkeyBaseId(algorithm), algorithm)

        val ctx = EVP_MD_CTX_new()
        if (ctx == null) throw opensslError("EVP_MD_CTX_new")
        try {
          if (EVP_DigestVerifyInit(ctx, null, null, null, pkey) != 1)
            throw opensslError("EVP_DigestVerifyInit")

          val data = message.toArrayUnsafe
          val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)

          val sig = signature.toByteVector.toArrayUnsafe
          val sigPtr = if (sig.isEmpty) null else sig.atUnsafe(0)
          EVP_DigestVerify(ctx, sigPtr, sig.length.toCSize, dataPtr, data.length.toCSize) match {
            case 1 => Verified.Valid
            case 0 => Verified.Invalid
            case _ => throw opensslError("EVP_DigestVerify")
          }
        } finally EVP_MD_CTX_free(ctx)
      } finally EVP_PKEY_free(pkey)
    }

  private[this] def verifyRsa[F[_]: Sync](
    algorithm: AsymmetricAlgorithm,
    hashAlgorithm: HashAlgorithm,
    publicKey: PublicKey,
    message: ByteVector,
    signature: Signature,
    pss: Option[Int]
  ): F[Verified] =
    Sync[F].delay {
      Zone.acquire { implicit zone =>
        val name = nameOf(hashAlgorithm)
        val evpMd = EVP_get_digestbyname(toCString(name))
        if (evpMd == null) throw opensslError("EVP_get_digestbyname")

        val pkey = loadPublicKey(publicKey)
        try {
          val id = EVP_PKEY_get_base_id(pkey)
          if (id != EVP_PKEY_RSA) throw new WrongKeyType(id, EVP_PKEY_RSA, algorithm)

          val ctx = EVP_MD_CTX_new()
          if (ctx == null) throw opensslError("EVP_MD_CTX_new")
          try {
            val pctxPtr = stackalloc[Ptr[EVP_PKEY_CTX]]()
            !pctxPtr = null

            if (EVP_DigestVerifyInit(ctx, pctxPtr, evpMd, null, pkey) != 1)
              throw opensslError("EVP_DigestVerifyInit")

            pss.foreach(saltLength => rsaSetPss(!pctxPtr, evpMd, saltLength))

            val data = message.toArrayUnsafe
            val dataPtr = if (data.isEmpty) null else data.atUnsafe(0)
            if (EVP_DigestVerifyUpdate(ctx, dataPtr, data.length.toCSize) != 1)
              throw opensslError("EVP_DigestVerifyUpdate")

            val sig = signature.toByteVector.toArrayUnsafe
            val sigPtr = if (sig.isEmpty) null else sig.atUnsafe(0)
            EVP_DigestVerifyFinal(ctx, sigPtr, sig.length.toCSize) match {
              case 1 => Verified.Valid
              case 0 => Verified.Invalid
              case _ => throw opensslError("EVP_DigestVerifyFinal")
            }
          } finally EVP_MD_CTX_free(ctx)
        } finally EVP_PKEY_free(pkey)
      }
    }

  private[this] def rsaSetPss(
    pctx: Ptr[EVP_PKEY_CTX],
    evpMd: Ptr[EVP_MD],
    saltLength: Int
  ): Unit = {
    if (
      EVP_PKEY_CTX_ctrl(
        pctx,
        EVP_PKEY_RSA,
        -1,
        EVP_PKEY_CTRL_RSA_PADDING,
        RSA_PKCS1_PSS_PADDING,
        null
      ) != 1
    ) throw opensslError("EVP_PKEY_CTX_set_rsa_padding")

    if (
      EVP_PKEY_CTX_ctrl(
        pctx,
        EVP_PKEY_RSA,
        -1,
        EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
        saltLength,
        null
      ) != 1
    ) throw opensslError("EVP_PKEY_CTX_set_rsa_pss_saltlen")

    if (
      EVP_PKEY_CTX_ctrl(
        pctx,
        EVP_PKEY_RSA,
        -1,
        EVP_PKEY_CTRL_RSA_MGF1_MD,
        0,
        evpMd.asInstanceOf[CVoidPtr]
      ) != 1
    ) throw opensslError("EVP_PKEY_CTX_set_rsa_mgf1_md")
  }

  private[this] def derToP1363(
    der: Array[Byte],
    derLen: Int,
    fieldSize: Int
  ): ByteVector = {
    val pp = stackalloc[Ptr[CUnsignedChar]]()
    !pp =
      if (der.isEmpty) null
      else der.atUnsafe(0).asInstanceOf[Ptr[CUnsignedChar]]

    val sig = d2i_ECDSA_SIG(null, pp, derLen.toCSSize)
    if (sig == null) throw opensslError("d2i_ECDSA_SIG")
    try {
      val rPtr = stackalloc[Ptr[BIGNUM]]()
      val sPtr = stackalloc[Ptr[BIGNUM]]()
      ECDSA_SIG_get0(sig, rPtr, sPtr)

      val rBytes = (BN_num_bits(!rPtr) + 7) / 8
      val sBytes = (BN_num_bits(!sPtr) + 7) / 8
      if (rBytes > fieldSize || sBytes > fieldSize)
        throw new EcdsaFieldSizeMismatch(fieldSize, rBytes, sBytes)

      val out = new Array[Byte](fieldSize * 2)
      if (BN_bn2binpad(!rPtr, out.atUnsafe(0), fieldSize) < 0)
        throw opensslError("BN_bn2binpad (r)")
      if (BN_bn2binpad(!sPtr, out.atUnsafe(fieldSize), fieldSize) < 0)
        throw opensslError("BN_bn2binpad (s)")
      ByteVector.view(out)
    } finally ECDSA_SIG_free(sig)
  }

  private[this] def p1363ToDer(
    rawSig: Array[Byte],
    fieldSize: Int
  ): Array[Byte] = {
    val rSig = if (rawSig.isEmpty) null else rawSig.atUnsafe(0)
    val r = BN_bin2bn(rSig, fieldSize, null)
    if (r == null) throw opensslError("BN_bin2bn")

    val sSig = if (rawSig.length <= fieldSize) null else rawSig.atUnsafe(fieldSize)
    val s = BN_bin2bn(sSig, fieldSize, null)
    if (s == null) {
      BN_free(r)
      throw opensslError("BN_bin2bn")
    }

    val ecdsaSig = ECDSA_SIG_new()
    if (ecdsaSig == null) {
      BN_free(r)
      BN_free(s)
      throw opensslError("ECDSA_SIG_new")
    }

    var ownsRS = true
    try {
      if (ECDSA_SIG_set0(ecdsaSig, r, s) != 1)
        throw opensslError("ECDSA_SIG_set0")
      ownsRS = false

      val derLen = i2d_ECDSA_SIG(ecdsaSig, null)
      if (derLen <= 0) throw opensslError("i2d_ECDSA_SIG")

      val out = new Array[Byte](derLen)
      val pp = stackalloc[Ptr[CUnsignedChar]]()
      !pp = out.atUnsafe(0).asInstanceOf[Ptr[CUnsignedChar]]
      if (i2d_ECDSA_SIG(ecdsaSig, pp) <= 0)
        throw opensslError("i2d_ECDSA_SIG")

      out
    } finally {
      if (ownsRS) {
        BN_free(r)
        BN_free(s)
      }

      ECDSA_SIG_free(ecdsaSig)
    }
  }

  private[this] def loadPrivateKey(privateKey: PrivateKey): Ptr[EVP_PKEY] = {
    val bytes = privateKey.toPkcs8.toArrayUnsafe
    val pp = stackalloc[Ptr[CUnsignedChar]]()
    !pp =
      if (bytes.isEmpty) null
      else bytes.atUnsafe(0).asInstanceOf[Ptr[CUnsignedChar]]
    val pkey = d2i_AutoPrivateKey(null, pp, bytes.length.toCSSize)
    if (pkey == null) throw opensslError("d2i_AutoPrivateKey")
    pkey
  }

  private[this] def loadPublicKey(publicKey: PublicKey): Ptr[EVP_PKEY] = {
    val bytes = publicKey.toX509Spki.toArrayUnsafe
    val pp = stackalloc[Ptr[CUnsignedChar]]()
    !pp =
      if (bytes.isEmpty) null
      else bytes.atUnsafe(0).asInstanceOf[Ptr[CUnsignedChar]]
    val pkey = d2i_PUBKEY(null, pp, bytes.length.toCSSize)
    if (pkey == null) throw opensslError("d2i_PUBKEY")
    pkey
  }

  private[this] def nameOf(algorithm: HashAlgorithm): String =
    algorithm match {
      case HashAlgorithms.SHA224 => "SHA-224"
      case HashAlgorithms.SHA256 => "SHA-256"
      case HashAlgorithms.SHA384 => "SHA-384"
      case HashAlgorithms.SHA512 => "SHA-512"
      case HashAlgorithms.SHA512_224 => "SHA-512/224"
      case HashAlgorithms.SHA512_256 => "SHA-512/256"
      case HashAlgorithms.SHA3_224 => "SHA3-224"
      case HashAlgorithms.SHA3_256 => "SHA3-256"
      case HashAlgorithms.SHA3_384 => "SHA3-384"
      case HashAlgorithms.SHA3_512 => "SHA3-512"
    }

  private[this] def opensslError(functionName: String): Throwable = {
    val code = ERR_get_error()
    val reasonPtr = ERR_reason_error_string(code)
    val reason =
      if (reasonPtr == null) s"unknown error (code $code)"
      else fromCString(reasonPtr)
    new OpensslError(functionName, reason)
  }

  private[this] def pkeyBaseId(algorithm: EddsaAlgorithm): Int =
    algorithm match {
      case EddsaAlgorithms.Ed25519 => EVP_PKEY_ED25519
      case EddsaAlgorithms.Ed448 => EVP_PKEY_ED448
    }
}

@link("crypto")
@extern
private object openssl {
  final val EVP_MAX_MD_SIZE = 64
  final val EVP_PKEY_RSA = 6
  final val EVP_PKEY_EC = 408
  final val EVP_PKEY_ED25519 = 1087
  final val EVP_PKEY_ED448 = 1088

  final val RSA_PKCS1_PSS_PADDING = 6

  final val EVP_PKEY_ALG_CTRL = 0x1000
  final val EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1
  final val EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 2
  final val EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL + 5

  type BIGNUM
  type ECDSA_SIG
  type ENGINE
  type EVP_MD
  type EVP_MD_CTX
  type EVP_PKEY
  type EVP_PKEY_CTX

  def d2i_AutoPrivateKey(
    a: Ptr[Ptr[EVP_PKEY]],
    pp: Ptr[Ptr[CUnsignedChar]],
    length: CSSize
  ): Ptr[EVP_PKEY] = extern

  def d2i_PUBKEY(
    a: Ptr[Ptr[EVP_PKEY]],
    pp: Ptr[Ptr[CUnsignedChar]],
    length: CSSize
  ): Ptr[EVP_PKEY] = extern

  def EVP_DigestVerifyInit(
    ctx: Ptr[EVP_MD_CTX],
    pctx: Ptr[Ptr[EVP_PKEY_CTX]],
    `type`: Ptr[EVP_MD],
    e: Ptr[ENGINE],
    pkey: Ptr[EVP_PKEY]
  ): Int = extern

  def EVP_DigestVerifyUpdate(
    ctx: Ptr[EVP_MD_CTX],
    d: CVoidPtr,
    cnt: CSize
  ): Int = extern

  def EVP_DigestVerifyFinal(
    ctx: Ptr[EVP_MD_CTX],
    sig: Ptr[Byte],
    siglen: CSize
  ): Int = extern

  def EVP_DigestSignInit(
    ctx: Ptr[EVP_MD_CTX],
    pctx: Ptr[Ptr[EVP_PKEY_CTX]],
    `type`: Ptr[EVP_MD],
    e: Ptr[ENGINE],
    pkey: Ptr[EVP_PKEY]
  ): Int = extern

  def EVP_DigestSignUpdate(
    ctx: Ptr[EVP_MD_CTX],
    d: CVoidPtr,
    cnt: CSize
  ): Int = extern

  def EVP_DigestSignFinal(
    ctx: Ptr[EVP_MD_CTX],
    sig: Ptr[Byte],
    siglen: Ptr[CSize]
  ): CInt = extern

  def EVP_DigestSign(
    ctx: Ptr[EVP_MD_CTX],
    sigret: Ptr[Byte],
    siglen: Ptr[CSize],
    tbs: CVoidPtr,
    tbslen: CSize
  ): CInt = extern

  def EVP_DigestVerify(
    ctx: Ptr[EVP_MD_CTX],
    sigret: Ptr[Byte],
    siglen: CSize,
    tbs: CVoidPtr,
    tbslen: CSize
  ): CInt = extern

  def EVP_PKEY_CTX_ctrl(
    ctx: Ptr[EVP_PKEY_CTX],
    keytype: CInt,
    optype: CInt,
    cmd: CInt,
    p1: CInt,
    p2: CVoidPtr
  ): CInt = extern

  def EVP_PKEY_free(key: Ptr[EVP_PKEY]): Unit = extern

  def EVP_PKEY_get_base_id(key: Ptr[EVP_PKEY]): Int = extern

  def ERR_get_error(): ULong = extern

  def ERR_reason_error_string(e: ULong): CString = extern

  def EVP_get_digestbyname(name: CString): Ptr[EVP_MD] = extern

  def EVP_MD_CTX_new(): Ptr[EVP_MD_CTX] = extern

  def EVP_MD_CTX_free(ctx: Ptr[EVP_MD_CTX]): Unit = extern

  def HMAC(
    evpMd: Ptr[EVP_MD],
    key: CVoidPtr,
    keyLen: CInt,
    data: CVoidPtr,
    dataLen: CSize,
    md: Ptr[Byte],
    mdLen: Ptr[CUnsignedInt]
  ): Ptr[Byte] = extern

  def d2i_ECDSA_SIG(
    sig: Ptr[Ptr[ECDSA_SIG]],
    pp: Ptr[Ptr[CUnsignedChar]],
    length: CSSize
  ): Ptr[ECDSA_SIG] = extern

  def i2d_ECDSA_SIG(
    sig: Ptr[ECDSA_SIG],
    pp: Ptr[Ptr[CUnsignedChar]]
  ): CInt = extern

  def ECDSA_SIG_new(): Ptr[ECDSA_SIG] = extern

  def ECDSA_SIG_free(sig: Ptr[ECDSA_SIG]): Unit = extern

  def ECDSA_SIG_get0(
    sig: Ptr[ECDSA_SIG],
    pr: Ptr[Ptr[BIGNUM]],
    ps: Ptr[Ptr[BIGNUM]]
  ): Unit = extern

  def ECDSA_SIG_set0(
    sig: Ptr[ECDSA_SIG],
    r: Ptr[BIGNUM],
    s: Ptr[BIGNUM]
  ): CInt = extern

  def BN_bin2bn(
    s: Ptr[Byte],
    len: CInt,
    ret: Ptr[BIGNUM]
  ): Ptr[BIGNUM] = extern

  def BN_bn2binpad(
    a: Ptr[BIGNUM],
    to: Ptr[Byte],
    tolen: CInt
  ): CInt = extern

  def BN_free(a: Ptr[BIGNUM]): Unit = extern

  def BN_num_bits(a: Ptr[BIGNUM]): CInt = extern
}
