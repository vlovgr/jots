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

package jots.crypto.internal

import jots.crypto.PrivateKey
import jots.crypto.PublicKey
import jots.crypto.internal.asn1.Asn1
import jots.crypto.internal.asn1.Oid

/**
  * Used to determine the algorithm of an asymmetric key.
  */
private[jots] object KeyAlgorithm {

  /**
    * Returns `true` if the specified private key is
    * restricted to RSASSA-PSS; `false` otherwise.
    */
  def isRsaPss(privateKey: PrivateKey): Boolean = {
    val pkcs8 =
      privateKey.toPkcs8

    val rsaPss =
      for {
        outer <- Asn1.readTlv(pkcs8, 0L) if outer.isSeq && outer.end == pkcs8.size
        version <- Asn1.readTlv(outer.contents, 0L) if version.isInt
        algorithmId <- Asn1.readTlv(outer.contents, version.end) if algorithmId.isSeq
        oid <- Asn1.readTlv(algorithmId.contents, 0L) if oid.isOid
      } yield oid.contents == Oid.RsaPss.contents

    rsaPss.getOrElse(false)
  }

  /**
    * Returns `true` if the specified public key is
    * restricted to RSASSA-PSS; `false` otherwise.
    */
  def isRsaPss(publicKey: PublicKey): Boolean = {
    val spki =
      publicKey.toX509Spki

    val rsaPss =
      for {
        outer <- Asn1.readTlv(spki, 0L) if outer.isSeq && outer.end == spki.size
        algorithmId <- Asn1.readTlv(outer.contents, 0L) if algorithmId.isSeq
        oid <- Asn1.readTlv(algorithmId.contents, 0L) if oid.isOid
      } yield oid.contents == Oid.RsaPss.contents

    rsaPss.getOrElse(false)
  }
}
