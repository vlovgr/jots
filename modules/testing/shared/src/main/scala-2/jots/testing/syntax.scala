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

package jots.testing

import jots.SignedJwt
import jots.VerifiedJwt
import jots.crypto.PrivateKey
import jots.crypto.SecretKey
import jots.testing.literals.*

object syntax {
  implicit final class JotsTestingSignedJwtSyntax(private val signedJwt: SignedJwt) extends AnyVal {

    /**
      * Returns a new [[VerifiedJwt]] from an _unverified_ [[SignedJwt]].
      *
      * Note this is generally unsafe and should only be done in tests.
      */
    def toVerifiedUnsafe: VerifiedJwt =
      VerifiedJwt.fromVerified(signedJwt)
  }

  implicit final class JotsTestingVerifiedJwtCompanionSyntax(
    private val verifiedJwt: VerifiedJwt.type
  ) extends AnyVal {

    /**
      * Returns a new [[VerifiedJwt]] from an _unverified_ [[SignedJwt]].
      *
      * Note this is generally unsafe and should only be done in tests.
      */
    def fromSignedUnsafe(jwt: SignedJwt): VerifiedJwt =
      VerifiedJwt.fromVerified(jwt)
  }

  implicit final class JotsTestingStringContextSyntax(private val ctx: StringContext) extends AnyVal {
    def privateKey(args: Any*): PrivateKey = macro PrivateKeyLiteral.make

    def secretKey(args: Any*): SecretKey = macro SecretKeyLiteral.make

    def signedJwt(args: Any*): SignedJwt = macro SignedJwtLiteral.make
  }
}
