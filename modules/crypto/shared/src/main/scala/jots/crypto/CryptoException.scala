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

import scala.util.control.NoStackTrace

/**
  * Exception raised for issues related to cryptographic operations.
  */
abstract class CryptoException(val message: String, val cause: Option[Throwable] = None)
  extends RuntimeException(message, cause.orNull)
  with NoStackTrace

object CryptoException extends CryptoExceptionCompanionPlatform {

  /**
    * Exception raised when there is an issue creating a [[PrivateKey]].
    */
  final class InvalidPrivateKey(details: String, cause: Option[Throwable] = None)
    extends CryptoException(s"invalid private key: $details", cause)

  /**
    * Exception raised when there is an issue creating a [[PublicKey]].
    */
  final class InvalidPublicKey(details: String, cause: Option[Throwable] = None)
    extends CryptoException(s"invalid public key: $details", cause)

  /**
    * Exception raised when there is an issue creating a [[SecretKey]].
    */
  final class InvalidSecretKey(details: String, cause: Option[Throwable] = None)
    extends CryptoException(s"invalid secret key: $details", cause)
}
