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

package jots.internal

import jots.Jwk
import jots.JwtException

/**
  * Keys in a [[jots.JwkSet]] which were skipped, together with the
  * reason, since they could not be used for signature verification.
  *
  * Note the http4s module depends on this trait, so it must keep
  * binary compatibility, even though it is package-private.
  */
private[jots] trait SkippedKeys {
  def skippedKeys: List[(Jwk, JwtException)]
}
