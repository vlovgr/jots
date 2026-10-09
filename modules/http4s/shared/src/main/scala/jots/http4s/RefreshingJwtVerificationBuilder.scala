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

package jots.http4s

import cats.effect.Resource
import cats.effect.Temporal
import jots.JwkSet
import jots.JwtVerification
import org.http4s.Uri
import org.http4s.client.Client
import org.http4s.client.middleware.RetryPolicy
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.noop.NoOpLogger
import scala.concurrent.duration.*

/**
  * [[RefreshingJwtVerification]] builder which allows customizing options.
  */
sealed abstract class RefreshingJwtVerificationBuilder[F[_]] {

  /**
    * Returns the `Client` with which to periodically issue requests.
    */
  def client: Client[F]

  /**
    * Returns the `Logger` instance that should be used for logging.
    *
    * The default is a no-op instance that does not log anything.
    */
  def logger: Logger[F]

  /**
    * Sets the `Logger` instance that should be used for logging.
    *
    * The default is a no-op instance that does not log anything.
    */
  def withLogger(logger: Logger[F]): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the duration to wait between refresh attempts.
    *
    * The default refresh interval is 60 minutes.
    */
  def refreshInterval: FiniteDuration

  /**
    * Sets the duration to wait between refresh attempts.
    *
    * The default refresh interval is 60 minutes.
    */
  def withRefreshInterval(refreshInterval: FiniteDuration): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the duration to wait between refresh attempts
    * when the most recent refresh attempt failed.
    *
    * The default refresh interval on errors is 60 seconds.
    */
  def refreshIntervalOnError: FiniteDuration

  /**
    * Sets the duration to wait between refresh attempts
    * when the most recent refresh attempt failed.
    *
    * The default refresh interval on errors is 60 seconds.
    */
  def withRefreshIntervalOnError(refreshIntervalOnError: FiniteDuration): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the minimum duration between the last refresh attempt
    * and an extra refresh attempt, which is made when verification
    * fails because no key matched the token key id (kid).
    *
    * The default minimum refresh interval on missing keys is 60 seconds.
    */
  def minRefreshIntervalOnMissingKey: FiniteDuration

  /**
    * Sets the minimum duration between the last refresh attempt and
    * an extra refresh attempt, which is made when verification
    * fails because no key matched the token key id (kid).
    *
    * The default minimum refresh interval on missing keys is 60 seconds.
    */
  def withMinRefreshIntervalOnMissingKey(
    minRefreshIntervalOnMissingKey: FiniteDuration
  ): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the maximum duration since the last successful refresh
    * during which the keys are used. Once the keys are older, they
    * are not used, and verification fails until keys are refreshed.
    *
    * The default max key age is unlimited (`Duration.Inf`).
    */
  def maxKeyAge: Duration

  /**
    * Sets the maximum duration since the last successful refresh
    * during which the keys are used. Once the keys are older, they
    * are not used, and verification fails until keys are refreshed.
    *
    * Note the max key age should be longer than the refresh interval.
    *
    * The default max key age is unlimited (`Duration.Inf`).
    */
  def withMaxKeyAge(maxKeyAge: Duration): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the retry policy used when refreshing keys.
    *
    * The default retry policy is a jittered exponential
    * backoff with up to 4 retries and a maximum wait of
    * 5 seconds between retries.
    */
  def retryPolicy: RetryPolicy[F]

  /**
    * Sets the retry policy used when refreshing keys.
    *
    * The default retry policy is a jittered exponential
    * backoff with up to 4 retries and a maximum wait of
    * 5 seconds between retries.
    */
  def withRetryPolicy(retryPolicy: RetryPolicy[F]): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns `true` if the `Uri` is required to use HTTPS;
    * `false` otherwise.
    *
    * Note HTTP is always allowed for loopback hosts.
    *
    * The default is to require HTTPS.
    */
  def requireHttps: Boolean

  /**
    * Sets whether the `Uri` is required to use HTTPS.
    *
    * Note HTTP is always allowed for loopback hosts.
    *
    * The default is to require HTTPS.
    */
  def withRequireHttps(requireHttps: Boolean): RefreshingJwtVerificationBuilder[F]

  /**
    * Returns the `Uri` to which requests for keys should be issued.
    */
  def uri: Uri

  /**
    * Returns the function that should be used to create
    * [[JwtVerification]] from [[JwkSet]] when new keys
    * have been retrieved.
    */
  def verification: JwkSet => F[JwtVerification[F]]

  /**
    * Returns a new [[RefreshingJwtVerification]] using
    * the builder's settings.
    */
  def build: Resource[F, RefreshingJwtVerification[F]]
}

object RefreshingJwtVerificationBuilder {
  private final case class RefreshingJwtVerificationBuilderImpl[F[_]: Temporal](
    override val client: Client[F],
    override val logger: Logger[F],
    override val refreshInterval: FiniteDuration,
    override val refreshIntervalOnError: FiniteDuration,
    override val minRefreshIntervalOnMissingKey: FiniteDuration,
    override val maxKeyAge: Duration,
    override val retryPolicy: RetryPolicy[F],
    override val requireHttps: Boolean,
    override val uri: Uri,
    override val verification: JwkSet => F[JwtVerification[F]]
  ) extends RefreshingJwtVerificationBuilder[F] {
    override def withLogger(logger: Logger[F]): RefreshingJwtVerificationBuilder[F] =
      copy(logger = logger)

    override def withRefreshInterval(refreshInterval: FiniteDuration): RefreshingJwtVerificationBuilder[F] = {
      require(
        refreshInterval > Duration.Zero,
        s"refresh interval must be positive, was $refreshInterval"
      )

      copy(refreshInterval = refreshInterval)
    }

    override def withRefreshIntervalOnError(
      refreshIntervalOnError: FiniteDuration
    ): RefreshingJwtVerificationBuilder[F] = {
      require(
        refreshIntervalOnError > Duration.Zero,
        s"refresh interval on error must be positive, was $refreshIntervalOnError"
      )

      copy(refreshIntervalOnError = refreshIntervalOnError)
    }

    override def withMinRefreshIntervalOnMissingKey(
      minRefreshIntervalOnMissingKey: FiniteDuration
    ): RefreshingJwtVerificationBuilder[F] = {
      require(
        minRefreshIntervalOnMissingKey > Duration.Zero,
        s"minimum refresh interval on missing key must be positive, was $minRefreshIntervalOnMissingKey"
      )

      copy(minRefreshIntervalOnMissingKey = minRefreshIntervalOnMissingKey)
    }

    override def withMaxKeyAge(maxKeyAge: Duration): RefreshingJwtVerificationBuilder[F] = {
      require(
        maxKeyAge > Duration.Zero,
        s"max key age must be positive, was $maxKeyAge"
      )

      copy(maxKeyAge = maxKeyAge)
    }

    override def withRetryPolicy(retryPolicy: RetryPolicy[F]): RefreshingJwtVerificationBuilder[F] =
      copy(retryPolicy = retryPolicy)

    override def withRequireHttps(requireHttps: Boolean): RefreshingJwtVerificationBuilder[F] =
      copy(requireHttps = requireHttps)

    override def build: Resource[F, RefreshingJwtVerification[F]] =
      RefreshingJwtVerification.fromBuilder(this)
  }

  /**
    * Returns a new [[RefreshingJwtVerificationBuilder]] instance
    * which verifies tokens using the provided verification function.
    *
    * The keys will be fetched by issuing a request to the `Uri`
    * with the specified `Client`. Note there is a default retry
    * policy in place and keys are refreshed every 60 minutes.
    */
  def refreshWith[F[_]](client: Client[F], uri: Uri)(
    verification: JwkSet => F[JwtVerification[F]]
  )(implicit F: Temporal[F]): RefreshingJwtVerificationBuilder[F] =
    new RefreshingJwtVerificationBuilderImpl(
      client = client,
      logger = NoOpLogger[F],
      refreshInterval = 60.minutes,
      refreshIntervalOnError = 60.seconds,
      minRefreshIntervalOnMissingKey = 60.seconds,
      maxKeyAge = Duration.Inf,
      retryPolicy = RetryPolicy(RetryPolicy.exponentialBackoff(maxWait = 5.seconds, maxRetry = 4)),
      requireHttps = true,
      uri = uri,
      verification = verification
    )
}
