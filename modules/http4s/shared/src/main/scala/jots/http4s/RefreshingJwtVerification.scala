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

import cats.data.NonEmptyList
import cats.effect.Deferred
import cats.effect.Outcome
import cats.effect.Ref
import cats.effect.Resource
import cats.effect.Temporal
import cats.effect.syntax.all.*
import cats.syntax.all.*
import jots.JwkSet
import jots.JwtAlgorithm
import jots.JwtVerification
import jots.SignedJwt
import jots.VerifiedJwt
import jots.crypto.Crypto
import org.http4s.Uri
import org.http4s.client.Client
import org.http4s.client.middleware.Retry
import scala.concurrent.duration.FiniteDuration

/**
  * [[JwtVerification]] backed by a periodically refreshed [[JwkSet]].
  *
  * The [[JwkSet]] is retrieved by issuing requests to a `Uri` using a
  * `Client`. There is a default retry policy to recover any temporary
  * network issues. By default, the keys will be refreshed every hour.
  * If we fail to request keys despite retries, or in case decoding is
  * not successful or we fail to create a [[JwtVerification]], we will
  * try again after 60 seconds.
  *
  * Keys are refreshed in the background, so all verifications and the
  * [[keys]] method will semantically block until some initial key set
  * has been retrieved. Errors will be surfaced until the initial keys
  * are available. Subsequent errors retrieving keys continues to keep
  * the current [[JwkSet]] instead of surfacing the errors.
  *
  * If the `Resource` is released, verification will continue with the
  * current [[JwkSet]] and refreshing stops. If no initial key set has
  * been retrieved and no error has occurred, callers will instead get
  * a `CancellationException` raised.
  *
  * The [[RefreshingJwtVerification.refreshWith]] function accepts the
  * function to use for refreshing [[JwtVerification]], while there is
  * [[jwkSet]] and [[jwkSetAll]] provided as convenience functions.
  *
  * The [[RefreshingJwtVerificationBuilder]] provides customization of
  * the default settings. Notably, logging is no-op by default, so set
  * up logging using [[RefreshingJwtVerificationBuilder#withLogger]].
  */
trait RefreshingJwtVerification[F[_]] extends JwtVerification[F] {

  /**
    * Returns the current set of keys used for verification.
    *
    * If no keys have been retrieved yet, this will semantically
    * block until either keys have been retrieved, or there is a
    * problem retrieving keys, in which case an error is raised.
    */
  def keys: F[JwkSet]
}

object RefreshingJwtVerification {
  def apply[F[_]](implicit F: RefreshingJwtVerification[F]): RefreshingJwtVerification[F] = F

  /**
    * Returns a new [[RefreshingJwtVerification]] instance which
    * verifies tokens using a list of algorithms.
    *
    * The keys will be fetched by issuing a request to the `Uri`
    * with the specified `Client`. Note there is a default retry
    * policy in place and keys are refreshed every 60 minutes.
    *
    * Use [[RefreshingJwtVerificationBuilder.jwkSet]] if there
    * is a need to customize the default options.
    */
  def jwkSet[F[_]](
    algorithms: NonEmptyList[JwtAlgorithm],
    client: Client[F],
    uri: Uri
  )(implicit
    F: Temporal[F],
    crypto: Crypto[F]
  ): Resource[F, RefreshingJwtVerification[F]] =
    RefreshingJwtVerificationBuilder.jwkSet(algorithms, client, uri).build

  /**
    * Returns a new [[RefreshingJwtVerification]] instance which
    * verifies tokens using all recognized algorithms.
    *
    * The keys will be fetched by issuing a request to the `Uri`
    * with the specified `Client`. Note there is a default retry
    * policy in place and keys are refreshed every 60 minutes.
    *
    * Use [[RefreshingJwtVerificationBuilder.jwkSetAll]] if
    * there is a need to customize the default options.
    */
  def jwkSetAll[F[_]](
    client: Client[F],
    uri: Uri
  )(implicit
    F: Temporal[F],
    crypto: Crypto[F]
  ): Resource[F, RefreshingJwtVerification[F]] =
    RefreshingJwtVerificationBuilder.jwkSetAll(client, uri).build

  /**
    * Returns a new [[RefreshingJwtVerification]] instance which
    * verifies tokens using the provided verification function.
    *
    * The keys will be fetched by issuing a request to the `Uri`
    * with the specified `Client`. Note there is a default retry
    * policy in place and keys are refreshed every 60 minutes.
    *
    * Use [[RefreshingJwtVerificationBuilder.refreshWith]] if
    * there is a need to customize the default options.
    */
  def refreshWith[F[_]](client: Client[F], uri: Uri)(
    verification: JwkSet => F[JwtVerification[F]]
  )(implicit F: Temporal[F]): Resource[F, RefreshingJwtVerification[F]] =
    RefreshingJwtVerificationBuilder.refreshWith(client, uri)(verification).build

  private[jots] def fromBuilder[F[_]](
    builder: RefreshingJwtVerificationBuilder[F]
  )(implicit F: Temporal[F]): Resource[F, RefreshingJwtVerification[F]] = {
    import builder.*

    val retryClient: Client[F] =
      Retry(retryPolicy)(client)

    def fetchState: F[State[F]] =
      for {
        keys <- retryClient.expect[JwkSet](uri)
        verification <- builder.verification(keys)
        state = State(keys, verification)
      } yield state

    def refreshState(ref: PhaseRef[F]): F[Unit] =
      for {
        result <- fetchState.attempt
        _ <- logResult(result)
        _ <- updateState(ref, result)
        wait <- nextRefresh(result)
        _ <- F.sleep(wait)
      } yield ()

    def logResult(result: StateResult[F]): F[Unit] =
      result match {
        case Right(state) => logger.debug(s"Refreshed key set with ${state.keys.size} key(s)")
        case Left(cause) => logger.warn(cause)(s"Failed to refresh key set: ${cause.getMessage}")
      }

    def nextRefresh(result: StateResult[F]): F[FiniteDuration] = {
      val wait = if (result.isRight) refreshInterval else refreshIntervalOnError
      logger.debug(s"Next refresh is in $wait").as(wait)
    }

    def updateState(ref: PhaseRef[F], result: StateResult[F]): F[Unit] =
      ref.flatModify {
        case ready @ Phase.Ready(_) if result.isLeft => (ready, F.unit)
        case Phase.Pending(deferred) => (Phase.fromResult(result), deferred.complete(result).void)
        case _ => (Phase.fromResult(result), F.unit)
      }

    def completePending(ref: PhaseRef[F])(outcome: Outcome[F, Throwable, Unit]): F[Unit] =
      outcome.embedError.attempt.flatMap {
        case Left(error) =>
          logComplete(error) >> ref.flatModify {
            case Phase.Pending(deferred) => (Phase.Failed(error), deferred.complete(error.asLeft).void)
            case phase => (phase, F.unit)
          }
        case Right(_) =>
          F.unit
      }

    def logComplete(cause: Throwable): F[Unit] =
      logger.debug(cause)(s"Refreshing stopped: ${cause.getMessage}")

    for {
      deferred <- Deferred[F, StateResult[F]].toResource
      ref <- Ref.of[F, Phase[F]](Phase.Pending(deferred)).toResource
      _ <- refreshState(ref).foreverM[Unit].guaranteeCase(completePending(ref)).background
    } yield new RefreshingJwtVerification[F] {
      override def keys: F[JwkSet] =
        state.map(_.keys)

      private def state: F[State[F]] =
        ref.get.flatMap {
          case Phase.Ready(state) => state.pure
          case Phase.Failed(error) => error.raiseError
          case Phase.Pending(deferred) => deferred.get.rethrow
        }

      override def verify(jwt: SignedJwt): F[VerifiedJwt] =
        state.flatMap(_.verification.verify(jwt))
    }
  }

  private final case class State[F[_]](keys: JwkSet, verification: JwtVerification[F])

  private type StateResult[F[_]] = Either[Throwable, State[F]]

  private type DeferredStateResult[F[_]] = Deferred[F, StateResult[F]]

  private sealed abstract class Phase[F[_]]

  private object Phase {
    final case class Pending[F[_]](deferred: DeferredStateResult[F]) extends Phase[F]

    final case class Failed[F[_]](error: Throwable) extends Phase[F]

    final case class Ready[F[_]](state: State[F]) extends Phase[F]

    def fromResult[F[_]](result: StateResult[F]): Phase[F] =
      result match {
        case Left(error) => Failed[F](error)
        case Right(state) => Ready[F](state)
      }
  }

  private type PhaseRef[F[_]] = Ref[F, Phase[F]]
}
