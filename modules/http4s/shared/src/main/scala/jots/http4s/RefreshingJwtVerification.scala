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
import java.util.concurrent.CancellationException
import jots.JwkSet
import jots.JwtAlgorithm
import jots.JwtException
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
  * When verification fails because there is no key in the current set
  * with a matching key id (kid), an extra refresh is requested, and a
  * second verification attempt is done with the refreshed keys. These
  * refreshes are by default run at most every 60 seconds. If the keys
  * already changed while verifying, then no extra refresh is run, and
  * the changed keys are used for the second attempt.
  *
  * If the `Resource` is released, verification will continue with the
  * current [[JwkSet]] and refreshing stops. When a key is missing, no
  * extra refresh is requested. If no initial key set is available and
  * no error occurred, a `CancellationException` is raised instead.
  *
  * The [[RefreshingJwtVerification.refreshWith]] function accepts the
  * function to use for refreshing [[JwtVerification]], while there is
  * [[RefreshingJwtVerification.jwkSet]] for convenience.
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
        state <- State.next(keys, verification)
      } yield state

    def refreshState(ref: PhaseRef[F]): F[Unit] =
      for {
        result <- fetchState.attempt
        phase <- updateState(ref, result)
        _ <- logResult(result)
        wait <- nextWait(result)
        _ <- awaitRefresh(phase, wait)
      } yield ()

    def awaitRefresh(phase: Phase[F], wait: FiniteDuration): F[Unit] =
      phase match {
        case Phase.Ready(state) => F.race(F.sleep(wait), state.requestRefresh.get).void
        case _ => F.sleep(wait)
      }

    def nextWait(result: StateResult[F]): F[FiniteDuration] = {
      val wait = if (result.isRight) refreshInterval else refreshIntervalOnError
      logger.debug(s"The next key set refresh is in $wait").as(wait)
    }

    def nextPhase(ref: PhaseRef[F], result: StateResult[F]): F[Phase[F]] =
      result match {
        case Right(state) =>
          F.pure(Phase.Ready(state))
        case Left(error) =>
          ref.get.flatMap {
            case ready @ Phase.Ready(_) => ready.next
            case _ => F.pure(Phase.Unavailable(error))
          }
      }

    def updateState(ref: PhaseRef[F], result: StateResult[F]): F[Phase[F]] =
      nextPhase(ref, result).flatTap { next =>
        ref.flatModify {
          case Phase.Pending(deferred) => (next, deferred.complete(result).void)
          case Phase.Ready(state) => (next, state.refresh.complete(result).void)
          case _ => (next, F.unit)
        }
      }

    def refreshOnMissingKey(ref: PhaseRef[F], current: State[F]): F[Option[State[F]]] =
      (ref.get, F.monotonic).tupled.flatMap {
        case (Phase.Ready(state), _) if state.keys =!= current.keys =>
          state.some.pure
        case (Phase.Stopped(Right(state)), _) if state.keys =!= current.keys =>
          state.some.pure
        case (Phase.Ready(state), now) if now - state.refreshAttemptedAt >= minRefreshIntervalOnMissingKey =>
          requestRefresh(state) >> state.refresh.get.map(_.toOption)
        case _ =>
          none[State[F]].pure
      }

    def requestRefresh(state: State[F]): F[Unit] =
      state.requestRefresh.complete(()).ifM(logRequestRefresh, F.unit)

    def cancel(ref: PhaseRef[F]): F[Unit] =
      stop(ref, new CancellationException("Key set refreshing was canceled"))(logCanceled)

    def fail(ref: PhaseRef[F])(error: Throwable): F[Unit] =
      stop(ref, error)(logFailed)

    def complete(ref: PhaseRef[F])(outcome: Outcome[F, Throwable, Unit]): F[Unit] =
      outcome.fold(cancel(ref), fail(ref), _ => F.unit)

    def stop(ref: PhaseRef[F], cause: Throwable)(log: Throwable => F[Unit]): F[Unit] =
      ref.flatModify {
        case Phase.Pending(deferred) =>
          val stopped = deferred.complete(cause.asLeft) >> log(cause)
          (Phase.Stopped(cause.asLeft[State[F]]), stopped)
        case Phase.Ready(state) =>
          val preventRefresh = state.requestRefresh.complete(())
          val completeRefresh = state.refresh.complete(cause.asLeft)
          val stopped = preventRefresh >> completeRefresh >> log(cause)
          (Phase.Stopped(state.asRight[Throwable]), stopped)
        case Phase.Unavailable(error) =>
          (Phase.Stopped(error.asLeft[State[F]]), log(cause))
        case stopped @ Phase.Stopped(_) =>
          (stopped, F.unit)
      }

    def logCanceled(cause: Throwable): F[Unit] =
      logger.debug(cause)("Key set refreshing was stopped")

    def logFailed(cause: Throwable): F[Unit] =
      logger.warn(cause)("Key set refreshing was stopped unexpectedly")

    def logRequestRefresh: F[Unit] =
      logger.debug("Refreshing key set since a referenced key is missing")

    def logResult(result: StateResult[F]): F[Unit] =
      result match {
        case Right(state) => logger.debug(s"Refreshed key set ${state.keys}")
        case Left(cause) => logger.warn(cause)("Failed to refresh key set")
      }

    for {
      deferred <- Deferred[F, StateResult[F]].toResource
      ref <- Ref.of[F, Phase[F]](Phase.Pending(deferred)).toResource
      _ <- Resource.onFinalize(cancel(ref))
      _ <- refreshState(ref).foreverM[Unit].guaranteeCase(complete(ref)).background
    } yield new RefreshingJwtVerification[F] {
      override def keys: F[JwkSet] =
        state.map(_.keys)

      private def state: F[State[F]] =
        ref.get.flatMap {
          case Phase.Ready(state) => state.pure
          case Phase.Stopped(result) => result.liftTo[F]
          case Phase.Unavailable(error) => error.raiseError
          case Phase.Pending(deferred) => deferred.get.rethrow
        }

      override def verify(jwt: SignedJwt): F[VerifiedJwt] =
        state.flatMap { current =>
          current.verification.verify(jwt).recoverWith { case missingKey: JwtException.MissingKey =>
            refreshOnMissingKey(ref, current).flatMap {
              case Some(refreshed) => refreshed.verification.verify(jwt)
              case None => missingKey.raiseError
            }
          }
        }
    }
  }

  private final case class State[F[_]](
    keys: JwkSet,
    verification: JwtVerification[F],
    refreshAttemptedAt: FiniteDuration,
    requestRefresh: Deferred[F, Unit],
    refresh: DeferredStateResult[F]
  ) {
    def next(implicit F: Temporal[F]): F[State[F]] =
      State.next(keys, verification)
  }

  private object State {
    def next[F[_]](
      keys: JwkSet,
      verification: JwtVerification[F]
    )(implicit F: Temporal[F]): F[State[F]] =
      for {
        refreshAttemptedAt <- F.monotonic
        requested <- Deferred[F, Unit]
        refreshed <- Deferred[F, StateResult[F]]
      } yield State(keys, verification, refreshAttemptedAt, requested, refreshed)
  }

  private type StateResult[F[_]] = Either[Throwable, State[F]]

  private type DeferredStateResult[F[_]] = Deferred[F, StateResult[F]]

  private sealed abstract class Phase[F[_]]

  private object Phase {
    final case class Pending[F[_]](deferred: DeferredStateResult[F]) extends Phase[F]

    final case class Unavailable[F[_]](error: Throwable) extends Phase[F]

    final case class Ready[F[_]](state: State[F]) extends Phase[F] {
      def next(implicit F: Temporal[F]): F[Phase[F]] =
        state.next.map(Ready(_))
    }

    final case class Stopped[F[_]](result: StateResult[F]) extends Phase[F]
  }

  private type PhaseRef[F[_]] = Ref[F, Phase[F]]
}
