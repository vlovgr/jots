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
import cats.effect.IO
import cats.effect.Ref
import cats.effect.Resource
import cats.syntax.all.*
import io.circe.syntax.*
import java.util.concurrent.CancellationException
import jots.Jwk
import jots.JwkKeyId
import jots.JwkSet
import jots.JwtAlgorithm
import jots.JwtBuilder
import jots.JwtClaims
import jots.JwtException
import jots.JwtHeader
import jots.JwtHmacAlgorithm
import jots.JwtSigning
import jots.JwtVerification
import jots.SignedJwt
import jots.crypto.SecretKey
import jots.testing.*
import jots.testing.syntax.*
import org.http4s.DecodeFailure
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Response
import org.http4s.Status
import org.http4s.Uri
import org.http4s.client.Client
import org.http4s.client.UnexpectedStatus
import org.http4s.client.middleware.RetryPolicy
import org.http4s.headers.`Content-Type`
import org.http4s.implicits.*
import scala.concurrent.duration.*
import weaver.SimpleIOSuite
import weaver.scalacheck.Checkers

object RefreshingJwtVerificationSuite extends SimpleIOSuite with Checkers {
  test("RefreshingJwtVerification.keys") {
    forall { (keySet: JwkSet) =>
      TestClient(keysResponse(keySet)).flatMap { testClient =>
        RefreshingJwtVerification
          .refreshWith[IO](testClient.client, uri)(_ => IO.pure(rejectAll))
          .use(_.keys)
          .map(keys => expect.eql(keySet, keys))
      }
    }
  }

  test("RefreshingJwtVerification.keysAwaitRefresh") {
    for {
      testClient <- TestClient(IO.sleep(50.millis) *> keysResponse(keySet))
      keys <- builder(testClient.client).build.use(_.keys)
    } yield expect.eql(keySet, keys)
  }

  test("RefreshingJwtVerification.keysDuringRefresh") {
    for {
      testClient <- TestClient(keysResponse(keySet), IO.never[Response[IO]])
      keys <- builder(testClient.client).build.use { verification =>
        eventually(testClient.requests)(_.size >= 2) *> verification.keys
      }
    } yield expect.eql(keySet, keys)
  }

  test("RefreshingJwtVerification.keysRequest") {
    for {
      testClient <- TestClient(keysResponse(keySet))
      _ <- builder(testClient.client).build.use(_.keys)
      requests <- testClient.requests
    } yield expect.eql(1, requests.size) &&
      requests.headOption.foldMap { request =>
        expect.eql(Method.GET.name, request.method.name) &&
        expect.eql(uri.renderString, request.uri.renderString)
      }
  }

  test("RefreshingJwtVerification.apply") {
    TestClient(keysResponse(keySet)).flatMap { testClient =>
      builder(testClient.client).build.use { verification =>
        implicit val refreshing: RefreshingJwtVerification[IO] = verification
        IO.pure(expect(RefreshingJwtVerification[IO] eq verification))
      }
    }
  }

  test("RefreshingJwtVerification.jwkSet") {
    for {
      signed <- sign("key-1")
      testClient <- TestClient(keysResponse(keySet))
      algorithms = NonEmptyList.of(JwtAlgorithm.HS256)
      result <- RefreshingJwtVerification
        .jwkSet[IO](algorithms, testClient.client, uri)
        .use(_.verify(signed).attempt)
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("RefreshingJwtVerification.jwkSet.rejectKeyAlgorithm") {
    for {
      testClient <- TestClient(keysResponse(keySet))
      algorithms = NonEmptyList.of(JwtAlgorithm.HS384)
      result <- RefreshingJwtVerificationBuilder
        .jwkSet[IO](algorithms, testClient.client, uri)
        .withRetryPolicy(noRetries)
        .build
        .use(_.keys.attempt)
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.RejectedKeyAlgorithm) => () }
    } yield success
  }

  test("RefreshingJwtVerification.jwkSetAll") {
    for {
      signed <- sign("key-1")
      testClient <- TestClient(keysResponse(keySet))
      result <- RefreshingJwtVerification
        .jwkSetAll[IO](testClient.client, uri)
        .use(_.verify(signed).attempt)
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("RefreshingJwtVerification.refreshWith") {
    val error = new RuntimeException("the token could not be verified")
    for {
      signed <- sign("key-1")
      testClient <- TestClient(keysResponse(keySet))
      refreshed <- Ref[IO].of(Vector.empty[JwkSet])
      result <- RefreshingJwtVerification
        .refreshWith[IO](testClient.client, uri) { keys =>
          refreshed
            .update(_ :+ keys)
            .as(JwtVerification.verifyWith[IO](_ => IO.raiseError(error)))
        }
        .use(verification => (verification.keys, verification.verify(signed).attempt).tupled)
      (keys, verified) = result
      refreshedKeys <- refreshed.get
      _ <- matchOrFailFast[IO](verified) { case Left(`error`) => () }
    } yield expect.eql(keySet, keys) && expect.eql(Vector(keySet), refreshedKeys)
  }

  test("RefreshingJwtVerification.refreshKeys") {
    for {
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      keys <- builder(testClient.client).build.use { verification =>
        eventually(verification.keys)(_ === otherKeySet)
      }
    } yield expect.eql(otherKeySet, keys)
  }

  test("RefreshingJwtVerification.refreshVerification") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      result <- builder(testClient.client).build.use { verification =>
        eventually(verification.verify(signed).attempt)(_.isRight)
      }
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield success
  }

  test("RefreshingJwtVerification.refreshInterval") {
    for {
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      keys <- RefreshingJwtVerification
        .jwkSetAll[IO](testClient.client, uri)
        .use(verification => IO.sleep(refreshInterval * 10) *> verification.keys)
      requests <- testClient.requests
    } yield expect.eql(keySet, keys) && expect.eql(1, requests.size)
  }

  test("RefreshingJwtVerification.retryPolicy") {
    val retryPolicy = RetryPolicy[IO](attempt => Option.when(attempt <= 2)(Duration.Zero))
    for {
      testClient <- TestClient(errorResponse, errorResponse, keysResponse(keySet))
      keys <- RefreshingJwtVerificationBuilder
        .jwkSetAll[IO](testClient.client, uri)
        .withRetryPolicy(retryPolicy)
        .build
        .use(_.keys)
      requests <- testClient.requests
    } yield expect.eql(keySet, keys) && expect.eql(3, requests.size)
  }

  test("RefreshingJwtVerification.retryByDefault") {
    for {
      testClient <- TestClient(errorResponse, keysResponse(keySet))
      keys <- RefreshingJwtVerification.jwkSetAll[IO](testClient.client, uri).use(_.keys)
      requests <- testClient.requests
    } yield expect.eql(keySet, keys) && expect.eql(2, requests.size)
  }

  test("RefreshingJwtVerification.surfaceInitialError") {
    val error = new RuntimeException("the key set could not be fetched")
    for {
      signed <- sign("key-1")
      testClient <- TestClient(IO.raiseError(error))
      result <- builder(testClient.client).build.use { verification =>
        (verification.keys.attempt, verification.verify(signed).attempt).tupled
      }
      (keys, verified) = result
      _ <- matchOrFailFast[IO](keys) { case Left(`error`) => () }
      _ <- matchOrFailFast[IO](verified) { case Left(`error`) => () }
    } yield success
  }

  test("RefreshingJwtVerification.surfaceUnexpectedStatus") {
    for {
      testClient <- TestClient(errorResponse)
      result <- builder(testClient.client).build.use(_.keys.attempt)
      _ <- matchOrFailFast[IO](result) { case Left(_: UnexpectedStatus) => () }
    } yield success
  }

  test("RefreshingJwtVerification.surfaceInvalidKeySet") {
    for {
      testClient <- TestClient(invalidKeysResponse)
      result <- builder(testClient.client).build.use(_.keys.attempt)
      _ <- matchOrFailFast[IO](result) { case Left(_: DecodeFailure) => () }
    } yield success
  }

  test("RefreshingJwtVerification.retainKeysOnError") {
    for {
      signed <- sign("key-1")
      testClient <- TestClient(keysResponse(keySet), errorResponse)
      result <- builder(testClient.client).build.use { verification =>
        for {
          _ <- eventually(testClient.requests)(_.size >= 3)
          keys <- verification.keys
          verified <- verification.verify(signed).attempt
        } yield (keys, verified)
      }
      (keys, verified) = result
      _ <- matchOrFailFast[IO](verified) { case Right(_) => () }
    } yield expect.eql(keySet, keys)
  }

  test("RefreshingJwtVerification.recoverFromInitialError") {
    for {
      testClient <- TestClient(errorResponse, keysResponse(keySet))
      result <- builder(testClient.client).build.use { verification =>
        eventually(verification.keys.attempt)(_.isRight)
      }
      _ <- matchOrFailFast[IO](result) { case Right(`keySet`) => () }
    } yield success
  }

  test("RefreshingJwtVerification.releaseStopRefresh") {
    for {
      testClient <- TestClient(keysResponse(keySet))
      _ <- builder(testClient.client).build.use { _ =>
        eventually(testClient.requests)(_.size >= 2)
      }
      released <- testClient.requests
      _ <- IO.sleep(refreshInterval * 10)
      requests <- testClient.requests
    } yield expect.eql(released.size, requests.size)
  }

  test("RefreshingJwtVerification.refreshOnMissingKey") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      result <- missingKeyBuilder(testClient.client).build.use { verification =>
        awaitInitialKeys(verification) >> verification.verify(signed).attempt
      }
      requests <- testClient.requests
      _ <- matchOrFailFast[IO](result) { case Right(_) => () }
    } yield expect.eql(2, requests.size)
  }

  test("RefreshingJwtVerification.minRefreshIntervalOnMissingKey") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      result <- missingKeyBuilder(testClient.client)
        .withMinRefreshIntervalOnMissingKey(1.hour)
        .build
        .use { verification =>
          awaitInitialKeys(verification) >> verification.verify(signed).attempt
        }
      requests <- testClient.requests
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield expect.eql(1, requests.size)
  }

  test("RefreshingJwtVerification.refreshOnMissingKeyOnce") {
    for {
      signed <- sign("key-3")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      result <- missingKeyBuilder(testClient.client).build.use { verification =>
        awaitInitialKeys(verification) >> verification.verify(signed).attempt
      }
      requests <- testClient.requests
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield expect.eql(2, requests.size)
  }

  test("RefreshingJwtVerification.refreshOnMissingKeyConcurrently") {
    val delayedKeys = IO.sleep(100.millis) *> keysResponse(otherKeySet)
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), delayedKeys)
      results <- missingKeyBuilder(testClient.client).build.use { verification =>
        awaitInitialKeys(verification) >>
          List.fill(5)(verification.verify(signed).attempt).parSequence
      }
      requests <- testClient.requests
    } yield expect.eql(2, requests.size) && expect(results.forall(_.isRight))
  }

  test("RefreshingJwtVerification.missingKeyOnRefreshError") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), errorResponse)
      result <- missingKeyBuilder(testClient.client).build.use { verification =>
        awaitInitialKeys(verification) >> verification.verify(signed).attempt
      }
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield success
  }

  test("RefreshingJwtVerification.releaseRefreshOnMissingKey") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      verification <- missingKeyBuilder(testClient.client).build.use { verification =>
        awaitInitialKeys(verification).as(verification)
      }
      result <- verification.verify(signed).attempt.timeout(30.seconds)
      requests <- testClient.requests
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield expect.eql(1, requests.size)
  }

  test("RefreshingJwtVerification.releaseVerifyOnceOnMissingKey") {
    for {
      signed <- sign("key-2")
      testClient <- TestClient(keysResponse(keySet), keysResponse(otherKeySet))
      attempts <- Ref[IO].of(0)
      verification <- RefreshingJwtVerificationBuilder
        .refreshWith[IO](testClient.client, uri) { _ =>
          IO.pure(JwtVerification.verifyWith[IO] { _ =>
            attempts.update(_ + 1) *> IO.raiseError(new JwtException.MissingKey())
          })
        }
        .withRefreshInterval(1.hour)
        .withMinRefreshIntervalOnMissingKey(minRefreshIntervalOnMissingKey)
        .withRetryPolicy(noRetries)
        .build
        .use(verification => awaitInitialKeys(verification).as(verification))
      result <- verification.verify(signed).attempt.timeout(30.seconds)
      verified <- attempts.get
      requests <- testClient.requests
      _ <- matchOrFailFast[IO](result) { case Left(_: JwtException.MissingKey) => () }
    } yield expect.eql(1, verified) && expect.eql(1, requests.size)
  }

  test("RefreshingJwtVerification.releaseBeforeRefresh") {
    List
      .fill(50)(())
      .traverse { _ =>
        for {
          testClient <- TestClient(keysResponse(keySet))
          verification <- builder(testClient.client).build.use(IO.pure)
          keys <- verification.keys.attempt.timeout(30.seconds)
        } yield keys
      }
      .flatMap(_.traverse_ { keys =>
        matchOrFailFast[IO](keys) {
          case Right(`keySet`) => ()
          case Left(_: CancellationException) => ()
        }
      })
      .as(success)
  }

  private val uri: Uri =
    uri"https://localhost:8080/.well-known/jwks.json"

  private val refreshInterval: FiniteDuration =
    10.millis

  private val refreshIntervalOnError: FiniteDuration =
    5.millis

  private val minRefreshIntervalOnMissingKey: FiniteDuration =
    1.milli

  private val noRetries: RetryPolicy[IO] =
    RetryPolicy[IO](_ => None)

  private val secretKey: SecretKey =
    secretKey"a-string-secret-at-least-256-bits-long"

  private val keySet: JwkSet =
    JwkSet(octJwk("key-1"))

  private val otherKeySet: JwkSet =
    JwkSet(octJwk("key-2"))

  private val rejectAll: JwtVerification[IO] =
    JwtVerification.verifyWith[IO](_ => IO.raiseError(new JwtException.InvalidSignature()))

  private def builder(client: Client[IO]): RefreshingJwtVerificationBuilder[IO] =
    RefreshingJwtVerificationBuilder
      .jwkSetAll[IO](client, uri)
      .withRefreshInterval(refreshInterval)
      .withRefreshIntervalOnError(refreshIntervalOnError)
      .withRetryPolicy(noRetries)

  private def missingKeyBuilder(client: Client[IO]): RefreshingJwtVerificationBuilder[IO] =
    RefreshingJwtVerificationBuilder
      .jwkSetAll[IO](client, uri)
      .withRefreshInterval(1.hour)
      .withMinRefreshIntervalOnMissingKey(minRefreshIntervalOnMissingKey)
      .withRetryPolicy(noRetries)

  private def awaitInitialKeys(verification: RefreshingJwtVerification[IO]): IO[Unit] =
    verification.keys >> IO.sleep(minRefreshIntervalOnMissingKey * 10)

  private def keysResponse(keySet: JwkSet): IO[Response[IO]] =
    IO.pure(Response[IO](Status.Ok).withEntity(keySet))

  private val invalidKeysResponse: IO[Response[IO]] =
    IO.pure(
      Response[IO](Status.Ok)
        .withEntity("{}")
        .withContentType(`Content-Type`(MediaType.application.json))
    )

  private val errorResponse: IO[Response[IO]] =
    IO.pure(Response[IO](Status.ServiceUnavailable))

  private val claims: JwtClaims =
    JwtClaims("sub" -> "1234567890".asJson)

  private def sign(keyId: String): IO[SignedJwt] =
    signWith(JwtHeader.default.withKeyId(JwkKeyId(keyId)), secretKey)

  private def signWith(header: JwtHeader, secretKey: SecretKey): IO[SignedJwt] =
    JwtSigning
      .default[IO]
      .hmac(JwtHmacAlgorithm.HS256, secretKey)
      .flatMap(JwtBuilder(header, claims).signWith)

  private def octJwk(keyId: String): Jwk =
    Jwk(
      "kty" -> "oct".asJson,
      "kid" -> keyId.asJson,
      "alg" -> "HS256".asJson,
      "k" -> secretKey.toByteVector.toBase64UrlNoPad.asJson
    ).fold(throw _, identity)

  private def eventually[A](fa: IO[A])(f: A => Boolean): IO[A] =
    (fa <* IO.sleep(1.milli)).iterateUntil(f).timeout(30.seconds)

  private final class TestClient(
    requestsRef: Ref[IO, Vector[Request[IO]]],
    responses: NonEmptyList[IO[Response[IO]]]
  ) {
    val client: Client[IO] =
      Client[IO] { request =>
        Resource.eval {
          requestsRef.updateAndGet(_ :+ request).flatMap { requests =>
            responses.toList.lift(requests.size - 1).getOrElse(responses.last)
          }
        }
      }

    def requests: IO[Vector[Request[IO]]] =
      requestsRef.get
  }

  private object TestClient {
    def apply(response: IO[Response[IO]], responses: IO[Response[IO]]*): IO[TestClient] =
      Ref[IO]
        .of(Vector.empty[Request[IO]])
        .map(new TestClient(_, NonEmptyList(response, responses.toList)))
  }
}
