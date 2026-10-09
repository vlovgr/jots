# http4s

The `jots-http4s` module provides an integration with [http4s](https://http4s.org) servers and clients. There is an `AuthMiddleware` for verifying and decoding tokens in incoming requests. There's also support for refreshing verification by periodically fetching a `JwkSet` from an HTTP endpoint with a `Client`.

## Getting Started

To get started with [sbt](https://scala-sbt.org), add the following line to your `build.sbt` file.

```scala
libraryDependencies += "@ORGANIZATION@" %% "jots-http4s" % "@VERSION@"
```

If you are using Scala.js or Scala Native, replace the `%%` with `%%%` above.

## Request Headers

There is support for both reading and writing `SignedJwt` as [`Authorization: Bearer <token>`](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1) headers from and to requests. In the following example, we define a `SignedJwt` for demonstration purposes using syntax from the [testing module](../features/testing.md#string-interpolators). We then proceed to create a request with the `SignedJwt` in the headers and then read it back again.

```scala mdoc:silent
import cats.effect.IO
import jots.http4s.*
import jots.SignedJwt
import jots.testing.syntax.*
import org.http4s.Request

val signedJwt: SignedJwt =
  signedJwt"eyJ0eXAiOiJKV1QiLCJraWQiOiI2MzRjODBhMy0zN2Y5LTQyYmMtYTY1Ny0wYmY0Zjc1OWIxZTMiLCJhbGciOiJFUzI1NiJ9.eyJ1c2VySWQiOiI4ZDNiYmQxNC1kZmQ5LTQ3ZmEtYWFiNC1kNzZkYWYwMGI0ZjEiLCJleHAiOjMzNDUwNjI0MDAsImlhdCI6MTc2NzIyNTYwMH0.RRqlOw-CuSgt7-24kzsbVs5Te4WHhuOCzEVWsMZEtQTsHr2_Hkjk4qjE3PaEgFcYCOnsbs20QNQZZ5KSWm5bUQ"

val requestWithSignedJwt: Request[IO] =
  Request[IO]().withHeaders(signedJwt)

val signedJwtFromRequest: Option[SignedJwt] =
  requestWithSignedJwt.headers.get[SignedJwt]
```

## Auth Middleware

The `JwtAuthMiddleware` can be used to create `AuthMiddleware` for servers to parse, verify and decode tokens from incoming `Authorization: Bearer <token>` request headers. If the authentication fails, or if no token is provided, a `401 Unauthorized` response is sent along with a `WWW-Authenticate` header detailing the issue.

```scala mdoc:silent
import cats.syntax.all.*
import io.circe.Decoder
import jots.crypto.SecretKey
import jots.JwtDecoder
import jots.JwtHmacAlgorithm
import jots.JwtVerificationBuilder
import org.http4s.AuthedRoutes
import org.http4s.HttpRoutes
import org.http4s.dsl.io.*

final case class UserJwt(id: String)

object UserJwt {
  given Decoder[UserJwt] =
    Decoder.forProduct1("userId")(apply)

  given JwtDecoder[UserJwt] =
    JwtDecoder.decodeClaims
}

val routes: IO[HttpRoutes[IO]] =
  for {
    secretKey <- SecretKey("gbxZ8rjekZmYQxh24wsKcaUqPuBe7jg6").liftTo[IO]
    verification <- JwtVerificationBuilder.default[IO].hmac(JwtHmacAlgorithm.HS256, secretKey).build
    authMiddleware = JwtAuthMiddleware[IO, UserJwt](verification)
    authedRoutes = AuthedRoutes.of[UserJwt, IO] {
      case GET -> Root / "identity" as user => Ok(user.id)
    }
  } yield authMiddleware(authedRoutes)
```

@:callout(info)
We should take care to _not_ put secrets, like `SecretKey`, in source code.
@:@

Note the middleware protects every incoming request, so public routes should be combined before the authenticated routes. This normally looks something along the lines of: `publicRoutes <+> authMiddleware(authedRoutes)`. In case it is not done correctly, public routes will always get a `401 Unauthorized` without a token present.

## Refreshing Verification

There is `RefreshingJwtVerification` with support for periodically fetching a `JwkSet` from an HTTP endpoint and refreshing verification. The following example shows how to create a `RefreshingJwtVerification` instance, which accepts tokens issued by `https://example.auth0.com/` for the `https://api.example.com` audience. Note the example allows all supported asymmetric algorithms and uses the [default refresh settings](#default-refresh-settings).

```scala mdoc:silent
import cats.effect.Resource
import jots.JwtAsymmetricAlgorithm
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.syntax.all.*

val refreshingJwtVerification: Resource[IO, RefreshingJwtVerification[IO]] =
  for {
    client <- EmberClientBuilder.default[IO].build
    uri = uri"https://example.auth0.com/.well-known/jwks.json"
    refreshing <- RefreshingJwtVerificationBuilder
      .refreshWith(client, uri) { jwkSet =>
        JwtVerificationBuilder
          .default[IO]
          .jwkSet(JwtAsymmetricAlgorithm.All, jwkSet)
          .withAcceptedAudiences("https://api.example.com")
          .withAcceptedIssuers("https://example.auth0.com/")
          .build
      }
      .build
  } yield refreshing
```

@:callout(info)
Identity providers commonly sign tokens for many applications using the same keys. Make sure to set the accepted audiences, and preferably also the accepted issuers. Tokens with an audience (`aud`) are rejected unless the audience has been accepted.
@:@

The function passed to `refreshWith` creates the `JwtVerification` for each retrieved `JwkSet`, so the allowed algorithms (e.g. `JwtRsaAlgorithm.All`) and verifications are customized as with any `JwtVerificationBuilder`.

`RefreshingJwtVerification` extends `JwtVerification`, so it works everywhere `JwtVerification` is required. We also have the `keys` function to retrieve the current `JwkSet`. Note all functions semantically block until an initial key set is available (or an error occurred fetching the initial key set).

It is possible to directly use `RefreshingJwtVerification` with `JwtAuthMiddleware`.

```scala mdoc:silent
val refreshingJwtVerificationRoutes: Resource[IO, HttpRoutes[IO]] =
  for {
    verification <- refreshingJwtVerification
    authMiddleware = JwtAuthMiddleware[IO, UserJwt](verification)
    authedRoutes = AuthedRoutes.of[UserJwt, IO] {
      case GET -> Root / "identity" as user => Ok(user.id)
    }
  } yield authMiddleware(authedRoutes)
```

### Missing Key Refreshes

Tokens reference the key they were signed with using the `kid` (Key ID) in the token header, and verification selects the key with a matching `kid` from the current `JwkSet`. Since signing keys are rotated, a token can reference a key we have not yet retrieved, in which case we refresh the key set instead of failing right away.

- An extra refresh is requested and verification semantically blocks until the refreshed key set is available.
- Verification is then attempted a second time, rejecting the token if there is still no matching key in the set.
- If the key set already changed while verifying, no extra refresh is requested and the changed keys are used.
- Extra refreshes are run at most every 60 seconds by default (`minRefreshIntervalOnMissingKey` setting).

Note tokens without a `kid` in the header are rejected without requesting extra refreshes.

### Default Refresh Settings

The `RefreshingJwtVerificationBuilder` can be used to customize the following defaults.

- The key set will be automatically refreshed every 60 minutes (the `refreshInterval` setting).
- If the refresh attempt failed, we retry after 60 seconds (the `refreshIntervalOnError` setting).
- Keys from the last successful refresh are used without any age limit in place (the `maxKeyAge` setting).
- Missing keys cause an extra refresh at most every 60 seconds (`minRefreshIntervalOnMissingKey`).
- Retries with a jittered exponential backoff, up to 4 retries and max 5 seconds between (`retryPolicy`).
- The `Uri` for the key set must use HTTPS, except for loopback hosts like `localhost` (`requireHttps`).
- Logging is no-op by default; a custom `Logger` can be provided using the `withLogger` function.

Following is an example of how to customize the default settings.

```scala mdoc:silent
import jots.JwtRsaAlgorithm
import org.typelevel.log4cats.slf4j.Slf4jLogger
import scala.concurrent.duration.*

val refreshingJwtVerificationBuilderCustom: Resource[IO, RefreshingJwtVerification[IO]] =
  for {
    logger <- Slf4jLogger.create[IO].toResource
    client <- EmberClientBuilder.default[IO].build
    uri = uri"https://example.auth0.com/.well-known/jwks.json"
    refreshing <- RefreshingJwtVerificationBuilder
      .refreshWith(client, uri) { jwkSet =>
        JwtVerificationBuilder
          .default[IO]
          .jwkSet(JwtRsaAlgorithm.All, jwkSet)
          .withAcceptedAudiences("https://api.example.com")
          .withAcceptedIssuers("https://example.auth0.com/")
          .build
      }
      .withRefreshInterval(30.minutes)
      .withMinRefreshIntervalOnMissingKey(10.minutes)
      .withLogger(logger)
      .build
  } yield refreshing
```
