val caseInsensitiveVersion = "1.5.0"
val catsEffectVersion = "3.7.1"
val catsVersion = "2.13.0"
val circeVersion = "0.14.17"
val fs2Version = "3.14.0"
val http4sVersion = "0.23.38"
val literallyVersion = "1.2.0"
val log4catsVersion = "2.8.0"
val scala213Version = "2.13.18"
val scala3Version = "3.3.9"
val scalaCheckVersion = "1.20.0"
val scodecBitsVersion = "1.2.5"
val slf4jVersion = "2.0.20"
val vaultVersion = "3.7.0"
val weaverVersion = "0.13.0"

inThisBuild(
  Seq(
    crossScalaVersions := Seq(scala213Version, scala3Version),
    developers := List(tlGitHubDev("vlovgr", "Viktor Rudebeck")),
    githubWorkflowJavaVersions := Seq(JavaSpec.temurin("21")),
    githubWorkflowTargetBranches := Seq("**"),
    githubWorkflowBuildPreamble := Seq(
      WorkflowStep.Run(
        commands = List("/home/linuxbrew/.linuxbrew/bin/brew update"),
        name = Some("Update brew"),
        cond = Some("(matrix.project == 'rootNative') && startsWith(matrix.os, 'ubuntu')")
      )
    ) ++ githubWorkflowBuildPreamble.value,
    githubWorkflowBuildPreamble ++= nativeBrewInstallWorkflowSteps.value,
    githubWorkflowOSes := Seq("ubuntu-latest"),
    nativeBrewInstallCond := Some("matrix.project == 'rootNative'"),
    licenses := Seq(License.Apache2),
    organization := "se.vlovgr",
    organizationName := "Viktor Rudebeck",
    scalaVersion := scala3Version,
    semanticdbEnabled := true,
    semanticdbVersion := scalafixSemanticdb.revision,
    startYear := Some(2026),
    tlBaseVersion := "0.4",
    tlCiHeaderCheck := true,
    tlCiScalafixCheck := true,
    tlCiScalafmtCheck := true,
    tlFatalWarnings := true,
    tlJdkRelease := Some(8),
    tlSitePublishBranch := Some("main"),
    versionScheme := Some("early-semver"),
    mimaBinaryIssueFilters ++= {
      import com.typesafe.tools.mima.core._
      Seq(
        ProblemFilters.exclude[Problem]("jots.internal.*"),
        ProblemFilters.exclude[Problem]("jots.crypto.internal.*")
      )
    }
  )
)

lazy val root = tlCrossRootProject
  .aggregate(core, crypto, http4s, testing, tests, unidocs)

lazy val core = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("modules/core"))
  .dependsOn(crypto)
  .settings(
    name := "jots",
    libraryDependencies ++= Seq(
      "io.circe" %%% "circe-core" % circeVersion,
      "io.circe" %%% "circe-jawn" % circeVersion,
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.typelevel" %%% "cats-kernel" % catsVersion,
      "org.typelevel" %%% "literally" % literallyVersion
    ) ++ scalaReflect(scalaVersion.value)
  )

lazy val crypto = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("modules/crypto"))
  .settings(
    name := "jots-crypto",
    libraryDependencies ++= Seq(
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.typelevel" %%% "cats-kernel" % catsVersion,
      "org.typelevel" %%% "literally" % literallyVersion
    ) ++ scalaReflect(scalaVersion.value)
  )

lazy val docs = project
  .in(file("site"))
  .enablePlugins(TypelevelSitePlugin)
  .dependsOn(http4s.jvm, testing.jvm)
  .settings {
    import laika.ast.Image
    import laika.ast.InlineSVGIcon
    import laika.ast.LengthUnit.em
    import laika.ast.LengthUnit.px
    import laika.ast.Path.Root
    import laika.ast.Styles
    import laika.config.ApiLinks
    import laika.config.LinkConfig
    import laika.helium.Helium
    import laika.helium.config.ButtonLink
    import laika.helium.config.ColorQuintet
    import laika.helium.config.Favicon
    import laika.helium.config.HeliumIcon
    import laika.helium.config.IconLink
    import laika.helium.config.LinkGroup
    import laika.helium.config.LinkPanel
    import laika.helium.config.ReleaseInfo
    import laika.helium.config.TextLink
    import laika.theme.config.Color
    import org.typelevel.sbt.site.GenericSiteSettings

    Seq(
      crossScalaVersions := Seq(scala3Version),
      libraryDependencies ++= Seq(
        "org.http4s" %% "http4s-dsl" % http4sVersion,
        "org.http4s" %% "http4s-ember-client" % http4sVersion,
        "org.slf4j" % "slf4j-nop" % slf4jVersion % Runtime
      ),
      Compile / packageDoc / mappings := (unidocs / Compile / packageDoc / mappings).value.map {
        case (file, path) => file -> path.replace('\\', '/')
      },
      laikaConfig ~= (_.withConfigValue(LinkConfig.empty.addApiLinks(ApiLinks("/api/")))),
      laikaIncludeAPI := true,
      tlSiteApiUrl := None,
      tlSitePreview := tlSitePreview.dependsOn(laikaGenerateAPI).value,
      mdocVariables := mdocVariables.value
        .updated("CATS_EFFECT_VERSION", catsEffectVersion)
        .updated("CIRCE_VERSION", circeVersion)
        .updated("HTTP4S_VERSION", http4sVersion)
        .updated("LITERALLY_VERSION", literallyVersion)
        .updated("MAJOR_VERSION", majorVersion(version.value))
        .updated("ORGANIZATION", (ThisBuild / organization).value)
        .updated("SCALA_DOCS_VERSION", majorMinorVersion(scalaVersion.value))
        .updated("SCALA_JS_MAJOR_MINOR_VERSION", scalaJsMajorMinorVersion)
        .updated("SCALA_NATIVE_MAJOR_MINOR_VERSION", scalaNativeMajorMinorVersion)
        .updated("SCALA_PUBLISH_VERSIONS", majorMinorVersions((ThisBuild / crossScalaVersions).value))
        .updated("SCALACHECK_VERSION", scalaCheckVersion)
        .updated("SCODEC_BITS_VERSION", scodecBitsVersion),
      tlSiteHelium := {
        val gitHubUrl = "https://github.com/vlovgr/jots"

        val projectLinks = List(
          IconLink.internal(Root / "api" / "jots.html", HeliumIcon.api),
          IconLink.external(gitHubUrl, HeliumIcon.github)
        )

        Helium.defaults
          .extendWith(GenericSiteSettings.themeExtensions.value)
          .site
          .metadata(
            title = Some("Jots · Functional JWTs for Scala"),
            description =
              Some("Functional signing and verification of JWTs for Scala, Scala.js and Scala Native."),
            authors = developers.value.map(_.name),
            language = Some("en"),
            version = Some(version.value)
          )
          .site
          .themeColors(
            primary = Color.hex("1c1838"),
            secondary = Color.hex("5a44b8"),
            primaryMedium = Color.hex("d4cfeb"),
            primaryLight = Color.hex("f3f2f7"),
            text = Color.hex("24292e"),
            background = Color.hex("ffffff"),
            bgGradient = (Color.hex("1c1838"), Color.hex("251c49"))
          )
          .site
          .messageColors(
            info = Color.hex("5a44b8"),
            infoLight = Color.hex("eeebf9"),
            warning = Color.hex("b1a400"),
            warningLight = Color.hex("fcfacd"),
            error = Color.hex("d83030"),
            errorLight = Color.hex("ffe9e3")
          )
          .site
          .syntaxHighlightingColors(
            base = ColorQuintet(
              Color.hex("f8f8f8"), // background
              Color.hex("999988"), // comments
              Color.hex("333333"), // punctuation
              Color.hex("333333"), // identifiers
              Color.hex("333333") // unclassified
            ),
            wheel = ColorQuintet(
              Color.hex("999999"), // substitutions, annotations
              Color.hex("333333"), // keywords, escape sequences
              Color.hex("990000"), // declaration names
              Color.hex("dd1144"), // literals
              Color.hex("445588") // types
            )
          )
          .site
          .clearFontResources
          .site
          .fontSizes(
            body = px(16),
            code = em(0.85),
            title = px(32),
            header2 = px(24),
            header3 = px(20),
            header4 = px(16),
            small = px(12)
          )
          .site
          .darkMode
          .disabled
          .site
          .layout(topBarHeight = px(50))
          .site
          .topNavigationBar(
            homeLink = IconLink.internal(
              Root / "README",
              InlineSVGIcon(IO.read(file("docs/img/logo.svg"))),
              text = Some("Jots"),
              options = Styles("home-link")
            ),
            navLinks = projectLinks,
            highContrast = true
          )
          .site
          .internalCSS(Root / "css")
          .site
          .favIcons(
            Favicon.external("https://vlovgr.github.io/jots/img/logo.png", "180x180", "image/png"),
            Favicon.internal(Root / "img" / "logo.svg")
          )
          .site
          .landingPage(
            logo = Some(
              Image.internal(Root / "img" / "logo.svg", height = Some(px(150)), alt = Some(""))
            ),
            title = Some("Jots"),
            subtitle = Some("Functional JWTs for Scala"),
            latestReleases = tlLatestVersion.value.toList.map(ReleaseInfo("Latest Release", _)),
            license = Some("Apache 2.0"),
            titleLinks = Seq(
              ButtonLink.internal(Root / "overview.md", "Documentation"),
              LinkGroup.create(projectLinks.head, projectLinks.tail: _*)
            ),
            linkPanel = Some(
              LinkPanel(
                "Documentation",
                TextLink.internal(Root / "overview.md", "Overview"),
                TextLink.internal(Root / "introduction.md", "Introduction"),
                TextLink.internal(Root / "features" / "signing.md", "Features"),
                TextLink.internal(Root / "integrations" / "http4s.md", "Integrations")
              )
            )
          )
          .site
          .footer()
          .site
          .pageNavigation(sourceBaseURL = Some("https://github.com/vlovgr/jots/tree/main/docs"))
      }
    )
  }

lazy val http4s = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("modules/http4s"))
  .dependsOn(core)
  .settings(
    name := "jots-http4s",
    libraryDependencies ++= Seq(
      "co.fs2" %%% "fs2-core" % fs2Version,
      "io.circe" %%% "circe-core" % circeVersion,
      "org.http4s" %%% "http4s-circe" % http4sVersion,
      "org.http4s" %%% "http4s-client" % http4sVersion,
      "org.http4s" %%% "http4s-core" % http4sVersion,
      "org.http4s" %%% "http4s-server" % http4sVersion,
      "org.typelevel" %%% "case-insensitive" % caseInsensitiveVersion,
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect" % catsEffectVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.typelevel" %%% "cats-kernel" % catsVersion,
      "org.typelevel" %%% "log4cats-core" % log4catsVersion,
      "org.typelevel" %%% "vault" % vaultVersion
    )
  )

lazy val testing = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("modules/testing"))
  .dependsOn(core)
  .settings(
    name := "jots-testing",
    libraryDependencies ++= Seq(
      "io.circe" %%% "circe-core" % circeVersion,
      "org.scalacheck" %%% "scalacheck" % scalaCheckVersion,
      "org.scodec" %%% "scodec-bits" % scodecBitsVersion,
      "org.typelevel" %%% "cats-core" % catsVersion,
      "org.typelevel" %%% "cats-effect-kernel" % catsEffectVersion,
      "org.typelevel" %%% "cats-effect" % catsEffectVersion,
      "org.typelevel" %%% "cats-kernel" % catsVersion,
      "org.typelevel" %%% "literally" % literallyVersion
    ) ++ scalaReflect(scalaVersion.value)
  )

lazy val tests = crossProject(JVMPlatform, JSPlatform, NativePlatform)
  .in(file("tests"))
  .dependsOn(http4s, testing)
  .settings(
    name := "jots-tests",
    publish / skip := true,
    mimaPreviousArtifacts := Set(),
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-kernel-laws" % catsVersion % Test,
      "org.typelevel" %%% "cats-laws" % catsVersion % Test,
      "org.typelevel" %%% "weaver-cats" % weaverVersion % Test,
      "org.typelevel" %%% "weaver-discipline" % weaverVersion % Test,
      "org.typelevel" %%% "weaver-scalacheck" % weaverVersion % Test
    )
  )
  .jsSettings(
    Test / scalaJSStage := FastOptStage,
    jsEnv := new org.scalajs.jsenv.nodejs.NodeJSEnv(),
    scalaJSLinkerConfig ~= (_.withModuleKind(ModuleKind.CommonJSModule))
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "org.slf4j" % "slf4j-nop" % slf4jVersion % Runtime
    )
  )
  .nativeEnablePlugins(ScalaNativeBrewedConfigPlugin)
  .nativeSettings(Test / nativeBrewFormulas += "openssl")

lazy val unidocs = project
  .enablePlugins(TypelevelUnidocPlugin)
  .settings(
    name := "jots-docs",
    crossScalaVersions := Seq(scala3Version),
    semanticdbEnabled := false,
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(
      core.jvm,
      crypto.jvm,
      http4s.jvm,
      testing.jvm
    ),
    ScalaUnidoc / unidoc / apiMappings := {
      val docsApiUrl = apiURL.value.map(_.toString)
      (ScalaUnidoc / unidoc / apiMappings).value.filterNot { case (_, url) =>
        docsApiUrl.contains(url.toString)
      }
    },
    ScalaUnidoc / unidoc / scalacOptions := {
      val docVersion = tlLatestVersion.value.getOrElse(version.value)
      val logo = (LocalRootProject / baseDirectory).value / "docs" / "img" / "logo.svg"
      val options = (ScalaUnidoc / unidoc / scalacOptions).value.filterNot { option =>
        option == "-Werror" || option == "-Wvalue-discard" || option.startsWith("-Ykind-projector")
      }
      val projectOptions = withOption(options, "-project", "Jots")
      withOption(projectOptions, "-project-version", s"v$docVersion") ++ Seq(
        "-comment-syntax:wiki",
        "-doc-canonical-base-url:https://vlovgr.github.io/jots/api/",
        "-project-footer:Licensed under Apache License, Version 2.0.",
        s"-project-logo:${logo.getAbsolutePath}",
        "-social-links:github::https://github.com/vlovgr/jots"
      )
    }
  )

def scalaReflect(scalaVersion: String): Seq[ModuleID] =
  if (scalaVersion.startsWith("2."))
    Seq("org.scala-lang" % "scala-reflect" % scalaVersion % Provided)
  else Seq()

def majorVersion(version: String): String = {
  val parts = version.split('.')
  val major = parts(0)
  major
}

def majorMinorVersion(version: String): String = {
  val parts = version.split('.')
  val (major, minor) = (parts(0), parts(1))
  s"$major.$minor"
}

def majorMinorVersions(versions: Seq[String]): String = {
  val scalaVersions = versions.map(majorMinorVersion)
  if (scalaVersions.size <= 2) scalaVersions.mkString(" and ")
  else scalaVersions.init.mkString(", ") ++ " and " ++ scalaVersions.last
}

def withOption(options: Seq[String], name: String, value: String): Seq[String] =
  options.indexOf(name) match {
    case -1 => options ++ Seq(name, value)
    case index => options.updated(index + 1, value)
  }

lazy val scalaJsMajorMinorVersion =
  """"org.scala-js" % "sbt-scalajs" % "([^"]+)"""".r
    .findFirstMatchIn(IO.read(file("project/plugins.sbt")))
    .map(_.group(1))
    .flatMap(CrossVersion.partialVersion)
    .map { case (major, minor) => s"$major.$minor" }
    .getOrElse(throw new MessageOnlyException("unable to determine Scala.js plugin version"))

lazy val scalaNativeMajorMinorVersion =
  """"org.scala-native" % "sbt-scala-native" % "([^"]+)"""".r
    .findFirstMatchIn(IO.read(file("project/plugins.sbt")))
    .map(_.group(1))
    .flatMap(CrossVersion.partialVersion)
    .map { case (major, minor) => s"$major.$minor" }
    .getOrElse(throw new MessageOnlyException("unable to determine Scala Native plugin version"))
