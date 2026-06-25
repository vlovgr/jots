val catsEffectVersion = "3.7.0"
val catsVersion = "2.13.0"
val circeVersion = "0.14.16"
val literallyVersion = "1.2.0"
val scala213Version = "2.13.18"
val scala3Version = "3.3.8"
val scalaCheckVersion = "1.19.0"
val scodecBitsVersion = "1.2.5"
val weaverVersion = "0.13.0"

inThisBuild(
  Seq(
    crossScalaVersions := Seq(scala213Version, scala3Version),
    developers := List(tlGitHubDev("vlovgr", "Viktor Rudebeck")),
    githubWorkflowJavaVersions := Seq(JavaSpec.temurin("17")),
    githubWorkflowTargetBranches := Seq("**"),
    githubWorkflowBuildPreamble ++= nativeBrewInstallWorkflowSteps.value,
    nativeBrewInstallCond := Some("matrix.project == 'rootNative'"),
    licenses := Seq(License.Apache2),
    organization := "se.vlovgr",
    organizationName := "Viktor Rudebeck",
    scalaVersion := scala3Version,
    semanticdbEnabled := true,
    semanticdbVersion := scalafixSemanticdb.revision,
    startYear := Some(2026),
    tlBaseVersion := "0.1",
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
        ProblemFilters.exclude[Problem]("jots.crypto.internal.*"),
        ProblemFilters.exclude[Problem]("jots.testing.internal.*")
      )
    }
  )
)

lazy val root = tlCrossRootProject
  .aggregate(core, crypto, testing, tests, unidocs)

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
      "org.typelevel" %%% "cats-kernel" % catsVersion
    )
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
  .dependsOn(testing.jvm)
  .settings {
    import laika.ast.Path.Root
    import laika.config.LaikaKeys
    import laika.helium.config.HeliumIcon
    import laika.helium.config.IconLink

    Seq(
      laikaConfig := laikaConfig.value
        .withConfigValue(LaikaKeys.titleDocuments.inputName, "index"),
      mdocVariables := mdocVariables.value
        .updated("CATS_EFFECT_VERSION", catsEffectVersion)
        .updated("CATS_VERSION", catsVersion)
        .updated("CIRCE_VERSION", circeVersion)
        .updated("LITERALLY_VERSION", literallyVersion)
        .updated("MAJOR_VERSION", majorVersion(version.value))
        .updated("ORGANIZATION", (ThisBuild / organization).value)
        .updated("SCALA_DOCS_VERSION", majorMinorVersion(scalaVersion.value))
        .updated("SCALA_JS_MAJOR_MINOR_VERSION", scalaJsMajorMinorVersion)
        .updated("SCALA_NATIVE_MAJOR_MINOR_VERSION", scalaNativeMajorMinorVersion)
        .updated("SCALA_PUBLISH_VERSIONS", majorMinorVersions((ThisBuild / crossScalaVersions).value))
        .updated("SCALACHECK_VERSION", scalaCheckVersion)
        .updated("SCODEC_BITS_VERSION", scodecBitsVersion),
      tlSiteHelium := tlSiteHelium.value.site
        .topNavigationBar(homeLink = IconLink.internal(Root / "index.md", HeliumIcon.home))
        .site
        .footer(
          "Licensed under <a href=\"https://github.com/vlovgr/jots/blob/main/license.txt\">Apache License, Version 2.0</a>.<br>" +
            "Copyright © 2026 Viktor Rudebeck."
        )
        .site
        .pageNavigation(sourceBaseURL = Some("https://github.com/vlovgr/jots/tree/main/docs"))
    )
  }

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
  .dependsOn(testing)
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
  .nativeEnablePlugins(ScalaNativeBrewedConfigPlugin)
  .nativeSettings(
    Test / nativeBrewFormulas += "openssl",
    Test / test := {} // https://github.com/scala-native/scala-native/issues/4951
  )

lazy val unidocs = project
  .enablePlugins(TypelevelUnidocPlugin)
  .settings(
    name := "jots-docs",
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(
      core.jvm,
      crypto.jvm,
      testing.jvm
    )
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
