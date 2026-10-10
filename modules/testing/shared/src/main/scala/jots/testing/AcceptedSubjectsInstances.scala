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

import cats.data.NonEmptyList
import jots.AcceptedSubjects
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Cogen
import org.scalacheck.Gen

/**
  * ScalaCheck generators and instances for [[jots.AcceptedSubjects]].
  */
object AcceptedSubjectsInstances extends AcceptedSubjectsInstances

private[jots] trait AcceptedSubjectsInstances {
  lazy val acceptedSubjectsGen: Gen[AcceptedSubjects] =
    Gen.oneOf(
      Gen.const(AcceptedSubjects.any),
      for {
        subject <- arbitrary[String]
        subjects <- arbitrary[List[String]]
      } yield AcceptedSubjects.fromList(NonEmptyList(subject, subjects))
    )

  implicit lazy val acceptedSubjectsArbitrary: Arbitrary[AcceptedSubjects] =
    Arbitrary(acceptedSubjectsGen)

  implicit lazy val acceptedSubjectsCogen: Cogen[AcceptedSubjects] =
    Cogen[String].contramap(_.show)

  lazy val acceptedSubjectsFunGen: Gen[AcceptedSubjects => AcceptedSubjects] =
    Gen.function1(acceptedSubjectsGen)

  implicit lazy val acceptedSubjectsFunArbitrary: Arbitrary[AcceptedSubjects => AcceptedSubjects] =
    Arbitrary(acceptedSubjectsFunGen)
}
