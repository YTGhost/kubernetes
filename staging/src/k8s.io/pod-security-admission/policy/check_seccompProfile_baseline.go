/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/pod-security-admission/api"
)

/*
If seccomp profiles are specified, only runtime default and localhost profiles are allowed.

v1.0 - v1.18:
**Restricted Fields:**
metadata.annotations['seccomp.security.alpha.kubernetes.io/pod']
metadata.annotations['container.seccomp.security.alpha.kubernetes.io/*']

**Allowed Values:** 'runtime/default', 'docker/default', 'localhost/*', undefined

v1.19+:
**Restricted Fields:**
spec.securityContext.seccompProfile.type
spec.containers[*].securityContext.seccompProfile.type
spec.initContainers[*].securityContext.seccompProfile.type

**Allowed Values:** 'RuntimeDefault', 'Localhost', undefined
*/
const (
	annotationKeyPod             = "seccomp.security.alpha.kubernetes.io/pod"
	annotationKeyContainerPrefix = "container.seccomp.security.alpha.kubernetes.io/"

	checkSeccompBaselineID CheckID = "seccompProfile_baseline"
)

func init() {
	addCheck(CheckSeccompBaseline)
}

func CheckSeccompBaseline() Check {
	return Check{
		ID:    checkSeccompBaselineID,
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       withOptions(seccompProfileBaseline_1_0),
			},
			{
				MinimumVersion: api.MajorMinorVersion(1, 19),
				CheckPod:       withOptions(seccompProfileBaseline_1_19),
			},
		},
	}
}

func validSeccomp(t corev1.SeccompProfileType) bool {
	return t == corev1.SeccompProfileTypeLocalhost ||
		t == corev1.SeccompProfileTypeRuntimeDefault
}

func validSeccompAnnotationValue(v string) bool {
	return v == corev1.SeccompProfileRuntimeDefault ||
		v == corev1.DeprecatedSeccompProfileDockerDefault ||
		strings.HasPrefix(v, corev1.SeccompLocalhostProfileNamePrefix)
}

// seccompProfileBaseline_1_0 checks baseline policy on seccomp alpha annotation
func seccompProfileBaseline_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	forbidden := sets.NewString()
	var errList field.ErrorList

	if val, ok := podMetadata.Annotations[annotationKeyPod]; ok {
		if !validSeccompAnnotationValue(val) {
			forbidden.Insert(fmt.Sprintf("%s=%q", annotationKeyPod, val))
			if opts.withErrList {
				errList = append(errList, withBadValue(field.Forbidden(annotationsPath.Key(annotationKeyPod), ""), []string{
					val,
				}))
			}
		}
	}

	visitContainersWithPath(podSpec, func(c *corev1.Container, path *field.Path) {
		annotation := annotationKeyContainerPrefix + c.Name
		if val, ok := podMetadata.Annotations[annotation]; ok {
			if !validSeccompAnnotationValue(val) {
				forbidden.Insert(fmt.Sprintf("%s=%q", annotation, val))
				if opts.withErrList {
					errList = append(errList, withBadValue(field.Forbidden(annotationsPath.Key(annotation), ""), []string{
						val,
					}))
				}
			}
		}
	})

	if len(forbidden) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "seccompProfile",
			ForbiddenDetail: fmt.Sprintf(
				"forbidden %s %s",
				pluralize("annotation", "annotations", len(forbidden)),
				strings.Join(forbidden.List(), ", "),
			),
			ErrList: errList,
		}
	}

	return CheckResult{Allowed: true}
}

// seccompProfileBaseline_1_19 checks baseline policy on securityContext.seccompProfile field
func seccompProfileBaseline_1_19(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	// things that explicitly set seccompProfile.type to a bad value
	var badSetters []string
	badValues := sets.NewString()
	var errList field.ErrorList

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		if !validSeccomp(podSpec.SecurityContext.SeccompProfile.Type) {
			badSetters = append(badSetters, "pod")
			badValues.Insert(string(podSpec.SecurityContext.SeccompProfile.Type))
			opts.errListHandler(func() {
				err := withBadValue(field.Forbidden(seccompProfileTypePath, ""), []string{
					string(podSpec.SecurityContext.SeccompProfile.Type),
				})
				errList = append(errList, err)
			})
		}
	}

	// containers that explicitly set seccompProfile.type to a bad value
	var explicitlyBadContainers []string

	visitContainersWithPath(podSpec, func(c *corev1.Container, path *field.Path) {
		if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
			// container explicitly set seccompProfile
			if !validSeccomp(c.SecurityContext.SeccompProfile.Type) {
				// container explicitly set seccompProfile to a bad value
				explicitlyBadContainers = append(explicitlyBadContainers, c.Name)
				badValues.Insert(string(c.SecurityContext.SeccompProfile.Type))
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(path.Child("securityContext").Child("seccompProfile").Child("type"), ""), []string{
						string(podSpec.SecurityContext.SeccompProfile.Type),
					})
					errList = append(errList, err)
				})
			}
		}
	})

	if len(explicitlyBadContainers) > 0 {
		badSetters = append(
			badSetters,
			fmt.Sprintf(
				"%s %s",
				pluralize("container", "containers", len(explicitlyBadContainers)),
				joinQuote(explicitlyBadContainers),
			),
		)
	}
	// pod or containers explicitly set bad seccompProfiles
	if len(badSetters) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "seccompProfile",
			ForbiddenDetail: fmt.Sprintf(
				"%s must not set securityContext.seccompProfile.type to %s",
				strings.Join(badSetters, " and "),
				joinQuote(badValues.List()),
			),
			ErrList: errList,
		}
	}

	return CheckResult{Allowed: true}
}
