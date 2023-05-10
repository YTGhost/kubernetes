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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/pod-security-admission/api"
)

/*
Containers must not set runAsUser: 0

**Restricted Fields:**

spec.securityContext.runAsUser
spec.containers[*].securityContext.runAsUser
spec.initContainers[*].securityContext.runAsUser

**Allowed Values:**
non-zero values
undefined/null

*/

func init() {
	addCheck(CheckRunAsUser)
}

// CheckRunAsUser returns a restricted level check
// that forbides runAsUser=0 in 1.23+
func CheckRunAsUser() Check {
	return Check{
		ID:    "runAsUser",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 23),
				CheckPod:       withOptions(runAsUser_1_23),
			},
		},
	}
}

func runAsUser_1_23(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	// things that explicitly set runAsUser=0
	badSetters := NewViolations[string](opts.withFieldErrors)

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsUser != nil && *podSpec.SecurityContext.RunAsUser == 0 {
		var errFn ErrFn
		if opts.withFieldErrors {
			errFn = forbidden(runAsUserPath).withBadValue(0)
		}
		badSetters.Add("pod", errFn)
	}

	// containers that explicitly set runAsUser=0
	explicitlyBadContainers := NewViolations[string](opts.withFieldErrors)
	var explicitlyErrFns []ErrFn

	visitContainers(podSpec, opts, func(container *corev1.Container, pathFn PathFn) {
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			explicitlyBadContainers.Add(container.Name)
			explicitlyErrFns = append(explicitlyErrFns, forbidden(pathFn.child("securityContext", "runAsUser")).withBadValue(0))
		}
	})

	if !explicitlyBadContainers.Empty() {
		badSetters.Add(
			fmt.Sprintf(
				"%s %s",
				pluralize("container", "containers", explicitlyBadContainers.Len()),
				joinQuote(explicitlyBadContainers.Data()),
			),
			explicitlyErrFns...,
		)
	}
	// pod or containers explicitly set runAsUser=0
	if !badSetters.Empty() {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "runAsUser=0",
			ForbiddenDetail: fmt.Sprintf("%s must not set runAsUser=0", strings.Join(badSetters.Data(), " and ")),
			ErrList:         badSetters.Errs(),
		}
	}

	return CheckResult{Allowed: true}
}
