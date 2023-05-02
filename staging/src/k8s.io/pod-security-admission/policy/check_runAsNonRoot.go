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
Containers must be required to run as non-root users.

**Restricted Fields:**

spec.securityContext.runAsNonRoot
spec.containers[*].securityContext.runAsNonRoot
spec.initContainers[*].securityContext.runAsNonRoot

**Allowed Values:**
true
undefined/null at container-level if pod-level is set to true
*/

func init() {
	addCheck(CheckRunAsNonRoot)
}

// CheckRunAsNonRoot returns a restricted level check
// that requires runAsNonRoot=true in 1.0+
func CheckRunAsNonRoot() Check {
	return Check{
		ID:    "runAsNonRoot",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       withOptions(runAsNonRoot_1_0),
			},
		},
	}
}

func runAsNonRoot_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	// things that explicitly set runAsNonRoot=false
	var badSetters violations[string]

	podRunAsNonRoot := false
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsNonRoot != nil {
		if !*podSpec.SecurityContext.RunAsNonRoot {
			var errFn ErrFn
			if opts.withFieldErrors {
				errFn = forbidden(runAsNonRootPath, []string{"false"})
			}
			badSetters.Add("pod", errFn)
		} else {
			podRunAsNonRoot = true
		}
	}

	// containers that explicitly set runAsNonRoot=false
	var explicitlyBadContainers violations[string]
	// containers that didn't set runAsNonRoot and aren't caught by a pod-level runAsNonRoot=true
	var implicitlyBadContainers violations[string]
	var explicitlyErrFns []ErrFn

	visitContainers(podSpec, opts, func(container *corev1.Container, pathFn PathFn) {
		if container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil {
			// container explicitly set runAsNonRoot
			if !*container.SecurityContext.RunAsNonRoot {
				explicitlyBadContainers.Add(container.Name)
				explicitlyErrFns = append(explicitlyErrFns, forbidden(pathFn.child("securityContext").child("runAsNonRoot"), []string{
					"false",
				}))
			}
		} else {
			// container did not explicitly set runAsNonRoot
			if !podRunAsNonRoot {
				// no pod-level runAsNonRoot=true, so this container implicitly has a bad value
				var errFn ErrFn
				if opts.withFieldErrors {
					errFn = required(runAsNonRootPath)
				}
				implicitlyBadContainers.Add(container.Name, errFn)
			}
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
	// pod or containers explicitly set runAsNonRoot=false
	if !badSetters.Empty() {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "runAsNonRoot != true",
			ForbiddenDetail: fmt.Sprintf("%s must not set securityContext.runAsNonRoot=false", strings.Join(badSetters.Data(), " and ")),
			ErrList:         badSetters.Errs(),
		}
	}

	// pod didn't set runAsNonRoot and not all containers opted into runAsNonRoot
	if !implicitlyBadContainers.Empty() {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "runAsNonRoot != true",
			ForbiddenDetail: fmt.Sprintf(
				"pod or %s %s must set securityContext.runAsNonRoot=true",
				pluralize("container", "containers", implicitlyBadContainers.Len()),
				joinQuote(implicitlyBadContainers.Data()),
			),
			ErrList: implicitlyBadContainers.Errs(),
		}
	}

	return CheckResult{Allowed: true}
}
