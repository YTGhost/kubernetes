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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/pod-security-admission/api"
)

/*
Setting the SELinux type is restricted, and setting a custom SELinux user or role option is forbidden.

**Restricted Fields:**
spec.securityContext.seLinuxOptions.type
spec.containers[*].securityContext.seLinuxOptions.type
spec.initContainers[*].securityContext.seLinuxOptions.type

**Allowed Values:**
undefined/empty
container_t
container_init_t
container_kvm_t

**Restricted Fields:**
spec.securityContext.seLinuxOptions.user
spec.containers[*].securityContext.seLinuxOptions.user
spec.initContainers[*].securityContext.seLinuxOptions.user
spec.securityContext.seLinuxOptions.role
spec.containers[*].securityContext.seLinuxOptions.role
spec.initContainers[*].securityContext.seLinuxOptions.role

**Allowed Values:** undefined/empty
*/

func init() {
	addCheck(CheckSELinuxOptions)
}

// CheckSELinuxOptions returns a baseline level check
// that limits seLinuxOptions type, user, and role values in 1.0+
func CheckSELinuxOptions() Check {
	return Check{
		ID:    "seLinuxOptions",
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       withOptions(seLinuxOptions_1_0),
			},
		},
	}
}

var (
	selinux_allowed_types_1_0 = sets.NewString("", "container_t", "container_init_t", "container_kvm_t")
)

func seLinuxOptions_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	var (
		// sources that set bad seLinuxOptions
		badSetters violations[string]

		// invalid type values set
		badTypes = sets.NewString()
		// was user set?
		setUser = false
		// was role set?
		setRole = false
	)

	validSELinuxOptions := func(opts *corev1.SELinuxOptions) bool {
		valid := true
		if !selinux_allowed_types_1_0.Has(opts.Type) {
			valid = false
			badTypes.Insert(opts.Type)
		}
		if len(opts.User) > 0 {
			valid = false
			setUser = true
		}
		if len(opts.Role) > 0 {
			valid = false
			setRole = true
		}
		return valid
	}

	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SELinuxOptions != nil {
		if !validSELinuxOptions(podSpec.SecurityContext.SELinuxOptions) {
			badSetters.Add("pod", opts, forbidden(seLinuxOptionsTypePath, []string{
				podSpec.SecurityContext.SELinuxOptions.Type,
			}))
		}
	}

	var badContainers violations[string]
	var errFns []ErrFn
	visitContainersWithPath(podSpec, func(container *corev1.Container, pathFn PathFn) {
		if container.SecurityContext != nil && container.SecurityContext.SELinuxOptions != nil {
			if !validSELinuxOptions(container.SecurityContext.SELinuxOptions) {
				badContainers.Add(container.Name, opts)
				errFns = append(errFns, forbidden(pathFn.child("securityContext").child("seLinuxOptions").child("type"), []string{
					container.SecurityContext.SELinuxOptions.Type,
				}))
			}
		}
	})
	if !badContainers.Empty() {
		badSetters.Add(
			fmt.Sprintf(
				"%s %s",
				pluralize("container", "containers", badContainers.Len()),
				joinQuote(badContainers.Data()),
			),
			opts,
			errFns...,
		)
	}

	if !badSetters.Empty() {
		var badData []string
		if len(badTypes) > 0 {
			badData = append(badData, fmt.Sprintf(
				"%s %s",
				pluralize("type", "types", len(badTypes)),
				joinQuote(badTypes.List()),
			))
		}
		if setUser {
			badData = append(badData, "user may not be set")
		}
		if setRole {
			badData = append(badData, "role may not be set")
		}

		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "seLinuxOptions",
			ForbiddenDetail: fmt.Sprintf(
				`%s set forbidden securityContext.seLinuxOptions: %s`,
				strings.Join(badSetters.Data(), " and "),
				strings.Join(badData, "; "),
			),
			ErrList: badSetters.Errs(),
		}
	}
	return CheckResult{Allowed: true}
}
