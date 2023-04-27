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

const (
	capabilityAll            = "ALL"
	capabilityNetBindService = "NET_BIND_SERVICE"
)

/*
Containers must drop ALL, and may only add NET_BIND_SERVICE.

**Restricted Fields:**
spec.containers[*].securityContext.capabilities.drop
spec.initContainers[*].securityContext.capabilities.drop

**Allowed Values:**
Must include "ALL"

**Restricted Fields:**
spec.containers[*].securityContext.capabilities.add
spec.initContainers[*].securityContext.capabilities.add

**Allowed Values:**
undefined / empty
"NET_BIND_SERVICE"
*/

func init() {
	addCheck(CheckCapabilitiesRestricted)
}

// CheckCapabilitiesRestricted returns a restricted level check
// that ensures ALL capabilities are dropped in 1.22+
func CheckCapabilitiesRestricted() Check {
	return Check{
		ID:    "capabilities_restricted",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			{
				MinimumVersion:   api.MajorMinorVersion(1, 22),
				CheckPod:         withOptions(capabilitiesRestricted_1_22),
				OverrideCheckIDs: []CheckID{checkCapabilitiesBaselineID},
			},
			// Starting 1.25, windows pods would be exempted from this check using pod.spec.os field when set to windows.
			{
				MinimumVersion:   api.MajorMinorVersion(1, 25),
				CheckPod:         withOptions(capabilitiesRestricted_1_25),
				OverrideCheckIDs: []CheckID{checkCapabilitiesBaselineID},
			},
		},
	}
}

func capabilitiesRestricted_1_22(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	var forbiddenCapabilities = sets.NewString()
	var containersMissingDropAll violations[string]
	var containersAddingForbidden violations[string]

	visitContainersWithPath(podSpec, func(container *corev1.Container, pathFn PathFn) {
		if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
			containersMissingDropAll.Add(container.Name, opts, required(pathFn.child("securityContext").child("capabilities").child("drop")))
			return
		}

		droppedAll := false
		for _, c := range container.SecurityContext.Capabilities.Drop {
			if c == capabilityAll {
				droppedAll = true
				break
			}
		}
		if !droppedAll {
			strSlice := make([]string, len(container.SecurityContext.Capabilities.Drop))
			for i, v := range container.SecurityContext.Capabilities.Drop {
				strSlice[i] = string(v)
			}
			containersMissingDropAll.Add(container.Name, opts, forbidden(pathFn.child("securityContext").child("capabilities").child("drop"), strSlice))
		}

		addedForbidden := false
		for _, c := range container.SecurityContext.Capabilities.Add {
			if c != capabilityNetBindService {
				addedForbidden = true
				forbiddenCapabilities.Insert(string(c))
			}
		}
		if addedForbidden {
			containersAddingForbidden.Add(container.Name, opts, forbidden(pathFn.child("securityContext").child("capabilities").child("add"), forbiddenCapabilities.List()))
		}
	})

	var forbiddenDetails []string
	errList := append(containersMissingDropAll.Errs(), containersAddingForbidden.Errs()...)
	if !containersMissingDropAll.Empty() {
		forbiddenDetails = append(forbiddenDetails, fmt.Sprintf(
			`%s %s must set securityContext.capabilities.drop=["ALL"]`,
			pluralize("container", "containers", containersMissingDropAll.Len()),
			joinQuote(containersMissingDropAll.Data())))
	}
	if !containersAddingForbidden.Empty() {
		forbiddenDetails = append(forbiddenDetails, fmt.Sprintf(
			`%s %s must not include %s in securityContext.capabilities.add`,
			pluralize("container", "containers", containersAddingForbidden.Len()),
			joinQuote(containersAddingForbidden.Data()),
			joinQuote(forbiddenCapabilities.List())))
	}
	if len(forbiddenDetails) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "unrestricted capabilities",
			ForbiddenDetail: strings.Join(forbiddenDetails, "; "),
			ErrList:         errList,
		}
	}
	return CheckResult{Allowed: true}
}

func capabilitiesRestricted_1_25(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	// Pod API validation would have failed if podOS == Windows and if capabilities have been set.
	// We can admit the Windows pod even if capabilities has not been set.
	if podSpec.OS != nil && podSpec.OS.Name == corev1.Windows {
		return CheckResult{Allowed: true}
	}
	return capabilitiesRestricted_1_22(podMetadata, podSpec, opts)
}
