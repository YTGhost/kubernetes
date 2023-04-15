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
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/pod-security-admission/api"
)

/*
HostPort ports must be forbidden.

**Restricted Fields:**

spec.containers[*].ports[*].hostPort
spec.initContainers[*].ports[*].hostPort

**Allowed Values:** undefined/0
*/

func init() {
	addCheck(CheckHostPorts)
}

// CheckHostPorts returns a baseline level check
// that forbids any host ports in 1.0+
func CheckHostPorts() Check {
	return Check{
		ID:    "hostPorts",
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       withOptions(hostPorts_1_0),
			},
		},
	}
}

func hostPorts_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	var badContainers []string
	var errList field.ErrorList
	forbiddenHostPorts := sets.NewString()
	visitContainersWithPath(podSpec, func(container *corev1.Container, path *field.Path) {
		valid := true
		for i, c := range container.Ports {
			if c.HostPort != 0 {
				valid = false
				forbiddenHostPorts.Insert(strconv.Itoa(int(c.HostPort)))
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(path.Child("ports").Index(i).Child("hostPort"), ""), []string{
						strconv.Itoa(int(c.HostPort)),
					})
					errList = append(errList, err)
				})
			}
		}
		if !valid {
			badContainers = append(badContainers, container.Name)
		}
	})

	if len(badContainers) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "hostPort",
			ForbiddenDetail: fmt.Sprintf(
				"%s %s %s %s %s",
				pluralize("container", "containers", len(badContainers)),
				joinQuote(badContainers),
				pluralize("uses", "use", len(badContainers)),
				pluralize("hostPort", "hostPorts", len(forbiddenHostPorts)),
				strings.Join(forbiddenHostPorts.List(), ", "),
			),
			ErrList: errList,
		}
	}
	return CheckResult{Allowed: true}
}
