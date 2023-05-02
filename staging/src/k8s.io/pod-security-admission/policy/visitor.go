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
	corev1 "k8s.io/api/core/v1"
)

// ContainerVisitor is called with each container and the pathFn to that container.
type ContainerVisitor func(container *corev1.Container, pathFn PathFn)

// visitContainers invokes the visitor function with a pointer to the spec
// of every container in the given pod spec.
func visitContainers(podSpec *corev1.PodSpec, opts options, visitor ContainerVisitor) {
	for i := range podSpec.InitContainers {
		if opts.withFieldErrors {
			visitor(&podSpec.InitContainers[i], initContainersFldPath.index(i))
		} else {
			visitor(&podSpec.InitContainers[i], nil)
		}
	}
	for i := range podSpec.Containers {
		if opts.withFieldErrors {
			visitor(&podSpec.Containers[i], containersFldPath.index(i))
		} else {
			visitor(&podSpec.Containers[i], nil)
		}
	}
	for i := range podSpec.EphemeralContainers {
		if opts.withFieldErrors {
			visitor((*corev1.Container)(&podSpec.EphemeralContainers[i].EphemeralContainerCommon), ephemeralContainersFldPath.index(i))
		} else {
			visitor((*corev1.Container)(&podSpec.EphemeralContainers[i].EphemeralContainerCommon), nil)
		}
	}
}
