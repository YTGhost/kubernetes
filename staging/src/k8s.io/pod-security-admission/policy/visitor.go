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
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	specPath                   = field.NewPath("spec")
	initContainersFldPath      = specPath.Child("initContainers")
	containersFldPath          = specPath.Child("containers")
	ephemeralContainersFldPath = specPath.Child("ephemeralContainers")
)

// ContainerVisitorWithPath is called with each container, the field.Path and the ErrListHandler to that container.
type ContainerVisitorWithPath func(container *corev1.Container, path *field.Path, errListHandler ErrListHandler)

// visitContainersWithPath invokes the visitor function with a pointer to the spec
// of every container in the given pod spec, the field.Path and the ErrListHandler to that container.
func visitContainersWithPath(podSpec *corev1.PodSpec, visitor ContainerVisitorWithPath, errListHandler ErrListHandler) {
	for i := range podSpec.InitContainers {
		visitor(&podSpec.InitContainers[i], initContainersFldPath.Index(i), errListHandler)
	}
	for i := range podSpec.Containers {
		visitor(&podSpec.Containers[i], containersFldPath.Index(i), errListHandler)
	}
	for i := range podSpec.EphemeralContainers {
		visitor((*corev1.Container)(&podSpec.EphemeralContainers[i].EphemeralContainerCommon), ephemeralContainersFldPath.Index(i), errListHandler)
	}
}
