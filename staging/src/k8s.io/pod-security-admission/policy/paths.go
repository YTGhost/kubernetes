/*
Copyright 2023 The Kubernetes Authors.

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

import "k8s.io/apimachinery/pkg/util/validation/field"

var (
	annotationsPath            = withPath(field.NewPath("metadata", "annotations"))
	specPath                   = withPath(field.NewPath("spec"))
	initContainersFldPath      = specPath.child("initContainers")
	containersFldPath          = specPath.child("containers")
	ephemeralContainersFldPath = specPath.child("ephemeralContainers")
	securityContextPath        = specPath.child("securityContext")
	hostNetworkPath            = specPath.child("hostNetwork")
	hostPIDPath                = specPath.child("hostPID")
	hostIPCPath                = specPath.child("hostIPC")
	volumesPath                = specPath.child("volumes")
	runAsNonRootPath           = securityContextPath.child("runAsNonRoot")
	runAsUserPath              = securityContextPath.child("runAsUser")
	seccompProfileTypePath     = securityContextPath.child("seccompProfile").child("type")
	seLinuxOptionsTypePath     = securityContextPath.child("seLinuxOptions").child("type")
	seLinuxOptionsUserPath     = securityContextPath.child("seLinuxOptions").child("user")
	seLinuxOptionsRolePath     = securityContextPath.child("seLinuxOptions").child("role")
	sysctlsPath                = securityContextPath.child("sysctls")
	hostProcessPath            = securityContextPath.child("windowsOptions").child("hostProcess")
)

type PathFn func() *field.Path

func withPath(path *field.Path) PathFn {
	if path == nil {
		return nil
	}
	return func() *field.Path {
		return path
	}
}

func (parent PathFn) index(i int) PathFn {
	if parent == nil {
		return nil
	}
	return func() *field.Path {
		parent := parent()
		if parent == nil {
			return nil
		}
		return parent.Index(i)
	}
}

func (parent PathFn) child(name string) PathFn {
	if parent == nil {
		return nil
	}
	return func() *field.Path {
		p := parent()
		if p == nil {
			return nil
		}
		return p.Child(name)
	}
}

func (parent PathFn) key(key string) PathFn {
	if parent == nil {
		return nil
	}
	return func() *field.Path {
		p := parent()
		if p == nil {
			return nil
		}
		return p.Key(key)
	}
}
