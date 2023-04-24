package policy

import "k8s.io/apimachinery/pkg/util/validation/field"

var (
	annotationsPath        = field.NewPath("metadata", "annotations")
	specPath               = field.NewPath("spec")
	securityContextPath    = specPath.Child("securityContext")
	volumesPath            = specPath.Child("volumes")
	runAsNonRootPath       = securityContextPath.Child("runAsNonRoot")
	runAsUserPath          = securityContextPath.Child("runAsUser")
	seccompProfileTypePath = securityContextPath.Child("seccompProfile").Child("type")
	seLinuxOptionsTypePath = securityContextPath.Child("seLinuxOptions").Child("type")
	sysctlsPath            = securityContextPath.Child("sysctls")
	hostProcessPath        = securityContextPath.Child("windowsOptions").Child("hostProcess")
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
