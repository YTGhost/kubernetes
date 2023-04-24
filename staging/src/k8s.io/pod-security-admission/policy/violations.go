package policy

import "k8s.io/apimachinery/pkg/util/validation/field"

type violations[T any] struct {
	data          []T
	badContainers []string
	errs          field.ErrorList
	errFn         func(*field.Path, T) *field.Error
}

func (v *violations[T]) Add(data T, badContainer string, pathFn func() *field.Path, opts options) {
	v.data = append(v.data, data)
	if badContainer != "" {
		v.badContainers = append(v.badContainers, badContainer)
	}
	opts.errListHandler(func() {
		if v.errFn != nil {
			var path *field.Path
			if pathFn != nil {
				path = pathFn()
			}
			if path != nil {
				if err := v.errFn(path, data); err != nil {
					v.errs = append(v.errs, err)
				}
			}
		}
	})
}

func (v *violations[T]) DataEmpty() bool {
	return len(v.data) == 0
}

func (v *violations[T]) BadContainersEmpty() bool {
	return len(v.badContainers) == 0
}

func (v *violations[T]) Data() []T {
	return v.data
}

func (v *violations[T]) BadContainers() []string {
	return v.badContainers
}

func (v *violations[T]) Errs() field.ErrorList {
	return v.errs
}
