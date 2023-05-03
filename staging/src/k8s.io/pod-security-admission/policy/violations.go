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

import (
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type ErrFn func() *field.Error

type violations[T any] struct {
	data            []T
	errs            field.ErrorList
	withFieldErrors bool
}

func (v *violations[T]) Add(data T, errFns ...ErrFn) {
	v.data = append(v.data, data)
	if v.withFieldErrors {
		for _, errFn := range errFns {
			if errFn != nil {
				if err := errFn(); err != nil {
					v.errs = append(v.errs, err)
				}
			}
		}
	}
}

func (v *violations[T]) Empty() bool {
	return len(v.data) == 0
}

func (v *violations[T]) Data() []T {
	return v.data
}

func (v *violations[T]) Len() int {
	return len(v.data)
}

func (v *violations[T]) Errs() field.ErrorList {
	return v.errs
}

func (f ErrFn) withBadValue(badValue interface{}) ErrFn {
	if f == nil {
		return nil
	}
	return func() *field.Error {
		err := f()
		if err == nil {
			return nil
		}
		err.BadValue = badValue
		return err
	}
}

func forbidden(pathFn func() *field.Path) ErrFn {
	if pathFn == nil {
		return nil
	}
	return func() *field.Error {
		path := pathFn()
		if path == nil {
			return nil
		}
		return field.Forbidden(path, "")
	}
}

func required(pathFn func() *field.Path) ErrFn {
	if pathFn == nil {
		return nil
	}
	return func() *field.Error {
		path := pathFn()
		if path == nil {
			return nil
		}
		return field.Required(path, "")
	}
}
