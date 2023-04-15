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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type options struct {
	withErrList bool
}

type Option func(*options)

func withOptions(f func(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult) CheckPodFn {
	return func(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts ...Option) CheckResult {
		var opt options
		for _, o := range opts {
			if o != nil {
				o(&opt)
			}
		}
		return f(podMetadata, podSpec, opt)
	}
}

type ErrListHandler func(errList *field.ErrorList, error *field.Error)

func (o options) errListHandler(f func()) {
	if o.withErrList {
		if f != nil {
			f()
		}
	}
}

func WithErrList() Option {
	return func(opt *options) {
		opt.withErrList = true
	}
}
