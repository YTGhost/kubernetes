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
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestSysctls(t *testing.T) {
	tests := []struct {
		name          string
		pod           *corev1.Pod
		opts          options
		allowed       bool
		expectReason  string
		expectDetail  string
		expectErrList field.ErrorList
	}{
		{
			name: "forbidden sysctls",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "a"}, {Name: "b"}},
				},
			}},
			opts: options{
				withFieldErrors: false,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `a, b`,
		},
		{
			name: "forbidden sysctls, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "a"}, {Name: "b"}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `a, b`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.sysctls[0].name", BadValue: []string{"a"}},
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.sysctls[1].name", BadValue: []string{"b"}},
			},
		},
		{
			name: "new supported sysctls not supported",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_local_reserved_ports", Value: "1024-4999"}},
				},
			}},
			opts: options{
				withFieldErrors: false,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `net.ipv4.ip_local_reserved_ports`,
		},
		{
			name: "new supported sysctls not supported, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_local_reserved_ports", Value: "1024-4999"}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `net.ipv4.ip_local_reserved_ports`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.sysctls[0].name", BadValue: []string{"net.ipv4.ip_local_reserved_ports"}},
			},
		},
	}

	cmpOpts := []cmp.Option{cmpopts.IgnoreFields(field.Error{}, "Detail"), cmpopts.SortSlices(func(a, b *field.Error) bool { return a.Error() < b.Error() })}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sysctls_1_0(&tc.pod.ObjectMeta, &tc.pod.Spec, tc.opts)
			if !tc.allowed {
				if result.Allowed {
					t.Fatal("expected disallowed")
				}
				if e, a := tc.expectReason, result.ForbiddenReason; e != a {
					t.Errorf("expected\n%s\ngot\n%s", e, a)
				}
				if e, a := tc.expectDetail, result.ForbiddenDetail; e != a {
					t.Errorf("expected\n%s\ngot\n%s", e, a)
				}
				if diff := cmp.Diff(tc.expectErrList, result.ErrList, cmpOpts...); diff != "" {
					t.Errorf("unexpected field errors (-want,+got):\n%s", diff)
				}
			} else {
				if !result.Allowed {
					t.Fatal("expected allowed")
				}
			}
		})
	}
}

func TestSysctls_1_27(t *testing.T) {
	tests := []struct {
		name          string
		pod           *corev1.Pod
		opts          options
		allowed       bool
		expectReason  string
		expectDetail  string
		expectErrList field.ErrorList
	}{
		{
			name: "forbidden sysctls",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "a"}, {Name: "b"}},
				},
			}},
			opts: options{
				withFieldErrors: false,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `a, b`,
		},
		{
			name: "forbidden sysctls, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "a"}, {Name: "b"}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			allowed:      false,
			expectReason: `forbidden sysctls`,
			expectDetail: `a, b`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.sysctls[0].name", BadValue: []string{"a"}},
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.sysctls[1].name", BadValue: []string{"b"}},
			},
		},
		{
			name: "new supported sysctls",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_local_reserved_ports", Value: "1024-4999"}},
				},
			}},
			opts: options{
				withFieldErrors: false,
			},
			allowed: true,
		},
		{
			name: "new supported sysctls, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_local_reserved_ports", Value: "1024-4999"}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			allowed: true,
		},
	}

	cmpOpts := []cmp.Option{cmpopts.IgnoreFields(field.Error{}, "Detail"), cmpopts.SortSlices(func(a, b *field.Error) bool { return a.Error() < b.Error() })}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sysctls_1_27(&tc.pod.ObjectMeta, &tc.pod.Spec, tc.opts)
			if !tc.allowed {
				if result.Allowed {
					t.Fatal("expected disallowed")
				}
				if e, a := tc.expectReason, result.ForbiddenReason; e != a {
					t.Errorf("expected\n%s\ngot\n%s", e, a)
				}
				if e, a := tc.expectDetail, result.ForbiddenDetail; e != a {
					t.Errorf("expected\n%s\ngot\n%s", e, a)
				}
				if diff := cmp.Diff(tc.expectErrList, result.ErrList, cmpOpts...); diff != "" {
					t.Errorf("unexpected field errors (-want,+got):\n%s", diff)
				}
			} else {
				if !result.Allowed {
					t.Fatal("expected allowed")
				}
			}
		})
	}
}
