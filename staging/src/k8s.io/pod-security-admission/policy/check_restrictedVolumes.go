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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/pod-security-admission/api"
)

/*
In addition to restricting HostPath volumes, the restricted profile
limits usage of inline pod volume sources to:
* configMap
* downwardAPI
* emptyDir
* projected
* secret
* csi
* persistentVolumeClaim
* ephemeral

**Restricted Fields:**

spec.volumes[*].hostPath
spec.volumes[*].gcePersistentDisk
spec.volumes[*].awsElasticBlockStore
spec.volumes[*].gitRepo
spec.volumes[*].nfs
spec.volumes[*].iscsi
spec.volumes[*].glusterfs
spec.volumes[*].rbd
spec.volumes[*].flexVolume
spec.volumes[*].cinder
spec.volumes[*].cephfs
spec.volumes[*].flocker
spec.volumes[*].fc
spec.volumes[*].azureFile
spec.volumes[*].vsphereVolume
spec.volumes[*].quobyte
spec.volumes[*].azureDisk
spec.volumes[*].portworxVolume
spec.volumes[*].photonPersistentDisk
spec.volumes[*].scaleIO
spec.volumes[*].storageos

**Allowed Values:** undefined/null
*/

func init() {
	addCheck(CheckRestrictedVolumes)
}

// CheckRestrictedVolumes returns a restricted level check
// that limits usage of specific volume types in 1.0+
func CheckRestrictedVolumes() Check {
	return Check{
		ID:    "restrictedVolumes",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			{
				MinimumVersion:   api.MajorMinorVersion(1, 0),
				CheckPod:         withOptions(restrictedVolumes_1_0),
				OverrideCheckIDs: []CheckID{checkHostPathVolumesID},
			},
		},
	}
}

func restrictedVolumes_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	var badVolumes []string
	var errList field.ErrorList
	badVolumeTypes := sets.NewString()

	for i, volume := range podSpec.Volumes {
		switch {
		case volume.ConfigMap != nil,
			volume.CSI != nil,
			volume.DownwardAPI != nil,
			volume.EmptyDir != nil,
			volume.Ephemeral != nil,
			volume.PersistentVolumeClaim != nil,
			volume.Projected != nil,
			volume.Secret != nil:
			continue

		default:
			badVolumes = append(badVolumes, volume.Name)
			volumesIndexPath := volumesPath.Index(i)

			switch {
			case volume.HostPath != nil:
				badVolumeTypes.Insert("hostPath")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("hostPath").String(),
					})
					errList = append(errList, err)
				})
			case volume.GCEPersistentDisk != nil:
				badVolumeTypes.Insert("gcePersistentDisk")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("gcePersistentDisk").String(),
					})
					errList = append(errList, err)
				})
			case volume.AWSElasticBlockStore != nil:
				badVolumeTypes.Insert("awsElasticBlockStore")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("awsElasticBlockStore").String(),
					})
					errList = append(errList, err)
				})
			case volume.GitRepo != nil:
				badVolumeTypes.Insert("gitRepo")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("gitRepo").String(),
					})
					errList = append(errList, err)
				})
			case volume.NFS != nil:
				badVolumeTypes.Insert("nfs")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("gitRepo").String(),
					})
					errList = append(errList, err)
				})
			case volume.ISCSI != nil:
				badVolumeTypes.Insert("iscsi")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("iscsi").String(),
					})
					errList = append(errList, err)
				})
			case volume.Glusterfs != nil:
				badVolumeTypes.Insert("glusterfs")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("glusterfs").String(),
					})
					errList = append(errList, err)
				})
			case volume.RBD != nil:
				badVolumeTypes.Insert("rbd")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("rbd").String(),
					})
					errList = append(errList, err)
				})
			case volume.FlexVolume != nil:
				badVolumeTypes.Insert("flexVolume")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("flexVolume").String(),
					})
					errList = append(errList, err)
				})
			case volume.Cinder != nil:
				badVolumeTypes.Insert("cinder")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("cinder").String(),
					})
					errList = append(errList, err)
				})
			case volume.CephFS != nil:
				badVolumeTypes.Insert("cephfs")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("cephfs").String(),
					})
					errList = append(errList, err)
				})
			case volume.Flocker != nil:
				badVolumeTypes.Insert("flocker")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("flocker").String(),
					})
					errList = append(errList, err)
				})
			case volume.FC != nil:
				badVolumeTypes.Insert("fc")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("fc").String(),
					})
					errList = append(errList, err)
				})
			case volume.AzureFile != nil:
				badVolumeTypes.Insert("azureFile")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("azureFile").String(),
					})
					errList = append(errList, err)
				})
			case volume.VsphereVolume != nil:
				badVolumeTypes.Insert("vsphereVolume")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("vsphereVolume").String(),
					})
					errList = append(errList, err)
				})
			case volume.Quobyte != nil:
				badVolumeTypes.Insert("quobyte")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("quobyte").String(),
					})
					errList = append(errList, err)
				})
			case volume.AzureDisk != nil:
				badVolumeTypes.Insert("azureDisk")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("azureDisk").String(),
					})
					errList = append(errList, err)
				})
			case volume.PhotonPersistentDisk != nil:
				badVolumeTypes.Insert("photonPersistentDisk")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("photonPersistentDisk").String(),
					})
					errList = append(errList, err)
				})
			case volume.PortworxVolume != nil:
				badVolumeTypes.Insert("portworxVolume")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("portworxVolume").String(),
					})
					errList = append(errList, err)
				})
			case volume.ScaleIO != nil:
				badVolumeTypes.Insert("scaleIO")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("scaleIO").String(),
					})
					errList = append(errList, err)
				})
			case volume.StorageOS != nil:
				badVolumeTypes.Insert("storageos")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("storageos").String(),
					})
					errList = append(errList, err)
				})
			default:
				badVolumeTypes.Insert("unknown")
				opts.errListHandler(func() {
					err := withBadValue(field.Forbidden(volumesIndexPath, ""), []string{
						volumesIndexPath.Child("unknown").String(),
					})
					errList = append(errList, err)
				})
			}
		}
	}

	if len(badVolumes) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "restricted volume types",
			ForbiddenDetail: fmt.Sprintf(
				"%s %s %s %s %s",
				pluralize("volume", "volumes", len(badVolumes)),
				joinQuote(badVolumes),
				pluralize("uses", "use", len(badVolumes)),
				pluralize("restricted volume type", "restricted volume types", len(badVolumeTypes)),
				joinQuote(badVolumeTypes.List()),
			),
			ErrList: errList,
		}
	}

	return CheckResult{Allowed: true}
}
