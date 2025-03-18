/*
Copyright 2022 The Crossplane Authors.

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

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// NbDnsSettingParameters are the configurable fields of a NbDnsSetting.
type NbDnsSettingParameters struct {
	DisabledManagementGroups []string `json:"disabled_management_groups"`
}

// NbDnsSettingObservation are the observable fields of a NbDnsSetting.
type NbDnsSettingObservation struct {
	DisabledManagementGroups []string `json:"disabled_management_groups"`
}

// A NbDnsSettingSpec defines the desired state of a NbDnsSetting.
type NbDnsSettingSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbDnsSettingParameters `json:"forProvider"`
}

// A NbDnsSettingStatus represents the observed state of a NbDnsSetting.
type NbDnsSettingStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbDnsSettingObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbDnsSetting is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbDnsSetting struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbDnsSettingSpec   `json:"spec"`
	Status NbDnsSettingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbDnsSettingList contains a list of NbDnsSetting
type NbDnsSettingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbDnsSetting `json:"items"`
}

// NbDnsSetting type metadata.
var (
	NbDnsSettingKind             = reflect.TypeOf(NbDnsSetting{}).Name()
	NbDnsSettingGroupKind        = schema.GroupKind{Group: Group, Kind: NbDnsSettingKind}.String()
	NbDnsSettingKindAPIVersion   = NbDnsSettingKind + "." + SchemeGroupVersion.String()
	NbDnsSettingGroupVersionKind = SchemeGroupVersion.WithKind(NbDnsSettingKind)
)

func init() {
	SchemeBuilder.Register(&NbDnsSetting{}, &NbDnsSettingList{})
}
