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

// NbNetworkResourceParameters are the configurable fields of a NbNetworkResource.
type NbNetworkResourceParameters struct {
	// Address Network resource address (either a direct host like 1.1.1.1 or 1.1.1.1/32, or a subnet like 192.168.178.0/24, or domains like example.com and *.example.com)
	Address string `json:"address"`

	// Description Network resource description
	Description *string `json:"description,omitempty"`

	// Enabled Network resource status
	Enabled bool `json:"enabled"`

	// Groups Groups that the resource belongs to
	Groups []GroupMinimum `json:"groups"`

	// Name Network resource name
	Name string `json:"name"`

	// Type Network resource type based of the address
	Type string `json:"type"`

	NetworkName string `json:"network_name"`
}
type GroupMinimum struct {
	// Id Group ID
	Id string `json:"id"`

	// Issued How the group was issued (api, integration, jwt)
	Issued string `json:"issued,omitempty"`

	// Name Group Name identifier
	Name string `json:"name"`

	// PeersCount Count of peers associated to the group
	PeersCount int `json:"peers_count"`

	// ResourcesCount Count of resources associated to the group
	ResourcesCount int `json:"resources_count"`
}

// NbNetworkResourceObservation are the observable fields of a NbNetworkResource.
type NbNetworkResourceObservation struct {
	// Address Network resource address (either a direct host like 1.1.1.1 or 1.1.1.1/32, or a subnet like 192.168.178.0/24, or domains like example.com and *.example.com)
	Address string `json:"address"`

	// Description Network resource description
	Description *string `json:"description,omitempty"`

	// Enabled Network resource status
	Enabled bool `json:"enabled"`

	// Groups Groups that the resource belongs to
	Groups []GroupMinimum `json:"groups"`

	// Id Network Resource ID
	Id string `json:"id"`

	// Name Network resource name
	Name string `json:"name"`

	// Type Network resource type based of the address
	Type string `json:"type"`
}

// A NbNetworkResourceSpec defines the desired state of a NbNetworkResource.
type NbNetworkResourceSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbNetworkResourceParameters `json:"forProvider"`
}

// A NbNetworkResourceStatus represents the observed state of a NbNetworkResource.
type NbNetworkResourceStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbNetworkResourceObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbNetworkResource is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbNetworkResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbNetworkResourceSpec   `json:"spec"`
	Status NbNetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbNetworkResourceList contains a list of NbNetworkResource
type NbNetworkResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbNetworkResource `json:"items"`
}

// NbNetworkResource type metadata.
var (
	NbNetworkResourceKind             = reflect.TypeOf(NbNetworkResource{}).Name()
	NbNetworkResourceGroupKind        = schema.GroupKind{Group: Group, Kind: NbNetworkResourceKind}.String()
	NbNetworkResourceKindAPIVersion   = NbNetworkResourceKind + "." + SchemeGroupVersion.String()
	NbNetworkResourceGroupVersionKind = SchemeGroupVersion.WithKind(NbNetworkResourceKind)
)

func init() {
	SchemeBuilder.Register(&NbNetworkResource{}, &NbNetworkResourceList{})
}
