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

// NbNetworkParameters are the configurable fields of a NbNetwork.
type NbNetworkParameters struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// NbNetworkObservation are the observable fields of a NbNetwork.
type NbNetworkObservation struct {
	// Description Network description
	Description *string `json:"description,omitempty"`
	// Id Network ID
	Id string `json:"id"`

	// Name Network name
	Name string `json:"name"`

	// Policies List of policy IDs associated with the network
	Policies []string `json:"policies"`

	// Resources List of network resource IDs associated with the network
	Resources []string `json:"resources"`

	// Routers List of router IDs associated with the network
	Routers []string `json:"routers"`

	// RoutingPeersCount Count of routing peers associated with the network
	RoutingPeersCount int `json:"routing_peers_count"`
}

// A NbNetworkSpec defines the desired state of a NbNetwork.
type NbNetworkSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbNetworkParameters `json:"forProvider"`
}

// A NbNetworkStatus represents the observed state of a NbNetwork.
type NbNetworkStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbNetworkObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbNetwork is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbNetworkSpec   `json:"spec"`
	Status NbNetworkStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbNetworkList contains a list of NbNetwork
type NbNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbNetwork `json:"items"`
}

// NbNetwork type metadata.
var (
	NbNetworkKind             = reflect.TypeOf(NbNetwork{}).Name()
	NbNetworkGroupKind        = schema.GroupKind{Group: Group, Kind: NbNetworkKind}.String()
	NbNetworkKindAPIVersion   = NbNetworkKind + "." + SchemeGroupVersion.String()
	NbNetworkGroupVersionKind = SchemeGroupVersion.WithKind(NbNetworkKind)
)

func init() {
	SchemeBuilder.Register(&NbNetwork{}, &NbNetworkList{})
}
