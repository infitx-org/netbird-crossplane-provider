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

// NbNetworkRouterParameters are the configurable fields of a NbNetworkRouter.
type NbNetworkRouterParameters struct {
	// Enabled Network router status
	Enabled bool `json:"enabled"`

	// Masquerade Indicate if peer should masquerade traffic to this route's prefix
	Masquerade bool `json:"masquerade"`

	// Metric Route metric number. Lowest number has higher priority
	Metric int `json:"metric"`

	// Peer Peer Identifier associated with route. This property can not be set together with `peer_groups`
	Peer *string `json:"peer,omitempty"`

	// PeerGroups Peers Group Identifier associated with route. This property can not be set together with `peer`
	PeerGroups *[]string `json:"peer_groups,omitempty"`
}

// NbNetworkRouterObservation are the observable fields of a NbNetworkRouter.
type NbNetworkRouterObservation struct {
	// Enabled Network router status
	Enabled bool `json:"enabled"`

	// Id Network Router Id
	Id string `json:"id"`

	// Masquerade Indicate if peer should masquerade traffic to this route's prefix
	Masquerade bool `json:"masquerade"`

	// Metric Route metric number. Lowest number has higher priority
	Metric int `json:"metric"`

	// Peer Peer Identifier associated with route. This property can not be set together with `peer_groups`
	Peer *string `json:"peer,omitempty"`

	// PeerGroups Peers Group Identifier associated with route. This property can not be set together with `peer`
	PeerGroups *[]string `json:"peer_groups,omitempty"`
}

// A NbNetworkRouterSpec defines the desired state of a NbNetworkRouter.
type NbNetworkRouterSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbNetworkRouterParameters `json:"forProvider"`
}

// A NbNetworkRouterStatus represents the observed state of a NbNetworkRouter.
type NbNetworkRouterStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbNetworkRouterObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbNetworkRouter is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbNetworkRouter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbNetworkRouterSpec   `json:"spec"`
	Status NbNetworkRouterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbNetworkRouterList contains a list of NbNetworkRouter
type NbNetworkRouterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbNetworkRouter `json:"items"`
}

// NbNetworkRouter type metadata.
var (
	NbNetworkRouterKind             = reflect.TypeOf(NbNetworkRouter{}).Name()
	NbNetworkRouterGroupKind        = schema.GroupKind{Group: Group, Kind: NbNetworkRouterKind}.String()
	NbNetworkRouterKindAPIVersion   = NbNetworkRouterKind + "." + SchemeGroupVersion.String()
	NbNetworkRouterGroupVersionKind = SchemeGroupVersion.WithKind(NbNetworkRouterKind)
)

func init() {
	SchemeBuilder.Register(&NbNetworkRouter{}, &NbNetworkRouterList{})
}
