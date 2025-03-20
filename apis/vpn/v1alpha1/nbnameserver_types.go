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

// NbNameServerParameters are the configurable fields of a NbNameServer.
type NbNameServerParameters struct {
	// Description Description of the nameserver group
	Description string `json:"description"`

	// Domains Match domain list. It should be empty only if primary is true.
	Domains []string `json:"domains"`

	// Enabled Nameserver group status
	Enabled bool `json:"enabled"`

	// Groups Distribution group IDs that defines group of peers that will use this nameserver group
	Groups []string `json:"groups"`

	// Name Name of nameserver group name
	Name string `json:"name"`

	// Nameservers Nameserver list
	Nameservers []Nameserver `json:"nameservers"`

	// Primary Defines if a nameserver group is primary that resolves all domains. It should be true only if domains list is empty.
	Primary bool `json:"primary"`

	// SearchDomainsEnabled Search domain status for match domains. It should be true only if domains list is not empty.
	SearchDomainsEnabled bool `json:"search_domains_enabled"`
}

type Nameserver struct {
	// Ip Nameserver IP
	Ip string `json:"ip"`

	// NsType Nameserver Type
	NsType NameserverNsType `json:"ns_type"`

	// Port Nameserver Port
	Port int `json:"port"`
}

// NameserverNsType Nameserver Type
type NameserverNsType string

// NbNameServerObservation are the observable fields of a NbNameServer.
type NbNameServerObservation struct {
	Id string `json:"id"`
	// Description Description of the nameserver group
	Description string `json:"description"`

	// Domains Match domain list. It should be empty only if primary is true.
	Domains []string `json:"domains"`

	// Enabled Nameserver group status
	Enabled bool `json:"enabled"`

	// Groups Distribution group IDs that defines group of peers that will use this nameserver group
	Groups []string `json:"groups"`

	// Name Name of nameserver group name
	Name string `json:"name"`

	// Nameservers Nameserver list
	Nameservers []Nameserver `json:"nameservers"`

	// Primary Defines if a nameserver group is primary that resolves all domains. It should be true only if domains list is empty.
	Primary bool `json:"primary"`

	// SearchDomainsEnabled Search domain status for match domains. It should be true only if domains list is not empty.
	SearchDomainsEnabled bool `json:"search_domains_enabled"`
}

// A NbNameServerSpec defines the desired state of a NbNameServer.
type NbNameServerSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbNameServerParameters `json:"forProvider"`
}

// A NbNameServerStatus represents the observed state of a NbNameServer.
type NbNameServerStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbNameServerObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbNameServer is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbNameServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbNameServerSpec   `json:"spec"`
	Status NbNameServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbNameServerList contains a list of NbNameServer
type NbNameServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbNameServer `json:"items"`
}

// NbNameServer type metadata.
var (
	NbNameServerKind             = reflect.TypeOf(NbNameServer{}).Name()
	NbNameServerGroupKind        = schema.GroupKind{Group: Group, Kind: NbNameServerKind}.String()
	NbNameServerKindAPIVersion   = NbNameServerKind + "." + SchemeGroupVersion.String()
	NbNameServerGroupVersionKind = SchemeGroupVersion.WithKind(NbNameServerKind)
)

func init() {
	SchemeBuilder.Register(&NbNameServer{}, &NbNameServerList{})
}
