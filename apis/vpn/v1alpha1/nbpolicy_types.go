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

// NbPolicyParameters are the configurable fields of a NbPolicy.
type NbPolicyParameters struct {
	Description *string `json:"description,omitempty"`

	// Enabled Policy status
	Enabled bool `json:"enabled"`

	// Name Policy name identifier
	Name string `json:"name"`

	// Rules Policy rule object for policy UI editor
	Rules []PolicyRule `json:"rules"`

	// SourcePostureChecks Posture checks ID's applied to policy source groups
	SourcePostureChecks *[]string `json:"source_posture_checks,omitempty"`
}

// NbPolicyObservation are the observable fields of a NbPolicy.
type NbPolicyObservation struct {
	Description *string `json:"description,omitempty"`

	// Enabled Policy status
	Enabled bool `json:"enabled"`

	// Id Policy ID
	Id *string `json:"id,omitempty"`

	// Name Policy name identifier
	Name string `json:"name"`

	// Rules Policy rule object for policy UI editor
	Rules []PolicyRule `json:"rules"`

	// SourcePostureChecks Posture checks ID's applied to policy source groups
	SourcePostureChecks *[]string `json:"source_posture_checks,omitempty"`
}
type PolicyRule struct {
	// Action Policy rule accept or drops packets
	Action string `json:"action"`

	// Bidirectional Define if the rule is applicable in both directions, sources, and destinations.
	Bidirectional bool `json:"bidirectional"`

	// Description Policy rule friendly description
	Description             *string `json:"description,omitempty"`
	DestinationResourceName *string `json:"destinationResource,omitempty"`

	// Destinations Policy rule destination group IDs
	Destinations *[]GroupMinimum `json:"destinations,omitempty"`

	// Enabled Policy rule status
	Enabled bool `json:"enabled"`

	// Id Policy rule ID
	Id *string `json:"id,omitempty"`

	// Name Policy rule name identifier
	Name string `json:"name"`

	// PortRanges Policy rule affected ports ranges list
	PortRanges *[]RulePortRange `json:"port_ranges,omitempty"`

	// Ports Policy rule affected ports
	Ports *[]string `json:"ports,omitempty"`

	// Protocol Policy rule type of the traffic
	Protocol           string  `json:"protocol"`
	SourceResourceName *string `json:"source_resource_name,omitempty"`

	// Sources Policy rule source group IDs
	Sources *[]GroupMinimum `json:"sources,omitempty"`
}
type RulePortRange struct {
	// End The ending port of the range
	End int `json:"end"`

	// Start The starting port of the range
	Start int `json:"start"`
}

// A NbPolicySpec defines the desired state of a NbPolicy.
type NbPolicySpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbPolicyParameters `json:"forProvider"`
}

// A NbPolicyStatus represents the observed state of a NbPolicy.
type NbPolicyStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbPolicyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbPolicy is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbPolicySpec   `json:"spec"`
	Status NbPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbPolicyList contains a list of NbPolicy
type NbPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbPolicy `json:"items"`
}

// NbPolicy type metadata.
var (
	NbPolicyKind             = reflect.TypeOf(NbPolicy{}).Name()
	NbPolicyGroupKind        = schema.GroupKind{Group: Group, Kind: NbPolicyKind}.String()
	NbPolicyKindAPIVersion   = NbPolicyKind + "." + SchemeGroupVersion.String()
	NbPolicyGroupVersionKind = SchemeGroupVersion.WithKind(NbPolicyKind)
)

func init() {
	SchemeBuilder.Register(&NbPolicy{}, &NbPolicyList{})
}
