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

// NbSetupKeyParameters are the configurable fields of a NbSetupKey.
type NbSetupKeyParameters struct {
	// AllowExtraDnsLabels Allow extra DNS labels to be added to the peer
	AllowExtraDnsLabels bool `json:"allow_extra_dns_labels"`

	// AutoGroups List of group IDs to auto-assign to peers registered with this key
	AutoGroups []string `json:"auto_groups"`

	// Ephemeral Indicate that the peer will be ephemeral or not
	Ephemeral bool `json:"ephemeral"`

	// Expires Setup Key expiration date
	ExpiresIn int `json:"expires_in"`

	// Name Setup key name identifier
	Name string `json:"name"`

	// Type Setup key type, one-off for single time usage and reusable
	Type string `json:"type"`

	// UsageLimit A number of times this key can be used. The value of 0 indicates the unlimited usage.
	UsageLimit int `json:"usage_limit"`

	Revoked bool `json:"revoked"`
}

// NbSetupKeyObservation are the observable fields of a NbSetupKey.
type NbSetupKeyObservation struct {
	// AllowExtraDnsLabels Allow extra DNS labels to be added to the peer
	AllowExtraDnsLabels bool `json:"allow_extra_dns_labels"`

	// AutoGroups List of group IDs to auto-assign to peers registered with this key
	AutoGroups []string `json:"auto_groups,omitempty"`

	// Ephemeral Indicate that the peer will be ephemeral or not
	Ephemeral bool `json:"ephemeral"`

	Expires string `json:"expires"`

	// Id Setup Key ID
	Id string `json:"id"`

	// LastUsed Setup key last usage date
	LastUsed string `json:"last_used"`

	// Name Setup key name identifier
	Name string `json:"name"`

	// Revoked Setup key revocation status
	Revoked bool `json:"revoked"`

	// State Setup key status, "valid", "overused","expired" or "revoked"
	State string `json:"state"`

	// Type Setup key type, one-off for single time usage and reusable
	Type string `json:"type"`

	// UpdatedAt Setup key last update date
	UpdatedAt string `json:"updated_at"`

	// UsageLimit A number of times this key can be used. The value of 0 indicates the unlimited usage.
	UsageLimit int `json:"usage_limit"`

	// UsedTimes Usage count of setup key
	UsedTimes int `json:"used_times"`

	// Valid Setup key validity status
	Valid bool `json:"valid"`
}

// A NbSetupKeySpec defines the desired state of a NbSetupKey.
type NbSetupKeySpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbSetupKeyParameters `json:"forProvider"`
}

// A NbSetupKeyStatus represents the observed state of a NbSetupKey.
type NbSetupKeyStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbSetupKeyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbSetupKey is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbSetupKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbSetupKeySpec   `json:"spec"`
	Status NbSetupKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbSetupKeyList contains a list of NbSetupKey
type NbSetupKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbSetupKey `json:"items"`
}

// NbSetupKey type metadata.
var (
	NbSetupKeyKind             = reflect.TypeOf(NbSetupKey{}).Name()
	NbSetupKeyGroupKind        = schema.GroupKind{Group: Group, Kind: NbSetupKeyKind}.String()
	NbSetupKeyKindAPIVersion   = NbSetupKeyKind + "." + SchemeGroupVersion.String()
	NbSetupKeyGroupVersionKind = SchemeGroupVersion.WithKind(NbSetupKeyKind)
)

func init() {
	SchemeBuilder.Register(&NbSetupKey{}, &NbSetupKeyList{})
}
