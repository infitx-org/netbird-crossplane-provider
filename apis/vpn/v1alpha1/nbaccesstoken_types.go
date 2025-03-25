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

// NbAccessTokenParameters are the configurable fields of a NbAccessToken.
type NbAccessTokenParameters struct {
	ExpiresIn int `json:"expires_in"`

	// Name Name of the token
	Name     string `json:"name"`
	UserName string `json:"user_name"`
}

// NbAccessTokenObservation are the observable fields of a NbAccessToken.
type NbAccessTokenObservation struct {
	// CreatedAt Date the token was created
	CreatedAt string `json:"created_at"`

	// CreatedBy User ID of the user who created the token
	CreatedBy string `json:"created_by"`

	// ExpirationDate Date the token expires
	ExpirationDate string `json:"expiration_date"`

	// Id ID of a token
	Id string `json:"id"`

	// LastUsed Date the token was last used
	LastUsed *string `json:"last_used,omitempty"`

	// Name Name of the token
	Name string `json:"name"`
}

// A NbAccessTokenSpec defines the desired state of a NbAccessToken.
type NbAccessTokenSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbAccessTokenParameters `json:"forProvider"`
}

// A NbAccessTokenStatus represents the observed state of a NbAccessToken.
type NbAccessTokenStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbAccessTokenObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbAccessToken is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbAccessToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbAccessTokenSpec   `json:"spec"`
	Status NbAccessTokenStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbAccessTokenList contains a list of NbAccessToken
type NbAccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbAccessToken `json:"items"`
}

// NbAccessToken type metadata.
var (
	NbAccessTokenKind             = reflect.TypeOf(NbAccessToken{}).Name()
	NbAccessTokenGroupKind        = schema.GroupKind{Group: Group, Kind: NbAccessTokenKind}.String()
	NbAccessTokenKindAPIVersion   = NbAccessTokenKind + "." + SchemeGroupVersion.String()
	NbAccessTokenGroupVersionKind = SchemeGroupVersion.WithKind(NbAccessTokenKind)
)

func init() {
	SchemeBuilder.Register(&NbAccessToken{}, &NbAccessTokenList{})
}
