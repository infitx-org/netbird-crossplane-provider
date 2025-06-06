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

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NbUserParameters are the configurable fields of a NbUser.
type NbUserParameters struct {
	Email         string    `json:"email,omitempty"`
	Name          string    `json:"name,omitempty"`
	Role          string    `json:"role,omitempty"`
	IsServiceUser *bool     `json:"is_service_user,omitempty"`
	AutoGroups    *[]string `json:"auto_groups,omitempty"`
}

// NbUserObservation are the observable fields of a NbUser.
type NbUserObservation struct {
	// AutoGroups Group IDs to auto-assign to peers registered by this user
	AutoGroups *[]string `json:"auto_groups,omitempty"`

	// Email User's email address
	Email string `json:"email"`

	// Id User ID
	Id string `json:"id"`

	// IsBlocked Is true if this user is blocked. Blocked users can't use the system
	IsBlocked bool `json:"is_blocked"`

	// IsCurrent Is true if authenticated user is the same as this user
	IsCurrent *bool `json:"is_current,omitempty"`

	// IsServiceUser Is true if this user is a service user
	IsServiceUser *bool `json:"is_service_user,omitempty"`

	// Issued How user was issued by API or Integration
	Issued *string `json:"issued,omitempty"`

	// Name User's name from idp provider
	Name string `json:"name"`

	// Role User's NetBird account role
	Role string `json:"role"`

	// Status User's status
	Status UserStatus `json:"status"`
}
type UserStatus string
type UserPermissionsDashboardView string
type UserPermissions struct {
	// DashboardView User's permission to view the dashboard
	DashboardView *UserPermissionsDashboardView `json:"dashboard_view,omitempty"`
}

// A NbUserSpec defines the desired state of a NbUser.
type NbUserSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       NbUserParameters `json:"forProvider"`
}

// A NbUserStatus represents the observed state of a NbUser.
type NbUserStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          NbUserObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A NbUser is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,netbird}
type NbUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NbUserSpec   `json:"spec"`
	Status NbUserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NbUserList contains a list of NbUser
type NbUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NbUser `json:"items"`
}

// NbUser type metadata.
var (
	NbUserKind             = reflect.TypeOf(NbUser{}).Name()
	NbUserGroupKind        = schema.GroupKind{Group: Group, Kind: NbUserKind}.String()
	NbUserKindAPIVersion   = NbUserKind + "." + SchemeGroupVersion.String()
	NbUserGroupVersionKind = SchemeGroupVersion.WithKind(NbUserKind)
)

func init() {
	SchemeBuilder.Register(&NbUser{}, &NbUserList{})
}
