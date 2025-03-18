//go:build !ignore_autogenerated

/*
Copyright 2020 The Crossplane Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"github.com/netbirdio/netbird/management/server/http/api"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccountExtraSettings) DeepCopyInto(out *AccountExtraSettings) {
	*out = *in
	if in.PeerApprovalEnabled != nil {
		in, out := &in.PeerApprovalEnabled, &out.PeerApprovalEnabled
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccountExtraSettings.
func (in *AccountExtraSettings) DeepCopy() *AccountExtraSettings {
	if in == nil {
		return nil
	}
	out := new(AccountExtraSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccountSettings) DeepCopyInto(out *AccountSettings) {
	*out = *in
	if in.Extra != nil {
		in, out := &in.Extra, &out.Extra
		*out = new(AccountExtraSettings)
		(*in).DeepCopyInto(*out)
	}
	if in.GroupsPropagationEnabled != nil {
		in, out := &in.GroupsPropagationEnabled, &out.GroupsPropagationEnabled
		*out = new(bool)
		**out = **in
	}
	if in.JwtAllowGroups != nil {
		in, out := &in.JwtAllowGroups, &out.JwtAllowGroups
		*out = new([]string)
		if **in != nil {
			in, out := *in, *out
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
	}
	if in.JwtGroupsClaimName != nil {
		in, out := &in.JwtGroupsClaimName, &out.JwtGroupsClaimName
		*out = new(string)
		**out = **in
	}
	if in.JwtGroupsEnabled != nil {
		in, out := &in.JwtGroupsEnabled, &out.JwtGroupsEnabled
		*out = new(bool)
		**out = **in
	}
	if in.RoutingPeerDnsResolutionEnabled != nil {
		in, out := &in.RoutingPeerDnsResolutionEnabled, &out.RoutingPeerDnsResolutionEnabled
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccountSettings.
func (in *AccountSettings) DeepCopy() *AccountSettings {
	if in == nil {
		return nil
	}
	out := new(AccountSettings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Nameserver) DeepCopyInto(out *Nameserver) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Nameserver.
func (in *Nameserver) DeepCopy() *Nameserver {
	if in == nil {
		return nil
	}
	out := new(Nameserver)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccount) DeepCopyInto(out *NbAccount) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccount.
func (in *NbAccount) DeepCopy() *NbAccount {
	if in == nil {
		return nil
	}
	out := new(NbAccount)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbAccount) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccountList) DeepCopyInto(out *NbAccountList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NbAccount, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccountList.
func (in *NbAccountList) DeepCopy() *NbAccountList {
	if in == nil {
		return nil
	}
	out := new(NbAccountList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbAccountList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccountObservation) DeepCopyInto(out *NbAccountObservation) {
	*out = *in
	in.Settings.DeepCopyInto(&out.Settings)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccountObservation.
func (in *NbAccountObservation) DeepCopy() *NbAccountObservation {
	if in == nil {
		return nil
	}
	out := new(NbAccountObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccountParameters) DeepCopyInto(out *NbAccountParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccountParameters.
func (in *NbAccountParameters) DeepCopy() *NbAccountParameters {
	if in == nil {
		return nil
	}
	out := new(NbAccountParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccountSpec) DeepCopyInto(out *NbAccountSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	out.ForProvider = in.ForProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccountSpec.
func (in *NbAccountSpec) DeepCopy() *NbAccountSpec {
	if in == nil {
		return nil
	}
	out := new(NbAccountSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbAccountStatus) DeepCopyInto(out *NbAccountStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbAccountStatus.
func (in *NbAccountStatus) DeepCopy() *NbAccountStatus {
	if in == nil {
		return nil
	}
	out := new(NbAccountStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSetting) DeepCopyInto(out *NbDnsSetting) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSetting.
func (in *NbDnsSetting) DeepCopy() *NbDnsSetting {
	if in == nil {
		return nil
	}
	out := new(NbDnsSetting)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbDnsSetting) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSettingList) DeepCopyInto(out *NbDnsSettingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NbDnsSetting, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSettingList.
func (in *NbDnsSettingList) DeepCopy() *NbDnsSettingList {
	if in == nil {
		return nil
	}
	out := new(NbDnsSettingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbDnsSettingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSettingObservation) DeepCopyInto(out *NbDnsSettingObservation) {
	*out = *in
	if in.DisabledManagementGroups != nil {
		in, out := &in.DisabledManagementGroups, &out.DisabledManagementGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSettingObservation.
func (in *NbDnsSettingObservation) DeepCopy() *NbDnsSettingObservation {
	if in == nil {
		return nil
	}
	out := new(NbDnsSettingObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSettingParameters) DeepCopyInto(out *NbDnsSettingParameters) {
	*out = *in
	if in.DisabledManagementGroups != nil {
		in, out := &in.DisabledManagementGroups, &out.DisabledManagementGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSettingParameters.
func (in *NbDnsSettingParameters) DeepCopy() *NbDnsSettingParameters {
	if in == nil {
		return nil
	}
	out := new(NbDnsSettingParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSettingSpec) DeepCopyInto(out *NbDnsSettingSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSettingSpec.
func (in *NbDnsSettingSpec) DeepCopy() *NbDnsSettingSpec {
	if in == nil {
		return nil
	}
	out := new(NbDnsSettingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbDnsSettingStatus) DeepCopyInto(out *NbDnsSettingStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbDnsSettingStatus.
func (in *NbDnsSettingStatus) DeepCopy() *NbDnsSettingStatus {
	if in == nil {
		return nil
	}
	out := new(NbDnsSettingStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroup) DeepCopyInto(out *NbGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroup.
func (in *NbGroup) DeepCopy() *NbGroup {
	if in == nil {
		return nil
	}
	out := new(NbGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroupList) DeepCopyInto(out *NbGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NbGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroupList.
func (in *NbGroupList) DeepCopy() *NbGroupList {
	if in == nil {
		return nil
	}
	out := new(NbGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroupObservation) DeepCopyInto(out *NbGroupObservation) {
	*out = *in
	if in.Issued != nil {
		in, out := &in.Issued, &out.Issued
		*out = new(api.GroupIssued)
		**out = **in
	}
	if in.Peers != nil {
		in, out := &in.Peers, &out.Peers
		*out = make([]api.PeerMinimum, len(*in))
		copy(*out, *in)
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = make([]api.Resource, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroupObservation.
func (in *NbGroupObservation) DeepCopy() *NbGroupObservation {
	if in == nil {
		return nil
	}
	out := new(NbGroupObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroupParameters) DeepCopyInto(out *NbGroupParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroupParameters.
func (in *NbGroupParameters) DeepCopy() *NbGroupParameters {
	if in == nil {
		return nil
	}
	out := new(NbGroupParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroupSpec) DeepCopyInto(out *NbGroupSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	out.ForProvider = in.ForProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroupSpec.
func (in *NbGroupSpec) DeepCopy() *NbGroupSpec {
	if in == nil {
		return nil
	}
	out := new(NbGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbGroupStatus) DeepCopyInto(out *NbGroupStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbGroupStatus.
func (in *NbGroupStatus) DeepCopy() *NbGroupStatus {
	if in == nil {
		return nil
	}
	out := new(NbGroupStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServer) DeepCopyInto(out *NbNameServer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServer.
func (in *NbNameServer) DeepCopy() *NbNameServer {
	if in == nil {
		return nil
	}
	out := new(NbNameServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbNameServer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServerList) DeepCopyInto(out *NbNameServerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NbNameServer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServerList.
func (in *NbNameServerList) DeepCopy() *NbNameServerList {
	if in == nil {
		return nil
	}
	out := new(NbNameServerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NbNameServerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServerObservation) DeepCopyInto(out *NbNameServerObservation) {
	*out = *in
	if in.Domains != nil {
		in, out := &in.Domains, &out.Domains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Nameservers != nil {
		in, out := &in.Nameservers, &out.Nameservers
		*out = make([]Nameserver, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServerObservation.
func (in *NbNameServerObservation) DeepCopy() *NbNameServerObservation {
	if in == nil {
		return nil
	}
	out := new(NbNameServerObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServerParameters) DeepCopyInto(out *NbNameServerParameters) {
	*out = *in
	if in.Domains != nil {
		in, out := &in.Domains, &out.Domains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Nameservers != nil {
		in, out := &in.Nameservers, &out.Nameservers
		*out = make([]Nameserver, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServerParameters.
func (in *NbNameServerParameters) DeepCopy() *NbNameServerParameters {
	if in == nil {
		return nil
	}
	out := new(NbNameServerParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServerSpec) DeepCopyInto(out *NbNameServerSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServerSpec.
func (in *NbNameServerSpec) DeepCopy() *NbNameServerSpec {
	if in == nil {
		return nil
	}
	out := new(NbNameServerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NbNameServerStatus) DeepCopyInto(out *NbNameServerStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NbNameServerStatus.
func (in *NbNameServerStatus) DeepCopy() *NbNameServerStatus {
	if in == nil {
		return nil
	}
	out := new(NbNameServerStatus)
	in.DeepCopyInto(out)
	return out
}
