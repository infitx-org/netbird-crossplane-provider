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

package controller

import (
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/netbird-crossplane-provider/internal/controller/config"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbaccesstoken"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbaccount"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbdnssetting"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbgroup"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbnameserver"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbnetwork"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbnetworkresource"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbnetworkrouter"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbpolicy"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbsetupkey"
	"github.com/crossplane/netbird-crossplane-provider/internal/controller/nbuser"
)

// Setup creates all Netbird controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		config.Setup,
		nbgroup.Setup,
		nbaccount.Setup,
		nbdnssetting.Setup,
		nbnameserver.Setup,
		nbuser.Setup,
		nbsetupkey.Setup,
		nbaccesstoken.Setup,
		nbnetwork.Setup,
		nbnetworkresource.Setup,
		nbnetworkrouter.Setup,
		nbpolicy.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
