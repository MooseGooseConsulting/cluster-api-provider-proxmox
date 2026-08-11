/*
Copyright 2024-2026 IONOS Cloud.

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

package inject

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"testing"

	"github.com/go-logr/logr"
	"github.com/jarcoal/httpmock"
	"github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"

	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/cloudinit"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/ignition"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/network"
	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox/goproxmox"
)

const (
	baseURLWithTrailingSlash = "http://pve.local.test/"
	bootstrapData            = `{
  "ignition": {
    "config": {},
    "security": {
      "tls": {}
    },
    "timeouts": {},
    "version": "2.3.0"
  },
  "networkd": {},
  "passwd": {
    "users": [
      {
        "name": "core",
        "sshAuthorizedKeys": [
          "ssh-ed25519 ..."
        ]
      }
    ]
  },
  "storage": {
    "files": [
      {
        "filesystem": "root",
        "path": "/etc/sudoers.d/core",
        "contents": {
          "source": "data:,core%20ALL%3D(ALL)%20NOPASSWD%3AALL%0A",
          "verification": {}
        },
        "mode": 384
      }
    ]
  },
  "systemd": {
    "units": [
      {
        "contents": "[Unit]\nDescription=kubeadm\n# Run only once. After successful run, this file is moved to /tmp/.\nConditionPathExists=/etc/kubeadm.yml\nAfter=network.target\n[Service]\n# To not restart the unit when it exits, as it is expected.\nType=oneshot\nExecStart=/etc/kubeadm.sh\n[Install]\nWantedBy=multi-user.target\n",
        "enabled": true,
        "name": "kubeadm.service"
      }
    ]
  }
}`
)

func TestISOInjectorInjectCloudInit(t *testing.T) {
	client := newTestClient(t)

	vm := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(100),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{
			Agent:     "1",
			TagsSlice: []string{"my-vm"},
			Tags:      "my-vm",
		},
	}

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/status`, "pve"),
		newJSONResponder(200, proxmox.Node{Name: "pve"}, 2))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/status/current`, "pve", 100),
		newJSONResponder(200, vm, 1))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/config`, "pve", 100),
		newJSONResponder(200, vm.VirtualMachineConfig, 1))

	vm, err := client.GetVM(context.Background(), "pve", 100)
	require.NoError(t, err)

	var uploadStates []capmox.CloudInitUpload
	injector := &ISOInjector{
		VirtualMachine:  vm,
		ProxmoxClient:   client,
		MachineIdentity: "test-machine-uid",
		UploadRecorder: func(upload capmox.CloudInitUpload) error {
			uploadStates = append(uploadStates, upload)
			return nil
		},
		BootstrapData: []byte(""),
		MetaRenderer:  cloudinit.NewMetadata("xxx-xxxx", "my-custom-vm", "1.2.3", true),
		NetworkRenderer: cloudinit.NewNetworkConfig([]network.ConfigData{
			{
				Type:       "ethernet",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				IPConfigs:  []network.IPConfig{{IPAddress: netip.MustParsePrefix("10.1.1.6/24")}},
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				Routes:     []network.RoutingData{{To: netip.MustParsePrefix("0.0.0.0/0")}},
			},
		}),
	}

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/storage$`, "pve"),
		newJSONResponder(200, &proxmox.Storages{{Name: "iso", Content: "iso", Enabled: 1}}, 1))

	ptask := &proxmox.Task{
		UPID:      "UPID:pve:003B4235:1DF4ABCA:667C1C45:vncproxy:103:root@pam:",
		Type:      "upload",
		User:      "foo",
		Status:    "completed",
		Node:      "pve",
		IsRunning: false,
	}
	var uploadedName string
	var uploadedSize uint64
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/storage/iso/content`, "pve"),
		storageContentsResponder(&uploadedName, &uploadedSize))

	httpmock.RegisterResponder(http.MethodPost, fmt.Sprintf(`=~/nodes/%s/storage/iso/upload`, "pve"),
		captureUploadResponder(t, &uploadedName, &uploadedSize, ptask.UPID))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/tasks/%s/status`, "pve", string(ptask.UPID)),
		newJSONResponder(200, ptask, 6))

	httpmock.RegisterResponder(http.MethodPost, fmt.Sprintf(`=~/nodes/%s/qemu/%d/config`, "pve", 100),
		newJSONResponder(200, ptask.UPID, 2))

	err = injector.Inject(context.Background(), "cloud-config")
	require.NoError(t, err)
	require.Len(t, uploadStates, 3)
	require.Equal(t, capmox.CloudInitUploadPhaseIntent, uploadStates[0].Phase)
	require.Equal(t, capmox.CloudInitUploadPhaseAccepted, uploadStates[1].Phase)
	require.Equal(t, string(ptask.UPID), uploadStates[1].UPID)
	require.Equal(t, capmox.CloudInitUploadPhaseComplete, uploadStates[2].Phase)
}

func TestISOInjectorInjectCloudInit_Errors(t *testing.T) {
	vm := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(100),
	}
	injector := &ISOInjector{
		VirtualMachine: vm,
		BootstrapData:  []byte(""),
		MetaRenderer:   cloudinit.NewMetadata("xxx-xxxx", "", "", true),
		NetworkRenderer: cloudinit.NewNetworkConfig([]network.ConfigData{
			{
				Type:       "ethernet",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				IPConfigs:  []network.IPConfig{{IPAddress: netip.MustParsePrefix("10.1.1.6/24")}},
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				Routes: []network.RoutingData{{
					To:  netip.MustParsePrefix("0.0.0.0/0"),
					Via: netip.MustParseAddr("10.1.1.1"),
				}},
			},
		}),
	}

	// missing hostname
	err := injector.Inject(context.Background(), "cloud-config")
	require.Error(t, err)

	// missing network
	injector.MetaRenderer = cloudinit.NewMetadata("xxx-xxxx", "my-custom-vm", "1.2.3", false)
	injector.NetworkRenderer = cloudinit.NewNetworkConfig(nil)
	err = injector.Inject(context.Background(), "cloudinit")
	require.Error(t, err)

	// missing Proxmox client
	injector.NetworkRenderer = cloudinit.NewNetworkConfig([]network.ConfigData{{
		Type: "ethernet", Name: "eth0", MacAddress: "aa:bb:cc:dd:ee:ff",
	}})
	err = injector.Inject(context.Background(), CloudConfigFormat)
	require.ErrorContains(t, err, "proxmox client is not defined")
}

func TestISOInjectorInjectIgnition(t *testing.T) {
	client := newTestClient(t)

	vm := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(100),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{
			Agent:     "1",
			TagsSlice: []string{"flatcar"},
			Tags:      "flatcar",
		},
	}

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/status`, "pve"),
		newJSONResponder(200, proxmox.Node{Name: "pve"}, 2))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/status/current`, "pve", 100),
		newJSONResponder(200, vm, 1))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/config`, "pve", 100),
		newJSONResponder(200, vm.VirtualMachineConfig, 1))

	vm, err := client.GetVM(context.Background(), "pve", 100)
	require.NoError(t, err)

	enricher := &ignition.Enricher{
		BootstrapData: []byte(bootstrapData),
		Hostname:      "my-custom-vm",
		InstanceID:    "xxxx-xxx",
		ProviderID:    "proxmox://xxxx-xxx",
		Network: []network.ConfigData{
			{
				Name:       "eth0",
				IPConfigs:  []network.IPConfig{{IPAddress: netip.MustParsePrefix("10.1.1.6/24")}},
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				Routes: []network.RoutingData{{
					To:  netip.MustParsePrefix("0.0.0.0/0"),
					Via: netip.MustParseAddr("10.1.1.1"),
				}},
			},
		},
	}

	injector := &ISOInjector{
		VirtualMachine:   vm,
		ProxmoxClient:    client,
		MachineIdentity:  "test-machine-uid",
		UploadRecorder:   func(capmox.CloudInitUpload) error { return nil },
		BootstrapData:    []byte(bootstrapData),
		MetaRenderer:     cloudinit.NewMetadata("xxx-xxxx", "my-custom-vm", "1.2.3", false),
		IgnitionEnricher: enricher,
	}

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/storage$`, "pve"),
		newJSONResponder(200, &proxmox.Storages{{Name: "iso", Content: "iso", Enabled: 1}}, 1))

	ptask := &proxmox.Task{
		UPID:      "UPID:pve:003B4235:1DF4ABCA:667C1C45:vncproxy:103:root@pam:",
		Type:      "upload",
		User:      "foo",
		Status:    "completed",
		Node:      "pve",
		IsRunning: false,
	}
	var uploadedName string
	var uploadedSize uint64
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/storage/iso/content`, "pve"),
		storageContentsResponder(&uploadedName, &uploadedSize))

	httpmock.RegisterResponder(http.MethodPost, fmt.Sprintf(`=~/nodes/%s/storage/iso/upload`, "pve"),
		captureUploadResponder(t, &uploadedName, &uploadedSize, ptask.UPID))

	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/tasks/%s/status`, "pve", string(ptask.UPID)),
		newJSONResponder(200, ptask, 6))

	httpmock.RegisterResponder(http.MethodPost, fmt.Sprintf(`=~/nodes/%s/qemu/%d/config`, "pve", 100),
		newJSONResponder(200, ptask.UPID, 2))

	err = injector.Inject(context.Background(), "ignition")
	require.NoError(t, err)
}

func captureUploadResponder(t *testing.T, uploadedName *string, uploadedSize *uint64, upid proxmox.UPID) httpmock.Responder {
	t.Helper()
	return func(request *http.Request) (*http.Response, error) {
		reader, err := request.MultipartReader()
		require.NoError(t, err)
		for {
			part, partErr := reader.NextPart()
			if errors.Is(partErr, io.EOF) {
				break
			}
			require.NoError(t, partErr)
			contents, readErr := io.ReadAll(part)
			require.NoError(t, readErr)
			if part.FormName() == "filename" {
				*uploadedName = part.FileName()
				*uploadedSize = uint64(len(contents))
			}
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	}
}

func storageContentsResponder(uploadedName *string, uploadedSize *uint64) httpmock.Responder {
	return func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if *uploadedName != "" {
			contents = append(contents, &proxmox.StorageContent{Volid: "iso:iso/" + *uploadedName, Format: "iso", Size: *uploadedSize})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	}
}

func TestISOInjectorInjectIgnition_Errors(t *testing.T) {
	vm := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(100),
	}
	e := &ignition.Enricher{
		BootstrapData: []byte(bootstrapData),
		Hostname:      "my-custom-vm",
		InstanceID:    "xxxx-xxx",
		ProviderID:    "proxmox://xxxx-xxx",
		Network: []network.ConfigData{
			{
				Name:       "eth0",
				IPConfigs:  []network.IPConfig{{IPAddress: netip.MustParsePrefix("10.1.1.9/24")}},
				DNSServers: []string{"10.1.1.1"},
				Routes: []network.RoutingData{{
					To:  netip.MustParsePrefix("0.0.0.0/0"),
					Via: netip.MustParseAddr("10.1.1.1"),
				}},
			},
		},
	}
	injector := &ISOInjector{
		VirtualMachine:   vm,
		MetaRenderer:     nil,
		IgnitionEnricher: e,
	}

	// missing metadata renderer
	e.BootstrapData = []byte(bootstrapData)
	err := injector.Inject(context.Background(), "ignition")
	require.Error(t, err)

	// missing hostname
	injector.MetaRenderer = cloudinit.NewMetadata("xxxx-xxxxx", "", "1.2.3", false)
	e.BootstrapData = []byte(bootstrapData)
	err = injector.Inject(context.Background(), "ignition")
	require.Error(t, err)

	// no bootstrapdata
	e.BootstrapData = nil
	injector.MetaRenderer = cloudinit.NewMetadata("xxxx-xxxxx", "my-custom-vm", "1.2.3", true)
	injector.BootstrapData = []byte("invalid")
	err = injector.Inject(context.Background(), "ignition")
	require.Error(t, err)

	// no enricher
	injector.IgnitionEnricher = nil
	err = injector.Inject(context.Background(), "ignition")
	require.Error(t, err, "ignition enricher is not defined")

	// enrich failed - invalid ignition
	e.BootstrapData = []byte("invalid")
	injector.IgnitionEnricher = e
	err = injector.Inject(context.Background(), "ignition")
	require.Error(t, err, "unable to enrich ignition")
}

func TestISOInjectorInject_Unsupported(t *testing.T) {
	vm := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(100),
	}
	injector := &ISOInjector{
		VirtualMachine: vm,
		BootstrapData:  []byte(""),
		MetaRenderer:   cloudinit.NewMetadata("xxx-xxxx", "", "1.2.3", false),
		NetworkRenderer: cloudinit.NewNetworkConfig([]network.ConfigData{
			{
				Type:       "ethernet",
				Name:       "eth0",
				MacAddress: "aa:bb:cc:dd:ee:ff",
				IPConfigs:  []network.IPConfig{{IPAddress: netip.MustParsePrefix("10.1.1.6/24")}},
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				Routes: []network.RoutingData{{
					To:  netip.MustParsePrefix("0.0.0.0/0"),
					Via: netip.MustParseAddr("10.1.1.1"),
				}},
			},
		}),
	}

	// unsupported format
	err := injector.Inject(context.Background(), "invalid")
	require.Error(t, err)
}

func newTestClient(t *testing.T) *goproxmox.APIClient {
	httpmock.Activate()
	t.Cleanup(httpmock.DeactivateAndReset)

	httpmock.RegisterResponder(http.MethodGet, baseURLWithTrailingSlash+"api2/json/version",
		newJSONResponder(200, proxmox.Version{Release: "test"}, 1))

	client, err := goproxmox.NewAPIClient(context.Background(), logr.Discard(), baseURLWithTrailingSlash)
	require.NoError(t, err)

	return client
}

func newJSONResponder(status int, data any, times int) httpmock.Responder {
	return httpmock.NewJsonResponderOrPanic(status, map[string]any{"data": data}).Times(times)
}
