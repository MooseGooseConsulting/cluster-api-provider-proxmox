/*
Copyright 2023-2026 IONOS Cloud.

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

package goproxmox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/jarcoal/httpmock"
	"github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
)

const testBaseURL = "http://pve.local.test/" // regression test against trailing /

func newTestClient(t *testing.T) *APIClient {
	httpmock.Activate()
	t.Cleanup(httpmock.DeactivateAndReset)

	httpmock.RegisterResponder(http.MethodGet, testBaseURL+"api2/json/version",
		newJSONResponder(200, proxmox.Version{Release: "test"}))

	client, err := NewAPIClient(context.Background(), logr.Discard(), testBaseURL, http.DefaultClient)
	require.NoError(t, err)

	return client
}

func newJSONResponder(status int, data any) httpmock.Responder {
	return httpmock.NewJsonResponderOrPanic(status, map[string]any{"data": data}).Once()
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestUploadContextTransportPropagatesCancellationToUploadRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	transport := &uploadContextTransport{base: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		close(requestStarted)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := transport.withContext(ctx, func() (*proxmox.Task, error) {
			request, requestErr := http.NewRequest(http.MethodPost, "http://pve.local.test/api2/json/nodes/pve/storage/local/upload", strings.NewReader("upload"))
			if requestErr != nil {
				return nil, requestErr
			}
			response, requestErr := transport.RoundTrip(request)
			if response != nil {
				_ = response.Body.Close()
			}
			return nil, requestErr
		})
		result <- err
	}()
	<-requestStarted
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
}

type closeTrackingReader struct {
	io.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

func TestUploadContextTransportClosesRejectedBody(t *testing.T) {
	baseCalls := 0
	transport := &uploadContextTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		baseCalls++
		return nil, errors.New("base transport must not be called")
	})}
	body := &closeTrackingReader{Reader: strings.NewReader("upload")}
	request, err := http.NewRequest(http.MethodPost, "http://pve.local.test/api2/json/nodes/pve/storage/local/upload", body)
	require.NoError(t, err)
	request.ContentLength = 0
	response, err := transport.RoundTrip(request)
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	require.ErrorContains(t, err, "finite body")
	require.True(t, body.closed)
	require.Zero(t, baseCalls)
}

func TestUploadContextTransportBuffersExactRequestBody(t *testing.T) {
	want := bytes.Repeat([]byte("cloud-init-body"), 4096)
	transport := &uploadContextTransport{base: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		require.Equal(t, int64(len(want)), request.ContentLength)
		require.NotNil(t, request.GetBody)
		got, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.Equal(t, want, got)
		replay, err := request.GetBody()
		require.NoError(t, err)
		defer func() { require.NoError(t, replay.Close()) }()
		replayed, err := io.ReadAll(replay)
		require.NoError(t, err)
		require.Equal(t, want, replayed)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	request, err := http.NewRequest(http.MethodPost, "http://pve.local.test/api2/json/nodes/pve/storage/local/upload", bytes.NewBuffer(want))
	require.NoError(t, err)
	response, err := transport.withContext(context.Background(), func() (*proxmox.Task, error) {
		response, err := transport.RoundTrip(request)
		if response != nil {
			defer func() { require.NoError(t, response.Body.Close()) }()
		}
		return nil, err
	})
	require.NoError(t, err)
	require.Nil(t, response)
}

func TestUploadContextTransportRejectsOversizedAndMismatchedRequestBodies(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		contentLength int64
		wantError     string
	}{
		{name: "oversized declaration", body: "x", contentLength: maxCloudInitUploadRequestBytes + 1, wantError: "exceeds"},
		{name: "short body", body: "short", contentLength: int64(len("short") + 1), wantError: "does not match Content-Length"},
		{name: "long body", body: "longer", contentLength: int64(len("longer") - 1), wantError: "does not match Content-Length"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseCalls := 0
			transport := &uploadContextTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				baseCalls++
				return nil, errors.New("base transport must not be called")
			})}
			request, err := http.NewRequest(http.MethodPost, "http://pve.local.test/api2/json/nodes/pve/storage/local/upload", strings.NewReader(test.body))
			require.NoError(t, err)
			request.ContentLength = test.contentLength
			response, err := transport.RoundTrip(request)
			if response != nil {
				require.NoError(t, response.Body.Close())
			}
			require.ErrorContains(t, err, test.wantError)
			require.Zero(t, baseCalls)
		})
	}
}

func TestDeleteVMCompleteMountedUploadUnmountsBeforeDeletingArtifact(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("b", cloudInitDigestLength)
	upload := &capmox.CloudInitUpload{
		Version: 1,
		Node:    "test",
		Storage: "local",
		VolID:   "local:iso/user-data-machine-uid-" + digest + ".iso",
		Size:    4096,
		Attempt: 1,
		Phase:   capmox.CloudInitUploadPhaseComplete,
	}
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	ide0 := upload.VolID + ",media=cdrom,size=4M"
	artifactPresent := true
	tagPresent := true
	events := []string{}
	taskUPID := proxmox.UPID("UPID:test:1:2:3:qmconfig:320:root@pam:")
	deleteUPID := proxmox.UPID("UPID:test:1:2:4:qmdestroy:320:root@pam:")

	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if artifactPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: upload.VolID, Format: "iso", Size: upload.Size})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/storage/local/content/.+$`, func(*http.Request) (*http.Response, error) {
		events = append(events, "storage-delete")
		artifactPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": taskUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "test"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(400, map[string]any{"data": "VM 320 already exists"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "test", VMID: 320, Status: "stopped"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		config := proxmox.VirtualMachineConfig{IDE0: ide0}
		if tagPresent {
			config.Tags = cloudInitTag
			config.TagsSlice = []string{cloudInitTag}
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": config})
	})
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		if ide0 != cloudInitUnmountedDeviceValue {
			events = append(events, "unmount")
			ide0 = cloudInitUnmountedDeviceValue
		} else {
			events = append(events, "tag-remove")
			tagPresent = false
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": taskUPID})
	})
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/320$`, func(*http.Request) (*http.Response, error) {
		events = append(events, "vm-delete")
		return httpmock.NewJsonResponse(200, map[string]any{"data": deleteUPID})
	})

	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return nil }
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	task, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.NoError(t, err)
	require.Equal(t, deleteUPID, task.UPID)
	require.Equal(t, []string{"unmount", "storage-delete", "tag-remove", "vm-delete"}, events)
}

func TestDeleteVMPresentCanonicalPlaceholderWithRecordedAbsentUploadSkipsBroadRecovery(t *testing.T) {
	assertDeleteVMPresentNarrowRecordedCleanupSkipsBroadRecovery(t, strings.Join([]string{"fast", "vm-320-cloudinit,media=cdrom,size=4M"}, ":"), capmox.CloudInitUploadPhaseAccepted)
}

func TestDeleteVMPresentUnmountedRecordedUploadSkipsUnavailableUnrelatedStorage(t *testing.T) {
	assertDeleteVMPresentNarrowRecordedCleanupSkipsBroadRecovery(t, cloudInitUnmountedDeviceValue, capmox.CloudInitUploadPhaseComplete)
}

func assertDeleteVMPresentNarrowRecordedCleanupSkipsBroadRecovery(t *testing.T, device, phase string) {
	t.Helper()
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	upload := &capmox.CloudInitUpload{
		Version: 1,
		Node:    "test",
		Storage: "local",
		VolID:   "local:iso/user-data-machine-uid-" + digest + ".iso",
		Size:    4096,
		Attempt: 3,
		Phase:   phase,
	}
	if phase == capmox.CloudInitUploadPhaseAccepted {
		upload.UPID = "UPID:test:1:2:3:imgcopy:320:root@pam:"
	}
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	tagPresent := true
	tagUPID := proxmox.UPID("UPID:test:1:2:3:qmconfig:320:root@pam:")
	deleteUPID := proxmox.UPID("UPID:test:1:2:4:qmdestroy:320:root@pam:")

	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.Storage{{Name: "local", Content: "iso", Enabled: 1}, {Name: "vmdata", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/vmdata/status$`,
		httpmock.NewJsonResponderOrPanic(500, map[string]any{"errors": "unavailable unrelated storage"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/.+/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": map[string]any{"status": "stopped", "exitstatus": "OK"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "test"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(400, map[string]any{"data": "VM 320 already exists"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "test", VMID: 320, Status: "stopped"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		config := proxmox.VirtualMachineConfig{IDE0: device}
		if tagPresent {
			config.Tags = cloudInitTag
			config.TagsSlice = []string{cloudInitTag}
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": config})
	})
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		tagPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": tagUPID})
	})
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/320$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": deleteUPID}))

	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return nil }
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	task, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.NoError(t, err)
	require.Equal(t, deleteUPID, task.UPID)
	require.False(t, tagPresent)
	require.Equal(t, 1, httpmock.GetCallCountInfo()["GET =~/nodes/test/storage/local/content$"])
	require.Zero(t, httpmock.GetCallCountInfo()["GET =~/nodes/test/storage$"])
}

func TestProxmoxAPIClient_GetReservableMemoryBytes(t *testing.T) {
	tests := []struct {
		name                 string
		maxMem               uint64 // memory size of already provisioned guest
		expect               uint64 // expected available memory of the host
		nodeMemoryAdjustment int64  // factor like 100 to multiply host memory with for overprovisioning
	}{
		{
			name:                 "under zero - no overprovisioning",
			maxMem:               29,
			expect:               1,
			nodeMemoryAdjustment: 100,
		},
		{
			name:                 "exact zero - no overprovisioning",
			maxMem:               30,
			expect:               0,
			nodeMemoryAdjustment: 100,
		},
		{
			name:                 "over zero - no overprovisioning",
			maxMem:               31,
			expect:               0,
			nodeMemoryAdjustment: 100,
		},
		{
			name:                 "under zero - overprovisioning",
			maxMem:               58,
			expect:               2,
			nodeMemoryAdjustment: 200,
		},
		{
			name:                 "exact zero - overprovisioning",
			maxMem:               30 * 2,
			expect:               0,
			nodeMemoryAdjustment: 200,
		},
		{
			name:                 "over zero - overprovisioning",
			maxMem:               31 * 2,
			expect:               0,
			nodeMemoryAdjustment: 200,
		},
		{
			name:                 "scheduler disabled",
			maxMem:               100,
			expect:               30,
			nodeMemoryAdjustment: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
				newJSONResponder(200, proxmox.Node{Memory: proxmox.Memory{Total: 30}, Name: "test"}))

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu`,
				// Somehow, setting proxmox.VirtualMachines{} ALWAYS has `Template: true` when defined this way.
				// So it's better to just define a legitimate json response
				newJSONResponder(200, []any{
					map[string]any{
						"name":      "legit-worker",
						"maxmem":    test.maxMem,
						"vmid":      1111,
						"diskwrite": 0,
						"mem":       0,
						"uptime":    0,
						"disk":      0,
						"cpu":       0,
						"cpus":      1,
						"status":    "stopped",
						"netout":    0,
						"maxdisk":   0,
						"netin":     0,
						"diskread":  0,
					},
					map[string]any{
						"name":      "template",
						"maxmem":    102400,
						"vmid":      2222,
						"diskwrite": 0,
						"mem":       0,
						"uptime":    0,
						"disk":      0,
						"cpu":       0,
						"template":  1,
						"cpus":      1,
						"status":    "stopped",
						"netout":    0,
						"maxdisk":   0,
						"netin":     0,
						"diskread":  0,
					}}))

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/lxc`,
				newJSONResponder(200, proxmox.Containers{}))

			reservable, err := client.GetReservableMemoryBytes(context.Background(), "test", test.nodeMemoryAdjustment)
			require.NoError(t, err)
			require.Equal(t, test.expect, reservable)
		})
	}

	t.Run("Fail to access endpoint", func(t *testing.T) {
		client := newTestClient(t)
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
			newJSONResponder(401, "Forbidden"))
		reservable, err := client.GetReservableMemoryBytes(context.Background(), "test", 0)
		require.Error(t, err)
		require.Equal(t, uint64(0), reservable)
		require.Equal(t,
			"cannot find node with name test: not authorized to access endpoint",
			err.Error())
	})

	t.Run("Fail to list VMs", func(t *testing.T) {
		client := newTestClient(t)
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
			newJSONResponder(200, proxmox.Node{Memory: proxmox.Memory{Total: 30}, Name: "test"}))
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu`,
			newJSONResponder(401, nil))
		reservable, err := client.GetReservableMemoryBytes(context.Background(), "test", 1)
		require.Error(t, err)
		require.Equal(t, uint64(0), reservable)
		require.Equal(t,
			"cannot list vms for node test: not authorized to access endpoint",
			err.Error())
	})
}

func TestProxmoxAPIClient_CloneVM(t *testing.T) {
	tests := []struct {
		name  string
		http  []int
		fails bool
		err   string
	}{
		{name: "no node", http: []int{500, 200, 200, 200, 200, 200}, fails: true,
			err: "cannot find node with name test: 500 Internal Server Error"},
		{name: "no template", http: []int{200, 200, 403, 200, 200, 200}, fails: true,
			err: "unable to find vm template: not authorized to access endpoint"},
		{name: "clone fails", http: []int{200, 200, 200, 200, 500, 200}, fails: true,
			err: "unable to create new vm: 500 Internal Server Error"},
		{name: "no node", http: []int{200, 200, 200, 200, 200, 200}, fails: false,
			err: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
				newJSONResponder(test.http[0], proxmox.Node{Name: "test"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/100/status/current`,
				newJSONResponder(test.http[1], proxmox.VirtualMachine{Node: "test"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/100/config`,
				newJSONResponder(test.http[2], proxmox.VirtualMachineConfig{CPU: "kvm64"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(test.http[3],
					proxmox.NodeStatuses{{Name: "test"}, {Name: "test2"}}))
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/0/clone`,
				newJSONResponder(test.http[4], nil))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid`,
				newJSONResponder(test.http[5], "101"))

			clone := capmox.VMCloneRequest{Node: "test"}
			cloneresponse, err := client.CloneVM(context.Background(), 100, clone)

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, capmox.VMCloneResponse{NewID: 101, Task: nil},
					cloneresponse)
			}
		})
	}
}

func TestProxmoxAPIClient_ConfigureVM(t *testing.T) {
	tests := []struct {
		name  string
		http  []int
		fails bool
		err   string
	}{
		{name: "create conf task", fails: false, err: ""},
		{name: "conf error", fails: true,
			err: "unable to configure vm: not authorized to access endpoint"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			// "UPID:$node:$pid:$pstart:$startime:$dtype:$id:$user"
			upid := "UPID:test:00303F51:09D93CFE:61CCA568:download:test.iso:root@pam:"

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
				newJSONResponder(200, proxmox.Node{Name: "test"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/status/current`,
				newJSONResponder(200, proxmox.VirtualMachine{Node: "test", VMID: 101}))
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/101/config`,
				newJSONResponder(200, upid))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/config`,
				newJSONResponder(200, proxmox.VirtualMachineConfig{CPU: "kvm64"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(200,
					proxmox.NodeStatuses{{Name: "test"}, {Name: "test2"}}))

			node := (&proxmox.Node{}).New(client.Client, "test")
			err := node.Status(context.Background())
			require.NoError(t, err)
			vm, err := node.VirtualMachine(context.Background(), 101)
			require.NoError(t, err)

			if test.fails {
				httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/101/config`,
					newJSONResponder(403, upid))
			}
			//  These two are merely to use the variadic interface
			oName := capmox.VirtualMachineOption{Name: "name", Value: "RenameTest"}
			oMem := capmox.VirtualMachineOption{Name: "memory", Value: 4096}
			task, err := client.ConfigureVM(context.Background(), vm, oName, oMem)

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, "download", task.Type)
				require.Equal(t, upid, string(task.UPID))
				require.Equal(t, "root@pam", task.User)
			}
		})
	}
}

func TestProxmoxAPIClient_GetVM(t *testing.T) {
	tests := []struct {
		name  string
		node  string
		vmID  int64
		fails bool
		err   string
	}{
		{name: "get", node: "test", vmID: 101, fails: false, err: ""},
		{name: "node not found", node: "enoent", vmID: 101, fails: true,
			err: "cannot find node with name enoent: 500 Internal Server Error"},
		{name: "vm not found", node: "test", vmID: 102, fails: true,
			err: "cannot find vm with id 102: 500 Internal Server Error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
				newJSONResponder(200, proxmox.Node{Name: "test"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/enoent/status`,
				newJSONResponder(500, nil))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/status/current`,
				newJSONResponder(200, proxmox.VirtualMachine{Node: "test"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/102/status/current`,
				newJSONResponder(500, nil))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/config`,
				newJSONResponder(200, proxmox.VirtualMachineConfig{CPU: "kvm64"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(200,
					proxmox.NodeStatuses{{Name: "test"}, {Name: "test2"}}))

			vm, err := client.GetVM(context.Background(), test.node, test.vmID)

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, "kvm64", vm.VirtualMachineConfig.CPU)
				require.Equal(t, "test", vm.Node)
			}
		})
	}
}

func TestProxmoxAPIClient_FindVMResource(t *testing.T) {
	tests := []struct {
		name  string
		http  []int
		vmID  uint64
		fails bool
		err   string
	}{
		{name: "find", http: []int{200, 200}, vmID: 101, fails: false, err: ""},
		{name: "clusterstatus broken", http: []int{500, 200}, vmID: 101, fails: true,
			err: "cannot get cluster status: 500 Internal Server Error"},
		{name: "resourcelisting broken", http: []int{200, 500}, vmID: 102, fails: true,
			err: "could not list vm resources: 500 Internal Server Error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(test.http[0],
					proxmox.NodeStatuses{{Name: "test"}, {Name: "test2"}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/resources`,
				newJSONResponder(test.http[1], proxmox.ClusterResources{
					&proxmox.ClusterResource{VMID: 101},
				}))

			clusterResource, err := client.FindVMResource(context.Background(), test.vmID)

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, proxmox.ClusterResource{VMID: 101}, *clusterResource)
			}
		})
	}
}

func TestProxmoxAPIClient_FindVMTemplateByTags(t *testing.T) {
	proxmoxClusterResources := proxmox.ClusterResources{
		&proxmox.ClusterResource{VMID: 101, Name: "k8s-node01", Node: "capmox01", Tags: ""},
		&proxmox.ClusterResource{VMID: 102, Name: "k8s-node02", Node: "capmox02", Tags: ""},
		&proxmox.ClusterResource{VMID: 150, Name: "template-without-tags", Node: "capmox01", Tags: "", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 201, Name: "ubuntu-22.04-k8s-v1.28.3", Node: "capmox01", Tags: "template;TEMPLATE;capmox;v1.28.3", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 202, Name: "ubuntu-22.04-k8s-v1.30.2", Node: "capmox02", Tags: "capmox;template;v1.30.2", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 301, Name: "ubuntu-22.04-k8s-v1.29.2", Node: "capmox02", Tags: "capmox;template;v1.29.2", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 302, Name: "ubuntu-22.04-k8s-v1.29.2", Node: "capmox02", Tags: "capmox;template;v1.29.2", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 700, Name: "template-superset", Node: "capmox01", Tags: "template-superset;extra-tag", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 401, Name: "flatcar-k8s-v1.32.2", Node: "capmox03", Tags: "capmox;flatcar;v1.32.2", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 402, Name: "flatcar-k8s-v1.33.9", Node: "capmox03", Tags: "capmox;flatcar;staging;v1.33.9", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 403, Name: "flatcar-k8s-v1.34.5", Node: "capmox03", Tags: "capic;flatcar;devel;v1.34.5", Template: uint64(1)},
		&proxmox.ClusterResource{VMID: 404, Name: "flatcar-k8s-v1.35.2", Node: "capmox03", Tags: "capmox;flatcar;devel;v1.35.1", Template: uint64(1)},
	}
	tests := []struct {
		name           string
		http           []int
		vmTags         []string
		matchPolicy    infrav1.TemplateMatchPolicy
		fails          bool
		err            string
		vmTemplateNode string
		vmTemplateID   int32
	}{
		{
			name:  "clusterstatus broken",
			http:  []int{500, 200},
			fails: true,
			err:   "cannot get cluster status: 500 Internal Server Error",
		},
		{
			name:  "resourcelisting broken",
			http:  []int{200, 500},
			fails: true,
			err:   "could not list vm resources: 500 Internal Server Error",
		},
		{
			name:           "find-template",
			http:           []int{200, 200},
			vmTags:         []string{"template", "capmox", "v1.28.3"},
			matchPolicy:    infrav1.TemplateMatchPolicyExact,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox01",
			vmTemplateID:   201,
		},
		{
			name:           "find-template-nil",
			http:           []int{200, 200},
			vmTags:         nil,
			matchPolicy:    infrav1.TemplateMatchPolicySubset,
			fails:          true,
			err:            "VM template not found: found 9 VM templates with tags \"\"",
			vmTemplateNode: "capmox01",
			vmTemplateID:   201,
		},
		{
			// Proxmox VM tags are always lowercase
			name:           "find-template-uppercase",
			http:           []int{200, 200},
			vmTags:         []string{"TEMPLATE", "CAPMOX", "v1.28.3"},
			matchPolicy:    infrav1.TemplateMatchPolicyExact,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox01",
			vmTemplateID:   201,
		},
		{
			name:           "find-template-unordered",
			http:           []int{200, 200},
			vmTags:         []string{"template", "capmox", "v1.30.2"},
			matchPolicy:    infrav1.TemplateMatchPolicyExact,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox02",
			vmTemplateID:   202,
		},
		{
			name:           "find-template-duplicate-tag",
			http:           []int{200, 200},
			vmTags:         []string{"template", "capmox", "capmox", "v1.30.2"},
			matchPolicy:    infrav1.TemplateMatchPolicyExact,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox02",
			vmTemplateID:   202,
		},
		{
			name:           "find-multiple-templates-any-version",
			http:           []int{200, 200},
			vmTags:         []string{"template", "capmox"},
			matchPolicy:    infrav1.TemplateMatchPolicySubset,
			fails:          true,
			err:            "VM template not found: found 4 VM templates with tags \"capmox;template\"",
			vmTemplateID:   0x45,
			vmTemplateNode: "satisfactory",
		},
		{
			name:           "find-multiple-templates-v1.29.2",
			http:           []int{200, 200},
			vmTags:         []string{"template", "capmox", "v1.29.2"},
			matchPolicy:    infrav1.TemplateMatchPolicyExact,
			fails:          true,
			err:            "VM template not found: found 2 VM templates with tags \"capmox;template;v1.29.2\"",
			vmTemplateID:   0x45,
			vmTemplateNode: "agreeable",
		},
		{
			name:           "find-template-superset-subset",
			http:           []int{200, 200},
			vmTags:         []string{"template-superset"},
			matchPolicy:    infrav1.TemplateMatchPolicySubset,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox01",
			vmTemplateID:   700,
		},
		{
			name:           "find-template-best-subset",
			http:           []int{200, 200},
			vmTags:         []string{"capmox", "flatcar"},
			matchPolicy:    infrav1.TemplateMatchPolicyBest,
			fails:          false,
			err:            "",
			vmTemplateNode: "capmox03",
			vmTemplateID:   401,
		},
		{
			name:           "find-multiple-templates-best-subset",
			http:           []int{200, 200},
			vmTags:         []string{"flatcar", "devel", "devel"},
			matchPolicy:    infrav1.TemplateMatchPolicyBest,
			fails:          true,
			err:            "VM template not found: found 2 VM templates with tags \"devel;flatcar\"",
			vmTemplateID:   19229,
			vmTemplateNode: "we're a serious company, sir",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(test.http[0], proxmox.NodeStatuses{}))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/resources`,
				newJSONResponder(test.http[1], proxmoxClusterResources))

			vmTemplateNode, vmTemplateID, err := client.FindVMTemplateByTags(context.Background(), test.vmTags, string(test.matchPolicy))

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, vmTemplateID, test.vmTemplateID)
				require.Equal(t, vmTemplateNode, test.vmTemplateNode)
			}
		})
	}
}

func TestProxmoxAPIClient_DeleteVM(t *testing.T) {
	tests := []struct {
		name               string
		node               string
		vmID               int64
		vmFree             bool
		tagged             bool
		contentPresent     bool
		storageUnavailable bool
		wantStorageDeletes int
		wantNoContentReads bool
		fails              bool
		err                string
	}{
		{name: "delete", node: "test", vmID: 101, tagged: true, contentPresent: true, wantStorageDeletes: 1},
		{name: "node not found", node: "enoent", vmID: 101, fails: true,
			err: "cannot find node with name enoent: 500 Internal Server Error"},
		{name: "delete fails", node: "test", vmID: 102, tagged: true, contentPresent: true, wantStorageDeletes: 1, fails: true,
			err: "cannot delete vm with id 102: not authorized to access endpoint"},
		{name: "absent vm removes exact immutable artifact", node: "test", vmID: 103, vmFree: true,
			contentPresent: true, wantStorageDeletes: 1, fails: true, err: ErrVMIDFree.Error()},
		{name: "absent vm with absent artifact is replay safe", node: "test", vmID: 104, vmFree: true,
			contentPresent: false, wantStorageDeletes: 0, fails: true, err: ErrVMIDFree.Error()},
		{name: "clean untagged vm deletion ignores unrelated unavailable storage", node: "test", vmID: 105,
			storageUnavailable: true, wantNoContentReads: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			// "UPID:$node:$pid:$pstart:$startime:$dtype:$id:$user"
			upid := "UPID:test:000D6BDA:041E0A54:654A5A1D:qmdestroy:101:root@pam:"
			logicalDigest := cloudInitBootstrapDigest("delete-before-ready", "metadata", "", "network")
			volID := "local:iso/user-data-machine-uid-" + logicalDigest + ".iso"
			contentPresent := test.contentPresent
			storageDeleteCalls := 0
			storageContentCalls := 0
			vmConfig := proxmox.VirtualMachineConfig{CPU: "kvm64"}
			if test.tagged {
				cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
				vmConfig.Tags = cloudInitTag
				vmConfig.TagsSlice = []string{cloudInitTag}
			}

			if test.vmFree {
				httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid`, newJSONResponder(200, fmt.Sprintf("%d", test.vmID)))
			} else {
				httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid`,
					newJSONResponder(400, fmt.Sprintf("VM %d already exists", test.vmID)))
			}
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/enoent/status`,
				newJSONResponder(500, nil))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/status/current`,
				newJSONResponder(200, proxmox.VirtualMachine{Node: "test", VMID: 101}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/102/status/current`,
				newJSONResponder(200, proxmox.VirtualMachine{Node: "test", VMID: 102}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/105/status/current`,
				newJSONResponder(200, proxmox.VirtualMachine{Node: "test", VMID: 105}))
			httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/101`,
				newJSONResponder(200, upid))
			httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/102`,
				newJSONResponder(403, nil))
			httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/105`,
				newJSONResponder(200, upid))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/101/config`,
				newJSONResponder(200, vmConfig))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/102/config`,
				newJSONResponder(200, vmConfig))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/105/config`,
				newJSONResponder(200, vmConfig))
			httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status`,
				newJSONResponder(200,
					proxmox.NodeStatuses{{Name: "test"}, {Name: "test2"}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status`,
				newJSONResponder(200, proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content`, func(*http.Request) (*http.Response, error) {
				storageContentCalls++
				if test.storageUnavailable {
					return httpmock.NewJsonResponse(500, map[string]any{"data": nil})
				}
				contents := []*proxmox.StorageContent{}
				if contentPresent {
					contents = append(contents, &proxmox.StorageContent{Volid: volID, Format: "iso", Size: 4096})
				}
				return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
			})
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/101/config`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": upid}))
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/102/config`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": upid}))
			httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/storage/local/content/.*`, func(*http.Request) (*http.Response, error) {
				storageDeleteCalls++
				contentPresent = false
				return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
			})
			completedTask := proxmox.Task{UPID: proxmox.UPID(upid), Node: "test", Status: "completed", IsRunning: false}
			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/test/tasks/%s/status`, upid),
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": completedTask}))

			task, err := client.DeleteVM(context.Background(), test.node, test.vmID, "machine-uid", nil)

			if test.fails {
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, "qmdestroy", task.Type)
				require.Equal(t, "root@pam", task.User)
			}
			require.Equal(t, test.wantStorageDeletes, storageDeleteCalls, "deletion must remove only the exact immutable Machine ISO")
			require.False(t, contentPresent)
			if test.wantNoContentReads {
				require.Zero(t, storageContentCalls, "clean untagged deletion must not require global storage absence proof")
			}
		})
	}
}

func TestDeleteVMAbsentLegacyRecoverySkipsIneligibleUnavailableStorages(t *testing.T) {
	client := newTestClient(t)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve-n5"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "pve-n5"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": "320"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "local", Content: "iso,vztmpl", Enabled: 1},
			{Name: "local-zfs", Content: "images,rootdir", Enabled: 1},
			{Name: "vmdata", Content: "images", Enabled: 1},
			{Name: "aoostar-usb-staging", Content: "iso", Enabled: 0},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	for _, storageName := range []string{"local-zfs", "vmdata", "aoostar-usb-staging"} {
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage/`+storageName+`/content$`,
			httpmock.NewJsonResponderOrPanic(500, map[string]any{"data": nil}))
	}

	_, err := client.DeleteVM(context.Background(), "pve-n5", 320, "machine-uid", nil)
	require.ErrorIs(t, err, ErrVMIDFree)
	require.Equal(t, 1, httpmock.GetCallCountInfo()["GET =~/nodes/pve-n5/storage/local/content$"])
	for _, storageName := range []string{"local-zfs", "vmdata", "aoostar-usb-staging"} {
		require.Zero(t, httpmock.GetCallCountInfo()["GET =~/nodes/pve-n5/storage/"+storageName+"/content$"],
			"legacy recovery must not inspect an ineligible storage")
	}
}

func TestRecoverLegacyOwnedCloudInitVolumeFailsClosedOnEligibleStorageError(t *testing.T) {
	client := newTestClient(t)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve-n5"}}))
	node, err := client.Node(context.Background(), "pve-n5")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(500, map[string]any{"data": nil}))

	_, _, err = recoverLegacyOwnedCloudInitVolume(context.Background(), node, "machine-uid")
	require.ErrorContains(t, err, `inspect storage "local"`)
}

func TestRecoverLegacyOwnedCloudInitVolumeRejectsEligibleDuplicates(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	isoName := "user-data-machine-uid-" + digest + ".iso"
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve-n5"}}))
	node, err := client.Node(context.Background(), "pve-n5")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "local", Content: "iso", Enabled: 1},
			{Name: "shared", Content: "images,iso", Enabled: 1},
		}}))
	for _, storageName := range []string{"local", "shared"} {
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve-n5/storage/`+storageName+`/content$`,
			httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{
				Volid: storageName + ":iso/" + isoName, Format: "iso", Size: 4096,
			}}}))
	}

	_, _, err = recoverLegacyOwnedCloudInitVolume(context.Background(), node, "machine-uid")
	require.ErrorContains(t, err, "multiple owned cloud-init volumes")
}

func TestDeleteVMWaitsForRecordedUploadThenCleansLateArtifact(t *testing.T) {
	client := newTestClient(t)
	uploadUPID := "UPID:test:000D6BDA:041E0A54:654A5A1D:imgcopy:local:root@pam:"
	deleteUPID := "UPID:test:000D6BDB:041E0A55:654A5A1E:imgdel:local:root@pam:"
	digest := cloudInitBootstrapDigest("late", "metadata", "", "network")
	isoName := "user-data-machine-uid-" + digest + ".iso"
	volID := "local:iso/" + isoName
	upload := &capmox.CloudInitUpload{
		Version: 1,
		Node:    "test",
		Storage: "local",
		VolID:   volID,
		Size:    4096,
		UPID:    uploadUPID,
		Phase:   capmox.CloudInitUploadPhaseAccepted,
	}

	uploadRunning := true
	taskHistoryExpired := false
	artifactPresent := false
	deleteCalls := 0
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "test"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": "320"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+uploadUPID+`/status$`, func(*http.Request) (*http.Response, error) {
		if taskHistoryExpired {
			return httpmock.NewStringResponse(500, "no such task"), nil
		}
		task := proxmox.Task{UPID: proxmox.UPID(uploadUPID), Node: "test", Status: "running", IsRunning: true}
		if !uploadRunning {
			task.Status = "stopped"
			task.ExitStatus = "OK"
			task.IsRunning = false
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": task})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if artifactPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: volID, Format: "iso", Size: 4096})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks\?limit=1&source=active&typefilter=imgcopy$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.Task{}}))
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/storage/local/content/.*$`, func(*http.Request) (*http.Response, error) {
		deleteCalls++
		artifactPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": deleteUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+deleteUPID+`/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: proxmox.UPID(deleteUPID), Node: "test", Status: "stopped", ExitStatus: "OK"}}))

	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(_ context.Context, task *proxmox.Task, _ int) error {
		if task.IsRunning {
			return errors.New("task still running")
		}
		return nil
	}
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	_, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.ErrorContains(t, err, "is not terminal")
	require.NotErrorIs(t, err, ErrVMIDFree, "a VM-free scan must not release ownership while the upload can still materialize")
	require.Zero(t, deleteCalls)

	// Simulate the controller having crashed after upload dispatch, the VM being
	// removed independently, and the accepted task materializing its ISO later.
	uploadRunning = false
	taskHistoryExpired = true
	artifactPresent = true
	_, err = client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.ErrorIs(t, err, ErrVMIDFree)
	require.Equal(t, 1, deleteCalls)
	require.False(t, artifactPresent)
}

func TestDeleteVMIntentWaitsForImgcopyThenAllowsAbsentVMFinalization(t *testing.T) {
	client := newTestClient(t)
	digest := cloudInitBootstrapDigest("orphan", "metadata", "", "network")
	isoName := "user-data-machine-uid-" + digest + ".iso"
	upload := &capmox.CloudInitUpload{
		Version: 1, Node: "test", Storage: "local", VolID: "local:iso/" + isoName,
		Size: 4096, Attempt: 1, Phase: capmox.CloudInitUploadPhaseIntent,
	}
	active := true
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "test"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": "320"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks\?limit=1&source=active&typefilter=imgcopy$`, func(*http.Request) (*http.Response, error) {
		tasks := []*proxmox.Task{}
		if active {
			tasks = append(tasks, &proxmox.Task{Type: "imgcopy", Status: "running", IsRunning: true})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": tasks})
	})

	_, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.ErrorIs(t, err, capmox.ErrCloudInitUploadPending)
	require.NotErrorIs(t, err, ErrVMIDFree)

	active = false
	_, err = client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.ErrorIs(t, err, ErrVMIDFree, "quiescent intent with exact artifact absence may release VM ownership")
}

func TestDeleteVMReconcilesRecordedUploadOnOriginalNodeAfterMigration(t *testing.T) {
	client := newTestClient(t)
	digest := cloudInitBootstrapDigest("migrated", "metadata", "", "network")
	isoName := "user-data-machine-uid-" + digest + ".iso"
	upload := &capmox.CloudInitUpload{
		Version: 1, Node: "old-node", Storage: "shared", VolID: "shared:iso/" + isoName,
		Size: 4096, Attempt: 1, Phase: capmox.CloudInitUploadPhaseComplete,
	}
	for _, nodeName := range []string{"new-node", "old-node"} {
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/`+nodeName+`/status$`,
			httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: nodeName}}))
	}
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "new-node"}, {Name: "old-node"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": "320"}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/old-node/storage/shared/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "shared", Content: "iso", Enabled: 1}}))
	present := true
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/old-node/storage/shared/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if present {
			contents = append(contents, &proxmox.StorageContent{Volid: upload.VolID, Format: "iso", Size: upload.Size})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	deleteUPID := proxmox.UPID("UPID:old-node:1:2:3:imgdel:shared:root@pam:")
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/old-node/storage/shared/content/.*$`, func(*http.Request) (*http.Response, error) {
		present = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": deleteUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/old-node/tasks/%s/status$`, string(deleteUPID)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: deleteUPID, Node: "old-node", Status: "stopped", ExitStatus: "OK"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/new-node/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{}}))

	_, err := client.DeleteVM(context.Background(), "new-node", 320, "machine-uid", upload)
	require.ErrorIs(t, err, ErrVMIDFree)
	require.False(t, present)
}

func TestDeleteVMPresentWaitsForRecordedUploadThenCleansBeforeDeletion(t *testing.T) {
	client := newTestClient(t)
	uploadUPID := "UPID:test:000D6BDA:041E0A54:654A5A1D:imgcopy:local:root@pam:"
	storageDeleteUPID := "UPID:test:000D6BDB:041E0A55:654A5A1E:imgdel:local:root@pam:"
	tagUPID := "UPID:test:000D6BDC:041E0A56:654A5A1F:qmconfig:320:root@pam:"
	vmDeleteUPID := "UPID:test:000D6BDD:041E0A57:654A5A20:qmdestroy:320:root@pam:"
	digest := cloudInitBootstrapDigest("late", "metadata", "", "network")
	isoName := "user-data-machine-uid-" + digest + ".iso"
	volID := "local:iso/" + isoName
	upload := &capmox.CloudInitUpload{
		Version: 1,
		Node:    "test",
		Storage: "local",
		VolID:   volID,
		Size:    4096,
		UPID:    uploadUPID,
		Phase:   capmox.CloudInitUploadPhaseAccepted,
	}

	uploadRunning := true
	artifactPresent := false
	storageDeleteCalls := 0
	tagRemovalCalls := 0
	vmDeleteCalls := 0
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "test"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.NodeStatuses{{Name: "test"}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/cluster/nextid$`,
		httpmock.NewJsonResponderOrPanic(400, map[string]any{"data": fmt.Sprintf("VM %d already exists", 320)}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+uploadUPID+`/status$`, func(*http.Request) (*http.Response, error) {
		task := proxmox.Task{UPID: proxmox.UPID(uploadUPID), Node: "test", Status: "running", IsRunning: true}
		if !uploadRunning {
			task.Status = "stopped"
			task.ExitStatus = "OK"
			task.IsRunning = false
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": task})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if artifactPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: volID, Format: "iso", Size: 4096})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/storage/local/content/.*$`, func(*http.Request) (*http.Response, error) {
		storageDeleteCalls++
		artifactPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": storageDeleteUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+storageDeleteUPID+`/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: proxmox.UPID(storageDeleteUPID), Node: "test", Status: "stopped", ExitStatus: "OK"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "test", VMID: 320}}))
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachineConfig{
			IDE0: cloudInitUnmountedDeviceValue, Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
		}}))
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/test/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		tagRemovalCalls++
		return httpmock.NewJsonResponse(200, map[string]any{"data": tagUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+tagUPID+`/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: proxmox.UPID(tagUPID), Node: "test", Status: "stopped", ExitStatus: "OK"}}))
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/test/qemu/320$`, func(*http.Request) (*http.Response, error) {
		vmDeleteCalls++
		return httpmock.NewJsonResponse(200, map[string]any{"data": vmDeleteUPID})
	})

	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(_ context.Context, task *proxmox.Task, _ int) error {
		if task.IsRunning {
			return errors.New("task still running")
		}
		return nil
	}
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	_, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.ErrorContains(t, err, "is not terminal")
	require.Zero(t, storageDeleteCalls)
	require.Zero(t, tagRemovalCalls, "ownership marker must remain while a recorded upload can still materialize")
	require.Zero(t, vmDeleteCalls, "VM deletion must wait for recorded upload reconciliation")

	uploadRunning = false
	artifactPresent = true
	task, err := client.DeleteVM(context.Background(), "test", 320, "machine-uid", upload)
	require.NoError(t, err)
	require.Equal(t, "qmdestroy", task.Type)
	require.Equal(t, 1, storageDeleteCalls)
	require.Equal(t, 1, tagRemovalCalls)
	require.Equal(t, 1, vmDeleteCalls)
	require.False(t, artifactPresent)
}

func TestProxmoxAPIClient_GetTask(t *testing.T) {
	// "UPID:$node:$pid:$pstart:$startime:$dtype:$id:$user"
	upid := "UPID:test:000D6BDA:041E0A54:654A5A1D:qmdestroy:101:root@pam:"
	upid2 := "UPID:test:000D6BDA:041E0A54:654A5A1D:qmdestroy:102:root@pam:"
	tests := []struct {
		name  string
		fails bool
		err   string
	}{
		{name: "get", fails: false, err: ""},
		{name: "get fails", fails: true, err: fmt.Sprintf("cannot get task with UPID %s: 501 Not Implemented", upid2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`+upid,
				newJSONResponder(200,
					proxmox.Task{UPID: proxmox.UPID(upid), ID: "101"}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/test/tasks/`,
				newJSONResponder(501, nil))

			if test.fails {
				_, err := client.GetTask(context.Background(), upid2)
				require.Error(t, err)
				require.Equal(t, test.err, err.Error())
			} else {
				task, err := client.GetTask(context.Background(), upid)
				require.NoError(t, err)
				require.Equal(t, upid, string(task.UPID))
				require.Equal(t, "101", task.ID)
			}
		})
	}
}

func TestProxmoxAPIClient_CloudInitStatus(t *testing.T) {
	tests := []struct {
		name     string
		node     string  // node name
		vmid     int64   // vmid
		pid      float64 // pid of agent
		exited   int     // exited state
		exitcode int     // exitcode
		outData  string  // out-data
		running  bool    // expected running state
		err      error   // expected error
	}{
		{
			name:     "cloud-init success",
			node:     "pve",
			vmid:     1111,
			pid:      12234,
			exited:   1,
			exitcode: 0,
			outData:  "status: done\n",
			running:  false,
			err:      nil,
		},
		{
			name:     "cloud-init running",
			node:     "pve",
			vmid:     1111,
			pid:      12234,
			exited:   1,
			exitcode: 0,
			outData:  "status: running\n",
			running:  true,
			err:      nil,
		},
		{
			name:     "cloud-init failed",
			node:     "pve",
			vmid:     1111,
			pid:      12234,
			exited:   1,
			exitcode: 1,
			outData:  "status: error\n",
			running:  false,
			err:      ErrCloudInitFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)

			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/status`, test.node),
				newJSONResponder(200, proxmox.Node{Name: "pve"}))

			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/status/current`, test.node, test.vmid),
				newJSONResponder(200, proxmox.VirtualMachine{
					VMID: proxmox.StringOrUint64(test.vmid),
					Name: "legit-worker",
					Node: test.node,
				}))

			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/config`, test.node, test.vmid),
				newJSONResponder(200, proxmox.VirtualMachineConfig{
					Name: "legit-worker",
				}))

			vm, err := client.GetVM(context.Background(), test.node, test.vmid)
			require.NoError(t, err)
			require.NotNil(t, vm)

			// WaitForAgent mock
			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/agent/get-osinfo`, vm.Node, vm.VMID),
				newJSONResponder(200,
					map[string]*proxmox.AgentOsInfo{
						"result": {
							ID:            "ubuntu",
							VersionID:     "22.04",
							Machine:       "x86_64",
							KernelRelease: "5.15.0-89-generic",
							KernelVersion: "#99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023",
							Name:          "Ubuntu",
							Version:       "22.04.3 LTS (Jammy Jellyfish)",
							PrettyName:    "Ubuntu 22.04.3 LTS",
						},
					},
				))

			// AgentExec mock
			httpmock.RegisterResponder(http.MethodPost, fmt.Sprintf(`=~/nodes/%s/qemu/%d/agent/exec\z`, vm.Node, vm.VMID),
				newJSONResponder(200,
					map[string]any{
						"pid": test.pid,
					},
				))

			// AgentExecStatus mock
			httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/%s/qemu/%d/agent/exec-status\?pid=%v`, vm.Node, vm.VMID, test.pid),
				newJSONResponder(200,
					&proxmox.AgentExecStatus{
						Exited:   test.exited,
						ExitCode: test.exitcode,
						OutData:  test.outData,
					},
				))

			running, err := client.CloudInitStatus(context.Background(), vm)
			require.Equal(t, err, test.err)
			require.Equal(t, test.running, running)
		})
	}
}
