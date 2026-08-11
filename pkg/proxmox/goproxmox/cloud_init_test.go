/*
Copyright 2026 IONOS Cloud.

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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"

	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
)

type storageResult struct {
	contents []*proxmox.StorageContent
	err      error
}

type fakeCloudInitStorage struct {
	uploadErr       error
	results         []storageResult
	uploadCalls     int
	contentCalls    int
	contentType     string
	storageFilename string
	checksum        string
	algorithm       string
	deletedVolume   string
	deleteCalls     int
	deleteErr       error
	deleteTask      *proxmox.Task
}

func (s *fakeCloudInitStorage) DeleteContent(_ context.Context, content string) (*proxmox.Task, error) {
	s.deleteCalls++
	s.deletedVolume = content
	return s.deleteTask, s.deleteErr
}

func (s *fakeCloudInitStorage) UploadWithHash(content, _ string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error) {
	s.uploadCalls++
	s.contentType = content
	s.storageFilename = *storageFilename
	s.checksum = checksum
	s.algorithm = checksumAlgorithm
	return nil, s.uploadErr
}

func (s *fakeCloudInitStorage) GetContent(context.Context) ([]*proxmox.StorageContent, error) {
	result := storageResult{}
	if s.contentCalls < len(s.results) {
		result = s.results[s.contentCalls]
	}
	s.contentCalls++
	return result.contents, result.err
}

func TestCloudInitISONameBindsMachineAndPayload(t *testing.T) {
	digestA := strings.Repeat("a", cloudInitDigestLength)
	digestB := strings.Repeat("b", cloudInitDigestLength)
	nameA, err := cloudInitISOName("machine-a", digestA)
	require.NoError(t, err)
	nameOtherMachine, err := cloudInitISOName("machine-b", digestA)
	require.NoError(t, err)
	nameOtherPayload, err := cloudInitISOName("machine-a", digestB)
	require.NoError(t, err)
	require.NotEqual(t, nameA, nameOtherMachine, "reused VMID must not reuse a prior Machine's artifact")
	require.NotEqual(t, nameA, nameOtherPayload, "changed bootstrap data must select a new artifact")
	require.Contains(t, nameA, digestA)

	_, err = cloudInitISOName("unsafe/machine", digestA)
	require.ErrorContains(t, err, "safe PVE filename")
	_, err = cloudInitISOName(strings.Repeat("a", maxPVEStorageFilenameLength), digestA)
	require.ErrorContains(t, err, "exceeds PVE limit")
	_, err = cloudInitISOName("machine-a", strings.ToUpper(digestA))
	require.ErrorContains(t, err, "lowercase hexadecimal")
}

func TestCloudInitISONameIsStableAcrossDelayedGenerations(t *testing.T) {
	tests := []struct {
		name          string
		userdata      string
		metadata      string
		vendordata    string
		networkconfig string
	}{
		{
			name:          "cloud-config",
			userdata:      "#cloud-config\nusers: []\n",
			metadata:      "instance-id: machine-a\n",
			networkconfig: "version: 1\nconfig: []\n",
		},
		{
			name:       "ignition",
			userdata:   `{"ignition":{"version":"3.4.0"}}`,
			metadata:   `{"instance-id":"machine-a"}`,
			vendordata: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstPath, err := makeCloudInitISO(test.userdata, test.metadata, test.vendordata, test.networkconfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.Remove(firstPath) })
			firstDigest := cloudInitBootstrapDigest(test.userdata, test.metadata, test.vendordata, test.networkconfig)
			firstName, err := cloudInitISOName("machine-a", firstDigest)
			require.NoError(t, err)

			time.Sleep(1100 * time.Millisecond)
			secondPath, err := makeCloudInitISO(test.userdata, test.metadata, test.vendordata, test.networkconfig)
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.Remove(secondPath) })
			secondDigest := cloudInitBootstrapDigest(test.userdata, test.metadata, test.vendordata, test.networkconfig)
			secondName, err := cloudInitISOName("machine-a", secondDigest)
			require.NoError(t, err)
			require.Equal(t, firstName, secondName)

			byteDigest, size, err := fileSHA256(secondPath)
			require.NoError(t, err)
			storage := &fakeCloudInitStorage{results: []storageResult{{contents: []*proxmox.StorageContent{{
				Volid:  "local:iso/" + firstName,
				Format: "iso",
				Size:   size,
			}}}}}
			_, proven, err := uploadCloudInitISO(context.Background(), storage, "local", secondPath, secondName, byteDigest, size)
			require.NoError(t, err)
			require.True(t, proven)
			require.Equal(t, 0, storage.uploadCalls, "stable logical identity must reuse exact preflight artifact")
			require.Equal(t, 1, storage.contentCalls)
		})
	}
}

func TestUploadCloudInitISOProof(t *testing.T) {
	artifact, err := os.CreateTemp("", "cloud-init-upload-test-*.iso")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(artifact.Name()) })
	_, err = artifact.WriteString("verified cloud-init artifact")
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	digest, size, err := fileSHA256(artifact.Name())
	require.NoError(t, err)
	isoName, err := cloudInitISOName("machine-a", digest)
	require.NoError(t, err)
	exact := &proxmox.StorageContent{Volid: "local:iso/" + isoName, Format: "iso", Size: size}
	mismatch := &proxmox.StorageContent{Volid: exact.Volid, Format: "iso", Size: size + 1}
	otherMachineName, err := cloudInitISOName("machine-b", digest)
	require.NoError(t, err)
	otherMachine := &proxmox.StorageContent{Volid: "local:iso/" + otherMachineName, Format: "iso", Size: size}

	ambiguousEOF := &url.Error{Op: "Post", URL: "https://pve.test/api2/json/nodes/pve/storage/local/upload", Err: io.EOF}
	ambiguousUnexpectedEOF := &url.Error{Op: "Post", URL: "https://pve.test/api2/json/nodes/pve/storage/local/upload", Err: io.ErrUnexpectedEOF}
	ambiguousReset := &url.Error{Op: "Post", URL: "https://pve.test/api2/json/nodes/pve/storage/local/upload", Err: errors.New("connection reset")}
	tests := []struct {
		name             string
		storage          *fakeCloudInitStorage
		wantProven       bool
		wantError        string
		wantUploads      int
		wantContentCalls int
	}{
		{name: "accept then EOF proves exact content-addressed artifact", storage: &fakeCloudInitStorage{uploadErr: ambiguousEOF, results: []storageResult{{}, {contents: []*proxmox.StorageContent{exact}}}}, wantProven: true, wantUploads: 1, wantContentCalls: 2},
		{name: "accept then unexpected EOF proves exact content-addressed artifact", storage: &fakeCloudInitStorage{uploadErr: ambiguousUnexpectedEOF, results: []storageResult{{}, {contents: []*proxmox.StorageContent{exact}}}}, wantProven: true, wantUploads: 1, wantContentCalls: 2},
		{name: "accept then connection reset proves exact content-addressed artifact", storage: &fakeCloudInitStorage{uploadErr: ambiguousReset, results: []storageResult{{}, {contents: []*proxmox.StorageContent{exact}}}}, wantProven: true, wantUploads: 1, wantContentCalls: 2},
		{name: "exact pre-existing immutable artifact avoids duplicate upload", storage: &fakeCloudInitStorage{results: []storageResult{{contents: []*proxmox.StorageContent{exact}}}}, wantProven: true, wantUploads: 0, wantContentCalls: 1},
		{name: "pre-existing mismatch fails before dispatch", storage: &fakeCloudInitStorage{results: []storageResult{{contents: []*proxmox.StorageContent{mismatch}}}}, wantError: "preflight failed", wantUploads: 0, wantContentCalls: 1},
		{name: "pre-existing duplicate fails before dispatch", storage: &fakeCloudInitStorage{results: []storageResult{{contents: []*proxmox.StorageContent{exact, exact}}}}, wantError: "duplicate volume", wantUploads: 0, wantContentCalls: 1},
		{name: "reused VMID different Machine artifact cannot satisfy proof", storage: &fakeCloudInitStorage{uploadErr: ambiguousEOF, results: []storageResult{{contents: []*proxmox.StorageContent{otherMachine}}, {contents: []*proxmox.StorageContent{otherMachine}}}}, wantError: "exact volume", wantUploads: 1, wantContentCalls: 2},
		{name: "ambiguous response with artifact absent remains failure", storage: &fakeCloudInitStorage{uploadErr: ambiguousEOF, results: []storageResult{{}, {}}}, wantError: "exact volume", wantUploads: 1, wantContentCalls: 2},
		{name: "ambiguous response with metadata mismatch remains failure", storage: &fakeCloudInitStorage{uploadErr: ambiguousEOF, results: []storageResult{{}, {contents: []*proxmox.StorageContent{mismatch}}}}, wantError: "metadata mismatched", wantUploads: 1, wantContentCalls: 2},
		{name: "authoritative HTTP rejection remains failure without post-dispatch proof", storage: &fakeCloudInitStorage{uploadErr: errors.New("500 Internal Server Error"), results: []storageResult{{}}}, wantError: "500 Internal Server Error", wantUploads: 1, wantContentCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, proven, err := uploadCloudInitISO(context.Background(), test.storage, "local", artifact.Name(), isoName, digest, size)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			require.Equal(t, test.wantProven, proven)
			require.Equal(t, test.wantUploads, test.storage.uploadCalls)
			require.Equal(t, test.wantContentCalls, test.storage.contentCalls)
			if test.wantUploads == 1 {
				require.Equal(t, "iso", test.storage.contentType)
				require.Equal(t, isoName, test.storage.storageFilename)
				require.Equal(t, digest, test.storage.checksum)
				require.Equal(t, "sha256", test.storage.algorithm)
			}
		})
	}
}

func TestWaitForCloudInitEffectRequiresExactProofAndRejectsAuthoritativeFailure(t *testing.T) {
	originalWait := waitForCloudInitTask
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	tests := []struct {
		name       string
		waitErr    error
		proofErr   error
		taskFailed bool
		wantError  string
	}{
		{name: "lost task poll accepts exact effect", waitErr: io.ErrUnexpectedEOF},
		{name: "lost task poll without effect remains failure", waitErr: io.EOF, proofErr: errors.New("exact artifact absent"), wantError: "exact effect proof failed"},
		{name: "authoritative task failure overrides exact effect", taskFailed: true, wantError: "task failed with exit status"},
		{name: "successful task without effect remains failure", proofErr: errors.New("exact artifact absent"), wantError: "completed without exact effect proof"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proofCalls := 0
			waitForCloudInitTask = func(_ context.Context, task *proxmox.Task, _ int) error {
				if test.taskFailed {
					task.IsFailed = true
					task.ExitStatus = "storage error"
				}
				return test.waitErr
			}
			err := waitForCloudInitEffect(context.Background(), &proxmox.Task{}, 2, "test operation", true, func() error {
				proofCalls++
				return test.proofErr
			})
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			if test.taskFailed {
				require.Zero(t, proofCalls, "authoritative task failure must not be overridden by readback")
			} else {
				require.Equal(t, 1, proofCalls)
			}
		})
	}
}

func TestMountCloudInitISORecoversOnlyExactPostDispatchState(t *testing.T) {
	originalWait := waitForCloudInitTask
	t.Cleanup(func() { waitForCloudInitTask = originalWait })
	digest := strings.Repeat("a", cloudInitDigestLength)
	expectedVolID := "local:iso/user-data-machine-uid-" + digest + ".iso"
	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:qmconfig:320:root@pam:")

	tests := []struct {
		name             string
		initialMount     string
		postErr          error
		postStatus       int
		waitErr          error
		taskFailed       bool
		readbackMount    string
		wantError        string
		wantConfigCalls  int
		wantReadbackGets int
	}{
		{name: "preexisting exact mount is replay safe", initialMount: expectedVolID + ",media=cdrom,size=4M", wantConfigCalls: 0},
		{name: "lost config response accepts exact readback", postErr: io.EOF, readbackMount: expectedVolID + ",media=cdrom,size=4M", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "lost config response rejects absent readback", postErr: io.ErrUnexpectedEOF, wantError: "exact config proof failed", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "connection reset accepts exact readback", postErr: &url.Error{Op: "Post", URL: "https://pve.test/config", Err: errors.New("connection reset")}, readbackMount: expectedVolID + ",media=cdrom", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "lost task poll accepts exact readback", waitErr: io.ErrUnexpectedEOF, readbackMount: expectedVolID + ",media=cdrom", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "lost task poll rejects foreign readback", waitErr: io.EOF, readbackMount: "local:iso/foreign.iso,media=cdrom", wantError: "exact effect proof failed", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "authoritative task failure overrides exact readback", taskFailed: true, readbackMount: expectedVolID + ",media=cdrom", wantError: "task failed with exit status", wantConfigCalls: 1},
		{name: "authoritative config rejection remains failure", postStatus: http.StatusInternalServerError, readbackMount: expectedVolID + ",media=cdrom", wantError: "500 Internal Server Error", wantConfigCalls: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)
			vm := &proxmox.VirtualMachine{VirtualMachineConfig: &proxmox.VirtualMachineConfig{IDE0: test.initialMount}}
			vm.New(client.Client, "pve", 320)
			configCalls := 0
			readbackGets := 0
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
				configCalls++
				if test.postStatus != 0 {
					return httpmock.NewStringResponse(test.postStatus, "rejected"), nil
				}
				if test.postErr != nil {
					return nil, test.postErr
				}
				return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
			})
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "pve", VMID: 320}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
				readbackGets++
				return httpmock.NewJsonResponse(200, map[string]any{"data": proxmox.VirtualMachineConfig{IDE0: test.readbackMount}})
			})
			waitForCloudInitTask = func(_ context.Context, task *proxmox.Task, _ int) error {
				if test.taskFailed {
					task.IsFailed = true
					task.ExitStatus = "mount failed"
				}
				return test.waitErr
			}

			err := mountCloudInitISO(context.Background(), vm, "machine-uid", "ide0", expectedVolID)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			require.Equal(t, test.wantConfigCalls, configCalls)
			require.Equal(t, test.wantReadbackGets, readbackGets)
		})
	}
}

func TestAppendBootDevice(t *testing.T) {
	require.Equal(t, "order=scsi0;net0;ide0", appendBootDevice("order=scsi0;net0", "ide0"))
	require.Equal(t, "order=scsi0;ide0", appendBootDevice("order=scsi0;ide0", "ide0"))
	require.Empty(t, appendBootDevice("", "ide0"), "unset/default boot order must remain unset")
	require.Equal(t, "cdn", appendBootDevice("cdn", "ide0"), "legacy PVE boot syntax must remain unchanged")
}

func TestCloudInitConfigOptionsPreservesDefaultBoot(t *testing.T) {
	vm := &proxmox.VirtualMachine{VirtualMachineConfig: &proxmox.VirtualMachineConfig{}}
	options := cloudInitConfigOptions(vm, "ide0", "local:iso/owned.iso")
	require.Equal(t, []proxmox.VirtualMachineOption{{Name: "ide0", Value: "local:iso/owned.iso,media=cdrom"}}, options)
}

func TestCloudInitOwnershipTagTaskFailureBlocksContinuation(t *testing.T) {
	client := newTestClient(t)
	vmFixture := &proxmox.VirtualMachine{
		Node: "pve", VMID: proxmox.StringOrUint64(320),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{},
	}
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture.VirtualMachineConfig}))
	vm, err := client.GetVM(context.Background(), "pve", 320)
	require.NoError(t, err)

	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:qmconfig:320:root@pam:")
	configCalls := 0
	storageCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		configCalls++
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`, func(*http.Request) (*http.Response, error) {
		storageCalls++
		return httpmock.NewJsonResponse(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}})
	})
	originalWait := waitForCloudInitTask
	t.Cleanup(func() { waitForCloudInitTask = originalWait })
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return errors.New("tag task failed") }

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data", nil, func(capmox.CloudInitUpload) error { return nil })
	require.ErrorContains(t, err, "ownership tag task wait was ambiguous")
	require.Equal(t, 1, configCalls, "failed ownership task must not advance to upload or mount config")
	require.Zero(t, storageCalls, "ownership marker must be durable before storage discovery or upload")
}

func TestCloudInitOwnershipTagAcceptsAmbiguousWaitOnlyAfterExactReadback(t *testing.T) {
	client := newTestClient(t)
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{
		Node: "pve", VMID: proxmox.StringOrUint64(320),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{},
	}
	vm.New(client.Client, "pve", 320)
	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:qmconfig:320:root@pam:")
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": upid}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "pve", VMID: 320}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachineConfig{Tags: cloudInitTag, TagsSlice: []string{cloudInitTag}}}))
	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return io.ErrUnexpectedEOF }
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	require.NoError(t, addCloudInitOwnershipTag(context.Background(), vm))
	require.True(t, vm.HasTag(cloudInitTag))
}

func TestCloudInitOwnershipTagDispatchAmbiguityRequiresExactReadback(t *testing.T) {
	for _, test := range []struct {
		name       string
		tagPresent bool
		wantError  bool
	}{
		{name: "exact tag present", tagPresent: true},
		{name: "tag absent", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)
			cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
			vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{}}
			vm.New(client.Client, "pve", 320)
			configCalls := 0
			httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
				configCalls++
				return nil, io.ErrUnexpectedEOF
			})
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "pve", VMID: 320}}))
			config := proxmox.VirtualMachineConfig{}
			if test.tagPresent {
				config.Tags = cloudInitTag
				config.TagsSlice = []string{cloudInitTag}
			}
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": config}))

			err := addCloudInitOwnershipTag(context.Background(), vm)
			if test.wantError {
				require.ErrorContains(t, err, "exact tag proof failed")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 1, configCalls, "ambiguous dispatch must never be repeated")
		})
	}
}

func TestOwnedCloudInitVolume(t *testing.T) {
	digest := strings.Repeat("a", cloudInitDigestLength)
	owned := "local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom"
	storageName, volID, err := ownedCloudInitVolume(owned, "machine-a")
	require.NoError(t, err)
	require.Equal(t, "local", storageName)
	require.Equal(t, strings.TrimSuffix(owned, ",media=cdrom"), volID)

	for _, foreign := range []string{
		"local:iso/user-data-machine-b-" + digest + ".iso,media=cdrom",
		"local:iso/user-data-machine-a-short.iso,media=cdrom",
		"local:iso/user-data-machine-a-" + digest + ".iso,media=disk",
		"local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom,media=cdrom",
		"local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom,media=disk",
		"local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom,size=4M,size=4M",
		"local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom,serial=unsafe",
		"../local:iso/user-data-machine-a-" + digest + ".iso,media=cdrom",
	} {
		_, _, err := ownedCloudInitVolume(foreign, "machine-a")
		require.Error(t, err)
	}
}

func TestInspectOwnedCloudInitVolume(t *testing.T) {
	volID := "local:iso/user-data-machine-a-" + strings.Repeat("a", cloudInitDigestLength) + ".iso"
	tests := []struct {
		name      string
		contents  []*proxmox.StorageContent
		wantFound bool
		wantError string
	}{
		{name: "exact", contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}, wantFound: true},
		{name: "replay absent", contents: []*proxmox.StorageContent{{Volid: "local:iso/foreign.iso", Format: "iso"}}},
		{name: "format mismatch", contents: []*proxmox.StorageContent{{Volid: volID, Format: "raw"}}, wantError: "unexpected format"},
		{name: "duplicate", contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}, {Volid: volID, Format: "iso"}}, wantError: "duplicate exact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &fakeCloudInitStorage{results: []storageResult{{contents: test.contents}}}
			found, err := inspectOwnedCloudInitVolume(context.Background(), storage, volID)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			require.Equal(t, test.wantFound, found)
			require.Zero(t, storage.deleteCalls, "inspection must never perform broad or implicit deletion")
		})
	}
}

func TestDeleteOwnedCloudInitVolume(t *testing.T) {
	volID := "local:iso/user-data-machine-a-" + strings.Repeat("a", cloudInitDigestLength) + ".iso"
	tests := []struct {
		name        string
		contents    []*proxmox.StorageContent
		wantDeleted bool
		wantError   string
	}{
		{name: "exact", contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}, wantDeleted: true},
		{name: "replay absent", contents: []*proxmox.StorageContent{}},
		{name: "foreign only", contents: []*proxmox.StorageContent{{Volid: "local:iso/foreign.iso", Format: "iso"}}},
		{name: "format mismatch", contents: []*proxmox.StorageContent{{Volid: volID, Format: "raw"}}, wantError: "unexpected format"},
		{name: "duplicate", contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}, {Volid: volID, Format: "iso"}}, wantError: "duplicate exact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &fakeCloudInitStorage{results: []storageResult{{contents: test.contents}}}
			deleted, err := deleteOwnedCloudInitVolume(context.Background(), storage, volID)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			require.Equal(t, test.wantDeleted, deleted)
			if test.wantDeleted {
				require.Equal(t, 1, storage.deleteCalls)
				require.Equal(t, volID, storage.deletedVolume)
			} else {
				require.Zero(t, storage.deleteCalls, "foreign, absent, and mismatched volumes must never be deleted")
			}
		})
	}
}

func TestDeleteOwnedCloudInitVolumeAmbiguousResponse(t *testing.T) {
	volID := "local:iso/user-data-machine-a-" + strings.Repeat("a", cloudInitDigestLength) + ".iso"
	tests := []struct {
		name       string
		deleteErr  error
		postDelete []*proxmox.StorageContent
		wantError  bool
	}{
		{name: "EOF accepted after absence proof", deleteErr: io.EOF},
		{name: "UnexpectedEOF accepted after absence proof", deleteErr: io.ErrUnexpectedEOF},
		{name: "transport reset accepted after absence proof", deleteErr: &url.Error{Op: "DELETE", URL: "https://pve/storage", Err: errors.New("connection reset")}},
		{name: "EOF rejected while artifact remains", deleteErr: io.EOF, postDelete: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}, wantError: true},
		{name: "transport reset rejected while artifact remains", deleteErr: &url.Error{Op: "DELETE", URL: "https://pve/storage", Err: errors.New("connection reset")}, postDelete: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}, wantError: true},
		{name: "authoritative error not swallowed", deleteErr: errors.New("permission denied"), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := &fakeCloudInitStorage{
				deleteErr: test.deleteErr,
				results: []storageResult{
					{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
					{contents: test.postDelete},
				},
			}
			deleted, err := deleteOwnedCloudInitVolume(context.Background(), storage, volID)
			if test.wantError {
				require.Error(t, err)
				require.False(t, deleted)
			} else {
				require.NoError(t, err)
				require.True(t, deleted)
			}
			require.Equal(t, 1, storage.deleteCalls)
		})
	}
}

func TestDeleteOwnedCloudInitVolumeAuthoritativeRetry(t *testing.T) {
	volID := "local:iso/user-data-machine-a-" + strings.Repeat("a", cloudInitDigestLength) + ".iso"
	storage := &fakeCloudInitStorage{
		deleteErr: errors.New("permission denied"),
		results: []storageResult{
			{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
			{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
			{},
		},
	}
	deleted, err := deleteOwnedCloudInitVolume(context.Background(), storage, volID)
	require.ErrorContains(t, err, "permission denied")
	require.False(t, deleted)
	require.Equal(t, 1, storage.deleteCalls)

	storage.deleteErr = nil
	deleted, err = deleteOwnedCloudInitVolume(context.Background(), storage, volID)
	require.NoError(t, err)
	require.True(t, deleted)
	require.Equal(t, 2, storage.deleteCalls, "authoritative failure must retry rather than be swallowed")
}

func TestDeleteOwnedCloudInitVolumeTaskWaitAmbiguity(t *testing.T) {
	volID := "local:iso/user-data-machine-a-" + strings.Repeat("a", cloudInitDigestLength) + ".iso"
	originalWait := waitForCloudInitTask
	t.Cleanup(func() { waitForCloudInitTask = originalWait })
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return io.ErrUnexpectedEOF }

	storage := &fakeCloudInitStorage{
		deleteTask: &proxmox.Task{},
		results: []storageResult{
			{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
			{},
		},
	}
	deleted, err := deleteOwnedCloudInitVolume(context.Background(), storage, volID)
	require.NoError(t, err)
	require.True(t, deleted)

	storage = &fakeCloudInitStorage{
		deleteTask: &proxmox.Task{},
		results: []storageResult{
			{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
			{contents: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}},
		},
	}
	deleted, err = deleteOwnedCloudInitVolume(context.Background(), storage, volID)
	require.ErrorContains(t, err, "absence proof failed")
	require.False(t, deleted)
}

func TestOwnedCloudInitCandidate(t *testing.T) {
	digestA := strings.Repeat("a", cloudInitDigestLength)
	digestB := strings.Repeat("b", cloudInitDigestLength)
	ownedA := "local:iso/user-data-machine-a-" + digestA + ".iso"
	ownedB := "other:iso/user-data-machine-a-" + digestB + ".iso"

	volID, found, err := ownedCloudInitCandidate([]*proxmox.StorageContent{
		{Volid: "local:iso/user-data-machine-b-" + digestA + ".iso", Format: "iso"},
		{Volid: ownedA, Format: "iso"},
	}, "machine-a")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, ownedA, volID)

	_, _, err = ownedCloudInitCandidate([]*proxmox.StorageContent{{Volid: ownedA, Format: "iso"}, {Volid: ownedB, Format: "iso"}}, "machine-a")
	require.ErrorContains(t, err, "multiple owned")
	_, _, err = ownedCloudInitCandidate([]*proxmox.StorageContent{{Volid: ownedA, Format: "raw"}}, "machine-a")
	require.ErrorContains(t, err, "unexpected format")
}

func TestMakeCloudInitISOErrorRemovesTemporaryFile(t *testing.T) {
	var tempPath string
	createClosedTemp := func(dir, pattern string) (*os.File, error) {
		file, err := os.CreateTemp(dir, pattern)
		require.NoError(t, err)
		tempPath = file.Name()
		require.NoError(t, file.Close())
		return file, nil
	}
	_, err := makeCloudInitISOWithFactory(createClosedTemp, "data", "meta", "", "")
	require.Error(t, err)
	_, statErr := os.Stat(tempPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCloudInitRecoveredUploadTagsMountsAndPreservesBoot(t *testing.T) {
	client := newTestClient(t)
	vmFixture := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(320),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{
			Boot: "order=scsi0;net0", Tags: "worker", TagsSlice: []string{"worker"},
		},
	}
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture.VirtualMachineConfig}))
	vm, err := client.GetVM(context.Background(), "pve", 320)
	require.NoError(t, err)

	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30},
			{Name: "disabled", Content: "iso", Enabled: 0},
			{Name: "backup", Content: "backup", Enabled: 1},
		}}))

	var uploadedName, uploadedChecksum, uploadedAlgorithm, uploadedDigest string
	var uploadedSize uint64
	uploadCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/storage/local/upload$`, func(request *http.Request) (*http.Response, error) {
		uploadCalls++
		reader, multipartErr := request.MultipartReader()
		require.NoError(t, multipartErr)
		for {
			part, partErr := reader.NextPart()
			if errors.Is(partErr, io.EOF) {
				break
			}
			require.NoError(t, partErr)
			contents, readErr := io.ReadAll(part)
			require.NoError(t, readErr)
			switch part.FormName() {
			case "filename":
				uploadedName = part.FileName()
				uploadedSize = uint64(len(contents))
				digest := sha256.Sum256(contents)
				uploadedDigest = hex.EncodeToString(digest[:])
			case "checksum":
				uploadedChecksum = string(contents)
			case "checksum-algorithm":
				uploadedAlgorithm = string(contents)
			}
		}
		return nil, io.EOF
	})

	contentCalls := 0
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contentCalls++
		contents := []*proxmox.StorageContent{}
		if uploadedName != "" {
			contents = append(contents, &proxmox.StorageContent{Volid: "local:iso/" + uploadedName, Format: "iso", Size: uploadedSize})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/disabled/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/backup/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))

	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:qmconfig:320:root@pam:")
	var mounted, boot string
	configCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(request *http.Request) (*http.Response, error) {
		configCalls++
		config := map[string]string{}
		require.NoError(t, json.NewDecoder(request.Body).Decode(&config))
		if config["ide0"] != "" {
			mounted = config["ide0"]
			boot = config["boot"]
			vmFixture.VirtualMachineConfig.IDE0 = mounted
			vmFixture.VirtualMachineConfig.Boot = boot
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	completedTask := &proxmox.Task{UPID: upid, Node: "pve", Status: "completed", IsRunning: false}
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(upid)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": completedTask}))

	var uploadStates []capmox.CloudInitUpload
	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data", nil, func(upload capmox.CloudInitUpload) error {
		uploadStates = append(uploadStates, upload)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, uploadCalls)
	require.Equal(t, 3, contentCalls)
	require.Equal(t, 2, configCalls, "recovered upload must tag and then mount the ISO")
	require.True(t, vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)))
	require.Equal(t, "sha256", uploadedAlgorithm)
	require.Equal(t, cloudInitDigestLength, len(uploadedChecksum))
	require.Equal(t, uploadedDigest, uploadedChecksum)
	logicalDigest := cloudInitBootstrapDigest("user-data", "meta-data", "", "network-data")
	require.Equal(t, "user-data-machine-uid-"+logicalDigest+".iso", uploadedName)
	require.Equal(t, "local:iso/"+uploadedName+",media=cdrom", mounted)
	require.Equal(t, "order=scsi0;net0;ide0", boot)
	require.Len(t, uploadStates, 2, "an EOF response with exact storage proof has no task UPID to persist")
	require.Equal(t, capmox.CloudInitUploadPhaseIntent, uploadStates[0].Phase)
	require.Empty(t, uploadStates[0].UPID)
	require.Equal(t, capmox.CloudInitUploadPhaseComplete, uploadStates[1].Phase)
	require.Equal(t, "local:iso/"+uploadedName, uploadStates[1].VolID)
	_, decodeErr := hex.DecodeString(uploadedChecksum)
	require.NoError(t, decodeErr)
}

func TestCloudInitResumesAcceptedUploadWithoutRedispatch(t *testing.T) {
	client := newTestClient(t)
	const (
		userdata      = "user-data"
		metadata      = "meta-data"
		networkConfig = "network-data"
	)
	isoPath, err := makeCloudInitISO(userdata, metadata, "", networkConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(isoPath) })
	_, size, err := fileSHA256(isoPath)
	require.NoError(t, err)
	isoName, err := cloudInitISOName("machine-uid", cloudInitBootstrapDigest(userdata, metadata, "", networkConfig))
	require.NoError(t, err)
	uploadUPID := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:imgcopy:local:root@pam:")
	mountUPID := proxmox.UPID("UPID:pve:003B4236:1DF4ABCB:667C1C46:qmconfig:320:root@pam:")
	current := &capmox.CloudInitUpload{
		Version: 1, Node: "pve", Storage: "local", VolID: "local:iso/" + isoName, Size: size,
		UPID: string(uploadUPID), Phase: capmox.CloudInitUploadPhaseAccepted,
	}
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{
		IDE0: cloudInitUnmountedDeviceValue, Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
	}}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{Volid: current.VolID, Format: "iso", Size: size}}}))
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(uploadUPID)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: uploadUPID, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))
	mountCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(*http.Request) (*http.Response, error) {
		mountCalls++
		return httpmock.NewJsonResponse(200, map[string]any{"data": mountUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(mountUPID)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: mountUPID, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))
	var recorded []capmox.CloudInitUpload

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", userdata, metadata, "", networkConfig, current, func(upload capmox.CloudInitUpload) error {
		recorded = append(recorded, upload)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, recorded, 1)
	require.Equal(t, capmox.CloudInitUploadPhaseComplete, recorded[0].Phase)
	require.Equal(t, string(uploadUPID), recorded[0].UPID)
	require.Equal(t, 1, mountCalls)
	require.Zero(t, httpmock.GetCallCountInfo()["POST =~/nodes/pve/storage/local/upload$"], "restart replay must not dispatch a second upload")
}

func TestCloudInitRearmsQuiescentIntentAndDispatchesExactlyOnce(t *testing.T) {
	client := newTestClient(t)
	const (
		userdata      = "user-data"
		metadata      = "meta-data"
		networkConfig = "network-data"
	)
	isoPath, err := makeCloudInitISO(userdata, metadata, "", networkConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(isoPath) })
	_, size, err := fileSHA256(isoPath)
	require.NoError(t, err)
	isoName, err := cloudInitISOName("machine-uid", cloudInitBootstrapDigest(userdata, metadata, "", networkConfig))
	require.NoError(t, err)
	uploadUPID := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:imgcopy:upload:root@pam:")
	mountUPID := proxmox.UPID("UPID:pve:003B4236:1DF4ABCB:667C1C46:qmconfig:320:root@pam:")
	current := &capmox.CloudInitUpload{
		Version: 1, Node: "pve", Storage: "local", VolID: "local:iso/" + isoName, Size: size,
		Attempt: 1, Phase: capmox.CloudInitUploadPhaseIntent,
	}
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{
		IDE0: cloudInitUnmountedDeviceValue, Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
	}}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/tasks\?limit=1&source=active&typefilter=imgcopy$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.Task{}}))
	artifactPresent := false
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if artifactPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: current.VolID, Format: "iso", Size: size})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	uploadCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/storage/local/upload$`, func(*http.Request) (*http.Response, error) {
		uploadCalls++
		artifactPresent = true
		return httpmock.NewJsonResponse(200, map[string]any{"data": uploadUPID})
	})
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(uploadUPID)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: uploadUPID, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": mountUPID}))
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(mountUPID)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: mountUPID, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))

	var recorded []capmox.CloudInitUpload
	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", userdata, metadata, "", networkConfig, current, func(upload capmox.CloudInitUpload) error {
		recorded = append(recorded, upload)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, uploadCalls)
	require.Len(t, recorded, 3)
	require.Equal(t, capmox.CloudInitUploadPhaseIntent, recorded[0].Phase)
	require.Equal(t, uint64(2), recorded[0].Attempt, "restart must CAS-rearm the orphan intent before dispatch")
	require.Equal(t, capmox.CloudInitUploadPhaseAccepted, recorded[1].Phase)
	require.Equal(t, capmox.CloudInitUploadPhaseComplete, recorded[2].Phase)
	require.Equal(t, uint64(2), recorded[2].Attempt)
}

func TestCloudInitIntentDoesNotRedispatchWhileImgcopyIsActive(t *testing.T) {
	client := newTestClient(t)
	isoPath, err := makeCloudInitISO("user-data", "meta-data", "", "network-data")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(isoPath) })
	_, size, err := fileSHA256(isoPath)
	require.NoError(t, err)
	isoName, err := cloudInitISOName("machine-uid", cloudInitBootstrapDigest("user-data", "meta-data", "", "network-data"))
	require.NoError(t, err)
	current := &capmox.CloudInitUpload{Version: 1, Node: "pve", Storage: "local", VolID: "local:iso/" + isoName, Size: size, Attempt: 1, Phase: capmox.CloudInitUploadPhaseIntent}
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{IDE0: cloudInitUnmountedDeviceValue, Tags: cloudInitTag, TagsSlice: []string{cloudInitTag}}}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`, httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`, httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/tasks\?limit=1&source=active&typefilter=imgcopy$`, httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.Task{{Type: "imgcopy", Status: "running", IsRunning: true}}}))

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data", current, func(capmox.CloudInitUpload) error { return nil })
	require.ErrorIs(t, err, capmox.ErrCloudInitUploadPending)
	require.Zero(t, httpmock.GetCallCountInfo()["POST =~/nodes/pve/storage/local/upload$"])
	require.Equal(t, uint64(1), current.Attempt)
}

func TestRecoverOwnedCloudInitVolumeRejectsCrossStorageDuplicates(t *testing.T) {
	client := newTestClient(t)
	digestA := strings.Repeat("a", cloudInitDigestLength)
	digestB := strings.Repeat("b", cloudInitDigestLength)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30},
			{Name: "other", Content: "images,iso", Enabled: 1, Avail: 1 << 30},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{
			Volid: "local:iso/user-data-machine-uid-" + digestA + ".iso", Format: "iso",
		}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/other/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{
			Volid: "other:iso/user-data-machine-uid-" + digestB + ".iso", Format: "iso",
		}}}))

	_, _, err = recoverOwnedCloudInitVolume(context.Background(), node, "machine-uid")
	require.ErrorContains(t, err, "multiple owned")
}

func TestFindCloudInitUploadTargetReusesExactArtifactAcrossStorageOrderDrift(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	isoName, err := cloudInitISOName("machine-uid", digest)
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "new-first", Content: "iso", Enabled: 1, Avail: 1 << 30},
			{Name: "original", Content: "iso", Enabled: 1, Avail: 1 << 30},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/new-first/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/original/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{
			Volid: "original:iso/" + isoName, Format: "iso", Size: 4096,
		}}}))

	selection, err := findCloudInitUploadTarget(context.Background(), node, "machine-uid", isoName, 4096)
	require.NoError(t, err)
	require.Equal(t, "original", selection.storage.Name, "retry must reuse the existing exact artifact rather than the new first eligible storage")
}

func TestFindCloudInitUploadTargetBoundsDiscoveryAndSelectsCapacityDeterministically(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	isoName, err := cloudInitISOName("machine-uid", digest)
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "disabled", Content: "iso", Enabled: 0},
			{Name: "backup", Content: "backup", Enabled: 1},
			{Name: "full", Content: "iso", Enabled: 1, Avail: 4095},
			{Name: "zeta", Content: "iso", Enabled: 1, Avail: 8192},
			{Name: "alpha", Content: "images,iso", Enabled: 1, Avail: 8192},
		}}))
	for _, storageName := range []string{"full", "zeta", "alpha"} {
		httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/`+storageName+`/content$`,
			httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	}

	selection, err := findCloudInitUploadTarget(context.Background(), node, "machine-uid", isoName, 4096)
	require.NoError(t, err)
	require.Equal(t, "alpha", selection.storage.Name, "selection must skip full storage and be stable across API order")
	require.Zero(t, httpmock.GetCallCountInfo()["GET =~/nodes/pve/storage/disabled/content$"])
	require.Zero(t, httpmock.GetCallCountInfo()["GET =~/nodes/pve/storage/backup/content$"])
}

func TestFindCloudInitUploadTargetRelevantInspectionAndCapacityAreRetryable(t *testing.T) {
	for _, test := range []struct {
		name        string
		avail       uint64
		contentCode int
	}{
		{name: "relevant inspection unavailable", avail: 8192, contentCode: 500},
		{name: "no storage capacity", avail: 4095, contentCode: 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t)
			digest := strings.Repeat("a", cloudInitDigestLength)
			isoName, err := cloudInitISOName("machine-uid", digest)
			require.NoError(t, err)
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
			node, err := client.Node(context.Background(), "pve")
			require.NoError(t, err)
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
				httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: test.avail}}}))
			httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`,
				httpmock.NewJsonResponderOrPanic(test.contentCode, map[string]any{"data": []*proxmox.StorageContent{}}))

			_, err = findCloudInitUploadTarget(context.Background(), node, "machine-uid", isoName, 4096)
			require.ErrorIs(t, err, capmox.ErrCloudInitStorageDiscoveryRetryable)
		})
	}
}

func TestFindCloudInitUploadTargetDeletesOneSupersededMachineArtifactBeforeUpload(t *testing.T) {
	client := newTestClient(t)
	oldDigest := strings.Repeat("a", cloudInitDigestLength)
	newDigest := strings.Repeat("b", cloudInitDigestLength)
	oldName, err := cloudInitISOName("machine-uid", oldDigest)
	require.NoError(t, err)
	newName, err := cloudInitISOName("machine-uid", newDigest)
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storage{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}))
	oldPresent := true
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if oldPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: "local:iso/" + oldName, Format: "iso", Size: 4096})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:imgdel:320:root@pam:")
	deleteCalls := 0
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/pve/storage/local/content/.*$`, func(*http.Request) (*http.Response, error) {
		deleteCalls++
		oldPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(upid)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: upid, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))
	ide0Writes := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(request *http.Request) (*http.Response, error) {
		config := map[string]string{}
		require.NoError(t, json.NewDecoder(request.Body).Decode(&config))
		if config["ide0"] == cloudInitUnmountedDeviceValue {
			ide0Writes++
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})

	selection, err := findCloudInitUploadTarget(context.Background(), node, "machine-uid", newName, 8192)
	require.NoError(t, err)
	require.Equal(t, "local", selection.storage.Name)
	require.Equal(t, "local:iso/"+oldName, selection.supersededVolID)
	require.Zero(t, deleteCalls, "discovery alone must not delete an artifact that may still be mounted")
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{
		IDE0: "local:iso/" + oldName + ",media=cdrom,size=4M", Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
	}}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachine{Node: "pve", VMID: 320}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.VirtualMachineConfig{IDE0: cloudInitUnmountedDeviceValue}}))
	require.NoError(t, client.reconcileSupersededCloudInitArtifact(context.Background(), vm, "machine-uid", "ide0", "local:iso/"+newName, selection.supersededStorage, selection.supersededVolID))
	require.Equal(t, 1, deleteCalls, "changed bootstrap must reconcile the sole superseded immutable artifact before upload")
	require.Equal(t, 1, ide0Writes, "mounted superseded media must be unmounted before its backing volume is deleted")
	require.False(t, oldPresent)
	require.Equal(t, cloudInitUnmountedDeviceValue, vm.VirtualMachineConfig.IDE0, "caller must continue from refetched post-unmount state")
}

func TestFindCloudInitUploadTargetRejectsMultipleSupersededMachineArtifacts(t *testing.T) {
	client := newTestClient(t)
	oldNameA, err := cloudInitISOName("machine-uid", strings.Repeat("a", cloudInitDigestLength))
	require.NoError(t, err)
	oldNameB, err := cloudInitISOName("machine-uid", strings.Repeat("b", cloudInitDigestLength))
	require.NoError(t, err)
	newName, err := cloudInitISOName("machine-uid", strings.Repeat("c", cloudInitDigestLength))
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30},
			{Name: "other", Content: "iso", Enabled: 1, Avail: 1 << 30},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{Volid: "local:iso/" + oldNameA, Format: "iso", Size: 4096}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/other/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{Volid: "other:iso/" + oldNameB, Format: "iso", Size: 4096}}}))

	_, err = findCloudInitUploadTarget(context.Background(), node, "machine-uid", newName, 8192)
	require.ErrorContains(t, err, "multiple superseded")
	require.Zero(t, httpmock.GetCallCountInfo()["DELETE =~/nodes/pve/storage/local/content/.*"], "ambiguous ownership must fail before deletion")
}

func TestRecoverOwnedCloudInitVolumeRetainsStateWhenStorageCannotBeInspected(t *testing.T) {
	client := newTestClient(t)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	node, err := client.Node(context.Background(), "pve")
	require.NoError(t, err)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{
			{Name: "disabled", Content: "iso", Enabled: 0},
			{Name: "backup", Content: "backup", Enabled: 1},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/disabled/content$`,
		httpmock.NewJsonResponderOrPanic(500, map[string]any{"data": nil}))

	_, _, err = recoverOwnedCloudInitVolume(context.Background(), node, "machine-uid")
	require.ErrorContains(t, err, "inspect storage")
}

func TestUnmountCloudInitISOAcceptsNormalizedMountAndRecoversAfterTagFailure(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	volID := "local:iso/user-data-machine-uid-" + digest + ".iso"
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vmFixture := &proxmox.VirtualMachine{
		Node: "pve",
		VMID: proxmox.StringOrUint64(320),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{
			IDE0: volID + ",media=cdrom,size=4M", Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
		},
	}
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/status/current$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": vmFixture.VirtualMachineConfig}))
	vm, err := client.GetVM(context.Background(), "pve", 320)
	require.NoError(t, err)

	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storage{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}))
	contentPresent := true
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if contentPresent {
			contents = append(contents, &proxmox.StorageContent{Volid: volID, Format: "iso", Size: 4096})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})

	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:imgdel:320:root@pam:")
	deleteCalls := 0
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/pve/storage/local/content/.*$`, func(request *http.Request) (*http.Response, error) {
		deleteCalls++
		require.Contains(t, request.URL.Path, "user-data-machine-uid-"+digest+".iso")
		contentPresent = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	completedTask := &proxmox.Task{UPID: upid, Node: "pve", Status: "completed", IsRunning: false}
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(upid)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": completedTask}))

	tagCalls := 0
	unmountCalls := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(request *http.Request) (*http.Response, error) {
		config := map[string]string{}
		require.NoError(t, json.NewDecoder(request.Body).Decode(&config))
		if config["ide0"] == cloudInitUnmountedDeviceValue {
			unmountCalls++
			return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
		}
		tagCalls++
		if tagCalls == 1 {
			return httpmock.NewStringResponse(500, "tag update failed"), nil
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})

	err = client.UnmountCloudInitISO(context.Background(), vm, "machine-uid", "ide0")
	require.Error(t, err, "the first pass must surface tag removal failure after exact deletion")
	require.Equal(t, 1, deleteCalls)
	require.False(t, contentPresent)
	require.Equal(t, 1, unmountCalls)

	// A real reconciliation refetches the still-tagged VM after the failed tag
	// update. Exact absence is then safe replay state and no second delete occurs.
	vm.VirtualMachineConfig.Tags = cloudInitTag
	vm.VirtualMachineConfig.TagsSlice = []string{cloudInitTag}
	vm.VirtualMachineConfig.IDE0 = cloudInitUnmountedDeviceValue
	err = client.UnmountCloudInitISO(context.Background(), vm, "machine-uid", "ide0")
	require.NoError(t, err)
	require.Equal(t, 1, deleteCalls)
	require.Equal(t, 2, tagCalls)
}

func TestUnmountCloudInitISOPreservesForeignDeviceAndDeletesUnattachedOwnedArtifact(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	volID := "local:iso/user-data-machine-uid-" + digest + ".iso"
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{
		Node: "pve", VMID: proxmox.StringOrUint64(320),
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{
			IDE0: "local:iso/operator-owned.iso,media=cdrom", Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
		},
	}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}}))
	present := true
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`, func(*http.Request) (*http.Response, error) {
		contents := []*proxmox.StorageContent{}
		if present {
			contents = append(contents, &proxmox.StorageContent{Volid: volID, Format: "iso", Size: 4096})
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": contents})
	})
	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:imgdel:320:root@pam:")
	httpmock.RegisterResponder(http.MethodDelete, `=~/nodes/pve/storage/local/content/.*$`, func(*http.Request) (*http.Response, error) {
		present = false
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(upid)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: upid, Node: "pve", Status: "stopped", ExitStatus: "OK"}}))
	ide0Writes := 0
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`, func(request *http.Request) (*http.Response, error) {
		config := map[string]string{}
		require.NoError(t, json.NewDecoder(request.Body).Decode(&config))
		if _, ok := config["ide0"]; ok {
			ide0Writes++
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})

	require.NoError(t, client.UnmountCloudInitISO(context.Background(), vm, "machine-uid", "ide0"))
	require.False(t, present)
	require.Zero(t, ide0Writes, "foreign ide0 must remain outside CAPMOX mutation authority")
	require.Equal(t, "local:iso/operator-owned.iso,media=cdrom", vm.VirtualMachineConfig.IDE0)
}

func TestUnmountCloudInitISOTaskFailurePreservesMountedVolumeAndTag(t *testing.T) {
	client := newTestClient(t)
	digest := strings.Repeat("a", cloudInitDigestLength)
	volID := "local:iso/user-data-machine-uid-" + digest + ".iso"
	cloudInitTag := proxmox.MakeTag(proxmox.TagCloudInit)
	vm := &proxmox.VirtualMachine{Node: "pve", VMID: 320, VirtualMachineConfig: &proxmox.VirtualMachineConfig{
		IDE0: volID + ",media=cdrom", Tags: cloudInitTag, TagsSlice: []string{cloudInitTag},
	}}
	vm.New(client.Client, "pve", 320)
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Node{Name: "pve"}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Storage{Name: "local", Content: "iso", Enabled: 1, Avail: 1 << 30}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}}))
	upid := proxmox.UPID("UPID:pve:003B4235:1DF4ABCA:667C1C45:qmconfig:320:root@pam:")
	httpmock.RegisterResponder(http.MethodPost, `=~/nodes/pve/qemu/320/config$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": upid}))
	originalWait := waitForCloudInitTask
	waitForCloudInitTask = func(_ context.Context, task *proxmox.Task, _ int) error {
		task.IsFailed = true
		task.ExitStatus = "permission denied"
		return nil
	}
	t.Cleanup(func() { waitForCloudInitTask = originalWait })

	err := client.UnmountCloudInitISO(context.Background(), vm, "machine-uid", "ide0")
	require.ErrorContains(t, err, "task failed")
	require.Zero(t, httpmock.GetCallCountInfo()["DELETE =~/nodes/pve/storage/local/content/.*$"])
	require.True(t, vm.HasTag(cloudInitTag))
}
