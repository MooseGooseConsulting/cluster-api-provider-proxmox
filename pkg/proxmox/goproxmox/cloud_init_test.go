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
		{name: "lost task poll accepts exact readback", waitErr: io.ErrUnexpectedEOF, readbackMount: expectedVolID + ",media=cdrom", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "lost task poll rejects foreign readback", waitErr: io.EOF, readbackMount: "local:iso/foreign.iso,media=cdrom", wantError: "exact effect proof failed", wantConfigCalls: 1, wantReadbackGets: 1},
		{name: "authoritative task failure overrides exact readback", taskFailed: true, readbackMount: expectedVolID + ",media=cdrom", wantError: "task failed with exit status", wantConfigCalls: 1},
		{name: "authoritative config rejection remains failure", postErr: errors.New("500 Internal Server Error"), readbackMount: expectedVolID + ",media=cdrom", wantError: "500 Internal Server Error", wantConfigCalls: 1},
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
		return httpmock.NewJsonResponse(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}})
	})
	originalWait := waitForCloudInitTask
	t.Cleanup(func() { waitForCloudInitTask = originalWait })
	waitForCloudInitTask = func(context.Context, *proxmox.Task, int) error { return errors.New("tag task failed") }

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data")
	require.ErrorContains(t, err, "wait for cloud-init ownership tag")
	require.Equal(t, 1, configCalls, "failed ownership task must not advance to upload or mount config")
	require.Zero(t, storageCalls, "ownership marker must be durable before storage discovery or upload")
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
		{name: "EOF rejected while artifact remains", deleteErr: io.EOF, postDelete: []*proxmox.StorageContent{{Volid: volID, Format: "iso"}}, wantError: true},
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
			{Name: "local", Content: "iso", Enabled: 1},
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

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data")
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
	_, decodeErr := hex.DecodeString(uploadedChecksum)
	require.NoError(t, decodeErr)
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
			{Name: "local", Content: "iso", Enabled: 1},
			{Name: "other", Content: "images,iso", Enabled: 1},
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
			{Name: "new-first", Content: "iso", Enabled: 1},
			{Name: "original", Content: "iso", Enabled: 1},
		}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/new-first/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/original/content$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": []*proxmox.StorageContent{{
			Volid: "original:iso/" + isoName, Format: "iso", Size: 4096,
		}}}))

	storage, err := findCloudInitUploadTarget(context.Background(), node, "machine-uid", isoName, 4096)
	require.NoError(t, err)
	require.Equal(t, "original", storage.Name, "retry must reuse the existing exact artifact rather than the new first eligible storage")
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
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
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
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": proxmox.Task{UPID: upid, Status: "stopped", ExitStatus: "OK"}}))

	storage, err := findCloudInitUploadTarget(context.Background(), node, "machine-uid", newName, 8192)
	require.NoError(t, err)
	require.Equal(t, "local", storage.Name)
	require.Equal(t, 1, deleteCalls, "changed bootstrap must reconcile the sole superseded immutable artifact before upload")
	require.False(t, oldPresent)
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
			{Name: "local", Content: "iso", Enabled: 1},
			{Name: "other", Content: "iso", Enabled: 1},
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
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))
	httpmock.RegisterResponder(http.MethodGet, `=~/nodes/pve/storage/local/status$`,
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storage{Name: "local", Content: "iso", Enabled: 1}}))
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
