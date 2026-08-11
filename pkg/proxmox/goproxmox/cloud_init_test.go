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

func TestAppendBootDevice(t *testing.T) {
	require.Equal(t, "order=scsi0;net0;ide0", appendBootDevice("order=scsi0;net0", "ide0"))
	require.Equal(t, "order=scsi0;ide0", appendBootDevice("order=scsi0;ide0", "ide0"))
	require.Equal(t, "order=ide0", appendBootDevice("", "ide0"))
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
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": &proxmox.Storages{{Name: "local", Content: "iso", Enabled: 1}}}))

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
		}
		return httpmock.NewJsonResponse(200, map[string]any{"data": upid})
	})
	completedTask := &proxmox.Task{UPID: upid, Node: "pve", Status: "completed", IsRunning: false}
	httpmock.RegisterResponder(http.MethodGet, fmt.Sprintf(`=~/nodes/pve/tasks/%s/status$`, string(upid)),
		httpmock.NewJsonResponderOrPanic(200, map[string]any{"data": completedTask}))

	err = client.CloudInit(context.Background(), vm, "machine-uid", "ide0", "user-data", "meta-data", "", "network-data")
	require.NoError(t, err)
	require.Equal(t, 1, uploadCalls)
	require.Equal(t, 2, contentCalls)
	require.Equal(t, 2, configCalls, "recovered upload must tag and then mount the ISO")
	require.True(t, vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)))
	require.Equal(t, "sha256", uploadedAlgorithm)
	require.Equal(t, cloudInitDigestLength, len(uploadedChecksum))
	require.Equal(t, uploadedDigest, uploadedChecksum)
	require.Equal(t, "user-data-machine-uid-"+uploadedChecksum+".iso", uploadedName)
	require.Equal(t, "local:iso/"+uploadedName+",media=cdrom", mounted)
	require.Equal(t, "order=scsi0;net0;ide0", boot)
	_, decodeErr := hex.DecodeString(uploadedChecksum)
	require.NoError(t, decodeErr)
}
