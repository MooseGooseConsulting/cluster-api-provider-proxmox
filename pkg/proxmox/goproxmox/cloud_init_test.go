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
	"errors"
	"io"
	"net/url"
	"os"
	"testing"

	"github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"
)

type fakeCloudInitStorage struct {
	uploadErr       error
	contents        []*proxmox.StorageContent
	contentErr      error
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
	s.contentCalls++
	return s.contents, s.contentErr
}

func TestUploadCloudInitISOAmbiguousResponse(t *testing.T) {
	artifact, err := os.CreateTemp("", "cloud-init-upload-test-*.iso")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(artifact.Name()) })
	_, err = artifact.WriteString("verified cloud-init artifact")
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	digest, size, err := fileSHA256(artifact.Name())
	require.NoError(t, err)

	ambiguous := &url.Error{Op: "Post", URL: "https://pve.test/api2/json/nodes/pve/storage/local/upload", Err: io.EOF}
	tests := []struct {
		name             string
		storage          *fakeCloudInitStorage
		wantRecovered    bool
		wantError        string
		wantContentCalls int
	}{
		{
			name: "accept then response drop proves exact artifact without duplicate upload",
			storage: &fakeCloudInitStorage{
				uploadErr: ambiguous,
				contents:  []*proxmox.StorageContent{{Volid: "local:iso/user-data-320.iso", Format: "iso", Size: size}},
			},
			wantRecovered: true, wantContentCalls: 1,
		},
		{
			name:      "ambiguous response with artifact absent remains failure",
			storage:   &fakeCloudInitStorage{uploadErr: ambiguous},
			wantError: "exact volume", wantContentCalls: 1,
		},
		{
			name: "ambiguous response with size mismatch remains failure",
			storage: &fakeCloudInitStorage{
				uploadErr: ambiguous,
				contents:  []*proxmox.StorageContent{{Volid: "local:iso/user-data-320.iso", Format: "iso", Size: size + 1}},
			},
			wantError: "metadata mismatched", wantContentCalls: 1,
		},
		{
			name: "ambiguous response with format mismatch remains failure",
			storage: &fakeCloudInitStorage{
				uploadErr: ambiguous,
				contents:  []*proxmox.StorageContent{{Volid: "local:iso/user-data-320.iso", Format: "raw", Size: size}},
			},
			wantError: "metadata mismatched", wantContentCalls: 1,
		},
		{
			name: "authoritative HTTP rejection remains failure without existence probe",
			storage: &fakeCloudInitStorage{
				uploadErr: errors.New("500 Internal Server Error"),
				contents:  []*proxmox.StorageContent{{Volid: "local:iso/user-data-320.iso", Format: "iso", Size: size}},
			},
			wantError: "500 Internal Server Error", wantContentCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, recovered, err := uploadCloudInitISO(context.Background(), test.storage, "local", artifact.Name(), "user-data-320.iso", digest, size)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
			require.Equal(t, test.wantRecovered, recovered)
			require.Equal(t, 1, test.storage.uploadCalls)
			require.Equal(t, test.wantContentCalls, test.storage.contentCalls)
			require.Equal(t, "iso", test.storage.contentType)
			require.Equal(t, "user-data-320.iso", test.storage.storageFilename)
			require.Equal(t, digest, test.storage.checksum)
			require.Equal(t, "sha256", test.storage.algorithm)
		})
	}
}
