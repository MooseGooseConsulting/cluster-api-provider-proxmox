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
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/luthermonson/go-proxmox"
)

const (
	cloudInitISOBlockSize        = 2048
	cloudInitISOVolumeIdentifier = "cidata"
)

type cloudInitStorage interface {
	UploadWithHash(content, file string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error)
	GetContent(ctx context.Context) ([]*proxmox.StorageContent, error)
}

// CloudInit uploads and mounts a cloud-init ISO. PVE verifies the request body
// checksum. If the response is lost after dispatch, exact storage metadata is
// required before reconciliation may continue.
func (c *APIClient) CloudInit(ctx context.Context, vm *proxmox.VirtualMachine, device, userdata, metadata, vendordata, networkconfig string) error {
	isoName := fmt.Sprintf(proxmox.UserDataISOFormat, vm.VMID)
	isoPath, err := makeCloudInitISO(userdata, metadata, vendordata, networkconfig)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(isoPath) }()

	digest, size, err := fileSHA256(isoPath)
	if err != nil {
		return fmt.Errorf("hash cloud-init ISO: %w", err)
	}

	node, err := c.Client.Node(ctx, vm.Node)
	if err != nil {
		return err
	}
	storage, err := node.StorageISO(ctx)
	if err != nil {
		return err
	}

	uploadTask, recovered, err := uploadCloudInitISO(ctx, storage, storage.Name, isoPath, isoName, digest, size)
	if err != nil {
		return err
	}
	if !recovered {
		if err := uploadTask.WaitFor(ctx, 5); err != nil {
			return err
		}
	}

	if _, err := vm.AddTag(ctx, proxmox.MakeTag(proxmox.TagCloudInit)); err != nil && !proxmox.IsErrNoop(err) {
		return err
	}

	configTask, err := vm.Config(ctx, proxmox.VirtualMachineOption{
		Name:  device,
		Value: fmt.Sprintf("%s:iso/%s,media=cdrom", storage.Name, isoName),
	})
	if err != nil {
		return err
	}
	return configTask.WaitFor(ctx, 2)
}

func uploadCloudInitISO(ctx context.Context, storage cloudInitStorage, storageName, isoPath, isoName, digest string, size uint64) (*proxmox.Task, bool, error) {
	task, err := storage.UploadWithHash("iso", isoPath, &isoName, digest, "sha256")
	if err == nil {
		return task, false, nil
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, err
	}

	contents, proofErr := storage.GetContent(ctx)
	if proofErr != nil {
		return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and storage proof failed: %v", err, proofErr)
	}
	expectedVolID := fmt.Sprintf("%s:iso/%s", storageName, isoName)
	var matched *proxmox.StorageContent
	for _, content := range contents {
		if content.Volid != expectedVolID {
			continue
		}
		if matched != nil {
			return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and storage returned duplicate volume %q", err, expectedVolID)
		}
		matched = content
	}
	if matched == nil {
		return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and exact volume %q is absent", err, expectedVolID)
	}
	if matched.Format != "iso" || matched.Size != size {
		return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and volume %q metadata mismatched: format=%q size=%d expected_size=%d", err, expectedVolID, matched.Format, matched.Size, size)
	}

	return nil, true, nil
}

func fileSHA256(path string) (string, uint64, error) {
	// #nosec G304 -- path is the private temporary file returned by makeCloudInitISO.
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), uint64(n), nil
}

func makeCloudInitISO(userdata, metadata, vendordata, networkconfig string) (path string, err error) {
	temp, err := os.CreateTemp("", "capmox-cloud-init-*.iso")
	if err != nil {
		return "", err
	}
	path = temp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err := temp.Close(); err != nil {
		return "", err
	}

	iso, err := file.OpenFromPath(path, false)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := iso.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	fs, err := iso9660.Create(iso, 0, 0, cloudInitISOBlockSize, "")
	if err != nil {
		return "", err
	}
	if err = fs.Mkdir("/"); err != nil {
		return "", err
	}

	files := []struct{ name, contents string }{
		{"user-data", userdata},
		{"meta-data", metadata},
	}
	if vendordata != "" {
		files = append(files, struct{ name, contents string }{"vendor-data", vendordata})
	}
	if networkconfig != "" {
		files = append(files, struct{ name, contents string }{"network-config", networkconfig})
	}
	for _, cloudInitFile := range files {
		writer, openErr := fs.OpenFile("/"+cloudInitFile.name, os.O_CREATE|os.O_RDWR)
		if openErr != nil {
			return "", openErr
		}
		if _, writeErr := writer.Write([]byte(cloudInitFile.contents)); writeErr != nil {
			_ = writer.Close()
			return "", writeErr
		}
		if closeErr := writer.Close(); closeErr != nil {
			return "", closeErr
		}
	}

	if err = fs.Finalize(iso9660.FinalizeOptions{
		RockRidge:        true,
		Joliet:           true,
		VolumeIdentifier: cloudInitISOVolumeIdentifier,
	}); err != nil {
		return "", err
	}
	return path, nil
}
