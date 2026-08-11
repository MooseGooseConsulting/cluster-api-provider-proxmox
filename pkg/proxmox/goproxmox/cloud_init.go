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
	"strings"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/luthermonson/go-proxmox"
)

const (
	cloudInitISOBlockSize          = 2048
	cloudInitISOVolumeIdentifier   = "cidata"
	cloudInitDigestLength          = sha256.Size * 2
	maxPVEStorageFilenameLength    = 255
	cloudInitStorageFilenamePrefix = "user-data-"
)

type cloudInitStorage interface {
	UploadWithHash(content, file string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error)
	GetContent(ctx context.Context) ([]*proxmox.StorageContent, error)
}

// CloudInit uploads and mounts a cloud-init ISO. The storage filename binds
// the immutable ProxmoxMachine UID to the full payload digest. This makes an
// exact pre-existing object safe restart state even when PVE reuses a VMID.
func (c *APIClient) CloudInit(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, userdata, metadata, vendordata, networkconfig string) error {
	isoPath, err := makeCloudInitISO(userdata, metadata, vendordata, networkconfig)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(isoPath) }()

	digest, size, err := fileSHA256(isoPath)
	if err != nil {
		return fmt.Errorf("hash cloud-init ISO: %w", err)
	}
	isoName, err := cloudInitISOName(machineIdentity, digest)
	if err != nil {
		return err
	}

	node, err := c.Client.Node(ctx, vm.Node)
	if err != nil {
		return err
	}
	storage, err := node.StorageISO(ctx)
	if err != nil {
		return err
	}

	uploadTask, proven, err := uploadCloudInitISO(ctx, storage, storage.Name, isoPath, isoName, digest, size)
	if err != nil {
		return err
	}
	if !proven {
		if err := uploadTask.WaitFor(ctx, 5); err != nil {
			return err
		}
		if err := requireCloudInitISO(ctx, storage, storage.Name, isoName, size); err != nil {
			return fmt.Errorf("cloud-init ISO upload completed without exact storage proof: %w", err)
		}
	}

	if _, err := vm.AddTag(ctx, proxmox.MakeTag(proxmox.TagCloudInit)); err != nil && !proxmox.IsErrNoop(err) {
		return err
	}

	boot := appendBootDevice(vmBootOrder(vm), device)
	configTask, err := vm.Config(ctx,
		proxmox.VirtualMachineOption{Name: device, Value: fmt.Sprintf("%s:iso/%s,media=cdrom", storage.Name, isoName)},
		proxmox.VirtualMachineOption{Name: "boot", Value: boot},
	)
	if err != nil {
		return err
	}
	return configTask.WaitFor(ctx, 2)
}

func cloudInitISOName(machineIdentity, digest string) (string, error) {
	if machineIdentity == "" {
		return "", errors.New("cloud-init machine identity is empty")
	}
	for _, char := range machineIdentity {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return "", fmt.Errorf("cloud-init machine identity %q is not a safe PVE filename component", machineIdentity)
		}
	}
	if len(digest) != cloudInitDigestLength {
		return "", fmt.Errorf("cloud-init digest must be %d lowercase hexadecimal characters", cloudInitDigestLength)
	}
	for _, char := range digest {
		if (char < 'a' || char > 'f') && (char < '0' || char > '9') {
			return "", fmt.Errorf("cloud-init digest must be %d lowercase hexadecimal characters", cloudInitDigestLength)
		}
	}
	name := cloudInitStorageFilenamePrefix + machineIdentity + "-" + digest + ".iso"
	if len(name) > maxPVEStorageFilenameLength {
		return "", fmt.Errorf("cloud-init ISO filename length %d exceeds PVE limit %d", len(name), maxPVEStorageFilenameLength)
	}
	return name, nil
}

func uploadCloudInitISO(ctx context.Context, storage cloudInitStorage, storageName, isoPath, isoName, digest string, size uint64) (*proxmox.Task, bool, error) {
	present, err := inspectCloudInitISO(ctx, storage, storageName, isoName, size)
	if err != nil {
		return nil, false, fmt.Errorf("cloud-init ISO preflight failed: %w", err)
	}
	if present {
		return nil, true, nil
	}

	task, err := storage.UploadWithHash("iso", isoPath, &isoName, digest, "sha256")
	if err == nil {
		return task, false, nil
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, err
	}

	if proofErr := requireCloudInitISO(ctx, storage, storageName, isoName, size); proofErr != nil {
		return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and storage proof failed: %v", err, proofErr)
	}
	return nil, true, nil
}

func requireCloudInitISO(ctx context.Context, storage cloudInitStorage, storageName, isoName string, size uint64) error {
	present, err := inspectCloudInitISO(ctx, storage, storageName, isoName, size)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("exact volume %q is absent", fmt.Sprintf("%s:iso/%s", storageName, isoName))
	}
	return nil
}

func inspectCloudInitISO(ctx context.Context, storage cloudInitStorage, storageName, isoName string, size uint64) (bool, error) {
	contents, err := storage.GetContent(ctx)
	if err != nil {
		return false, err
	}
	expectedVolID := fmt.Sprintf("%s:iso/%s", storageName, isoName)
	var matched *proxmox.StorageContent
	for _, content := range contents {
		if content.Volid != expectedVolID {
			continue
		}
		if matched != nil {
			return false, fmt.Errorf("storage returned duplicate volume %q", expectedVolID)
		}
		matched = content
	}
	if matched == nil {
		return false, nil
	}
	if matched.Format != "iso" || matched.Size != size {
		return false, fmt.Errorf("volume %q metadata mismatched: format=%q size=%d expected_size=%d", expectedVolID, matched.Format, matched.Size, size)
	}
	return true, nil
}

func vmBootOrder(vm *proxmox.VirtualMachine) string {
	if vm.VirtualMachineConfig == nil {
		return ""
	}
	return vm.VirtualMachineConfig.Boot
}

func appendBootDevice(existing, device string) string {
	for index, entry := range strings.Split(existing, ";") {
		if entry == device || (index == 0 && strings.TrimPrefix(entry, "order=") == device) {
			return existing
		}
	}
	if existing == "" {
		return "order=" + device
	}
	return existing + ";" + device
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

type createTempFileFunc func(dir, pattern string) (*os.File, error)

func makeCloudInitISO(userdata, metadata, vendordata, networkconfig string) (string, error) {
	return makeCloudInitISOWithFactory(os.CreateTemp, userdata, metadata, vendordata, networkconfig)
}

func makeCloudInitISOWithFactory(createTemp createTempFileFunc, userdata, metadata, vendordata, networkconfig string) (path string, err error) {
	temp, err := createTemp("", "capmox-cloud-init-*.iso")
	if err != nil {
		return "", err
	}
	cleanupPath := temp.Name()
	path = cleanupPath
	defer func() {
		if err != nil {
			_ = os.Remove(cleanupPath)
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

	files := []struct{ name, contents string }{{"user-data", userdata}, {"meta-data", metadata}}
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

	if err = fs.Finalize(iso9660.FinalizeOptions{RockRidge: true, Joliet: true, VolumeIdentifier: cloudInitISOVolumeIdentifier}); err != nil {
		return "", err
	}
	return path, nil
}
