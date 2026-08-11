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
	"encoding/binary"
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
	cloudInitISOContentType        = "iso"
	cloudInitDigestLength          = sha256.Size * 2
	maxPVEStorageFilenameLength    = 255
	cloudInitStorageFilenamePrefix = "user-data-"
	cloudInitUnmountedDeviceValue  = "none,media=cdrom"
)

var waitForCloudInitTask = func(ctx context.Context, task *proxmox.Task, attempts int) error {
	return task.WaitFor(ctx, attempts)
}

type cloudInitStorage interface {
	UploadWithHash(content, file string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error)
	GetContent(ctx context.Context) ([]*proxmox.StorageContent, error)
	DeleteContent(ctx context.Context, content string) (*proxmox.Task, error)
}

// CloudInit uploads and mounts a cloud-init ISO. The storage filename binds
// the immutable ProxmoxMachine UID to a canonical digest of the logical
// bootstrap inputs. The upload checksum separately proves the finalized ISO
// bytes, whose filesystem metadata need not be reproducible between retries.
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
	bootstrapDigest := cloudInitBootstrapDigest(userdata, metadata, vendordata, networkconfig)
	isoName, err := cloudInitISOName(machineIdentity, bootstrapDigest)
	if err != nil {
		return err
	}

	node, err := c.Client.Node(ctx, vm.Node)
	if err != nil {
		return err
	}
	// The tag is the durable pre-mount ownership marker. Applying it before the
	// upload lets deletion distinguish a clean, untagged VM from a failed
	// provisioning attempt that may own an unattached immutable artifact.
	if err := addCloudInitOwnershipTag(ctx, vm); err != nil {
		return err
	}

	storage, err := findCloudInitUploadTarget(ctx, node, machineIdentity, isoName, size)
	if err != nil {
		return fmt.Errorf("find exact cloud-init ISO upload target on node %q: %w", vm.Node, err)
	}

	uploadTask, proven, err := uploadCloudInitISO(ctx, storage, storage.Name, isoPath, isoName, digest, size)
	if err != nil {
		return err
	}
	if !proven {
		if err := waitForCloudInitEffect(ctx, uploadTask, 5, "cloud-init ISO upload", true, func() error {
			return requireCloudInitISO(ctx, storage, storage.Name, isoName, size)
		}); err != nil {
			return err
		}
	}

	expectedVolID := fmt.Sprintf("%s:iso/%s", storage.Name, isoName)
	return mountCloudInitISO(ctx, vm, machineIdentity, device, expectedVolID)
}

func mountCloudInitISO(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string) error {
	mounted, err := cloudInitMountIsExact(vm, machineIdentity, device, expectedVolID)
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}

	options := cloudInitConfigOptions(vm, device, expectedVolID)
	configTask, err := vm.Config(ctx, options...)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if proofErr := requireCloudInitMount(ctx, vm, machineIdentity, device, expectedVolID); proofErr != nil {
			return fmt.Errorf("cloud-init mount response was ambiguous (%w) and exact config proof failed: %v", err, proofErr)
		}
		return nil
	}
	return waitForCloudInitEffect(ctx, configTask, 2, "cloud-init ISO mount", false, func() error {
		return requireCloudInitMount(ctx, vm, machineIdentity, device, expectedVolID)
	})
}

func findCloudInitUploadTarget(ctx context.Context, node *proxmox.Node, machineIdentity, isoName string, size uint64) (*proxmox.Storage, error) {
	storages, err := node.Storages(ctx)
	if err != nil {
		return nil, err
	}
	var eligible *proxmox.Storage
	var matched *proxmox.Storage
	var supersededStorage *proxmox.Storage
	var supersededVolID string
	for _, storage := range storages {
		if storage.Enabled != 0 && storageSupportsContent(storage.Content, cloudInitISOContentType) && eligible == nil {
			eligible = storage
		}
		contents, err := storage.GetContent(ctx)
		if err != nil {
			return nil, fmt.Errorf("inspect storage %q before cloud-init upload: %w", storage.Name, err)
		}
		expectedVolID := fmt.Sprintf("%s:iso/%s", storage.Name, isoName)
		candidate, found, err := ownedCloudInitCandidate(contents, machineIdentity)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		if candidate != expectedVolID {
			if supersededStorage != nil {
				return nil, fmt.Errorf("multiple superseded cloud-init artifacts found for Machine %q", machineIdentity)
			}
			supersededStorage = storage
			supersededVolID = candidate
			continue
		}
		for _, content := range contents {
			if content.Volid != candidate {
				continue
			}
			if matched != nil {
				return nil, fmt.Errorf("exact cloud-init artifact %q exists on multiple storages", isoName)
			}
			if content.Format != cloudInitISOContentType || content.Size != size {
				return nil, fmt.Errorf("volume %q metadata mismatched: format=%q size=%d expected_size=%d", expectedVolID, content.Format, content.Size, size)
			}
			if storage.Enabled == 0 || !storageSupportsContent(storage.Content, cloudInitISOContentType) {
				return nil, fmt.Errorf("exact cloud-init artifact %q exists on ineligible storage %q", isoName, storage.Name)
			}
			matched = storage
		}
	}
	if supersededStorage != nil {
		if _, err := deleteOwnedCloudInitVolume(ctx, supersededStorage, supersededVolID); err != nil {
			return nil, fmt.Errorf("delete superseded cloud-init artifact %q: %w", supersededVolID, err)
		}
	}
	if matched != nil {
		return matched, nil
	}
	if eligible == nil {
		return nil, errors.New("no enabled ISO storage found")
	}
	return eligible, nil
}

func addCloudInitOwnershipTag(ctx context.Context, vm *proxmox.VirtualMachine) error {
	tagTask, err := vm.AddTag(ctx, proxmox.MakeTag(proxmox.TagCloudInit))
	if err != nil && !proxmox.IsErrNoop(err) {
		return err
	}
	if err == nil {
		if tagTask == nil {
			return errors.New("cloud-init ownership tag returned no task")
		}
		if err := waitForCloudInitTask(ctx, tagTask, 2); err != nil {
			return fmt.Errorf("wait for cloud-init ownership tag: %w", err)
		}
	}
	return nil
}

func waitForCloudInitEffect(ctx context.Context, task *proxmox.Task, attempts int, operation string, proveOnSuccess bool, prove func() error) error {
	if task == nil {
		return fmt.Errorf("%s returned no task", operation)
	}
	waitErr := waitForCloudInitTask(ctx, task, attempts)
	if task.IsFailed || (task.ExitStatus != "" && task.ExitStatus != "OK") {
		return fmt.Errorf("%s task failed with exit status %q", operation, task.ExitStatus)
	}
	if waitErr != nil {
		proofErr := prove()
		if proofErr != nil {
			return fmt.Errorf("%s task wait was ambiguous (%w) and exact effect proof failed: %v", operation, waitErr, proofErr)
		}
		return nil
	}
	if proveOnSuccess {
		if proofErr := prove(); proofErr != nil {
			return fmt.Errorf("%s completed without exact effect proof: %w", operation, proofErr)
		}
	}
	return nil
}

func cloudInitBootstrapDigest(userdata, metadata, vendordata, networkconfig string) string {
	h := sha256.New()
	for _, part := range []string{"capmox-cloud-init-v1", userdata, metadata, vendordata, networkconfig} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, part)
	}
	return hex.EncodeToString(h.Sum(nil))
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

	task, err := storage.UploadWithHash(cloudInitISOContentType, isoPath, &isoName, digest, "sha256")
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
	if matched.Format != cloudInitISOContentType || matched.Size != size {
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
	if existing == "" {
		return ""
	}
	for index, entry := range strings.Split(existing, ";") {
		if entry == device || (index == 0 && strings.TrimPrefix(entry, "order=") == device) {
			return existing
		}
	}
	return existing + ";" + device
}

func cloudInitConfigOptions(vm *proxmox.VirtualMachine, device, volID string) []proxmox.VirtualMachineOption {
	options := []proxmox.VirtualMachineOption{{Name: device, Value: volID + ",media=cdrom"}}
	if boot := appendBootDevice(vmBootOrder(vm), device); boot != "" {
		options = append(options, proxmox.VirtualMachineOption{Name: "boot", Value: boot})
	}
	return options
}

func cloudInitMountIsExact(vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string) (bool, error) {
	if vm.VirtualMachineConfig == nil || device != "ide0" {
		return false, fmt.Errorf("unable to prove cloud-init mount device %q", device)
	}
	deviceValue := vm.VirtualMachineConfig.IDE0
	if deviceValue == "" || deviceValue == cloudInitUnmountedDeviceValue {
		return false, nil
	}
	_, mountedVolID, err := ownedCloudInitVolume(deviceValue, machineIdentity)
	if err != nil {
		return false, err
	}
	if mountedVolID != expectedVolID {
		return false, fmt.Errorf("cloud-init device mounts %q instead of exact expected volume %q", mountedVolID, expectedVolID)
	}
	return true, nil
}

func requireCloudInitMount(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string) error {
	if err := vm.Ping(ctx); err != nil {
		return fmt.Errorf("refetch VM config: %w", err)
	}
	mounted, err := cloudInitMountIsExact(vm, machineIdentity, device, expectedVolID)
	if err != nil {
		return err
	}
	if !mounted {
		return fmt.Errorf("exact expected cloud-init volume %q is not mounted", expectedVolID)
	}
	return nil
}

func ownedCloudInitVolume(deviceValue, machineIdentity string) (storageName, volID string, err error) {
	parts := strings.Split(deviceValue, ",")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("cloud-init device is not an exact ISO mount")
	}
	seenMedia := false
	seenSize := false
	for _, option := range parts[1:] {
		switch {
		case option == "media=cdrom":
			if seenMedia {
				return "", "", fmt.Errorf("cloud-init device has duplicate media option")
			}
			seenMedia = true
		case strings.HasPrefix(option, "media="):
			return "", "", fmt.Errorf("cloud-init device has conflicting media option")
		case strings.HasPrefix(option, "size="):
			if seenSize || !isNormalizedPVESize(strings.TrimPrefix(option, "size=")) {
				return "", "", fmt.Errorf("cloud-init device has invalid normalized size option")
			}
			seenSize = true
		default:
			return "", "", fmt.Errorf("cloud-init device has unsupported normalized option %q", option)
		}
	}
	if !seenMedia {
		return "", "", fmt.Errorf("cloud-init device is missing media=cdrom")
	}
	storageAndName := strings.Split(parts[0], ":iso/")
	if len(storageAndName) != 2 || !isSafePVEStorageName(storageAndName[0]) {
		return "", "", fmt.Errorf("cloud-init device has invalid storage volume identity")
	}
	prefix := cloudInitStorageFilenamePrefix + machineIdentity + "-"
	name := storageAndName[1]
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".iso") {
		return "", "", fmt.Errorf("cloud-init device is not owned by Machine %q", machineIdentity)
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".iso")
	expectedName, nameErr := cloudInitISOName(machineIdentity, digest)
	if nameErr != nil || expectedName != name {
		return "", "", fmt.Errorf("cloud-init device has invalid content-addressed filename")
	}
	return storageAndName[0], parts[0], nil
}

func isNormalizedPVESize(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if char >= '0' && char <= '9' {
			continue
		}
		return index > 0 && index == len(value)-1 && strings.ContainsRune("KMGTP", char)
	}
	return true
}

func isSafePVEStorageName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func inspectOwnedCloudInitVolume(ctx context.Context, storage cloudInitStorage, volID string) (bool, error) {
	contents, err := storage.GetContent(ctx)
	if err != nil {
		return false, err
	}
	var matched *proxmox.StorageContent
	for _, content := range contents {
		if content.Volid != volID {
			continue
		}
		if matched != nil {
			return false, fmt.Errorf("duplicate exact cloud-init volume %q", volID)
		}
		matched = content
	}
	if matched == nil {
		return false, nil
	}
	if matched.Format != cloudInitISOContentType {
		return false, fmt.Errorf("cloud-init volume %q has unexpected format %q", volID, matched.Format)
	}
	return true, nil
}

func deleteOwnedCloudInitVolume(ctx context.Context, storage cloudInitStorage, volID string) (bool, error) {
	present, err := inspectOwnedCloudInitVolume(ctx, storage, volID)
	if err != nil || !present {
		return false, err
	}
	task, err := storage.DeleteContent(ctx, volID)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return false, err
		}
		stillPresent, proofErr := inspectOwnedCloudInitVolume(ctx, storage, volID)
		if proofErr != nil || stillPresent {
			return false, fmt.Errorf("cloud-init volume delete response was ambiguous (%w) and absence proof failed: %v", err, proofErr)
		}
		return true, nil
	}
	if task != nil {
		if waitErr := waitForCloudInitTask(ctx, task, 2); waitErr != nil {
			stillPresent, proofErr := inspectOwnedCloudInitVolume(ctx, storage, volID)
			if proofErr != nil || stillPresent {
				return false, fmt.Errorf("cloud-init volume delete task failed (%w) and absence proof failed: %v", waitErr, proofErr)
			}
			return true, nil
		}
	}
	stillPresent, proofErr := inspectOwnedCloudInitVolume(ctx, storage, volID)
	if proofErr != nil {
		return false, proofErr
	}
	if stillPresent {
		return false, fmt.Errorf("cloud-init volume %q remains after successful delete", volID)
	}
	return true, nil
}

func ownedCloudInitCandidate(contents []*proxmox.StorageContent, machineIdentity string) (string, bool, error) {
	prefix := cloudInitStorageFilenamePrefix + machineIdentity + "-"
	var candidate string
	for _, content := range contents {
		separator := strings.Index(content.Volid, ":iso/")
		if separator < 1 {
			continue
		}
		name := content.Volid[separator+len(":iso/"):]
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		_, parsedVolID, err := ownedCloudInitVolume(content.Volid+",media=cdrom", machineIdentity)
		if err != nil {
			return "", false, err
		}
		if content.Format != cloudInitISOContentType {
			return "", false, fmt.Errorf("owned cloud-init volume %q has unexpected format %q", parsedVolID, content.Format)
		}
		if candidate != "" {
			return "", false, fmt.Errorf("multiple owned cloud-init volumes found for Machine %q", machineIdentity)
		}
		candidate = parsedVolID
	}
	return candidate, candidate != "", nil
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
