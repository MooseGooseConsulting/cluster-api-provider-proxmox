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
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
	"github.com/luthermonson/go-proxmox"

	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
)

const (
	cloudInitISOBlockSize          = 2048
	cloudInitISOVolumeIdentifier   = "cidata"
	cloudInitISOContentType        = "iso"
	cloudInitDigestLength          = sha256.Size * 2
	maxPVEStorageFilenameLength    = 255
	cloudInitStorageFilenamePrefix = "user-data-"
	cloudInitUnmountedDeviceValue  = "none,media=cdrom"
	cloudInitDevice                = "ide0"
	cloudInitDispatchLease         = 2 * time.Minute
)

var errCloudInitStorageInventoryUnavailable = errors.New("cloud-init storage inventory unavailable")

var waitForCloudInitTask = func(ctx context.Context, task *proxmox.Task, attempts int) error {
	return task.WaitFor(ctx, attempts)
}

var (
	cloudInitDispatchNow = time.Now
	cloudInitDispatchID  = func() (string, error) {
		var id [16]byte
		if _, err := cryptorand.Read(id[:]); err != nil {
			return "", err
		}
		return hex.EncodeToString(id[:]), nil
	}
	cloudInitDispatchLocksMu sync.Mutex
	cloudInitDispatchLocks   = map[string]*cloudInitDispatchLock{}
)

type cloudInitDispatchLock struct {
	mu   sync.Mutex
	refs int
}

func acquireCloudInitDispatch(machineIdentity string) func() {
	cloudInitDispatchLocksMu.Lock()
	lock := cloudInitDispatchLocks[machineIdentity]
	if lock == nil {
		lock = &cloudInitDispatchLock{}
		cloudInitDispatchLocks[machineIdentity] = lock
	}
	lock.refs++
	cloudInitDispatchLocksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		cloudInitDispatchLocksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(cloudInitDispatchLocks, machineIdentity)
		}
		cloudInitDispatchLocksMu.Unlock()
	}
}

type cloudInitStorage interface {
	GetContent(ctx context.Context) ([]*proxmox.StorageContent, error)
	DeleteContent(ctx context.Context, content string) (*proxmox.Task, error)
}

type cloudInitUploadStorage interface {
	cloudInitStorage
	UploadWithHash(ctx context.Context, content, file string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error)
}

type contextCloudInitStorage struct {
	storage   *proxmox.Storage
	transport *uploadContextTransport
	node      string
	address   netip.Addr
}

func (s *contextCloudInitStorage) UploadWithHash(ctx context.Context, content, file string, storageFilename *string, checksum, checksumAlgorithm string) (*proxmox.Task, error) {
	return s.transport.withRoute(ctx, s.node, s.storage.Name, s.address, func() (*proxmox.Task, error) {
		return s.storage.UploadWithHash(content, file, storageFilename, checksum, checksumAlgorithm)
	})
}

func (s *contextCloudInitStorage) GetContent(ctx context.Context) ([]*proxmox.StorageContent, error) {
	return s.storage.GetContent(ctx)
}

func (s *contextCloudInitStorage) DeleteContent(ctx context.Context, content string) (*proxmox.Task, error) {
	return s.storage.DeleteContent(ctx, content)
}

// CloudInit uploads and mounts a cloud-init ISO. The storage filename binds
// the immutable ProxmoxMachine UID to a canonical digest of the logical
// bootstrap inputs. The upload checksum separately proves the finalized ISO
// bytes, whose filesystem metadata need not be reproducible between retries.
func (c *APIClient) CloudInit(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, userdata, metadata, vendordata, networkconfig string, current *capmox.CloudInitUpload, recorder capmox.CloudInitUploadRecorder) error {
	if recorder == nil {
		return errors.New("cloud-init upload recorder is required")
	}
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
	if err := c.reconcileLegacyCloudInitMount(ctx, vm, machineIdentity, device); err != nil {
		return err
	}
	if err := validateCloudInitTargetDevice(vm, machineIdentity, device); err != nil {
		return err
	}
	unlockDispatch := acquireCloudInitDispatch(machineIdentity)
	defer unlockDispatch()
	// The tag is the durable pre-mount ownership marker. Applying it before the
	// upload lets deletion distinguish a clean, untagged VM from a failed
	// provisioning attempt that may own an unattached immutable artifact.
	if err := addCloudInitOwnershipTag(ctx, vm); err != nil {
		return err
	}
	nextAttempt, intentAlreadyRecorded, handled, err := c.prepareCloudInitAttempt(ctx, node, vm, machineIdentity, device, isoName, size, current, recorder)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	selection, expectedVolID, err := c.selectCloudInitUploadTarget(ctx, node, vm, machineIdentity, device, isoName, size)
	if err != nil {
		return err
	}
	storage := selection.storage

	uploadState := capmox.CloudInitUpload{
		Version:        1,
		Node:           vm.Node,
		Storage:        storage.Name,
		VolID:          expectedVolID,
		Size:           size,
		Attempt:        nextAttempt,
		DispatchOwner:  "",
		LeaseUntilUnix: 0,
		Phase:          capmox.CloudInitUploadPhaseIntent,
	}
	if intentAlreadyRecorded {
		uploadState.DispatchOwner = current.DispatchOwner
		uploadState.LeaseUntilUnix = current.LeaseUntilUnix
	}
	if selection.exactArtifactPresent {
		uploadState.Phase = capmox.CloudInitUploadPhaseComplete
		if err := recordCloudInitUpload(recorder, uploadState, "record reused cloud-init upload completion"); err != nil {
			return err
		}
		return finishCloudInitMount(ctx, vm, machineIdentity, device, expectedVolID)
	}
	uploadAddress, err := c.resolveCloudInitUploadAddress(ctx, vm.Node)
	if err != nil {
		return err
	}
	if !intentAlreadyRecorded {
		if err := claimCloudInitDispatch(&uploadState); err != nil {
			return err
		}
	}
	if !intentAlreadyRecorded {
		if err := recordCloudInitUpload(recorder, uploadState, "record cloud-init upload intent"); err != nil {
			return err
		}
	}
	uploadState.Phase = capmox.CloudInitUploadPhaseDispatching
	if err := recordCloudInitUpload(recorder, uploadState, "revalidate cloud-init dispatch ownership"); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: cloud-init dispatch context ended after ownership validation: %w", capmox.ErrCloudInitUploadPending, err)
	}
	if cloudInitDispatchNow().Unix() >= uploadState.LeaseUntilUnix {
		return fmt.Errorf("%w: cloud-init dispatch ownership lease expired before POST", capmox.ErrCloudInitUploadPending)
	}

	uploadTask, proven, err := uploadCloudInitISO(ctx, &contextCloudInitStorage{storage: storage, transport: c.uploadTransport, node: vm.Node, address: uploadAddress}, storage.Name, isoPath, isoName, digest, size)
	if err != nil {
		return err
	}
	if !proven {
		if uploadTask == nil {
			return errors.New("cloud-init ISO upload returned no task")
		}
		uploadState.UPID = string(uploadTask.UPID)
		uploadState.Phase = capmox.CloudInitUploadPhaseAccepted
		if err := recordCloudInitUpload(recorder, uploadState, "record accepted cloud-init upload task"); err != nil {
			return err
		}
		if err := waitForCloudInitEffect(ctx, uploadTask, 5, "cloud-init ISO upload", true, func() error {
			return requireCloudInitISO(ctx, storage, storage.Name, isoName, size)
		}); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("%w: cloud-init upload wait ended with reconciliation context: %w", capmox.ErrCloudInitUploadPending, ctxErr)
			}
			return err
		}
	}
	uploadState.Phase = capmox.CloudInitUploadPhaseComplete
	if err := recordCloudInitUpload(recorder, uploadState, "record completed cloud-init upload"); err != nil {
		return err
	}
	return finishCloudInitMount(ctx, vm, machineIdentity, device, expectedVolID)
}

func (c *APIClient) selectCloudInitUploadTarget(ctx context.Context, node *proxmox.Node, vm *proxmox.VirtualMachine, machineIdentity, device, isoName string, size uint64) (*cloudInitUploadSelection, string, error) {
	selection, err := findCloudInitUploadTarget(ctx, node, machineIdentity, isoName, size)
	if err != nil {
		return nil, "", fmt.Errorf("find exact cloud-init ISO upload target on node %q: %w", vm.Node, err)
	}
	expectedVolID := fmt.Sprintf("%s:iso/%s", selection.storage.Name, isoName)
	if selection.supersededStorage != nil {
		if err := c.reconcileSupersededCloudInitArtifact(ctx, vm, machineIdentity, device, expectedVolID, selection.supersededStorage, selection.supersededVolID); err != nil {
			return nil, "", err
		}
	}
	return selection, expectedVolID, nil
}

func (c *APIClient) resolveCloudInitUploadAddress(ctx context.Context, nodeName string) (netip.Addr, error) {
	cluster := (&proxmox.Cluster{}).New(c.Client)
	if err := cluster.Status(ctx); err != nil {
		return netip.Addr{}, fmt.Errorf("%w: discover cloud-init upload node %q from cluster status: %w", capmox.ErrCloudInitUploadPending, nodeName, err)
	}
	var match *proxmox.NodeStatus
	for _, node := range cluster.Nodes {
		if node == nil || node.Name != nodeName {
			continue
		}
		if match != nil {
			return netip.Addr{}, fmt.Errorf("%w: cluster status returned multiple exact matches for cloud-init upload node %q", capmox.ErrCloudInitUploadPending, nodeName)
		}
		match = node
	}
	if match == nil {
		return netip.Addr{}, fmt.Errorf("%w: cluster status has no exact match for cloud-init upload node %q", capmox.ErrCloudInitUploadPending, nodeName)
	}
	if match.Online != 1 {
		return netip.Addr{}, fmt.Errorf("%w: cloud-init upload node %q is not online in cluster status", capmox.ErrCloudInitUploadPending, nodeName)
	}
	address, err := netip.ParseAddr(match.IP)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%w: cloud-init upload node %q has invalid cluster-status IP %q", capmox.ErrCloudInitUploadPending, nodeName, match.IP)
	}
	return address, nil
}

func finishCloudInitMount(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: exact cloud-init upload is complete; defer mount after reconciliation cancellation: %w", capmox.ErrCloudInitUploadPending, err)
	}
	if err := mountCloudInitISO(ctx, vm, machineIdentity, device, expectedVolID); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: cloud-init mount outcome requires successor reconciliation: %w", capmox.ErrCloudInitUploadPending, ctxErr)
		}
		return err
	}
	return nil
}

func (c *APIClient) prepareCloudInitAttempt(ctx context.Context, node *proxmox.Node, vm *proxmox.VirtualMachine, machineIdentity, device, isoName string, size uint64, current *capmox.CloudInitUpload, recorder capmox.CloudInitUploadRecorder) (uint64, bool, bool, error) {
	if current == nil {
		return 1, false, false, nil
	}
	recordedNode := node
	if current.Node != vm.Node {
		var err error
		recordedNode, err = c.Client.Node(ctx, current.Node)
		if err != nil {
			return 0, false, false, fmt.Errorf("get recorded cloud-init node %q: %w", current.Node, err)
		}
	}
	handled, rearmed, err := c.resumeCloudInitUpload(ctx, recordedNode, vm, machineIdentity, device, isoName, size, current, recorder)
	if err != nil || handled {
		return 0, false, handled, err
	}
	if rearmed {
		return current.Attempt, true, false, nil
	}
	if current.Attempt == ^uint64(0) {
		return 0, false, false, errors.New("cloud-init upload attempt generation overflow")
	}
	if current.Attempt > 0 {
		return current.Attempt + 1, false, false, nil
	}
	return 1, false, false, nil
}

func (c *APIClient) resumeCloudInitUpload(ctx context.Context, node *proxmox.Node, vm *proxmox.VirtualMachine, machineIdentity, device, isoName string, size uint64, current *capmox.CloudInitUpload, recorder capmox.CloudInitUploadRecorder) (bool, bool, error) {
	if current.Version != 1 || current.Node != node.Name || current.Storage == "" || current.Size == 0 {
		return true, false, fmt.Errorf("invalid durable cloud-init upload state: version=%d node=%q storage=%q size=%d", current.Version, current.Node, current.Storage, current.Size)
	}
	expectedVolID := current.Storage + ":iso/" + isoName
	exact := current.VolID == expectedVolID && current.Size == size
	if !exact {
		if err := c.reconcileMismatchedCloudInitUpload(ctx, node, vm, machineIdentity, device, expectedVolID, current); err != nil {
			return true, false, err
		}
		return false, false, nil
	}
	storage, err := node.Storage(ctx, current.Storage)
	if err != nil {
		return true, false, fmt.Errorf("%w: get recorded storage %q: %v", capmox.ErrCloudInitUploadPending, current.Storage, err)
	}
	switch current.Phase {
	case capmox.CloudInitUploadPhaseIntent, capmox.CloudInitUploadPhaseDispatching:
		rearmed, err := c.resumeUnacknowledgedCloudInitUpload(ctx, node, storage, isoName, size, current, recorder)
		if err != nil {
			return true, false, err
		}
		if rearmed {
			return false, true, nil
		}
	case capmox.CloudInitUploadPhaseAccepted:
		if err := c.resumeAcceptedCloudInitUpload(ctx, node, storage, isoName, size, current); err != nil {
			return true, false, err
		}
	case capmox.CloudInitUploadPhaseComplete:
		present, proofErr := inspectCloudInitISO(ctx, storage, current.Storage, isoName, size)
		if proofErr != nil {
			if errors.Is(proofErr, errCloudInitStorageInventoryUnavailable) {
				return true, false, fmt.Errorf("%w: completed durable upload storage proof is temporarily unavailable: %v", capmox.ErrCloudInitUploadPending, proofErr)
			}
			return true, false, fmt.Errorf("completed durable upload lost exact artifact proof: %w", proofErr)
		}
		if !present {
			return true, false, fmt.Errorf("completed durable upload lost exact artifact proof: exact volume %q is absent", current.VolID)
		}
	default:
		return true, false, fmt.Errorf("invalid durable cloud-init upload phase %q", current.Phase)
	}
	if current.Phase != capmox.CloudInitUploadPhaseComplete {
		completed := *current
		completed.Phase = capmox.CloudInitUploadPhaseComplete
		if err := recordCloudInitUpload(recorder, completed, "record resumed cloud-init upload completion"); err != nil {
			return true, false, err
		}
	}
	if err := mountCloudInitISO(ctx, vm, machineIdentity, device, expectedVolID); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return true, false, fmt.Errorf("%w: resumed cloud-init mount outcome requires successor reconciliation: %w", capmox.ErrCloudInitUploadPending, ctxErr)
		}
		return true, false, err
	}
	return true, false, nil
}

func (c *APIClient) reconcileLegacyCloudInitMount(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device string) error {
	if vm.VirtualMachineConfig == nil || !vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)) {
		return nil
	}
	if !isLegacyCloudInitVolume(cloudInitDeviceValue(vm, device), vm.VMID) {
		return nil
	}
	if err := c.UnmountCloudInitISO(ctx, vm, machineIdentity, device); err != nil {
		return fmt.Errorf("reconcile legacy cloud-init artifact before content-addressed upload: %w", err)
	}
	return nil
}

func isLegacyCloudInitVolume(deviceValue string, vmID proxmox.StringOrUint64) bool {
	_, _, err := legacyCloudInitVolume(deviceValue, vmID)
	return err == nil
}

func (c *APIClient) reconcileMismatchedCloudInitUpload(ctx context.Context, node *proxmox.Node, vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string, current *capmox.CloudInitUpload) error {
	if current.Phase != capmox.CloudInitUploadPhaseComplete {
		if err := c.reconcileRecordedCloudInitUpload(ctx, node, machineIdentity, current); err != nil {
			return fmt.Errorf("%w: reconcile superseded durable upload: %v", capmox.ErrCloudInitUploadPending, err)
		}
		return nil
	}
	if err := validateRecordedCloudInitUpload(node, machineIdentity, current); err != nil {
		return fmt.Errorf("invalid superseded durable upload: %w", err)
	}
	storage, err := node.Storage(ctx, current.Storage)
	if err != nil {
		return fmt.Errorf("%w: get superseded recorded storage %q: %v", capmox.ErrCloudInitUploadPending, current.Storage, err)
	}
	if err := c.reconcileSupersededCloudInitArtifact(ctx, vm, machineIdentity, device, expectedVolID, storage, current.VolID); err != nil {
		return fmt.Errorf("%w: reconcile mounted superseded durable upload: %v", capmox.ErrCloudInitUploadPending, err)
	}
	return nil
}

func (c *APIClient) resumeAcceptedCloudInitUpload(ctx context.Context, node *proxmox.Node, storage cloudInitStorage, isoName string, size uint64, current *capmox.CloudInitUpload) error {
	if current.UPID == "" {
		return errors.New("accepted durable cloud-init upload has no task UPID")
	}
	task, taskErr := c.GetTask(ctx, current.UPID)
	if taskErr != nil {
		return resumeAcceptedCloudInitWithoutTask(ctx, node, storage, isoName, size, current, taskErr.Error())
	}
	waitErr := waitForCloudInitTask(ctx, task, 2)
	if task.IsFailed || (task.ExitStatus != "" && task.ExitStatus != "OK") {
		return fmt.Errorf("accepted cloud-init upload task failed with exit status %q", task.ExitStatus)
	}
	if proofErr := requireCloudInitISO(ctx, storage, current.Storage, isoName, size); proofErr != nil {
		return fmt.Errorf("%w: accepted upload is not yet proven (wait=%v proof=%v)", capmox.ErrCloudInitUploadPending, waitErr, proofErr)
	}
	return nil
}

func resumeAcceptedCloudInitWithoutTask(ctx context.Context, node *proxmox.Node, storage cloudInitStorage, isoName string, size uint64, current *capmox.CloudInitUpload, taskError string) error {
	present, proofErr := proveCloudInitUploadWithoutTask(ctx, node, storage, current.Storage, isoName, size)
	if proofErr != nil {
		return fmt.Errorf("%w: accepted upload task %q is unavailable (%s) and exact recovery proof failed: %v", capmox.ErrCloudInitUploadPending, current.UPID, taskError, proofErr)
	}
	if !present {
		return fmt.Errorf("accepted cloud-init upload task %q is unavailable and its exact artifact is absent after upload quiescence: %s", current.UPID, taskError)
	}
	return nil
}

func proveCloudInitUploadWithoutTask(ctx context.Context, node *proxmox.Node, storage cloudInitStorage, storageName, isoName string, size uint64) (bool, error) {
	present, err := inspectCloudInitISO(ctx, storage, storageName, isoName, size)
	if err != nil {
		return false, fmt.Errorf("inspect exact upload artifact: %w", err)
	}
	if err := requireCloudInitUploadQuiescence(ctx, node); err != nil {
		return false, err
	}
	return present, nil
}

func (c *APIClient) resumeUnacknowledgedCloudInitUpload(ctx context.Context, node *proxmox.Node, storage cloudInitStorage, isoName string, size uint64, current *capmox.CloudInitUpload, recorder capmox.CloudInitUploadRecorder) (bool, error) {
	if current.DispatchOwner == "" && current.LeaseUntilUnix != 0 {
		return false, errors.New("cloud-init upload intent has a lease without an owner")
	}
	if current.Phase == capmox.CloudInitUploadPhaseDispatching && current.DispatchOwner == "" {
		return false, errors.New("dispatching cloud-init upload has no durable owner")
	}
	if current.DispatchOwner != "" && current.LeaseUntilUnix > cloudInitDispatchNow().Unix() {
		return false, fmt.Errorf("%w: durable cloud-init dispatch owner %q remains live", capmox.ErrCloudInitUploadPending, current.DispatchOwner)
	}
	present, inspectErr := inspectCloudInitISO(ctx, storage, current.Storage, isoName, size)
	if inspectErr != nil {
		return false, fmt.Errorf("%w: inspect exact intent artifact: %v", capmox.ErrCloudInitUploadPending, inspectErr)
	}
	if err := requireCloudInitUploadQuiescence(ctx, node); err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if current.Attempt == ^uint64(0) {
		return false, errors.New("cloud-init upload attempt generation overflow")
	}
	rearmed := *current
	rearmed.Attempt++
	if rearmed.Attempt == 0 {
		rearmed.Attempt = 1
	}
	rearmed.Phase = capmox.CloudInitUploadPhaseIntent
	if err := claimCloudInitDispatch(&rearmed); err != nil {
		return false, err
	}
	if err := recordCloudInitUpload(recorder, rearmed, "rearm quiescent cloud-init upload intent"); err != nil {
		return false, err
	}
	*current = rearmed
	return true, nil
}

func recordCloudInitUpload(recorder capmox.CloudInitUploadRecorder, upload capmox.CloudInitUpload, boundary string) error {
	if err := recorder(upload); err != nil {
		return fmt.Errorf("%w: %s: %w", capmox.ErrCloudInitUploadPending, boundary, err)
	}
	return nil
}

func claimCloudInitDispatch(upload *capmox.CloudInitUpload) error {
	owner, err := cloudInitDispatchID()
	if err != nil {
		return fmt.Errorf("create cloud-init dispatch owner: %w", err)
	}
	upload.DispatchOwner = owner
	upload.LeaseUntilUnix = cloudInitDispatchNow().Add(cloudInitDispatchLease).Unix()
	upload.UPID = ""
	upload.Phase = capmox.CloudInitUploadPhaseIntent
	return nil
}

func requireCloudInitUploadQuiescence(ctx context.Context, node *proxmox.Node) error {
	tasks, err := node.Tasks(ctx, &proxmox.NodeTasksOptions{Limit: 1, Source: "active", TypeFilter: "imgcopy"})
	if err != nil {
		return fmt.Errorf("%w: inspect active PVE cloud-init upload tasks: %v", capmox.ErrCloudInitUploadPending, err)
	}
	if len(tasks) != 0 {
		return fmt.Errorf("%w: an active PVE imgcopy task may still materialize the recorded cloud-init artifact", capmox.ErrCloudInitUploadPending)
	}
	return nil
}

func validateCloudInitTargetDevice(vm *proxmox.VirtualMachine, machineIdentity, device string) error {
	if device != cloudInitDevice {
		return fmt.Errorf("cloud-init target device %q is not supported", device)
	}
	deviceValue := cloudInitDeviceValue(vm, device)
	if deviceValue == "" || deviceValue == cloudInitUnmountedDeviceValue {
		return nil
	}
	if _, _, err := ownedCloudInitVolume(deviceValue, machineIdentity); err == nil {
		return nil
	}
	if err := validatePVECloudInitPlaceholder(deviceValue, vm.VMID); err != nil {
		return fmt.Errorf("cloud-init target device %q is occupied by foreign state: %w", device, err)
	}
	return nil
}

func cloudInitDeviceValue(vm *proxmox.VirtualMachine, device string) string {
	if vm.VirtualMachineConfig == nil || device != cloudInitDevice {
		return ""
	}
	return vm.VirtualMachineConfig.IDE0
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
		if !isAmbiguousTransportError(err) {
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

type cloudInitUploadSelection struct {
	storage              *proxmox.Storage
	supersededStorage    *proxmox.Storage
	supersededVolID      string
	exactArtifactPresent bool
}

func findCloudInitUploadTarget(ctx context.Context, node *proxmox.Node, machineIdentity, isoName string, size uint64) (*cloudInitUploadSelection, error) {
	storages, err := node.Storages(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list node storages: %v", capmox.ErrCloudInitStorageDiscoveryRetryable, err)
	}
	var eligible *proxmox.Storage
	var matched *proxmox.Storage
	var supersededStorage *proxmox.Storage
	var supersededVolID string
	for _, storage := range storages {
		if !cloudInitISOStorageEligible(storage) {
			continue
		}
		contents, err := storage.GetContent(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect relevant ISO storage %q: %v", capmox.ErrCloudInitStorageDiscoveryRetryable, storage.Name, err)
		}
		expectedVolID := fmt.Sprintf("%s:iso/%s", storage.Name, isoName)
		candidate, found, err := ownedCloudInitCandidate(contents, machineIdentity)
		if err != nil {
			return nil, err
		}
		if !found {
			if storage.Avail >= size && (eligible == nil || storage.Name < eligible.Name) {
				eligible = storage
			}
			continue
		}
		if candidate != expectedVolID {
			if supersededStorage != nil {
				return nil, fmt.Errorf("multiple superseded cloud-init artifacts found for Machine %q", machineIdentity)
			}
			supersededStorage = storage
			supersededVolID = candidate
			for _, content := range contents {
				if content.Volid != candidate {
					continue
				}
				if content.Format != cloudInitISOContentType {
					return nil, fmt.Errorf("superseded volume %q has unexpected format %q", candidate, content.Format)
				}
				if (storage.Avail >= size || content.Size >= size-storage.Avail) && (eligible == nil || storage.Name < eligible.Name) {
					eligible = storage
				}
				break
			}
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
			if !cloudInitISOStorageEligible(storage) {
				return nil, fmt.Errorf("exact cloud-init artifact %q exists on ineligible storage %q", isoName, storage.Name)
			}
			matched = storage
		}
	}
	if matched != nil {
		return &cloudInitUploadSelection{storage: matched, supersededStorage: supersededStorage, supersededVolID: supersededVolID, exactArtifactPresent: true}, nil
	}
	if eligible == nil {
		return nil, fmt.Errorf("%w: no enabled ISO storage has %d bytes available", capmox.ErrCloudInitStorageDiscoveryRetryable, size)
	}
	return &cloudInitUploadSelection{storage: eligible, supersededStorage: supersededStorage, supersededVolID: supersededVolID}, nil
}

func (c *APIClient) reconcileSupersededCloudInitArtifact(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, expectedVolID string, storage *proxmox.Storage, supersededVolID string) error {
	deviceValue := cloudInitDeviceValue(vm, device)
	if deviceValue != "" && deviceValue != cloudInitUnmountedDeviceValue {
		_, mountedVolID, err := ownedCloudInitVolume(deviceValue, machineIdentity)
		if err != nil {
			if placeholderErr := validatePVECloudInitPlaceholder(deviceValue, vm.VMID); placeholderErr != nil {
				return fmt.Errorf("cannot reconcile superseded cloud-init artifact while target device is foreign: %w", err)
			}
		} else {
			switch mountedVolID {
			case supersededVolID:
				if err := c.UnmountCloudInitISO(ctx, vm, machineIdentity, device); err != nil {
					return fmt.Errorf("unmount superseded cloud-init artifact %q: %w", supersededVolID, err)
				}
				if err := vm.Ping(ctx); err != nil {
					return fmt.Errorf("refetch VM after superseded cloud-init cleanup: %w", err)
				}
				if err := addCloudInitOwnershipTag(ctx, vm); err != nil {
					return fmt.Errorf("restore cloud-init ownership tag after superseded cleanup: %w", err)
				}
				return nil
			case expectedVolID:
				// The superseded artifact is unattached; delete it below.
			default:
				return fmt.Errorf("cloud-init device mounts %q while reconciling superseded volume %q", mountedVolID, supersededVolID)
			}
		}
	}
	if _, err := deleteOwnedCloudInitVolume(ctx, storage, supersededVolID); err != nil {
		return fmt.Errorf("delete unattached superseded cloud-init artifact %q: %w", supersededVolID, err)
	}
	return nil
}

func addCloudInitOwnershipTag(ctx context.Context, vm *proxmox.VirtualMachine) error {
	tagTask, err := vm.AddTag(ctx, proxmox.MakeTag(proxmox.TagCloudInit))
	if err != nil {
		if proxmox.IsErrNoop(err) {
			return nil
		}
		if !isAmbiguousTransportError(err) {
			return err
		}
		if proofErr := requireCloudInitOwnershipTag(ctx, vm); proofErr != nil {
			return fmt.Errorf("cloud-init ownership tag response was ambiguous (%w) and exact tag proof failed: %v", err, proofErr)
		}
		return nil
	}
	if tagTask == nil {
		return errors.New("cloud-init ownership tag returned no task")
	}
	waitErr := waitForCloudInitTask(ctx, tagTask, 2)
	if tagTask.IsFailed || (tagTask.ExitStatus != "" && tagTask.ExitStatus != "OK") {
		return fmt.Errorf("cloud-init ownership tag task failed with exit status %q", tagTask.ExitStatus)
	}
	if waitErr != nil {
		if proofErr := requireCloudInitOwnershipTag(ctx, vm); proofErr != nil {
			return fmt.Errorf("cloud-init ownership tag task wait was ambiguous (%w) and exact tag proof failed: %v", waitErr, proofErr)
		}
	}
	return nil
}

func requireCloudInitOwnershipTag(ctx context.Context, vm *proxmox.VirtualMachine) error {
	if err := vm.Ping(ctx); err != nil {
		return fmt.Errorf("refetch VM config: %w", err)
	}
	if !vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)) {
		return errors.New("cloud-init ownership tag is absent")
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

func uploadCloudInitISO(ctx context.Context, storage cloudInitUploadStorage, storageName, isoPath, isoName, digest string, size uint64) (*proxmox.Task, bool, error) {
	present, err := inspectCloudInitISO(ctx, storage, storageName, isoName, size)
	if err != nil {
		return nil, false, fmt.Errorf("cloud-init ISO preflight failed: %w", err)
	}
	if present {
		return nil, true, nil
	}

	task, err := storage.UploadWithHash(ctx, cloudInitISOContentType, isoPath, &isoName, digest, "sha256")
	if err == nil {
		return task, false, nil
	}
	if !isAmbiguousTransportError(err) {
		return nil, false, err
	}

	proofCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	present, proofErr := inspectCloudInitISO(proofCtx, storage, storageName, isoName, size)
	if proofErr != nil {
		return nil, false, fmt.Errorf("cloud-init ISO upload response was ambiguous (%w) and storage proof failed: %v", err, proofErr)
	}
	if !present {
		return nil, false, fmt.Errorf("%w: cloud-init ISO upload response was ambiguous and exact volume %q is not yet visible: %w", capmox.ErrCloudInitUploadPending, fmt.Sprintf("%s:iso/%s", storageName, isoName), err)
	}
	return nil, true, nil
}

func isAmbiguousTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var syntaxErr *json.SyntaxError
	return errors.As(err, &syntaxErr)
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
		return false, fmt.Errorf("%w: %w", errCloudInitStorageInventoryUnavailable, err)
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
	if !strings.HasPrefix(existing, "order=") {
		return existing
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
	if vm.VirtualMachineConfig == nil || device != cloudInitDevice {
		return false, fmt.Errorf("unable to prove cloud-init mount device %q", device)
	}
	deviceValue := vm.VirtualMachineConfig.IDE0
	if deviceValue == "" || deviceValue == cloudInitUnmountedDeviceValue {
		return false, nil
	}
	_, mountedVolID, err := ownedCloudInitVolume(deviceValue, machineIdentity)
	if err != nil {
		if placeholderErr := validatePVECloudInitPlaceholder(deviceValue, vm.VMID); placeholderErr == nil {
			return false, nil
		}
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

func parseCloudInitISOMount(deviceValue string) (storageName, volID, name string, err error) {
	parts := strings.Split(deviceValue, ",")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("cloud-init device is not an exact ISO mount")
	}
	if err := validateCloudInitMountOptions(parts[1:]); err != nil {
		return "", "", "", err
	}
	storageAndName := strings.Split(parts[0], ":iso/")
	if len(storageAndName) != 2 || !isSafePVEStorageName(storageAndName[0]) {
		return "", "", "", fmt.Errorf("cloud-init device has invalid storage volume identity")
	}
	return storageAndName[0], parts[0], storageAndName[1], nil
}

func validatePVECloudInitPlaceholder(deviceValue string, vmID proxmox.StringOrUint64) error {
	parts := strings.Split(deviceValue, ",")
	if len(parts) < 2 {
		return fmt.Errorf("cloud-init placeholder is not an exact CD-ROM mount")
	}
	if err := validateCloudInitMountOptions(parts[1:]); err != nil {
		return err
	}
	storageAndName := strings.Split(parts[0], ":")
	if len(storageAndName) != 2 || !isSafePVEStorageName(storageAndName[0]) {
		return fmt.Errorf("cloud-init placeholder has invalid storage volume identity")
	}
	expectedName := fmt.Sprintf("vm-%d-cloudinit", vmID)
	if storageAndName[1] != expectedName {
		return fmt.Errorf("cloud-init placeholder is not the exact same-VM artifact %q", expectedName)
	}
	return nil
}

func validateCloudInitMountOptions(options []string) error {
	seenMedia := false
	seenSize := false
	for _, option := range options {
		switch {
		case option == "media=cdrom":
			if seenMedia {
				return fmt.Errorf("cloud-init device has duplicate media option")
			}
			seenMedia = true
		case strings.HasPrefix(option, "media="):
			return fmt.Errorf("cloud-init device has conflicting media option")
		case strings.HasPrefix(option, "size="):
			if seenSize || !isNormalizedPVESize(strings.TrimPrefix(option, "size=")) {
				return fmt.Errorf("cloud-init device has invalid normalized size option")
			}
			seenSize = true
		default:
			return fmt.Errorf("cloud-init device has unsupported normalized option %q", option)
		}
	}
	if !seenMedia {
		return fmt.Errorf("cloud-init device is missing media=cdrom")
	}
	return nil
}

func ownedCloudInitVolume(deviceValue, machineIdentity string) (storageName, volID string, err error) {
	storageName, volID, name, err := parseCloudInitISOMount(deviceValue)
	if err != nil {
		return "", "", err
	}
	prefix := cloudInitStorageFilenamePrefix + machineIdentity + "-"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".iso") {
		return "", "", fmt.Errorf("cloud-init device is not owned by Machine %q", machineIdentity)
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".iso")
	expectedName, nameErr := cloudInitISOName(machineIdentity, digest)
	if nameErr != nil || expectedName != name {
		return "", "", fmt.Errorf("cloud-init device has invalid content-addressed filename")
	}
	return storageName, volID, nil
}

func legacyCloudInitVolume(deviceValue string, vmID proxmox.StringOrUint64) (storageName, volID string, err error) {
	storageName, volID, name, err := parseCloudInitISOMount(deviceValue)
	if err != nil {
		return "", "", err
	}
	expectedName := fmt.Sprintf(proxmox.UserDataISOFormat, vmID)
	if name != expectedName {
		return "", "", fmt.Errorf("cloud-init device is not the exact legacy VMID artifact %q", expectedName)
	}
	return storageName, volID, nil
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
		if !isAmbiguousTransportError(err) {
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
