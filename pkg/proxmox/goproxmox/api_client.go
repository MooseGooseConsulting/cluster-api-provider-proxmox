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

// Package goproxmox implements a client for Proxmox resource lifecycle management.
package goproxmox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/luthermonson/go-proxmox"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/log"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
)

var _ capmox.Client = &APIClient{}

// ErrVMIDFree is returned if the VMID is free.
var ErrVMIDFree = errors.New("VMID is free")

const maxCloudInitUploadRequestBytes int64 = 16 << 20

// APIClient Proxmox API client object.
type APIClient struct {
	*proxmox.Client
	logger          logr.Logger
	uploadTransport *uploadContextTransport
}

type uploadContextTransport struct {
	base    http.RoundTripper
	serial  sync.Mutex
	mu      sync.RWMutex
	context context.Context
}

func (t *uploadContextTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "/upload") {
		t.mu.RLock()
		ctx := t.context
		t.mu.RUnlock()
		if ctx != nil {
			request = request.Clone(ctx)
		}
		if request.Body == nil {
			return nil, errors.New("cloud-init upload request requires a finite body")
		}
		if request.ContentLength <= 0 {
			_ = request.Body.Close()
			return nil, errors.New("cloud-init upload request requires a finite body")
		}
		if request.ContentLength > maxCloudInitUploadRequestBytes {
			_ = request.Body.Close()
			return nil, fmt.Errorf("cloud-init upload request exceeds %d-byte limit", maxCloudInitUploadRequestBytes)
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, request.ContentLength+1))
		closeErr := request.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("buffer cloud-init upload request: %w", err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close cloud-init upload request body: %w", closeErr)
		}
		if int64(len(body)) != request.ContentLength {
			return nil, fmt.Errorf("cloud-init upload request body length %d does not match Content-Length %d", len(body), request.ContentLength)
		}
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return t.base.RoundTrip(request)
}

func (t *uploadContextTransport) withContext(ctx context.Context, dispatch func() (*proxmox.Task, error)) (*proxmox.Task, error) {
	t.serial.Lock()
	defer t.serial.Unlock()
	t.mu.Lock()
	t.context = ctx
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.context = nil
		t.mu.Unlock()
	}()
	return dispatch()
}

// NewAPIClient initializes a Proxmox API client. If the client is misconfigured, an error is returned.
func NewAPIClient(ctx context.Context, logger logr.Logger, baseURL string, httpClient *http.Client, options ...proxmox.Option) (*APIClient, error) {
	proxmoxAPIURL, err := url.JoinPath(baseURL, "api2", "json")
	if err != nil {
		return nil, fmt.Errorf("invalid proxmox base URL %q: %w", baseURL, err)
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	baseTransport := httpClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	uploadTransport := &uploadContextTransport{base: baseTransport}
	contextClient := *httpClient
	contextClient.Transport = uploadTransport
	options = append(options, proxmox.WithHTTPClient(&contextClient), proxmox.WithLogger(capmox.Logger{}))
	upstreamClient := proxmox.NewClient(proxmoxAPIURL, options...)
	version, err := upstreamClient.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize proxmox api client: %w", err)
	}
	logger.Info("Proxmox client initialized")
	logger.Info("Proxmox server", "version", version.Release)

	return &APIClient{
		Client:          upstreamClient,
		logger:          logger,
		uploadTransport: uploadTransport,
	}, nil
}

// CloneVM clones a VM based on templateID and VMCloneRequest.
func (c *APIClient) CloneVM(ctx context.Context, templateID int, clone capmox.VMCloneRequest) (capmox.VMCloneResponse, error) {
	// get the node
	node := (&proxmox.Node{}).New(c.Client, clone.Node)
	if err := node.Status(ctx); err != nil {
		return capmox.VMCloneResponse{}, fmt.Errorf("cannot find node with name %s: %w", clone.Node, err)
	}

	// get the vm template
	vmTemplate, err := node.VirtualMachine(ctx, templateID)
	if err != nil {
		return capmox.VMCloneResponse{}, fmt.Errorf("unable to find vm template: %w", err)
	}

	vmOptions := proxmox.VirtualMachineCloneOptions{
		NewID:       clone.NewID,
		Description: clone.Description,
		Format:      clone.Format,
		Full:        clone.Full,
		Name:        clone.Name,
		Pool:        clone.Pool,
		SnapName:    clone.SnapName,
		Storage:     clone.Storage,
		Target:      clone.Target,
	}
	newID, task, err := vmTemplate.Clone(ctx, &vmOptions)
	if err != nil {
		return capmox.VMCloneResponse{}, fmt.Errorf("unable to create new vm: %w", err)
	}

	return capmox.VMCloneResponse{NewID: int64(newID), Task: task}, nil
}

// ConfigureVM updates a VMs settings.
func (c *APIClient) ConfigureVM(ctx context.Context, vm *proxmox.VirtualMachine, options ...capmox.VirtualMachineOption) (*proxmox.Task, error) {
	task, err := vm.Config(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to configure vm: %w", err)
	}
	return task, nil
}

// GetVM returns a VM based on nodeName and vmID.
func (c *APIClient) GetVM(ctx context.Context, nodeName string, vmID int64) (*proxmox.VirtualMachine, error) {
	node := (&proxmox.Node{}).New(c.Client, nodeName)
	if err := node.Status(ctx); err != nil {
		return nil, fmt.Errorf("cannot find node with name %s: %w", nodeName, err)
	}

	vm, err := node.VirtualMachine(ctx, int(vmID))
	if err != nil {
		return nil, fmt.Errorf("cannot find vm with id %d: %w", vmID, err)
	}

	return vm, nil
}

// FindVMResource tries to find a VM by its ID on the whole cluster.
func (c *APIClient) FindVMResource(ctx context.Context, vmID uint64) (*proxmox.ClusterResource, error) {
	cluster, err := c.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get cluster status: %w", err)
	}

	vmResources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return nil, fmt.Errorf("could not list vm resources: %w", err)
	}

	for _, vm := range vmResources {
		if vm.VMID == vmID {
			return vm, nil
		}
	}

	return nil, fmt.Errorf("unable to find VM with ID %d on any of the nodes", vmID)
}

// FindVMTemplateByTags tries to find a VMID by its tags across the whole cluster.
func (c *APIClient) FindVMTemplateByTags(ctx context.Context, templateTags []string, matchPolicy string) (string, int32, error) {
	logger := log.FromContext(ctx)

	cluster, err := c.Cluster(ctx)
	if err != nil {
		return "", -1, fmt.Errorf("cannot get cluster status: %w", err)
	}
	vmResources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return "", -1, fmt.Errorf("could not list vm resources: %w", err)
	}

	for i, tag := range templateTags {
		// Proxmox VM tags are always lowercase
		templateTags[i] = strings.ToLower(tag)
	}
	// compact templateTags because of collisions after lowercasing
	slices.Sort(templateTags)
	templateTags = slices.Compact(templateTags)

	var vmTemplate *proxmox.ClusterResource
	matches, bestDistance := 0, int(^uint(0)>>1)
NEXT_VM:
	for _, vm := range vmResources {
		if vm.Template == 0 || len(vm.Tags) == 0 {
			continue NEXT_VM
		}

		vmTagMap := make(map[string]string)
		for tag := range strings.SplitSeq(vm.Tags, ";") {
			vmTagMap[strings.ToLower(strings.TrimSpace(tag))] = ""
		}

		logger.V(4).Info("VM Template Tags", "Name", vm.Name, "Tags", maps.Values(vmTagMap))

		for _, tag := range templateTags {
			if _, exists := vmTagMap[tag]; !exists {
				continue NEXT_VM
			}
		}

		// distance is always >= 0 because all other cases already jump to NEXT_VM.
		distance := len(vmTagMap) - len(templateTags)
		switch infrav1.TemplateMatchPolicy(matchPolicy) {
		case infrav1.TemplateMatchPolicyExact:
			if distance != 0 {
				continue NEXT_VM
			}
		case infrav1.TemplateMatchPolicyBest:
			if distance > bestDistance {
				continue NEXT_VM
			}
			bestDistance = distance
		}

		matches++
		vmTemplate = vm
	}

	if matches != 1 {
		return "", -1, fmt.Errorf("%w: found %d VM templates with tags %q", ErrTemplateNotFound, matches, strings.Join(templateTags, ";"))
	}

	return vmTemplate.Node, int32(vmTemplate.VMID), nil
}

// DeleteVM deletes a VM based on the nodeName and vmID.
func (c *APIClient) DeleteVM(ctx context.Context, nodeName string, vmID int64, machineIdentity string, upload *capmox.CloudInitUpload) (*proxmox.Task, error) {
	// A vmID can not be lower than 100.
	// If the provided vmID is lower (like -1 in issue #31), just error out without calling the API.
	if vmID < 100 {
		return nil, fmt.Errorf("%w: vm id %d is below the minimum", ErrVMIDFree, vmID)
	}
	unlockDispatch := acquireCloudInitDispatch(machineIdentity)
	defer unlockDispatch()

	node := (&proxmox.Node{}).New(c.Client, nodeName)
	if err := node.Status(ctx); err != nil {
		return nil, fmt.Errorf("cannot find node with name %s: %w", nodeName, err)
	}
	recordedNode := node
	if upload != nil && upload.Node != "" && upload.Node != nodeName {
		recordedNode = (&proxmox.Node{}).New(c.Client, upload.Node)
		if err := recordedNode.Status(ctx); err != nil {
			return nil, fmt.Errorf("cannot find recorded cloud-init node with name %s: %w", upload.Node, err)
		}
	}

	cluster, err := c.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get cluster")
	}

	if upload != nil && upload.Phase != capmox.CloudInitUploadPhaseComplete {
		if err := c.reconcileRecordedCloudInitUpload(ctx, recordedNode, machineIdentity, upload); err != nil {
			return nil, fmt.Errorf("cannot reconcile recorded cloud-init upload before deleting vm id %d: %w", vmID, err)
		}
	}
	if vmidFree, err := cluster.CheckID(ctx, int(vmID)); vmidFree {
		if err := c.reconcileRecordedCloudInitUpload(ctx, recordedNode, machineIdentity, upload); err != nil {
			return nil, fmt.Errorf("cannot reconcile recorded cloud-init upload for absent vm id %d: %w", vmID, err)
		}
		recoverVolume := recoverOwnedCloudInitVolume
		if upload == nil {
			recoverVolume = recoverLegacyOwnedCloudInitVolume
		}
		storage, volID, cleanupErr := recoverVolume(ctx, node, machineIdentity)
		if cleanupErr != nil {
			return nil, fmt.Errorf("cannot recover untagged cloud-init ISO for absent vm id %d: %w", vmID, cleanupErr)
		}
		if storage != nil {
			if _, cleanupErr := deleteOwnedCloudInitVolume(ctx, storage, volID); cleanupErr != nil {
				return nil, fmt.Errorf("cannot delete untagged cloud-init ISO for absent vm id %d: %w", vmID, cleanupErr)
			}
		}
		return nil, ErrVMIDFree
	} else if err != nil {
		return nil, err
	}

	vm, err := node.VirtualMachine(ctx, int(vmID))
	if err != nil {
		return nil, fmt.Errorf("cannot find vm with id %d: %w", vmID, err)
	}

	if vm.IsRunning() {
		if _, err = vm.Stop(ctx); err != nil {
			return nil, fmt.Errorf("cannot stop vm id %d: %w", vmID, err)
		}
	}
	if err := c.cleanupCloudInitBeforeVMDeletion(ctx, vm, recordedNode, machineIdentity, upload); err != nil {
		return nil, fmt.Errorf("cannot clean cloud-init ISO before deleting vm id %d: %w", vmID, err)
	}

	task, err := vm.Delete(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot delete vm with id %d: %w", vmID, err)
	}

	return task, nil
}

func (c *APIClient) cleanupCloudInitBeforeVMDeletion(ctx context.Context, vm *proxmox.VirtualMachine, recordedNode *proxmox.Node, machineIdentity string, upload *capmox.CloudInitUpload) error {
	if vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)) {
		placeholderProven := upload != nil && vm.VirtualMachineConfig != nil && validatePVECloudInitPlaceholder(vm.VirtualMachineConfig.IDE0, vm.VMID) == nil
		var cleanupErr error
		if placeholderProven {
			if upload.Phase == capmox.CloudInitUploadPhaseComplete {
				cleanupErr = c.reconcileRecordedCloudInitUpload(ctx, recordedNode, machineIdentity, upload)
			}
			if cleanupErr == nil {
				cleanupErr = removeCloudInitOwnershipTag(ctx, vm)
			}
		} else {
			cleanupErr = c.UnmountCloudInitISO(ctx, vm, machineIdentity, "ide0")
			if cleanupErr == nil && upload != nil && upload.Phase == capmox.CloudInitUploadPhaseComplete {
				cleanupErr = c.reconcileRecordedCloudInitUpload(ctx, recordedNode, machineIdentity, upload)
			}
		}
		if cleanupErr != nil {
			return cleanupErr
		}
	} else if upload != nil && upload.Phase == capmox.CloudInitUploadPhaseComplete {
		if err := c.reconcileRecordedCloudInitUpload(ctx, recordedNode, machineIdentity, upload); err != nil {
			return err
		}
	}
	return nil
}

func (c *APIClient) reconcileRecordedCloudInitUpload(ctx context.Context, node *proxmox.Node, machineIdentity string, upload *capmox.CloudInitUpload) error {
	if upload == nil {
		return nil
	}
	if err := validateRecordedCloudInitUpload(node, machineIdentity, upload); err != nil {
		return err
	}
	storage, err := node.Storage(ctx, upload.Storage)
	if err != nil {
		return fmt.Errorf("get recorded cloud-init storage %q: %w", upload.Storage, err)
	}
	if err := c.waitForRecordedCloudInitUpload(ctx, node, upload); err != nil {
		return err
	}
	isoName := strings.TrimPrefix(upload.VolID, upload.Storage+":iso/")
	present, err := inspectCloudInitISO(ctx, storage, upload.Storage, isoName, upload.Size)
	if err != nil {
		return fmt.Errorf("inspect recorded cloud-init upload %q: %w", upload.VolID, err)
	}
	if !present {
		return nil
	}
	if _, err := deleteOwnedCloudInitVolume(ctx, storage, upload.VolID); err != nil {
		return fmt.Errorf("delete recorded cloud-init upload %q: %w", upload.VolID, err)
	}
	return nil
}

func validateRecordedCloudInitUpload(node *proxmox.Node, machineIdentity string, upload *capmox.CloudInitUpload) error {
	if upload.Version != 1 || upload.Node != node.Name || upload.Storage == "" || upload.Size == 0 {
		return fmt.Errorf("invalid cloud-init upload record: version=%d node=%q storage=%q size=%d", upload.Version, upload.Node, upload.Storage, upload.Size)
	}
	switch upload.Phase {
	case capmox.CloudInitUploadPhaseIntent:
		if upload.UPID != "" {
			return errors.New("cloud-init upload intent unexpectedly contains a task UPID")
		}
	case capmox.CloudInitUploadPhaseDispatching:
		if upload.UPID != "" || upload.DispatchOwner == "" || upload.LeaseUntilUnix == 0 {
			return errors.New("dispatching cloud-init upload has invalid durable ownership")
		}
	case capmox.CloudInitUploadPhaseAccepted:
		if upload.UPID == "" {
			return errors.New("accepted cloud-init upload has no task UPID")
		}
	case capmox.CloudInitUploadPhaseComplete:
	default:
		return fmt.Errorf("invalid cloud-init upload phase %q", upload.Phase)
	}
	prefix := upload.Storage + ":iso/" + cloudInitStorageFilenamePrefix + machineIdentity + "-"
	if !strings.HasPrefix(upload.VolID, prefix) || !strings.HasSuffix(upload.VolID, ".iso") {
		return fmt.Errorf("recorded cloud-init volume %q is not owned by Machine %q on storage %q", upload.VolID, machineIdentity, upload.Storage)
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(upload.VolID, prefix), ".iso")
	if _, err := cloudInitISOName(machineIdentity, digest); err != nil {
		return fmt.Errorf("invalid recorded cloud-init volume %q: %w", upload.VolID, err)
	}
	return nil
}

func (c *APIClient) waitForRecordedCloudInitUpload(ctx context.Context, node *proxmox.Node, upload *capmox.CloudInitUpload) error {
	if upload.Phase == capmox.CloudInitUploadPhaseIntent || upload.Phase == capmox.CloudInitUploadPhaseDispatching {
		if upload.DispatchOwner == "" && upload.LeaseUntilUnix != 0 {
			return errors.New("cloud-init upload intent has a lease without an owner")
		}
		if upload.DispatchOwner != "" && upload.LeaseUntilUnix > cloudInitDispatchNow().Unix() {
			return fmt.Errorf("%w: durable cloud-init dispatch owner %q remains live", capmox.ErrCloudInitUploadPending, upload.DispatchOwner)
		}
		if err := requireCloudInitUploadQuiescence(ctx, node); err != nil {
			return err
		}
	}
	if upload.UPID != "" && upload.Phase != capmox.CloudInitUploadPhaseComplete {
		task, err := c.GetTask(ctx, upload.UPID)
		if err != nil {
			storage, storageErr := node.Storage(ctx, upload.Storage)
			if storageErr != nil {
				return fmt.Errorf("%w: get recorded storage after upload task %q became unavailable: %v", capmox.ErrCloudInitUploadPending, upload.UPID, storageErr)
			}
			isoName := strings.TrimPrefix(upload.VolID, upload.Storage+":iso/")
			if _, proofErr := proveCloudInitUploadWithoutTask(ctx, node, storage, upload.Storage, isoName, upload.Size); proofErr != nil {
				return fmt.Errorf("%w: recorded upload task %q is unavailable (%v) and cleanup proof failed: %v", capmox.ErrCloudInitUploadPending, upload.UPID, err, proofErr)
			}
			return nil
		}
		waitErr := waitForCloudInitTask(ctx, task, 2)
		taskFailed := task.IsFailed || (task.ExitStatus != "" && task.ExitStatus != "OK")
		if waitErr != nil && !taskFailed {
			return fmt.Errorf("recorded cloud-init upload task %q is not terminal: %w", upload.UPID, waitErr)
		}
	}
	return nil
}

// CheckID checks if the vmid is available on the cluster.
// Returns true if the vmid is available, false if it is taken.
func (c *APIClient) CheckID(ctx context.Context, vmid int64) (bool, error) {
	cluster, err := c.Cluster(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot get cluster")
	}
	return cluster.CheckID(ctx, int(vmid))
}

// GetTask returns a task associated with upID.
func (c *APIClient) GetTask(ctx context.Context, upID string) (*proxmox.Task, error) {
	task := proxmox.NewTask(proxmox.UPID(upID), c.Client)

	err := task.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get task with UPID %s: %w", upID, err)
	}

	return task, nil
}

// GetReservableMemoryBytes returns the memory that can be reserved by a new VM, in bytes.
func (c *APIClient) GetReservableMemoryBytes(ctx context.Context, nodeName string, nodeMemoryAdjustment int64) (uint64, error) {
	node := (&proxmox.Node{}).New(c.Client, nodeName)

	if err := node.Status(ctx); err != nil {
		return 0, fmt.Errorf("cannot find node with name %s: %w", nodeName, err)
	}

	reservableMemory := uint64(float64(node.Memory.Total) / 100 * float64(nodeMemoryAdjustment))

	if nodeMemoryAdjustment == 0 {
		return node.Memory.Total, nil
	}

	vms, err := node.VirtualMachines(ctx)
	if err != nil {
		return 0, fmt.Errorf("cannot list vms for node %s: %w", nodeName, err)
	}

	for _, vm := range vms {
		// Ignore VM Templates, as they can't be started.
		if vm.Template {
			continue
		}
		if reservableMemory < vm.MaxMem {
			reservableMemory = 0
		} else {
			reservableMemory -= vm.MaxMem
		}
	}

	containers, err := node.Containers(ctx)
	if err != nil {
		return 0, fmt.Errorf("cannot list containers for node %s: %w", nodeName, err)
	}

	for _, ct := range containers {
		if reservableMemory < ct.MaxMem {
			reservableMemory = 0
		} else {
			reservableMemory -= ct.MaxMem
		}
	}

	return reservableMemory, nil
}

// ResizeDisk resizes a VM disk to the specified size.
func (c *APIClient) ResizeDisk(ctx context.Context, vm *proxmox.VirtualMachine, disk, size string) (*proxmox.Task, error) {
	return vm.ResizeDisk(ctx, disk, size)
}

// ResumeVM resumes the VM.
func (c *APIClient) ResumeVM(ctx context.Context, vm *proxmox.VirtualMachine) (*proxmox.Task, error) {
	return vm.Resume(ctx)
}

// StartVM starts the VM.
func (c *APIClient) StartVM(ctx context.Context, vm *proxmox.VirtualMachine) (*proxmox.Task, error) {
	return vm.Start(ctx)
}

// TagVM tags the VM.
func (c *APIClient) TagVM(ctx context.Context, vm *proxmox.VirtualMachine, tag string) (*proxmox.Task, error) {
	return vm.AddTag(ctx, tag)
}

// UnmountCloudInitISO unmounts the cloud-init ISO and deletes only the exact
// content-addressed volume mounted for the immutable ProxmoxMachine identity.
func (c *APIClient) UnmountCloudInitISO(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device string) error {
	if !vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)) {
		return nil
	}
	if vm.VirtualMachineConfig == nil || device != cloudInitDevice {
		return fmt.Errorf("unable to prove mounted cloud-init device %q", device)
	}
	node, err := c.Node(ctx, vm.Node)
	if err != nil {
		return fmt.Errorf("get cloud-init node: %w", err)
	}

	deviceValue := vm.VirtualMachineConfig.IDE0
	var storage *proxmox.Storage
	var volID string
	if deviceValue == "" || deviceValue == cloudInitUnmountedDeviceValue {
		storage, volID, err = recoverOwnedCloudInitVolume(ctx, node, machineIdentity)
		if err != nil {
			return err
		}
	} else {
		storageName, mountedVolID, proofErr := ownedCloudInitVolume(deviceValue, machineIdentity)
		if proofErr != nil {
			legacyStorageName, legacyVolID, legacyErr := legacyCloudInitVolume(deviceValue, vm.VMID)
			if legacyErr == nil {
				storageName, mountedVolID, proofErr = legacyStorageName, legacyVolID, nil
			} else {
				// A foreign target device is outside CAPMOX authority. Preserve it, but
				// still recover and delete the sole unattached Machine-owned artifact.
				storage, volID, err = recoverOwnedCloudInitVolume(ctx, node, machineIdentity)
				if err != nil {
					return fmt.Errorf("recover unattached cloud-init artifact while preserving foreign device: %w", err)
				}
			}
		}
		if proofErr == nil {
			storage, err = node.Storage(ctx, storageName)
			if err != nil {
				return fmt.Errorf("get cloud-init storage %q: %w", storageName, err)
			}
			if _, err := inspectOwnedCloudInitVolume(ctx, storage, mountedVolID); err != nil {
				return fmt.Errorf("inspect mounted cloud-init volume: %w", err)
			}
			volID = mountedVolID
			unmountTask, unmountErr := vm.Config(ctx, proxmox.VirtualMachineOption{Name: device, Value: cloudInitUnmountedDeviceValue})
			if unmountErr != nil {
				return fmt.Errorf("unable to unmount cloud-init iso: %w", unmountErr)
			}
			if err := waitForCloudInitEffect(ctx, unmountTask, 2, "cloud-init ISO unmount", false, func() error {
				return requireCloudInitUnmount(ctx, vm, device)
			}); err != nil {
				return err
			}
		}
	}
	if storage != nil {
		if _, err := deleteOwnedCloudInitVolume(ctx, storage, volID); err != nil {
			return fmt.Errorf("delete exact cloud-init volume %q: %w", volID, err)
		}
	}

	return removeCloudInitOwnershipTag(ctx, vm)
}

func removeCloudInitOwnershipTag(ctx context.Context, vm *proxmox.VirtualMachine) error {
	removeTagTask, err := vm.RemoveTag(ctx, proxmox.MakeTag(proxmox.TagCloudInit))
	if err != nil && !proxmox.IsErrNoop(err) {
		return err
	}
	if err == nil {
		waitErr := waitForCloudInitEffect(ctx, removeTagTask, 2, "cloud-init ownership tag removal", false, func() error {
			if err := vm.Ping(ctx); err != nil {
				return fmt.Errorf("refetch VM config: %w", err)
			}
			if vm.HasTag(proxmox.MakeTag(proxmox.TagCloudInit)) {
				return errors.New("cloud-init ownership tag remains present")
			}
			return nil
		})
		if waitErr != nil {
			if refreshErr := vm.Ping(ctx); refreshErr != nil {
				return fmt.Errorf("%w; refetch VM config after failed ownership tag removal: %v", waitErr, refreshErr)
			}
			return waitErr
		}
		return nil
	}
	return nil
}

func requireCloudInitUnmount(ctx context.Context, vm *proxmox.VirtualMachine, device string) error {
	if err := vm.Ping(ctx); err != nil {
		return fmt.Errorf("refetch VM config: %w", err)
	}
	if deviceValue := cloudInitDeviceValue(vm, device); deviceValue != "" && deviceValue != cloudInitUnmountedDeviceValue {
		return fmt.Errorf("cloud-init device %q remains mounted as %q", device, deviceValue)
	}
	return nil
}

func recoverOwnedCloudInitVolume(ctx context.Context, node *proxmox.Node, machineIdentity string) (*proxmox.Storage, string, error) {
	return recoverOwnedCloudInitVolumeFrom(ctx, node, machineIdentity, func(*proxmox.Storage) bool { return true })
}

func recoverLegacyOwnedCloudInitVolume(ctx context.Context, node *proxmox.Node, machineIdentity string) (*proxmox.Storage, string, error) {
	return recoverOwnedCloudInitVolumeFrom(ctx, node, machineIdentity, cloudInitISOStorageEligible)
}

func recoverOwnedCloudInitVolumeFrom(ctx context.Context, node *proxmox.Node, machineIdentity string, include func(*proxmox.Storage) bool) (*proxmox.Storage, string, error) {
	if _, err := cloudInitISOName(machineIdentity, strings.Repeat("0", cloudInitDigestLength)); err != nil {
		return nil, "", err
	}
	storages, err := node.Storages(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("list ISO storages for cloud-init recovery: %w", err)
	}
	var matchedStorage *proxmox.Storage
	var matchedVolID string
	for _, storage := range storages {
		if !include(storage) {
			continue
		}
		contents, err := storage.GetContent(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("inspect storage %q for cloud-init recovery: %w", storage.Name, err)
		}
		volID, found, err := ownedCloudInitCandidate(contents, machineIdentity)
		if err != nil {
			return nil, "", err
		}
		if !found {
			continue
		}
		if matchedStorage != nil {
			return nil, "", fmt.Errorf("multiple owned cloud-init volumes found for Machine %q", machineIdentity)
		}
		matchedStorage = storage
		matchedVolID = volID
	}
	return matchedStorage, matchedVolID, nil
}

func cloudInitISOStorageEligible(storage *proxmox.Storage) bool {
	return storage.Enabled != 0 && storageSupportsContent(storage.Content, cloudInitISOContentType)
}

func storageSupportsContent(configured, expected string) bool {
	for content := range strings.SplitSeq(configured, ",") {
		if content == expected {
			return true
		}
	}
	return false
}

// CloudInitStatus returns the cloud-init status of the VM.
func (c *APIClient) CloudInitStatus(ctx context.Context, vm *proxmox.VirtualMachine) (running bool, err error) {
	if err := c.QemuAgentStatus(ctx, vm); err != nil {
		return false, errors.Wrap(err, "error waiting for agent")
	}

	pid, err := vm.AgentExec(ctx, []string{"cloud-init", "status"}, "")
	if err != nil {
		return false, errors.Wrap(err, "unable to get cloud-init status")
	}

	status, err := vm.WaitForAgentExecExit(ctx, pid, 2)
	if err != nil {
		return false, errors.Wrap(err, "unable to wait for agent exec")
	}

	if status.Exited == 1 && status.ExitCode == 0 && strings.Contains(status.OutData, "running") {
		return true, nil
	}
	if status.Exited == 1 && status.ExitCode != 0 {
		return false, ErrCloudInitFailed
	}

	return false, nil
}

// QemuAgentStatus returns the qemu-agent status of the VM.
func (c *APIClient) QemuAgentStatus(ctx context.Context, vm *proxmox.VirtualMachine) error {
	if err := vm.WaitForAgent(ctx, 5); err != nil {
		return errors.Wrap(err, "error waiting for agent")
	}

	return nil
}
