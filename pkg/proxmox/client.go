/*
Copyright 2023-2025 IONOS Cloud.

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

// Package proxmox defines Proxmox Client interface.
package proxmox

import (
	"context"

	"github.com/luthermonson/go-proxmox"
)

// CloudInitUpload records the durable identity and progress of one immutable
// cloud-init upload. Callers persist each update before CloudInit continues.
type CloudInitUpload struct {
	Version int    `json:"version"`
	Node    string `json:"node"`
	Storage string `json:"storage"`
	VolID   string `json:"volID"`
	Size    uint64 `json:"size"`
	UPID    string `json:"upid,omitempty"`
	Phase   string `json:"phase"`
}

// CloudInitUploadRecorder durably records an upload boundary.
type CloudInitUploadRecorder func(CloudInitUpload) error

const (
	// CloudInitUploadPhaseIntent means the exact target was durably recorded before dispatch.
	CloudInitUploadPhaseIntent = "intent"
	// CloudInitUploadPhaseAccepted means PVE returned a task UPID that was durably recorded.
	CloudInitUploadPhaseAccepted = "accepted"
	// CloudInitUploadPhaseComplete means the exact artifact was proven after task completion.
	CloudInitUploadPhaseComplete = "complete"
)

// Client Global Proxmox client interface.
type Client interface {
	CloneVM(ctx context.Context, templateID int, clone VMCloneRequest) (VMCloneResponse, error)

	ConfigureVM(ctx context.Context, vm *proxmox.VirtualMachine, options ...VirtualMachineOption) (*proxmox.Task, error)
	CloudInit(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device, userdata, metadata, vendordata, networkconfig string, recorder CloudInitUploadRecorder) error

	FindVMResource(ctx context.Context, vmID uint64) (*proxmox.ClusterResource, error)
	FindVMTemplateByTags(ctx context.Context, templateTags []string, resolutionPolicy string) (string, int32, error)

	CheckID(ctx context.Context, vmID int64) (bool, error)

	GetVM(ctx context.Context, nodeName string, vmID int64) (*proxmox.VirtualMachine, error)

	DeleteVM(ctx context.Context, nodeName string, vmID int64, machineIdentity string, upload *CloudInitUpload) (*proxmox.Task, error)

	GetTask(ctx context.Context, upID string) (*proxmox.Task, error)

	GetReservableMemoryBytes(ctx context.Context, nodeName string, nodeMemoryAdjustment int64) (uint64, error)

	ResizeDisk(ctx context.Context, vm *proxmox.VirtualMachine, disk, size string) (*proxmox.Task, error)

	ResumeVM(ctx context.Context, vm *proxmox.VirtualMachine) (*proxmox.Task, error)

	StartVM(ctx context.Context, vm *proxmox.VirtualMachine) (*proxmox.Task, error)

	TagVM(ctx context.Context, vm *proxmox.VirtualMachine, tag string) (*proxmox.Task, error)

	UnmountCloudInitISO(ctx context.Context, vm *proxmox.VirtualMachine, machineIdentity, device string) error

	CloudInitStatus(ctx context.Context, vm *proxmox.VirtualMachine) (bool, error)

	QemuAgentStatus(ctx context.Context, vm *proxmox.VirtualMachine) error
}
