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

package vmservice

import (
	"context"
	"fmt"
	"testing"

	lutherproxmox "github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/scheduler"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/scope"
)

func TestResolveCloneStorage_SER9UsesVmdata(t *testing.T) {
	require.Equal(t, "vmdata", resolveCloneStorage("pve-ser9", "local-zfs"))
	require.Equal(t, "vmdata", resolveCloneStorage("pve-ser9", ""))
	require.Equal(t, "local-zfs", resolveCloneStorage("pve-ser8", "local-zfs"))
	require.Equal(t, "local-zfs", resolveCloneStorage("pve-ser10", "local-zfs"))
}

func TestCreateVM_CloneOnNode_SameNodeNoMigrate(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTestWithCondition(t, infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.ProxmoxMachine.Spec.Storage = new("local-zfs")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"node1"}

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node1",
		Name:    "test",
		Full:    1,
		Storage: "local-zfs",
	}
	response := proxmox.VMCloneResponse{NewID: 200, Task: newTask()}
	proxmoxClient.EXPECT().GetReservableMemoryBytes(context.Background(), "node1", int64(100)).Return(^uint64(0), nil).Once()
	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(&lutherproxmox.VirtualMachine{Node: "node1", VMID: 123}, nil).Once()
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, "node1", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
}

func TestCreateVM_CloneOnNode_SER8LocalZFS(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTestWithCondition(t, infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.ProxmoxMachine.Spec.SourceNode = new("pve-ser10")
	machineScope.ProxmoxMachine.Spec.Storage = new("local-zfs")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"pve-ser8"}

	selectNextNode = func(context.Context, *scope.MachineScope) (string, error) {
		return "pve-ser8", nil
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "pve-ser8",
		Name:    "test",
		Full:    1,
		Storage: "local-zfs",
	}
	response := proxmox.VMCloneResponse{NewID: 200, Task: newTask()}
	proxmoxClient.EXPECT().GetVM(context.Background(), "pve-ser10", int64(123)).Return(&lutherproxmox.VirtualMachine{Node: "pve-ser10", VMID: 123}, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser10", "pve-ser8").Return(nil, nil).Once()
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser8", "pve-ser10").Return(nil, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, "pve-ser8", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
}

func TestCreateVM_CloneOnNode_SER9VmdataOverride(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTestWithCondition(t, infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.ProxmoxMachine.Spec.SourceNode = new("pve-ser10")
	machineScope.ProxmoxMachine.Spec.Storage = new("local-zfs")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"pve-ser9"}

	selectNextNode = func(context.Context, *scope.MachineScope) (string, error) {
		return "pve-ser9", nil
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "pve-ser9",
		Name:    "test",
		Full:    1,
		Storage: "vmdata",
	}
	response := proxmox.VMCloneResponse{NewID: 200, Task: newTask()}
	proxmoxClient.EXPECT().GetVM(context.Background(), "pve-ser10", int64(123)).Return(&lutherproxmox.VirtualMachine{Node: "pve-ser10", VMID: 123}, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser10", "pve-ser9").Return(nil, nil).Once()
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser9", "pve-ser10").Return(nil, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, "pve-ser9", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
}

func TestCreateVM_CloneOnNode_TemplateNotOnSourceNode(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTestWithCondition(t, infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.ProxmoxMachine.Spec.SourceNode = new("pve-ser10")
	machineScope.ProxmoxMachine.Spec.Storage = new("local-zfs")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"pve-ser9"}

	selectNextNode = func(context.Context, *scope.MachineScope) (string, error) {
		return "pve-ser9", nil
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "pve-ser9",
		Name:    "test",
		Full:    1,
		Storage: "vmdata",
	}
	response := proxmox.VMCloneResponse{NewID: 200, Task: newTask()}
	proxmoxClient.EXPECT().GetVM(context.Background(), "pve-ser10", int64(123)).Return(nil, fmt.Errorf("not found")).Once()
	proxmoxClient.EXPECT().FindVMResource(context.Background(), uint64(123)).Return(&lutherproxmox.ClusterResource{VMID: 123, Node: "pve-ser8"}, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser8", "pve-ser9").Return(nil, nil).Once()
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()
	proxmoxClient.EXPECT().MigrateVM(context.Background(), 123, "pve-ser9", "pve-ser10").Return(nil, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, "pve-ser9", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
}

func TestCreateVM_EmptyStorageKeepsTarget(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTestWithCondition(t, infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes = []string{"node1", "node2", "node3"}

	selectNextNode = func(context.Context, *scope.MachineScope) (string, error) {
		return "node3", nil
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	expectedOptions := proxmox.VMCloneRequest{Node: "node1", Name: "test", Target: "node3", Full: 1}
	response := proxmox.VMCloneResponse{NewID: 123, Task: newTask()}
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, "node3", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
}
