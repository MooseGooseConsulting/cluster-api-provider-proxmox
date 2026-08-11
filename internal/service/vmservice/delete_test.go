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

package vmservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	capmox "github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox/goproxmox"
)

func TestDeleteVM_SuccessNotFound(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.ProxmoxMachine.Spec.VirtualMachineID = new(int64(vm.VMID))
	machineScope.InfraCluster.ProxmoxCluster.AddNodeLocation(infrav1.NodeLocation{
		Machine: corev1.LocalObjectReference{Name: machineScope.Name()},
		Node:    "node1",
	}, false)

	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), (*capmox.CloudInitUpload)(nil)).Return(nil, goproxmox.ErrVMIDFree).Once()

	require.NoError(t, DeleteVM(context.TODO(), machineScope))
	require.Empty(t, machineScope.ProxmoxMachine.Finalizers)
	require.Empty(t, machineScope.InfraCluster.ProxmoxCluster.GetNode(machineScope.Name(), false))
}

func TestDeleteVMDoesNotTreatCleanupMessageAsVMAbsence(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.ProxmoxMachine.Spec.VirtualMachineID = new(int64(vm.VMID))
	machineScope.InfraCluster.ProxmoxCluster.AddNodeLocation(infrav1.NodeLocation{
		Machine: corev1.LocalObjectReference{Name: machineScope.Name()},
		Node:    "node1",
	}, false)
	cleanupErr := errors.New("recorded cloud-init storage does not exist")
	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), (*capmox.CloudInitUpload)(nil)).Return(nil, cleanupErr).Once()

	err := DeleteVM(context.TODO(), machineScope)
	require.ErrorIs(t, err, cleanupErr)
	require.NotEmpty(t, machineScope.ProxmoxMachine.Finalizers)
	require.NotEmpty(t, machineScope.InfraCluster.ProxmoxCluster.GetNode(machineScope.Name(), false))
}

func TestDeleteVMPreservesFinalizerUntilRecordedUploadIsReconciled(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.ProxmoxMachine.Spec.VirtualMachineID = new(int64(vm.VMID))
	machineScope.InfraCluster.ProxmoxCluster.AddNodeLocation(infrav1.NodeLocation{
		Machine: corev1.LocalObjectReference{Name: machineScope.Name()},
		Node:    "node1",
	}, false)
	upload := capmox.CloudInitUpload{
		Version: 1,
		Node:    "node1",
		Storage: "local",
		VolID:   "local:iso/user-data-" + string(machineScope.ProxmoxMachine.UID) + "-" + strings.Repeat("a", 64) + ".iso",
		Size:    4096,
		UPID:    "UPID:node1:1:2:3:imgcopy:local:root@pam:",
		Phase:   capmox.CloudInitUploadPhaseAccepted,
	}
	encoded, err := json.Marshal(upload)
	require.NoError(t, err)
	machineScope.ProxmoxMachine.Annotations = map[string]string{cloudInitUploadAnnotation: string(encoded)}

	pendingErr := errors.New("recorded cloud-init upload task is not terminal")
	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), &upload).Return(nil, pendingErr).Once()
	require.ErrorIs(t, DeleteVM(context.TODO(), machineScope), pendingErr)
	require.NotEmpty(t, machineScope.ProxmoxMachine.Finalizers)

	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), &upload).Return(nil, goproxmox.ErrVMIDFree).Once()
	require.NoError(t, DeleteVM(context.TODO(), machineScope))
	require.Empty(t, machineScope.ProxmoxMachine.Finalizers)
}

func TestDeleteVMPreservesFinalizerForIntentUntilUploadQuiescence(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.ProxmoxMachine.Spec.VirtualMachineID = new(int64(vm.VMID))
	machineScope.InfraCluster.ProxmoxCluster.AddNodeLocation(infrav1.NodeLocation{
		Machine: corev1.LocalObjectReference{Name: machineScope.Name()},
		Node:    "node1",
	}, false)
	upload := capmox.CloudInitUpload{
		Version: 1,
		Node:    "node1",
		Storage: "local",
		VolID:   "local:iso/user-data-" + string(machineScope.ProxmoxMachine.UID) + "-" + strings.Repeat("b", 64) + ".iso",
		Size:    4096,
		Attempt: 2,
		Phase:   capmox.CloudInitUploadPhaseIntent,
	}
	encoded, err := json.Marshal(upload)
	require.NoError(t, err)
	machineScope.ProxmoxMachine.Annotations = map[string]string{cloudInitUploadAnnotation: string(encoded)}

	pendingErr := fmt.Errorf("%w: active imgcopy task", capmox.ErrCloudInitUploadPending)
	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), &upload).Return(nil, pendingErr).Once()
	require.ErrorIs(t, DeleteVM(context.TODO(), machineScope), capmox.ErrCloudInitUploadPending)
	require.NotEmpty(t, machineScope.ProxmoxMachine.Finalizers)

	proxmoxClient.EXPECT().DeleteVM(context.TODO(), "node1", int64(123), string(machineScope.ProxmoxMachine.UID), &upload).Return(nil, goproxmox.ErrVMIDFree).Once()
	require.NoError(t, DeleteVM(context.TODO(), machineScope))
	require.Empty(t, machineScope.ProxmoxMachine.Finalizers)
}
