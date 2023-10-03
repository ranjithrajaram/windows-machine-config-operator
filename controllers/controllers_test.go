package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	stats "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openshift/windows-machine-config-operator/pkg/metadata"
)

func TestGetAddress(t *testing.T) {
	testCases := []struct {
		name        string
		input       []core.NodeAddress
		expectedOut []string
		expectedErr bool
	}{
		{
			name:        "no addresses",
			input:       []core.NodeAddress{{}},
			expectedOut: []string{""},
			expectedErr: true,
		},
		{
			name:        "ipv6",
			input:       []core.NodeAddress{{Type: core.NodeInternalIP, Address: "::1"}},
			expectedOut: []string{""},
			expectedErr: true,
		},
		{
			name:        "ipv4",
			input:       []core.NodeAddress{{Type: core.NodeInternalIP, Address: "127.0.0.1"}},
			expectedOut: []string{"127.0.0.1"},
			expectedErr: false,
		},
		{
			name:        "dns",
			input:       []core.NodeAddress{{Type: core.NodeInternalDNS, Address: "localhost"}},
			expectedOut: []string{"localhost"},
			expectedErr: false,
		},
		{
			name: "dns and ipv4",
			input: []core.NodeAddress{
				{Type: core.NodeInternalDNS, Address: "localhost"},
				{Type: core.NodeInternalIP, Address: "127.0.0.1"}},
			expectedOut: []string{"localhost", "127.0.0.1"},
			expectedErr: false,
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			out, err := GetAddress(test.input)
			if test.expectedErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			// The output can be any valid address in the expected list, so check that the output is one of the possible
			// correct ones
			assert.Contains(t, test.expectedOut, out)
		})
	}
}

func TestUpgradeBlocked(t *testing.T) {
	testCases := []struct {
		name           string
		override       bool
		hasCSILabel    bool
		volumeMounted  bool
		upgradingToCSI bool
		expected       bool
	}{
		{
			name:           "Upgrading from in tree to in tree with a volume mounted",
			override:       false,
			hasCSILabel:    false,
			volumeMounted:  true,
			upgradingToCSI: false,
			expected:       false,
		},
		{
			name:           "Upgrading from in tree with a volume mounted",
			override:       false,
			hasCSILabel:    false,
			volumeMounted:  true,
			upgradingToCSI: true,
			expected:       false,
		},
		{
			name:           "Upgrading from in tree without a volume mounted",
			override:       false,
			hasCSILabel:    false,
			volumeMounted:  false,
			upgradingToCSI: true,
			expected:       false,
		},
		{
			name:           "Upgrading from already migrated Node with a volume",
			override:       false,
			hasCSILabel:    true,
			volumeMounted:  true,
			upgradingToCSI: true,
			expected:       false,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			node := core.Node{
				ObjectMeta: meta.ObjectMeta{
					Name:        "node",
					Annotations: make(map[string]string),
					Labels:      make(map[string]string),
				},
				Status: core.NodeStatus{
					VolumesAttached: []core.AttachedVolume{},
				},
			}
			if tt.override {
				node.Labels[metadata.AllowUpgradeLabel] = ""
			}
			if tt.hasCSILabel {
				node.Labels[metadata.CSIConfiguredLabel] = "true"
			}
			pods := []stats.PodStats{}
			if tt.volumeMounted {
				pods = []stats.PodStats{{VolumeStats: []stats.VolumeStats{{PVCRef: &stats.PVCReference{
					Name:      "test-pvc",
					Namespace: "test",
				}}}}}
			}
			fakeClient := clientfake.NewClientBuilder().WithObjects(&node).Build()
			r := instanceReconciler{client: fakeClient}
			result := r.upgradeBlocked(&node, tt.upgradingToCSI, pods)
			assert.Equal(t, tt.expected, result)
		})
	}
}
