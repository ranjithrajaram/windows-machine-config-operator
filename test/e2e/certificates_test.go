package e2e

import (
	"context"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/windows-machine-config-operator/controllers"
	"github.com/openshift/windows-machine-config-operator/pkg/certificates"
	"github.com/openshift/windows-machine-config-operator/pkg/nodeconfig"
	"github.com/openshift/windows-machine-config-operator/pkg/retry"
	"github.com/openshift/windows-machine-config-operator/pkg/windows"
)

// testCertificates tests the CA certificates for Windows nodes
// The initial kubelet CA certificate is valid for 1 year, from the date of the cluster installation.
// Usually, the first rotation of the kubelet CA certificate is generated by the [API Server Operator](https://github.com/openshift/cluster-kube-apiserver-operator)
// at 80% for the CA certificate lifecycle (1 year), which is 292 days, and removes the previous CA certificate after 365 days.
func (tc *testContext) testCertificates(t *testing.T) {
	t.Run("Kubelet CA rotation", tc.testKubeletCARotation)
}

// testKubeletCARotation tests the rotation of the kubelet CA certificate by forcing the generation of a new CA
// certificate and ensuring the content of the CA bundle in all Windows nodes contains the new certificate. Once the
// rotation is triggered, WMCO detects the new CA certificate, merge it with the initial bundle, and copy the resulting
// bundle to all Windows nodes.
//
// This test accounts for the kubelet CA automatic rotation that takes place at 80% of the initial certificate's
// lifecycle (1 year).  Note that the old certificate is still present in the cluster until day 365, so clients may be
// able to use it.
func (tc *testContext) testKubeletCARotation(t *testing.T) {
	// force CA rotation
	err := tc.forceKubeApiServerCertificateRotation()
	require.NoError(t, err)
	// loop all Windows nodes
	for _, winNode := range gc.allNodes() {
		// spin-off subtests to ensure the CA bundle file is verified in all Windows nodes
		t.Run("node/"+winNode.Name, func(t *testing.T) {
			err := tc.waitForKubeletCACertificateInNode(&winNode)
			assert.NoErrorf(t, err, "kubelet CA certificate should be present in node %S", winNode.Name)
		})
	}
}

// forceKubeApiServerCertificateRotation forces the certificate rotation by setting the `certificate-not-after`
// annotation to nil in the `kube-apiserver-to-kubelet-signer` secret
func (tc *testContext) forceKubeApiServerCertificateRotation() error {
	// note that the slash had to be encoded as ~1 because it's a reference: https://www.rfc-editor.org/rfc/rfc6901#section-3
	patchData := fmt.Sprint(`[{"op":"replace","path":"/metadata/annotations/auth.openshift.io~1certificate-not-after","value": null }]`)
	// invoke request
	_, err := tc.client.K8s.CoreV1().Secrets("openshift-kube-apiserver-operator").Patch(context.TODO(),
		"kube-apiserver-to-kubelet-signer", types.JSONPatchType, []byte(patchData), meta.PatchOptions{})
	return err
}

// waitForKubeletCACertificateInNode waits for the kubelet CA certificate to be present in the CA bundle file for the
// given Windows node. After retry.Interval runs an SSH job to fetch the CA bundle, if the job fails or
// kubelet CA is not present in the node, retries every retry.Interval until retry.Timeout is reached.
func (tc *testContext) waitForKubeletCACertificateInNode(node *core.Node) error {
	addr, err := controllers.GetAddress(node.Status.Addresses)
	if err != nil {
		return err
	}
	// CA bundle location in Windows node. i.e. "C:\k\kubelet-ca.crt"
	caBundlePath := windows.GetK8sDir() + "\\" + nodeconfig.KubeletClientCAFilename
	// PowerShell command to fetch content in the file
	command := fmt.Sprintf("Get-Content -Raw -Path %s", caBundlePath)
	// wait retry.Interval and verify the CA bundle content, try if needed
	return wait.Poll(retry.Interval, retry.Timeout, func() (bool, error) {
		// invoke command
		bundleContent, err := tc.runPowerShellSSHJob("kubelet-ca-bundle-content", command, addr)
		if err != nil {
			// retry
			log.Printf("error fetching CA bundle in node %s with address %s, retrying in %s. %v",
				node.Name, addr, retry.Interval, err)
			return false, nil
		}
		// get the ConfigMap that contains the kubelet client CA
		cm, err := tc.client.K8s.CoreV1().ConfigMaps(certificates.KubeApiServerOperatorNamespace).Get(context.TODO(),
			certificates.KubeAPIServerServingCAConfigMapName, meta.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting kubelet client CA ConfigMap: %w", err)
		}
		// parse bundle from ConfigMap
		kubeletCABytes, err := certificates.GetCAsFromConfigMap(cm, certificates.CABundleKey)
		if err != nil {
			return false, fmt.Errorf("error parsing CA bundle from ConfigMap: %w", err)
		}
		kubeletCAString := strings.TrimSpace(string(kubeletCABytes))
		found := strings.Contains(bundleContent, kubeletCAString)
		if !found {
			log.Printf("kubelet CA certificate not found in node %s with address %s, retrying in %s...",
				node.Name, addr, retry.Interval)
		}
		// return if CA bundle contains the given certificate content, otherwise retry
		return found, nil
	})
}
