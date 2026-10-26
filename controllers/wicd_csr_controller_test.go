//go:build !windows

package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	certificatesv1 "k8s.io/api/certificates/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/windows-machine-config-operator/pkg/rbac"
	"github.com/openshift/windows-machine-config-operator/pkg/windows"
)

const testNamespace = "openshift-windows-machine-config-operator"

// newWICDCSRReconciler returns a minimal reconciler for predicate testing.
func newWICDCSRReconciler(namespace string) *wicdCSRReconciler {
	return &wicdCSRReconciler{watchNamespace: namespace}
}

func newCSR(username string, conditions []certificatesv1.CertificateSigningRequestCondition) *certificatesv1.CertificateSigningRequest {
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: meta.ObjectMeta{Name: "csr-test"},
		Spec:       certificatesv1.CertificateSigningRequestSpec{Username: username},
		Status:     certificatesv1.CertificateSigningRequestStatus{Conditions: conditions},
	}
}

func TestPendingCSRFilter(t *testing.T) {
	tests := []struct {
		name       string
		conditions []certificatesv1.CertificateSigningRequestCondition
		expected   bool
	}{
		{
			name:       "no conditions returns true",
			conditions: nil,
			expected:   true,
		},
		{
			name: "approved condition returns false",
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateApproved},
			},
			expected: false,
		},
		{
			name: "denied condition returns false",
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateDenied},
			},
			expected: false,
		},
		{
			name: "failed condition returns true",
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateFailed},
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := newCSR("system:wicd-node:accpwin1", tt.conditions)
			assert.Equal(t, tt.expected, pendingCSRFilter(csr))
		})
	}
}

func TestIsWICDServiceAccount(t *testing.T) {
	r := newWICDCSRReconciler(testNamespace)
	validUsername := "system:serviceaccount:" + testNamespace + ":" + windows.WicdServiceName

	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{
			name:     "valid WICD service account",
			username: validUsername,
			expected: true,
		},
		{
			name:     "wrong namespace",
			username: "system:serviceaccount:other-namespace:" + windows.WicdServiceName,
			expected: false,
		},
		{
			name:     "wrong service account name",
			username: "system:serviceaccount:" + testNamespace + ":other-daemon",
			expected: false,
		},
		{
			name:     "certificate identity username",
			username: "system:wicd-node:accpwin1",
			expected: false,
		},
		{
			name:     "kubelet username",
			username: "system:node:accpwin1",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := newCSR(tt.username, nil)
			assert.Equal(t, tt.expected, r.isWICDServiceAccount(csr))
		})
	}
}

func TestIsWICDCertificateIdentity(t *testing.T) {
	r := newWICDCSRReconciler(testNamespace)

	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{
			name:     "valid certificate identity",
			username: rbac.WICDUserPrefix + ":accpwin1",
			expected: true,
		},
		{
			name:     "bare prefix without colon-hostname suffix",
			username: rbac.WICDUserPrefix,
			expected: false,
		},
		{
			name:     "rogue suffix sharing the prefix",
			username: rbac.WICDUserPrefix + "-rogue",
			expected: false,
		},
		{
			name:     "kubelet node identity",
			username: "system:node:accpwin1",
			expected: false,
		},
		{
			name:     "service account username",
			username: "system:serviceaccount:" + testNamespace + ":" + windows.WicdServiceName,
			expected: false,
		},
		{
			name:     "empty username",
			username: "",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := newCSR(tt.username, nil)
			assert.Equal(t, tt.expected, r.isWICDCertificateIdentity(csr))
		})
	}
}

func TestIsWICDCSR(t *testing.T) {
	r := newWICDCSRReconciler(testNamespace)
	validSvcAccount := "system:serviceaccount:" + testNamespace + ":" + windows.WicdServiceName

	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{
			name:     "service account identity is a WICD CSR",
			username: validSvcAccount,
			expected: true,
		},
		{
			name:     "certificate identity is a WICD CSR",
			username: rbac.WICDUserPrefix + ":accpwin1",
			expected: true,
		},
		{
			name:     "kubelet node identity is not a WICD CSR",
			username: "system:node:accpwin1",
			expected: false,
		},
		{
			name:     "unknown identity is not a WICD CSR",
			username: "system:anonymous",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := newCSR(tt.username, nil)
			assert.Equal(t, tt.expected, r.isWICDCSR(csr))
		})
	}
}

// TestUpdateFuncPredicate validates the combined predicate used in SetupWithManager's UpdateFunc:
// isWICDCSR(e.ObjectNew) && pendingCSRFilter(e.ObjectNew). This is the predicate that processes
// resynced CSR objects fired by the 10-minute per-object SyncPeriod, ensuring missed pending
// WICD CSRs are re-enqueued for approval.
func TestUpdateFuncPredicate(t *testing.T) {
	r := newWICDCSRReconciler(testNamespace)
	validSvcAccount := "system:serviceaccount:" + testNamespace + ":" + windows.WicdServiceName
	certIdentity := rbac.WICDUserPrefix + ":accpwin58"

	tests := []struct {
		name       string
		username   string
		conditions []certificatesv1.CertificateSigningRequestCondition
		expected   bool
	}{
		{
			name:       "pending service account CSR is requeued by resync",
			username:   validSvcAccount,
			conditions: nil,
			expected:   true,
		},
		{
			name:       "pending certificate identity CSR is requeued by resync",
			username:   certIdentity,
			conditions: nil,
			expected:   true,
		},
		{
			name:     "approved service account CSR is filtered out",
			username: validSvcAccount,
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateApproved},
			},
			expected: false,
		},
		{
			name:     "approved certificate identity CSR is filtered out",
			username: certIdentity,
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateApproved},
			},
			expected: false,
		},
		{
			name:     "denied WICD CSR is filtered out",
			username: certIdentity,
			conditions: []certificatesv1.CertificateSigningRequestCondition{
				{Type: certificatesv1.CertificateDenied},
			},
			expected: false,
		},
		{
			name:       "pending kubelet CSR is not a WICD CSR and is filtered out",
			username:   "system:node:accpwin1",
			conditions: nil,
			expected:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := newCSR(tt.username, tt.conditions)
			result := r.isWICDCSR(csr) && pendingCSRFilter(csr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
