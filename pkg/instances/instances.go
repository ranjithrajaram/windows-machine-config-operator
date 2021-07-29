package instances

import (
	core "k8s.io/api/core/v1"

	"github.com/openshift/windows-machine-config-operator/pkg/metadata"
	"github.com/openshift/windows-machine-config-operator/version"
)

// InstanceInfo represents a host that is meant to be joined to the cluster
type InstanceInfo struct {
	// Address is the network address of the instance
	Address string
	// Username is the name of a user that can be ssh'd into.
	Username string
	// NewHostname being set means that the instance's hostname should be changed. An empty value is a no-op.
	NewHostname string
	// Node is an optional pointer to the Node object associated with the instance, if it has one.
	Node *core.Node
}

// NewInstanceInfo returns a new instanceInfo. newHostname being set means that the instance's hostname should be
// changed. An empty value is a no-op.
func NewInstanceInfo(address, username, newHostname string, node *core.Node) *InstanceInfo {
	return &InstanceInfo{Address: address, Username: username, NewHostname: newHostname, Node: node}
}

// UpToDate returns true if the instance was configured by the current WMCO version
func (i *InstanceInfo) UpToDate() bool {
	if i.Node == nil {
		return false
	}
	versionAnnotation, present := i.Node.GetAnnotations()[metadata.VersionAnnotation]
	return present && versionAnnotation == version.Get()
}

// UpgradeRequired returns true if the instance needs to go through the upgrade process
func (i *InstanceInfo) UpgradeRequired() bool {
	// instance being up to date implies instance is fully upgraded
	if i.UpToDate() {
		return false
	}

	// Instance has no node and should not go through the upgrade process
	if i.Node == nil {
		return false
	}

	// Version annotation not being present means that the node has been created but not fully configured.
	// The upgrade process is not required, the node should just be configured normally.
	_, present := i.Node.GetAnnotations()[metadata.VersionAnnotation]
	if !present {
		return false
	}

	// Version annotation has an incorrect value, this was configured by an older version of WMCO and should be
	// fully deconfigured before being configured by the current version.
	return true
}
