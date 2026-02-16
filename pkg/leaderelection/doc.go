// Package leaderelection implements Kubernetes lease-based leader election for
// the breakglass controller, coordinating background loop activation across
// replicas via a channel-based signal.
package leaderelection
