package webhook

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/telekom/k8s-breakglass/pkg/breakglass"
)

// EphemeralContainerWebhook handles admission of ephemeral containers
type EphemeralContainerWebhook struct {
	Client       client.Client
	Decoder      admission.Decoder
	Log          *zap.SugaredLogger
	DebugHandler *breakglass.KubectlDebugHandler
}

// Handle handles the admission request
func (w *EphemeralContainerWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Only intercept ephemeral container subresource
	if req.SubResource != "ephemeralcontainers" {
		return admission.Allowed("not an ephemeral container request")
	}

	pod := &corev1.Pod{}
	err := w.Decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	user := req.UserInfo.Username
	// Use explicit cluster from context if available, otherwise wildcard (empty)
	// For Phase 1 we rely on finding *any* active session for the user
	cluster := ""

	session, err := w.DebugHandler.FindActiveSession(ctx, user, cluster)
	if err != nil {
		w.Log.Errorw("Failed to find active session", "error", err)
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if session == nil {
		return admission.Denied(fmt.Sprintf("no active debug session found for user %s", user))
	}

	// Retrieve old object to determine what changed
	oldPod := &corev1.Pod{}
	if err := w.Decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Find newly added ephemeral containers
	newContainers := findNewEphemeralContainers(oldPod.Spec.EphemeralContainers, pod.Spec.EphemeralContainers)

	for _, c := range newContainers {
		caps := capsToStrings(c.SecurityContext)
		nonRoot := isRunAsNonRoot(c.SecurityContext)

		if err := w.DebugHandler.ValidateEphemeralContainerRequest(
			ctx, session, pod.Namespace, pod.Name, c.Image,
			caps, nonRoot); err != nil {
			return admission.Denied(fmt.Sprintf("ephemeral container denied: %v", err))
		}
	}

	return admission.Allowed("allowed by debug session")
}

func findNewEphemeralContainers(old, new []corev1.EphemeralContainer) []corev1.EphemeralContainer {
	added := []corev1.EphemeralContainer{}
	oldMap := make(map[string]bool)
	for _, c := range old {
		oldMap[c.Name] = true
	}
	for _, c := range new {
		if !oldMap[c.Name] {
			added = append(added, c)
		}
	}
	return added
}

func capsToStrings(sc *corev1.SecurityContext) []string {
	if sc == nil || sc.Capabilities == nil {
		return nil
	}
	res := []string{}
	for _, c := range sc.Capabilities.Add {
		res = append(res, string(c))
	}
	return res
}

func isRunAsNonRoot(sc *corev1.SecurityContext) bool {
	if sc == nil || sc.RunAsNonRoot == nil {
		return false
	}
	return *sc.RunAsNonRoot
}
