// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestApprovedTemplateRuntimePolicySurvivesTypedPersistence(t *testing.T) {
	const input = `{
 "podTemplateString":"spec: {}", "podOverridesTemplate":"nodeSelector: {approved: yes}",
 "podOverrides":{"spec":{"containers":[{"name":"debug","command":["safe"],"args":["arg"]}]}},
 "schedulingConstraints":{"nodeSelector":{"pool":"safe"},"deniedNodes":["unsafe"]},
 "schedulingOptions":{"required":true,"options":[{"name":"safe","default":true,"schedulingConstraints":{"nodeSelector":{"pool":"safe"}}}]},
 "namespaceConstraints":{"allowedNamespaces":{"patterns":["safe-*"]},"defaultNamespace":"safe","denyUserNamespace":true},
 "impersonation":{"mode":"user","userName":"approved","groups":["readers"]},
 "allowed":{"clusterSelector":{"matchLabels":{"safe":"true"},"matchExpressions":[{"key":"env","operator":"In","values":["prod"]}]}},
 "constraints":{"renewalLimit":2},
 "auxiliaryResources":[{"name":"policy","templateString":"kind: ConfigMap","createBefore":true,"deleteAfter":true,"failurePolicy":"fail","optional":true}],
 "auxiliaryResourceDefaults":{"policy":true},"requiredAuxiliaryResourceCategories":["security"],
 "notification":{"enabled":true,"notifyOnExpiry":true,"excludedRecipients":{"users":["excluded"]}},
 "requestReason":{"mandatory":true,"minLength":3,"maxLength":20,"suggestedReasons":["incident"]},
 "approvalReason":{"mandatory":true,"mandatoryForRejection":true,"minLength":3},
 "resourceQuota":{"maxPods":2,"maxCPU":"1","maxMemory":"1Gi","maxStorage":"2Gi","enforceResourceRequests":true,"enforceResourceLimits":true},
 "podDisruptionBudget":{"enabled":true,"minAvailable":1},
 "labels":{"approved":"yes"},"annotations":{"policy":"captured"},"priority":5,"hidden":true,"deprecated":true,"deprecationMessage":"replace",
 "expirationBehavior":"terminate","gracePeriodBeforeExpiry":"5m","allowedPodOperations":{"exec":true,"attach":false,"logs":true,"portForward":false}
 }`
	var original breakglassv1alpha1.DebugSessionTemplateSpec
	require.NoError(t, json.Unmarshal([]byte(input), &original))
	encoded, err := json.Marshal(DebugSessionTemplateSpecFrom(&original))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionTemplateSpec
	require.NoError(t, json.Unmarshal(encoded, &restored))
	require.Equal(t, original, restored)
}
