// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const toolboxSchemaImage = "registry.example/toolbox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCRDSchema_DebugSessionToolbox(t *testing.T) {
	c := impersonationEnvtestClient(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		toolbox DebugSessionToolbox
		wantErr string
	}{
		{name: "digest with default path", toolbox: DebugSessionToolbox{Image: toolboxSchemaImage}},
		{name: "digest with custom path", toolbox: DebugSessionToolbox{Image: toolboxSchemaImage, MountPath: "/usr/local/breakglass"}},
		{name: "tag only", toolbox: DebugSessionToolbox{Image: "registry.example/toolbox:v1"}, wantErr: "spec.toolbox.image"},
		{name: "relative path", toolbox: DebugSessionToolbox{Image: toolboxSchemaImage, MountPath: "opt/toolbox"}, wantErr: "spec.toolbox.mountPath"},
		{name: "dot-dot path", toolbox: DebugSessionToolbox{Image: toolboxSchemaImage, MountPath: "/opt/../etc"}, wantErr: "must not contain . or .. segments"},
		{name: "trailing slash", toolbox: DebugSessionToolbox{Image: toolboxSchemaImage, MountPath: "/opt/toolbox/"}, wantErr: "spec.toolbox.mountPath"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolbox := tt.toolbox
			template := &DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("toolbox-schema-%d", i)},
				Spec: DebugSessionTemplateSpec{
					Mode:         DebugSessionModeKubectlDebug,
					KubectlDebug: &KubectlDebugConfig{NodeDebug: &NodeDebugConfig{Enabled: true}},
					Toolbox:      &toolbox,
				},
			}
			err := c.Create(ctx, template)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				if tt.toolbox.MountPath == "" && template.Spec.Toolbox.MountPath != DefaultDebugSessionToolboxMountPath {
					t.Fatalf("mountPath default = %q", template.Spec.Toolbox.MountPath)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
