# Email Templates Customization

This guide explains how to customize Breakglass email notification templates by mounting custom templates from ConfigMaps.

## Overview

Breakglass sends email notifications for:
- **Session Requests**: Approvers are notified when a new session is requested
- **Session Approvals**: Requesters are notified when their session is approved (with IDP information if applicable)
- **Session Rejections**: Requesters are notified when their session is rejected

By default, built-in templates are used. You can override these templates with custom ones to match your organization's branding, language, or requirements.

## Built-in Templates

Breakglass includes the following built-in email templates:

| Template | File | Usage |
|----------|------|-------|
| Request | `request.html` | Sent when a user requests a session |
| Approved | `approved.html` | Sent when a session is approved (includes IDP info in multi-IDP mode) |
| Rejection | (inline) | Sent when a session is rejected |

## Template Variables

All templates receive the following variables and can access them with Go templating syntax `{{ .VariableName }}`:

### Request Email Template

**Sent to**: Approvers  
**File**: `request.html`

Available variables:
```go
- .Requester        string   // User who requested the escalation
- .Cluster          string   // Target cluster name
- .Escalation       string   // Escalation name
- .Reason          string   // Request reason (if provided)
- .SessionID        string   // Unique session identifier
- .ApprovalURL      string   // Link to approve/reject the session
- .ApprovalDeadline string   // When the request expires
- .IDPName         string   // Identity provider name (multi-IDP mode)
- .IDPIssuer       string   // Identity provider issuer URL
```

### Approved Email Template

**Sent to**: Requester  
**File**: `approved.html`

Available variables:
```go
- .Requester              string    // User who requested the escalation
- .Approver               string    // User who approved the request
- .Cluster                string    // Target cluster name
- .Escalation             string    // Escalation name
- .Reason                string    // Approval reason (if provided)
- .SessionID              string    // Unique session identifier
- .ApprovedAt             time.Time // When the session was approved
- .ActivationTime         time.Time // When the session becomes active
- .ExpirationTime         time.Time // When the session expires
- .IsScheduled            bool      // Whether the session is scheduled for later
- .ApprovalReason         string    // Reason from approver
- .IDPName               string    // Identity provider name (for display in multi-IDP)
- .IDPIssuer             string    // Identity provider issuer URL
```

## Creating Custom Templates

### Step 1: Create Your Template

Create your custom email template with HTML content. Use Go template syntax for variables:

**Example: custom-approved.html**

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #0066cc; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .footer { background-color: #f0f0f0; padding: 10px; text-align: center; font-size: 12px; }
        .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Your Escalation Request Has Been Approved!</h1>
        </div>
        
        <div class="content">
            <p>Hello {{ .Requester }},</p>
            
            <p>Your request for temporary escalated access has been <strong>approved</strong>.</p>
            
            <h3>Session Details</h3>
            <ul>
                <li><strong>Escalation:</strong> {{ .Escalation }}</li>
                <li><strong>Cluster:</strong> {{ .Cluster }}</li>
                <li><strong>Approved by:</strong> {{ .Approver }}</li>
                <li><strong>Activated:</strong> {{ .ActivationTime.Format "2006-01-02 15:04:05 MST" }}</li>
                <li><strong>Expires:</strong> {{ .ExpirationTime.Format "2006-01-02 15:04:05 MST" }}</li>
            </ul>
            
            {{ if .IDPName }}
            <div class="warning">
                <strong>⚠️ Important - Please use the correct Identity Provider</strong>
                <p>You requested access using: <strong>{{ .IDPName }}</strong></p>
                <p>When you log in or access resources, please ensure you authenticate using this same identity provider.</p>
                {{ if .IDPIssuer }}
                <p><em>IDP Issuer: {{ .IDPIssuer }}</em></p>
                {{ end }}
            </div>
            {{ end }}
            
            <p><strong>Important Security Notice:</strong></p>
            <ul>
                <li>This access is temporary and time-limited</li>
                <li>All actions are logged and audited</li>
                <li>Share your access responsibly - don't share credentials</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>&copy; 2024 Das SCHIFF Breakglass System</p>
        </div>
    </div>
</body>
</html>
```

### Step 2: Create a ConfigMap

Create a Kubernetes ConfigMap containing your custom template(s):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-custom-templates
  namespace: breakglass  # Match your Breakglass namespace
data:
  approved.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom approved email template here -->
    </html>
  request.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom request email template here -->
    </html>
```

**Apply the ConfigMap:**

```bash
kubectl apply -f custom-templates-configmap.yaml
```

### Step 3: Mount the ConfigMap in Breakglass Deployment

Update the Breakglass deployment to mount the custom template ConfigMap:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
  namespace: breakglass
spec:
  template:
    spec:
      containers:
      - name: manager
        # ... other container config ...
        volumeMounts:
        - name: custom-email-templates
          mountPath: /etc/breakglass/templates  # Mount point
          readOnly: true
        env:
        - name: BREAKGLASS_TEMPLATE_PATH
          value: "/etc/breakglass/templates"  # Path where to look for templates
      
      volumes:
      - name: custom-email-templates
        configMap:
          name: breakglass-custom-templates
```

## Using Custom Templates with Kustomize

If you're using Kustomize to manage your Breakglass deployment, add the ConfigMap and volume mounts in your `kustomization.yaml`:

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- base/deployment.yaml

configMapGenerator:
- name: breakglass-custom-templates
  files:
  - approved.html=patches/templates/approved.html
  - request.html=patches/templates/request.html

patchesStrategicMerge:
- deployment-volumes-patch.yaml
```

**deployment-volumes-patch.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
spec:
  template:
    spec:
      containers:
      - name: manager
        volumeMounts:
        - name: custom-email-templates
          mountPath: /etc/breakglass/templates
          readOnly: true
        env:
        - name: BREAKGLASS_TEMPLATE_PATH
          value: "/etc/breakglass/templates"
      volumes:
      - name: custom-email-templates
        configMap:
          name: breakglass-custom-templates
```

## Using Custom Templates with Helm

If deploying Breakglass via Helm, customize templates in `values.yaml`:

```yaml
# values.yaml
breakglass:
  templatePath: /etc/breakglass/templates

templates:
  approved:
    enabled: true
    content: |
      <!DOCTYPE html>
      <!-- Your custom approved template -->

  request:
    enabled: true
    content: |
      <!DOCTYPE html>
      <!-- Your custom request template -->
```

And update your Helm chart's deployment template:

```yaml
{{- if .Values.templates.approved.enabled }}
- name: BREAKGLASS_TEMPLATE_PATH
  value: /etc/breakglass/templates
{{- end }}

volumeMounts:
- name: custom-templates
  mountPath: /etc/breakglass/templates
  readOnly: true

volumes:
- name: custom-templates
  configMap:
    name: {{ include "breakglass.fullname" . }}-templates
```

## Template Best Practices

### Multi-IDP Support

When you have multiple identity providers configured, use the conditional template syntax to display IDP information:

```html
{{ if .IDPName }}
<div class="idp-section">
    <p>You authenticated with: <strong>{{ .IDPName }}</strong></p>
    {{ if .IDPIssuer }}
    <p>Provider: {{ .IDPIssuer }}</p>
    {{ end }}
</div>
{{ end }}
```

This ensures templates work in both single-IDP and multi-IDP modes.

### Scheduled Sessions

Check if a session is scheduled for later activation:

```html
{{ if .IsScheduled }}
<p><strong>Note:</strong> Your access is scheduled to activate at {{ .ActivationTime.Format "2006-01-02 15:04:05 MST" }}</p>
{{ else }}
<p><strong>Your access is active immediately.</strong></p>
{{ end }}
```

### Branding and Localization

Customize templates with your organization's branding:

```html
<style>
    .header { background-color: #YOUR_BRAND_COLOR; }
    .logo { background-image: url('https://your-domain.example.com/logo.png'); }
</style>

<p>{{ .CustomGreeting }}</p>  <!-- Pass in environment-specific greetings -->
```

### Security Notices

Always include security warnings:

```html
<div class="security-notice">
    <h4>⚠️ Security Notice</h4>
    <ul>
        <li>All access is logged and audited</li>
        <li>Do not share your credentials</li>
        <li>This access will expire on {{ .ExpirationTime.Format "2006-01-02 15:04:05 MST" }}</li>
    </ul>
</div>
```

## Troubleshooting

### Custom Templates Not Loading

**Symptom**: Default templates are still being used despite ConfigMap being mounted.

**Check 1**: Verify ConfigMap is mounted in the pod:

```bash
kubectl exec -n breakglass <pod-name> -- ls -la /etc/breakglass/templates/
```

**Check 2**: Verify environment variable is set:

```bash
kubectl exec -n breakglass <pod-name> -- env | grep BREAKGLASS_TEMPLATE_PATH
```

**Check 3**: Check pod logs for template loading errors:

```bash
kubectl logs -n breakglass <pod-name> | grep -i template
```

### Template Syntax Errors

**Symptom**: Emails don't render or show empty template fields.

**Solution**: Validate Go template syntax:

```bash
# Test template rendering locally
go run cmd/template-validator/main.go -template custom-approved.html
```

### Variables Not Appearing

**Symptom**: Template variables like `{{ .IDPName }}` appear as empty strings.

**Check**: Verify the variable is actually set by the application:

```bash
# Enable debug logging to see what variables are passed
BREAKGLASS_LOG_LEVEL=debug kubectl logs -n breakglass <pod-name>
```

## Real-World Examples

### Example 1: Branded Approval Email with IDP Info

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 20px auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .badge { display: inline-block; background-color: #28a745; color: white; padding: 5px 15px; border-radius: 20px; margin-top: 10px; }
        .content { padding: 30px; }
        .status-box { background-color: #e7f3e7; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .details { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .details-row { display: flex; justify-content: space-between; margin: 8px 0; padding: 5px 0; border-bottom: 1px solid #dee2e6; }
        .details-label { font-weight: 600; color: #495057; }
        .details-value { color: #212529; }
        .idp-info { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .security-notice { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; border-radius: 4px; font-size: 13px; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d; border-top: 1px solid #dee2e6; border-radius: 0 0 8px 8px; }
        a { color: #667eea; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .cta-button { display: inline-block; background-color: #667eea; color: white; padding: 10px 25px; border-radius: 4px; text-decoration: none; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Access Approved!</h1>
            <div class="badge">✓ Authorized</div>
        </div>
        
        <div class="content">
            <p>Hi {{ .Requester }},</p>
            
            <p>Your request for temporary escalated access has been <strong>approved</strong> by {{ .Approver }}.</p>
            
            <div class="status-box">
                <strong>✓ Status:</strong> Your escalation is now active and ready to use.
            </div>
            
            <div class="details">
                <div class="details-row">
                    <span class="details-label">Escalation:</span>
                    <span class="details-value">{{ .Escalation }}</span>
                </div>
                <div class="details-row">
                    <span class="details-label">Target Cluster:</span>
                    <span class="details-value">{{ .Cluster }}</span>
                </div>
                <div class="details-row">
                    <span class="details-label">Session ID:</span>
                    <span class="details-value"><code>{{ .SessionID }}</code></span>
                </div>
                <div class="details-row">
                    <span class="details-label">Activated:</span>
                    <span class="details-value">{{ .ActivationTime.Format "Jan 02, 2006 at 15:04 MST" }}</span>
                </div>
                <div class="details-row">
                    <span class="details-label">Expires:</span>
                    <span class="details-value">{{ .ExpirationTime.Format "Jan 02, 2006 at 15:04 MST" }}</span>
                </div>
            </div>
            
            {{ if .IDPName }}
            <div class="idp-info">
                <strong>⚠️ Identity Provider Information</strong>
                <p style="margin-top: 8px;">You authenticated using: <strong>{{ .IDPName }}</strong></p>
                <p style="margin-top: 5px; font-size: 13px;">When accessing resources, please ensure you're using the same identity provider to maintain authentication consistency.</p>
                {{ if .IDPIssuer }}<p style="margin-top: 5px; font-size: 11px; color: #666;">Issuer: {{ .IDPIssuer }}</p>{{ end }}
            </div>
            {{ end }}
            
            <div class="security-notice">
                <strong>Security Reminders:</strong>
                <ul style="margin-left: 15px; margin-top: 8px;">
                    <li>This access is <strong>temporary</strong> and will expire at the time shown above</li>
                    <li><strong>All actions</strong> performed with this escalation are logged and audited</li>
                    <li><strong>Never share</strong> your credentials with others</li>
                    <li>Use this access only for the <strong>authorized purpose</strong></li>
                </ul>
            </div>
            
            {{ if .ApprovalReason }}
            <div class="details" style="background-color: #e7f3f8;">
                <strong>Approval Notes:</strong>
                <p style="margin-top: 8px; font-style: italic;">{{ .ApprovalReason }}</p>
            </div>
            {{ end }}
            
            <p style="margin-top: 25px; color: #666;">Questions or issues? Contact your system administrators.</p>
        </div>
        
        <div class="footer">
            <p>Das SCHIFF Breakglass System</p>
            <p style="margin-top: 8px;">© 2024 Deutsche Telekom. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

### Example 2: Multilingual Support

Store different templates per language in separate ConfigMaps:

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-templates-en
  namespace: breakglass
data:
  approved.html: |
    <!DOCTYPE html>
    <html>...Your English template...</html>

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-templates-de
  namespace: breakglass
data:
  approved.html: |
    <!DOCTYPE html>
    <html>...Deine deutsche Vorlage...</html>
```

Then select the appropriate ConfigMap based on user locale.

## See Also

- [Configuration Reference](configuration-reference.md) - Email configuration options
- [Advanced Features](advanced-features.md) - Other advanced features
- [Identity Provider Configuration](identity-provider.md) - Multi-IDP setup for email context
