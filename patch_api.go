package main

import (
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/api/api.go")
	s := string(f)
	
	s = strings.Replace(s, "cfg *config.Config, log *zap.SugaredLogger, debugSessionCtrl *debug.DebugSessionAPIController,", "cfg *config.Config, log *zap.SugaredLogger, debugSessionCtrl *debug.DebugSessionAPIController,\n\tidpLoader *config.IdentityProviderLoader,", 1)
	
	s = strings.Replace(s, "webhook.NewWebhookController(log,\n\t\t*cfg,\n\t\tsessionManager,\n\t\tescalationManager,\n\t\tbreakglass.CanGroupsDo,\n\t\tccProvider,\n\t\tdenyEval,\n\t).", "webhook.NewWebhookController(log,\n\t\t*cfg,\n\t\tsessionManager,\n\t\tescalationManager,\n\t\tbreakglass.CanGroupsDo,\n\t\tccProvider,\n\t\tdenyEval,\n\t\tidpLoader,\n\t).", 1)

	ioutil.WriteFile("pkg/api/api.go", []byte(s), 0644)
	
	f2, _ := ioutil.ReadFile("cmd/main.go")
	s2 := string(f2)
	s2 = strings.Replace(s2, "&cfg, log, debugSessionAPICtrl, auditService)", "&cfg, log, debugSessionAPICtrl, idpLoader, auditService)", 1)
	ioutil.WriteFile("cmd/main.go", []byte(s2), 0644)
	
	f3, _ := ioutil.ReadFile("pkg/webhook/controller.go")
	s3 := string(f3)
	
	s3 = strings.Replace(s3, "type WebhookController struct {\n\tlog                    *zap.SugaredLogger", "type WebhookController struct {\n\tlog                    *zap.SugaredLogger\n\tidpLoader              *config.IdentityProviderLoader", 1)
	
	s3 = strings.Replace(s3, "ccProvider *cluster.ClientProvider,\n\tdenyEval *policy.Evaluator,\n) *WebhookController {\n\twc := &WebhookController{\n\t\tlog:          log,", "ccProvider *cluster.ClientProvider,\n\tdenyEval *policy.Evaluator,\n\tidpLoader *config.IdentityProviderLoader,\n) *WebhookController {\n\twc := &WebhookController{\n\t\tlog:          log,\n\t\tidpLoader:    idpLoader,", 1)

	s3 = strings.ReplaceAll(s3, "idpList := &breakglassv1alpha1.IdentityProviderList{}\n\tif err := wc.escalManager.List(ctx, idpList); err != nil {", "cachedIDPs := wc.idpLoader.GetCachedIdentityProviders()\n\tif cachedIDPs == nil {")
	
	s3 = strings.ReplaceAll(s3, "for _, idp := range idpList.Items {", "for _, idp := range cachedIDPs {")
	
	s3 = strings.ReplaceAll(s3, "reqLog.With(\"error\", err.Error()).Warn(\"Failed to list IdentityProviders for IDP hint\")", "reqLog.Warn(\"Failed to list IdentityProviders for IDP hint\")")
	s3 = strings.ReplaceAll(s3, "reqLog.With(\"error\", err.Error()).Error(\"Failed to list IdentityProviders for request validation - denying request (fail-closed)\")", "reqLog.Error(\"Failed to list IdentityProviders for request validation - denying request (fail-closed)\")")
	
	ioutil.WriteFile("pkg/webhook/controller.go", []byte(s3), 0644)
}
