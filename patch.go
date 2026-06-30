package main

import (
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/webhook/controller_test.go")
	s := string(f)
	
	s = strings.ReplaceAll(s, "escalMgr := &escalation.EscalationManager{Client: cli}", "escalMgr := &escalation.EscalationManager{Client: cli}\n\t\tidpLoader := config.NewIdentityProviderLoader(cli)\n\t\tidpLoader.UpdateCache(context.Background())")
	
	s = strings.ReplaceAll(s, "wcDefault := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tescalManager: escalMgr,", "wcDefault := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tidpLoader:    idpLoader,\n\t\t\tescalManager: escalMgr,")
	
	s = strings.ReplaceAll(s, "wcHardened := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tescalManager: escalMgr,", "wcHardened := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tidpLoader:    idpLoader,\n\t\t\tescalManager: escalMgr,")

	s = strings.ReplaceAll(s, "wc := &WebhookController{\n\t\t\t\tlog:          logger.Sugar(),\n\t\t\t\tescalManager: escalMgr,", "wc := &WebhookController{\n\t\t\t\tlog:          logger.Sugar(),\n\t\t\t\tidpLoader:    idpLoader,\n\t\t\t\tescalManager: escalMgr,")

	s = strings.ReplaceAll(s, "wc := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tescalManager: escalMgr,", "wc := &WebhookController{\n\t\t\tlog:          logger.Sugar(),\n\t\t\tidpLoader:    idpLoader,\n\t\t\tescalManager: escalMgr,")

	ioutil.WriteFile("pkg/webhook/controller_test.go", []byte(s), 0644)
}
