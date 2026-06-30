package main

import (
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/webhook/webhook_controller_test.go")
	s := string(f)
	
	s = strings.ReplaceAll(s, "require.NoError(t, controller.escalManager.Client.Create(context.Background(), pol))", "require.NoError(t, controller.escalManager.Client.Create(context.Background(), pol))\n\trequire.NoError(t, controller.denyEval.UpdateCache(context.Background()))")

	ioutil.WriteFile("pkg/webhook/webhook_controller_test.go", []byte(s), 0644)
}
