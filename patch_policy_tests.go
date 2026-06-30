package main

import (
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/policy/deny_test.go")
	s := string(f)
	
	// Wherever evaluator := NewEvaluator(cli, ...) is called, we should also call UpdateCache(ctx) right before we call Match() or RequireNamespaceLabels().
	// But it's easier to just call it inside the test functions right after Create(..., pol).
	
	s = strings.ReplaceAll(s, "evaluator := NewEvaluator(cli, log)", "evaluator := NewEvaluator(cli, log)\n\t_ = evaluator.UpdateCache(context.Background())")
	s = strings.ReplaceAll(s, "evaluator := NewEvaluator(client, log)", "evaluator := NewEvaluator(client, log)\n\t_ = evaluator.UpdateCache(context.Background())")

	ioutil.WriteFile("pkg/policy/deny_test.go", []byte(s), 0644)
}
