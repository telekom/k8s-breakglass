package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	content, err := os.ReadFile("pkg/bgctl/output/output.go")
	if err != nil {
		panic(err)
	}

	str := string(content)
	str = strings.ReplaceAll(str, "Mode:                 string(v.Spec.Mode),", "Mode:                 v.Spec.Mode,")

	err = os.WriteFile("pkg/bgctl/output/output.go", []byte(str), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("Patched output.go again")
}
