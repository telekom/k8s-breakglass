package main

import (
	"os"
	"strings"
)

func main() {
	content, err := os.ReadFile("pkg/bgctl/output/output.go")
	if err != nil {
		panic(err)
	}

	str := string(content)
	
	// Fix error check
	str = strings.ReplaceAll(str, "fmt.Fprintln(w, \"Operation completed successfully.\")", "_, _ = fmt.Fprintln(w, \"Operation completed successfully.\")")

	err = os.WriteFile("pkg/bgctl/output/output.go", []byte(str), 0644)
	if err != nil {
		panic(err)
	}
}
