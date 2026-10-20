package apiresponses

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// guardSkipDirs are pkg/ subtrees that do not serve the REST API: the bgctl
// client decodes error bodies, and the webhook answers Kubernetes
// SubjectAccessReview objects rather than REST errors.
var guardSkipDirs = map[string]bool{"apiresponses": true, "bgctl": true, "webhook": true}

// successStatuses are the http.Status* names a handler may write without an
// error body. Every other http.Status* constant is treated as an error.
var successStatuses = map[string]bool{
	"StatusContinue": true, "StatusSwitchingProtocols": true,
	"StatusOK": true, "StatusCreated": true, "StatusAccepted": true, "StatusNoContent": true, "StatusPartialContent": true,
	"StatusMovedPermanently": true, "StatusFound": true, "StatusSeeOther": true, "StatusNotModified": true,
	"StatusTemporaryRedirect": true, "StatusPermanentRedirect": true,
}

// TestHandlersUseStandardErrorSchema fails when a handler package writes an
// error body outside this package's schema (error, code, cid). Fix a hit by
// calling a Respond* helper, or by embedding NewError(...) in a struct when
// the response needs extra fields.
func TestHandlersUseStandardErrorSchema(t *testing.T) {
	root := filepath.Join("..")
	fset := token.NewFileSet()
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel, _ := filepath.Rel(root, path); guardSkipDirs[strings.Split(rel, string(filepath.Separator))[0]] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		violations = append(violations, errorSchemaViolations(fset, file)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("error responses must use pkg/apiresponses (error, code, cid):\n%s", strings.Join(violations, "\n"))
	}
}

func TestGuardDetectsRawErrorResponses(t *testing.T) {
	src := `package x
func h(c *gin.Context) {
	c.JSON(400, gin.H{"error": "bad"})
	c.JSON(http.StatusConflict, struct{ Valid bool }{})
	c.AbortWithStatusJSON(http.StatusForbidden, APIError{Error: "no"})
	c.Status(http.StatusNotFound)
	c.AbortWithStatus(http.StatusGone)
	c.AbortWithError(http.StatusBadRequest, err)
	c.SecureJSON(http.StatusBadRequest, gin.H{"items": 1})
	c.JSON(http.StatusConflict, struct{ apiresponses.APIError }{apiresponses.NewError(c, "CONFLICT", "ok")})
	c.JSON(http.StatusOK, gin.H{"items": 1})
	c.Status(http.StatusNoContent)
}
type bad struct { Error string ` + "`json:\"error\"`" + ` }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := errorSchemaViolations(fset, file)
	if len(got) != 10 {
		t.Fatalf("expected 10 violations, got %d:\n%s", len(got), strings.Join(got, "\n"))
	}
}

func errorSchemaViolations(fset *token.FileSet, file *ast.File) []string {
	var out []string
	report := func(n ast.Node, msg string) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), msg))
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if isAPIErrorType(n.Type) {
				report(n, "build APIError with NewError so code and cid are set")
			}
			if isMapType(n.Type) {
				for _, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok && isStringLit(kv.Key, "error") {
						report(n, `raw map with an "error" key`)
					}
				}
			}
		case *ast.StructType:
			for _, field := range n.Fields.List {
				if field.Tag == nil {
					continue
				}
				tag, _ := strconv.Unquote(field.Tag.Value)
				if name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ","); name == "error" {
					report(field, `struct field tagged json:"error"; embed apiresponses.APIError instead`)
				}
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || len(n.Args) == 0 || !isErrorStatus(n.Args[0]) {
				return true
			}
			switch sel.Sel.Name {
			case "Status", "AbortWithStatus", "AbortWithError", "String", "Data":
				report(n, "error status without the standard JSON body")
			case "JSON", "AbortWithStatusJSON", "IndentedJSON", "PureJSON", "SecureJSON", "AsciiJSON", "JSONP":
				if len(n.Args) < 2 || !containsNewError(n.Args[1]) {
					report(n, "error status with a body that does not embed NewError")
				}
			}
		}
		return true
	})
	return out
}

func isAPIErrorType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "APIError"
	case *ast.SelectorExpr:
		return t.Sel.Name == "APIError"
	}
	return false
}

func isMapType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.MapType:
		return true
	case *ast.SelectorExpr:
		return t.Sel.Name == "H"
	}
	return false
}

func isStringLit(expr ast.Expr, value string) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && s == value
}

// isErrorStatus reports whether expr is a literal or http.Status* constant
// for a 4xx/5xx status. Variable statuses are not classified.
func isErrorStatus(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		code, err := strconv.Atoi(e.Value)
		return err == nil && code >= 400 && code <= 599
	case *ast.SelectorExpr:
		if pkg, ok := e.X.(*ast.Ident); ok && pkg.Name == "http" && strings.HasPrefix(e.Sel.Name, "Status") {
			return !successStatuses[e.Sel.Name]
		}
	}
	return false
}

func containsNewError(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch f := call.Fun.(type) {
			case *ast.Ident:
				found = found || f.Name == "NewError"
			case *ast.SelectorExpr:
				found = found || f.Sel.Name == "NewError"
			}
		}
		return !found
	})
	return found
}
