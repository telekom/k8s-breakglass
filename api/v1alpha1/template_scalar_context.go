// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"strings"
	"text/template"
	"text/template/parse"
)

// scalarContext is deliberately conservative: it recognizes scalar boundaries,
// not the full YAML grammar. Ambiguous template control flow fails closed.
type scalarContext struct {
	start                                       bool
	quote                                       rune
	escaped, comment, serialized, singlePending bool
	flow                                        int
}

func (s scalarContext) text(text string) (scalarContext, error) {
	chars := []rune(text)
	for i, ch := range chars {
		if s.comment {
			if ch != '\n' {
				continue
			}
			s.comment = false
		}
		if s.singlePending {
			s.singlePending = false
			if ch == '\'' {
				continue
			}
			s.quote = 0
		}
		if s.quote != 0 {
			if s.escaped {
				s.escaped = false
				continue
			}
			if s.quote == '"' && ch == '\\' {
				s.escaped = true
				continue
			}
			if ch == s.quote {
				if ch == '\'' {
					s.singlePending = true
				} else {
					s.quote = 0
				}
			}
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\r' {
			continue
		}
		if ch == '\n' {
			if s.flow == 0 {
				s.start = true
				s.serialized = false
			}
			continue
		}
		nextSpace := i+1 < len(chars) && strings.ContainsRune(" \t\r\n", chars[i+1])
		delimiter := ch == ':' && (nextSpace || s.serialized) || s.flow > 0 && strings.ContainsRune(",]}", ch)
		if s.serialized && !delimiter && ch != '#' {
			return s, fmt.Errorf("serialized template output must occupy a complete YAML scalar; literal concatenation is not allowed")
		}
		if ch == '#' && (s.start || s.serialized || i > 0 && strings.ContainsRune(" \t", chars[i-1])) {
			s.comment = true
			continue
		}
		if delimiter {
			s.serialized = false
			s.start = ch == ':' || ch == ','
			if ch == ']' || ch == '}' {
				s.flow--
			}
			continue
		}
		if s.start && (ch == '[' || ch == '{') {
			s.flow++
			continue
		}
		if s.start && ch == '-' && nextSpace {
			continue
		}
		if s.start && (ch == '\'' || ch == '"') {
			s.quote = ch
		}
		s.start = false
	}
	return s, nil
}

func scalarSerializer(pipe *parse.PipeNode) bool {
	if len(pipe.Cmds) == 0 {
		return false
	}
	cmd := pipe.Cmds[len(pipe.Cmds)-1]
	if len(cmd.Args) == 0 {
		return false
	}
	if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok {
		return id.Ident == "yamlQuote" || id.Ident == "yamlSafe" || id.Ident == "quote"
	}
	if nested, ok := cmd.Args[0].(*parse.PipeNode); ok {
		return scalarSerializer(nested)
	}
	return false
}

func mergeScalarContexts(groups ...[]scalarContext) ([]scalarContext, error) {
	seen := map[scalarContext]bool{}
	var result []scalarContext
	for _, group := range groups {
		for _, state := range group {
			if !seen[state] {
				seen[state] = true
				result = append(result, state)
			}
		}
	}
	if len(result) > 32 {
		return nil, fmt.Errorf("template has too many ambiguous YAML scalar contexts")
	}
	return result, nil
}

func validateScalarContexts(tmpl *template.Template, list *parse.ListNode, states []scalarContext, calls map[string]bool) ([]scalarContext, error) {
	if list == nil {
		return states, nil
	}
	for _, node := range list.Nodes {
		switch n := node.(type) {
		case *parse.TextNode:
			for i, state := range states {
				next, err := state.text(string(n.Text))
				if err != nil {
					return nil, err
				}
				states[i] = next
			}
		case *parse.ActionNode:
			if len(n.Pipe.Decl) > 0 {
				continue
			}
			for i, state := range states {
				if scalarSerializer(n.Pipe) {
					if !state.start || state.quote != 0 || state.comment || state.serialized {
						return nil, fmt.Errorf("template output %s must occupy a complete YAML scalar; remove surrounding quotes or fragments", n.String())
					}
					state.start = false
					state.serialized = true
				} else {
					// Literal output can change the surrounding YAML context. Other outputs
					// have already been restricted to identifiers/booleans/numbers.
					text := "identifier"
					if literal, ok := outputLiteral(n.Pipe); ok {
						text = literal
					}
					var err error
					state, err = state.text(text)
					if err != nil {
						return nil, err
					}
				}
				states[i] = state
			}
		case *parse.IfNode:
			var err error
			states, err = scalarBranches(tmpl, n.List, n.ElseList, states, calls)
			if err != nil {
				return nil, err
			}
		case *parse.WithNode:
			var err error
			states, err = scalarBranches(tmpl, n.List, n.ElseList, states, calls)
			if err != nil {
				return nil, err
			}
		case *parse.RangeNode:
			first, err := validateScalarContexts(tmpl, n.List, append([]scalarContext(nil), states...), calls)
			if err != nil {
				return nil, err
			}
			second, err := validateScalarContexts(tmpl, n.List, append([]scalarContext(nil), first...), calls)
			if err != nil {
				return nil, err
			}
			// Repeated iterations must not accumulate quote/flow-delimiter context.
			stable, err := mergeScalarContexts(first, second)
			if err != nil {
				return nil, err
			}
			if len(stable) != len(first) {
				return nil, fmt.Errorf("range body must preserve YAML scalar context across iterations")
			}
			zero, err := validateScalarContexts(tmpl, n.ElseList, append([]scalarContext(nil), states...), calls)
			if err != nil {
				return nil, err
			}
			states, err = mergeScalarContexts(zero, first)
			if err != nil {
				return nil, err
			}
		case *parse.TemplateNode:
			if calls[n.Name] {
				return nil, fmt.Errorf("recursive template %q cannot establish YAML scalar context", n.Name)
			}
			target := tmpl.Lookup(n.Name)
			if target == nil || target.Tree == nil {
				return nil, fmt.Errorf("undefined template %q", n.Name)
			}
			calls[n.Name] = true
			var err error
			states, err = validateScalarContexts(tmpl, target.Tree.Root, states, calls)
			delete(calls, n.Name)
			if err != nil {
				return nil, err
			}
		case *parse.BreakNode, *parse.ContinueNode:
			return nil, fmt.Errorf("break/continue cannot establish YAML scalar context; use a conditional body")
		}
	}
	return mergeScalarContexts(states)
}

func scalarBranches(tmpl *template.Template, yes, no *parse.ListNode, states []scalarContext, calls map[string]bool) ([]scalarContext, error) {
	a, err := validateScalarContexts(tmpl, yes, append([]scalarContext(nil), states...), calls)
	if err != nil {
		return nil, err
	}
	b, err := validateScalarContexts(tmpl, no, append([]scalarContext(nil), states...), calls)
	if err != nil {
		return nil, err
	}
	return mergeScalarContexts(a, b)
}

func outputLiteral(pipe *parse.PipeNode) (string, bool) {
	if len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return "", false
	}
	switch n := pipe.Cmds[0].Args[0].(type) {
	case *parse.StringNode:
		return n.Text, true
	case *parse.PipeNode:
		return outputLiteral(n)
	}
	return "", false
}
