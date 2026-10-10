// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"slices"
)

type actorContextKey struct{}

type authenticatedActor struct {
	identifiers []string
	groups      []string
}

// WithAuthenticatedActor carries verified identity claims, never tokens, to audit
// emission sites. Call only after authentication, not from untrusted request input.
func WithAuthenticatedActor(ctx context.Context, identifiers, groups []string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, authenticatedActor{
		identifiers: slices.Clone(identifiers), groups: slices.Clone(groups),
	})
}

func enrichActor(ctx context.Context, event *Event) {
	actor, ok := ctx.Value(actorContextKey{}).(authenticatedActor)
	if ok && event.Actor.User != "" && slices.Contains(actor.identifiers, event.Actor.User) {
		event.Actor.Groups = slices.Clone(actor.groups)
	}
}
