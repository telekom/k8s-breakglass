package breakglass

import (
	"context"
	"errors"
	"fmt"

	"github.com/telekom/k8s-breakglass/pkg/system"
)

// GroupMemberResolver abstracts IdP (Keycloak) group membership queries.
// Implementations should return a slice of user identifiers (emails/usernames)
// for the provided group. An empty slice and a nil error mean that the group
// exists but has no resolvable members. Implementations must return
// NewGroupNotFoundError when the configured group does not exist.
// Defined in root so both root (EscalationManager) and sub-packages (escalation/) can use it.
type GroupMemberResolver interface {
	Members(ctx context.Context, group string) ([]string, error)
}

// ErrGroupNotFound identifies a configured group that does not exist in the
// identity provider.
var ErrGroupNotFound = errors.New("group not found")

// GroupNotFoundError includes the configured group name while preserving
// errors.Is(err, ErrGroupNotFound) classification for callers.
type GroupNotFoundError struct {
	Group string
}

// Error implements the error interface.
func (e GroupNotFoundError) Error() string {
	if e.Group == "" {
		return ErrGroupNotFound.Error()
	}
	// Errors are logged verbatim; honor server.redactLogs for the group name.
	return fmt.Sprintf("%s: %q", ErrGroupNotFound, system.RedactGroupName(e.Group))
}

// Unwrap exposes the stable ErrGroupNotFound classification.
func (e GroupNotFoundError) Unwrap() error {
	return ErrGroupNotFound
}

// NewGroupNotFoundError creates a classified error for a missing group.
func NewGroupNotFoundError(group string) error {
	return GroupNotFoundError{Group: group}
}

// IsGroupNotFound reports whether err identifies a missing identity-provider group.
func IsGroupNotFound(err error) bool {
	return errors.Is(err, ErrGroupNotFound)
}

// ErrGroupAmbiguous classifies a configured group name that matches more than
// one identity-provider group. It is a permanent resolution failure: callers
// must not reuse cached members for the group.
var ErrGroupAmbiguous = errors.New("group is ambiguous")

// GroupAmbiguousError includes the configured group name and the number of
// matching identity-provider groups while preserving errors.Is(err, ErrGroupAmbiguous).
type GroupAmbiguousError struct {
	Group   string
	Matches int
}

// Error implements the error interface.
func (e GroupAmbiguousError) Error() string {
	// Errors are logged verbatim; honor server.redactLogs for the group name.
	return fmt.Sprintf("%s: %q matches %d groups", ErrGroupAmbiguous, system.RedactGroupName(e.Group), e.Matches)
}

// Unwrap exposes the stable ErrGroupAmbiguous classification.
func (e GroupAmbiguousError) Unwrap() error {
	return ErrGroupAmbiguous
}

// NewGroupAmbiguousError creates a classified error for an ambiguous group.
func NewGroupAmbiguousError(group string, matches int) error {
	return GroupAmbiguousError{Group: group, Matches: matches}
}

// IsGroupAmbiguous reports whether err identifies an ambiguous identity-provider group.
func IsGroupAmbiguous(err error) bool {
	return errors.Is(err, ErrGroupAmbiguous)
}
