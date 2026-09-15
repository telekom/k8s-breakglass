package breakglass

import (
	"context"
	"errors"
	"fmt"
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
	return fmt.Sprintf("%s: %q", ErrGroupNotFound, e.Group)
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
