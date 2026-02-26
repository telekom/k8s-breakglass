package breakglass

import "context"

// GroupMemberResolver abstracts IdP (Keycloak) group membership queries.
// Implementations should return slice of user identifiers (emails/usernames) for provided group.
// Defined in root so both root (EscalationManager) and sub-packages (escalation/) can use it.
type GroupMemberResolver interface {
	Members(ctx context.Context, group string) ([]string, error)
}
