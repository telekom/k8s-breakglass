package breakglass

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GroupMemberResolver abstracts IdP (Keycloak) group membership queries.
// Implementations should return slice of user identifiers (emails/usernames) for provided group.
type GroupMemberResolver interface {
	Members(ctx context.Context, group string) ([]string, error)
}

// KeycloakGroupMemberResolver uses GoCloak client to fetch group members from Keycloak admin API.
type KeycloakGroupMemberResolver struct {
	log       *zap.SugaredLogger
	cfg       cfgpkg.KeycloakRuntimeConfig
	gocloak   *gocloak.GoCloak
	cache     *kcCache
	token     string
	tokenTime time.Time
	tokenLock sync.RWMutex
}

type kcCache struct {
	mu    sync.RWMutex
	items map[string]kcEntry
	ttl   time.Duration
}
type kcEntry struct {
	members []string
	expires time.Time
}

func newKCCache(ttl time.Duration) *kcCache { return &kcCache{items: map[string]kcEntry{}, ttl: ttl} }
func (c *kcCache) get(k string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[k]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return append([]string(nil), e.members...), true
}
func (c *kcCache) set(k string, v []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[k] = kcEntry{members: append([]string(nil), v...), expires: time.Now().Add(c.ttl)}
}

func NewKeycloakGroupMemberResolver(log *zap.SugaredLogger, cfg cfgpkg.KeycloakRuntimeConfig) *KeycloakGroupMemberResolver {
	ttl := 10 * time.Minute
	if d, err := time.ParseDuration(cfg.CacheTTL); err == nil && d > 0 {
		ttl = d
	}
	gc := gocloak.NewClient(cfg.BaseURL)
	return &KeycloakGroupMemberResolver{log: log, cfg: cfg, gocloak: gc, cache: newKCCache(ttl)}
}

func (k *KeycloakGroupMemberResolver) getToken(ctx context.Context) (string, error) {
	// Use configured service account token if available
	if k.cfg.ServiceAccountToken != "" {
		if k.log != nil {
			// Log a sanitized version of the token for debugging
			tokenPreview := k.cfg.ServiceAccountToken
			if len(tokenPreview) > 20 {
				tokenPreview = tokenPreview[:20] + "..."
			}
			k.log.Debugw("Using pre-configured service account token", "tokenPreview", tokenPreview)
		}
		return k.cfg.ServiceAccountToken, nil
	}

	// Check cached token
	k.tokenLock.RLock()
	if k.token != "" && time.Now().Before(k.tokenTime.Add(5*time.Minute)) {
		defer k.tokenLock.RUnlock()
		if k.log != nil {
			k.log.Debugw("Using cached token", "expiresIn", time.Until(k.tokenTime.Add(5*time.Minute)).Seconds())
		}
		return k.token, nil
	}
	k.tokenLock.RUnlock()

	// Acquire new token using client credentials
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.cfg.BaseURL, k.cfg.Realm)
	if k.log != nil {
		k.log.Debugw("Acquiring token via client credentials",
			"clientID", k.cfg.ClientID,
			"baseURL", k.cfg.BaseURL,
			"realm", k.cfg.Realm,
			"endpoint", tokenURL,
			"grantType", "client_credentials",
			"clientSecretProvided", k.cfg.ClientSecret != "")
	}
	token, err := k.gocloak.GetToken(ctx, k.cfg.Realm, gocloak.TokenOptions{
		ClientID:     &k.cfg.ClientID,
		ClientSecret: &k.cfg.ClientSecret,
		GrantType:    gocloak.StringP("client_credentials"),
	})
	if err != nil {
		if k.log != nil {
			k.log.Errorw("Failed to acquire token",
				"clientID", k.cfg.ClientID,
				"error", err,
				"endpoint", tokenURL,
				"grantType", "client_credentials")
		}
		return "", err
	}

	// Cache token
	k.tokenLock.Lock()
	k.token = token.AccessToken
	k.tokenTime = time.Now()
	k.tokenLock.Unlock()

	if k.log != nil {
		tokenPreview := k.token
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:20] + "..."
		}
		k.log.Debugw("Token acquired successfully",
			"clientID", k.cfg.ClientID,
			"tokenPreview", tokenPreview,
			"expiresIn", token.ExpiresIn,
			"tokenType", token.TokenType)
	}
	return token.AccessToken, nil
}

func (k *KeycloakGroupMemberResolver) Members(ctx context.Context, group string) ([]string, error) {
	if k == nil {
		return nil, nil
	}
	log := k.log
	if k.cfg.BaseURL == "" || k.cfg.Realm == "" || k.cfg.ClientID == "" {
		if log != nil {
			log.Debugw("Keycloak resolver missing configuration; skipping group lookup",
				"group", group,
				"baseURL", k.cfg.BaseURL,
				"realm", k.cfg.Realm,
				"clientID", k.cfg.ClientID)
		}
		return nil, nil // gracefully skip when not configured
	}
	if v, ok := k.cache.get(group); ok {
		if log != nil {
			log.Debugw("Keycloak cache hit for group", "group", group, "membersCount", len(v), "members", v)
		}
		return v, nil
	}
	if log != nil {
		log.Debugw("Keycloak cache miss for group; will perform lookup", "group", group)
	}

	// Get token
	token, err := k.getToken(ctx)
	if err != nil {
		if log != nil {
			log.Errorw("Failed to get Keycloak token", "group", group, "error", err)
		}
		return nil, err
	}

	// 1. Search for group by name
	if log != nil {
		log.Debugw("Starting group search step", "group", group)
		tokenPreview := token
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:20] + "..."
		}
		log.Debugw("GetGroups API call details",
			"baseURL", k.cfg.BaseURL,
			"realm", k.cfg.Realm,
			"searchParam", group,
			"tokenPreview", tokenPreview,
			"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups", k.cfg.BaseURL, k.cfg.Realm))
	}
	params := gocloak.GetGroupsParams{Search: gocloak.StringP(group)}
	groups, err := k.gocloak.GetGroups(ctx, token, k.cfg.Realm, params)
	if err != nil {
		if log != nil {
			tokenPreview := token
			if len(tokenPreview) > 20 {
				tokenPreview = tokenPreview[:20] + "..."
			}
			log.Errorw("Keycloak groups search failed",
				"group", group,
				"error", err,
				"errorType", fmt.Sprintf("%T", err),
				"tokenPreview", tokenPreview,
				"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups", k.cfg.BaseURL, k.cfg.Realm),
				"params", fmt.Sprintf("search=%s", group))
		}
		return nil, err
	}
	if log != nil {
		log.Debugw("Keycloak groups search completed", "group", group, "returnedGroupCount", len(groups))
		if len(groups) > 0 {
			for i, g := range groups {
				log.Debugw("Group search result",
					"index", i,
					"groupID", g.ID,
					"groupName", g.Name,
					"hasSubgroups", g.SubGroups != nil && len(*g.SubGroups) > 0)
			}
		}
	}

	// Find matching group by name
	var groupID *string
	for _, g := range groups {
		if g.Name != nil && strings.EqualFold(*g.Name, group) {
			groupID = g.ID
			if log != nil {
				log.Debugw("Found matching group by name", "group", group, "groupID", *groupID, "matchedName", *g.Name)
			}
			break
		}
	}
	if groupID == nil {
		if log != nil {
			log.Warnw("Group not found in search results", "group", group)
		}
		k.cache.set(group, []string{})
		return []string{}, nil
	}

	// 2. Get direct group members
	if log != nil {
		log.Debugw("Starting direct members fetch step", "group", group, "groupID", *groupID)
		tokenPreview := token
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:20] + "..."
		}
		log.Debugw("GetGroupMembers API call details",
			"baseURL", k.cfg.BaseURL,
			"realm", k.cfg.Realm,
			"groupID", *groupID,
			"tokenPreview", tokenPreview,
			"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s/members", k.cfg.BaseURL, k.cfg.Realm, *groupID))
	}
	params2 := gocloak.GetGroupsParams{}
	members, err := k.gocloak.GetGroupMembers(ctx, token, k.cfg.Realm, *groupID, params2)
	if err != nil {
		if log != nil {
			tokenPreview := token
			if len(tokenPreview) > 20 {
				tokenPreview = tokenPreview[:20] + "..."
			}
			log.Errorw("Keycloak members fetch failed",
				"group", group,
				"groupID", *groupID,
				"error", err,
				"errorType", fmt.Sprintf("%T", err),
				"tokenPreview", tokenPreview,
				"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s/members", k.cfg.BaseURL, k.cfg.Realm, *groupID))
		}
		return nil, err
	}
	if log != nil {
		log.Debugw("Direct members fetch completed", "group", group, "directMemberCount", len(members))
		for i, m := range members {
			log.Debugw("Direct group member",
				"index", i,
				"userID", m.ID,
				"username", m.Username,
				"email", m.Email)
		}
	}

	// Collect member identifiers
	out := make([]string, 0, len(members))
	for i, m := range members {
		identifier := ""
		if m.Email != nil && *m.Email != "" {
			identifier = *m.Email
			if log != nil {
				log.Debugw("Added direct member by email", "group", group, "index", i, "email", identifier)
			}
		} else if m.Username != nil && *m.Username != "" {
			identifier = *m.Username
			if log != nil {
				log.Debugw("Added direct member by username", "group", group, "index", i, "username", identifier)
			}
		}
		if identifier != "" {
			out = append(out, identifier)
		}
	}

	// 3. Get group detail to retrieve subgroups
	if log != nil {
		log.Debugw("Starting subgroups fetch step", "group", group, "groupID", *groupID, "currentMemberCount", len(out))
		tokenPreview := token
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:20] + "..."
		}
		log.Debugw("GetGroup API call details",
			"baseURL", k.cfg.BaseURL,
			"realm", k.cfg.Realm,
			"groupID", *groupID,
			"tokenPreview", tokenPreview,
			"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s", k.cfg.BaseURL, k.cfg.Realm, *groupID))
	}
	groupDetail, err := k.gocloak.GetGroup(ctx, token, k.cfg.Realm, *groupID)
	if err != nil {
		if log != nil {
			tokenPreview := token
			if len(tokenPreview) > 20 {
				tokenPreview = tokenPreview[:20] + "..."
			}
			log.Warnw("Keycloak group detail fetch failed",
				"group", group,
				"error", err,
				"errorType", fmt.Sprintf("%T", err),
				"tokenPreview", tokenPreview,
				"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s", k.cfg.BaseURL, k.cfg.Realm, *groupID))
		}
		// Continue with just direct members
	} else if groupDetail != nil && groupDetail.SubGroups != nil {
		if log != nil {
			log.Debugw("Subgroups fetch completed", "group", group, "subgroupCount", len(*groupDetail.SubGroups))
		}
		for sgIdx, sg := range *groupDetail.SubGroups {
			if sg.ID == nil {
				continue
			}
			if log != nil {
				log.Debugw("Processing subgroup", "group", group, "parentGroupID", *groupID, "subgroupIndex", sgIdx, "subgroupID", *sg.ID, "subgroupName", sg.Name)
			}

			// Fetch members of each subgroup
			if log != nil {
				tokenPreview := token
				if len(tokenPreview) > 20 {
					tokenPreview = tokenPreview[:20] + "..."
				}
				log.Debugw("GetGroupMembers API call for subgroup",
					"baseURL", k.cfg.BaseURL,
					"realm", k.cfg.Realm,
					"subgroupID", *sg.ID,
					"tokenPreview", tokenPreview,
					"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s/members", k.cfg.BaseURL, k.cfg.Realm, *sg.ID))
			}
			params3 := gocloak.GetGroupsParams{}
			sgMembers, err := k.gocloak.GetGroupMembers(ctx, token, k.cfg.Realm, *sg.ID, params3)
			if err != nil {
				if log != nil {
					tokenPreview := token
					if len(tokenPreview) > 20 {
						tokenPreview = tokenPreview[:20] + "..."
					}
					log.Warnw("Subgroup members fetch failed",
						"group", group,
						"subgroupID", *sg.ID,
						"error", err,
						"errorType", fmt.Sprintf("%T", err),
						"tokenPreview", tokenPreview,
						"endpoint", fmt.Sprintf("%s/admin/realms/%s/groups/%s/members", k.cfg.BaseURL, k.cfg.Realm, *sg.ID))
				}
				continue
			}

			if log != nil {
				log.Debugw("Subgroup members fetch completed", "subgroupID", *sg.ID, "memberCount", len(sgMembers))
			}

			for sgmIdx, m := range sgMembers {
				identifier := ""
				if m.Email != nil && *m.Email != "" {
					identifier = *m.Email
					if log != nil {
						log.Debugw("Added subgroup member by email", "group", group, "subgroupID", *sg.ID, "memberIndex", sgmIdx, "email", identifier)
					}
				} else if m.Username != nil && *m.Username != "" {
					identifier = *m.Username
					if log != nil {
						log.Debugw("Added subgroup member by username", "group", group, "subgroupID", *sg.ID, "memberIndex", sgmIdx, "username", identifier)
					}
				}
				if identifier != "" {
					out = append(out, identifier)
				}
			}
		}
	}

	// 4. Normalize and deduplicate members
	if log != nil {
		log.Debugw("Starting member list normalization", "group", group, "beforeNormalizationCount", len(out))
	}
	out = normalizeMembers(out)
	if log != nil {
		log.Infow("Keycloak group member resolution completed successfully", "group", group, "finalResolvedCount", len(out), "members", out)
	}

	// 5. Cache and return results
	k.cache.set(group, out)
	if log != nil {
		log.Debugw("Group member resolution returning successfully", "group", group, "memberCount", len(out))
	}
	return out, nil
}

// EscalationStatusUpdater periodically expands approver groups into member lists and stores in status.
type EscalationStatusUpdater struct {
	Log           *zap.SugaredLogger
	K8sClient     client.Client
	Resolver      GroupMemberResolver
	Interval      time.Duration
	LeaderElected <-chan struct{} // Optional: signal when leadership acquired (nil = start immediately for backward compatibility)
	EventRecorder record.EventRecorder
	IDPLoader     *cfgpkg.IdentityProviderLoader // For multi-IDP group fetching
}

func (u EscalationStatusUpdater) Start(ctx context.Context) {
	// ensure logger present
	log := u.Log

	log = log.With("component", "EscalationStatusUpdater")

	// Wait for leadership signal if provided (enables multi-replica scaling with leader election)
	if u.LeaderElected != nil {
		log.Info("Escalation status updater waiting for leadership signal before starting...")
		select {
		case <-ctx.Done():
			log.Infow("Escalation status updater stopping before acquiring leadership (context cancelled)")
			return
		case <-u.LeaderElected:
			log.Info("Leadership acquired - starting escalation status updater")
		}
	}

	if u.Interval <= 0 {
		u.Interval = 5 * time.Minute
	}
	ticker := time.NewTicker(u.Interval)
	defer ticker.Stop()
	log.Infow("Starting escalation status updater", "interval", u.Interval.String())
	u.runOnce(ctx, log)
	for {
		select {
		case <-ctx.Done():
			log.Infow("Escalation status updater stopping (context done)")
			return
		case <-ticker.C:
			u.runOnce(ctx, log)
		}
	}
}

func (u EscalationStatusUpdater) runOnce(ctx context.Context, log *zap.SugaredLogger) {
	log.Debugw("Starting escalation status update cycle", "resolver", fmt.Sprintf("%T", u.Resolver))
	escList := telekomv1alpha1.BreakglassEscalationList{}
	if err := u.K8sClient.List(ctx, &escList); err != nil {
		log.Errorw("Failed listing BreakglassEscalations for status update", "error", err)
		return
	}
	log.Debugw("Fetched escalations for status update", "count", len(escList.Items))

	for _, esc := range escList.Items {
		// Collect approver groups
		groups := esc.Spec.Approvers.Groups
		if len(groups) == 0 {
			log.Debugw("Escalation has no approver groups; skipping", "escalation", esc.Name)
			continue
		}
		log.Debugw("Processing escalation with approver groups", "escalation", esc.Name, "groupCount", len(groups), "groups", groups)

		updated := esc.DeepCopy()
		if updated.Status.ApproverGroupMembers == nil {
			updated.Status.ApproverGroupMembers = map[string][]string{}
		}

		// Check if multi-IDP fields are set (Phase 2 feature)
		hasMultiIDPFields := len(esc.Spec.AllowedIdentityProvidersForApprovers) > 0

		changed := false

		if hasMultiIDPFields {
			// Phase 2: Use multi-IDP group sync with IDP hierarchy storage
			log.Debugw("Using multi-IDP group sync", "escalation", esc.Name, "idps", esc.Spec.AllowedIdentityProvidersForApprovers)

			hierarchy, syncStatus, syncErrors := u.fetchGroupMembersFromMultipleIDPs(
				ctx,
				&esc,
				esc.Spec.AllowedIdentityProvidersForApprovers,
				groups,
				log,
			)

			// Store full IDP hierarchy in status (NOT deduplicated)
			if !equalIDPHierarchy(hierarchy, updated.Status.IDPGroupMemberships) {
				updated.Status.IDPGroupMemberships = hierarchy
				changed = true
			}

			// Store sync status
			if updated.Status.GroupSyncStatus != syncStatus {
				updated.Status.GroupSyncStatus = syncStatus
				changed = true
			}

			// Store sync errors
			if !equalStringSlices(syncErrors, updated.Status.GroupSyncErrors) {
				updated.Status.GroupSyncErrors = syncErrors
				changed = true
			}

			// Store deduplicated members in ApproverGroupMembers for immediate use
			// These are deduplicated across all IDPs by email/username and ready for:
			// - Email notifications (approvers list)
			// - Session approval validation
			// - Request validation
			// The full per-IDP hierarchy is preserved in IDPGroupMemberships for debugging/auditing
			for _, g := range groups {
				dedupMembers := deduplicateMembersFromHierarchy(hierarchy, g)
				if !equalStringSlices(dedupMembers, updated.Status.ApproverGroupMembers[g]) {
					updated.Status.ApproverGroupMembers[g] = dedupMembers
					changed = true
				}
			}
		} else {
			// Legacy single-resolver mode for backward compatibility
			log.Debugw("Using legacy single resolver mode", "escalation", esc.Name)

			for _, g := range groups {
				log.Debugw("Resolving group for escalation", "escalation", esc.Name, "group", g, "resolverType", fmt.Sprintf("%T", u.Resolver))
				var norm []string
				if u.Resolver != nil {
					log.Debugw("Calling group member resolver", "group", g, "escalation", esc.Name, "resolverType", fmt.Sprintf("%T", u.Resolver))
					members, err := u.Resolver.Members(ctx, g)
					if err != nil {
						log.Errorw("Failed resolving group members from resolver", "group", g, "escalation", esc.Name, "error", err, "resolverType", fmt.Sprintf("%T", u.Resolver))
						// record resolution error in status
						if updated.Status.GroupResolutionStatus == nil {
							updated.Status.GroupResolutionStatus = map[string]string{}
						}
						updated.Status.GroupResolutionStatus[g] = fmt.Sprintf("error: %v", err)
						continue
					}
					log.Debugw("Group member resolver returned members", "group", g, "escalation", esc.Name, "rawMemberCount", len(members), "members", members)
					norm = normalizeMembers(members)
					log.Infow("Resolved approver group members (normalized)", "group", g, "escalation", esc.Name, "rawCount", len(members), "normalizedCount", len(norm), "normalizedMembers", norm)
					// mark group resolution ok in status
					if updated.Status.GroupResolutionStatus == nil {
						updated.Status.GroupResolutionStatus = map[string]string{}
					}
					updated.Status.GroupResolutionStatus[g] = "ok"
				} else {
					log.Warnw("No group member resolver configured; skipping group resolution", "group", g, "escalation", esc.Name)
					if updated.Status.GroupResolutionStatus == nil {
						updated.Status.GroupResolutionStatus = map[string]string{}
					}
					updated.Status.GroupResolutionStatus[g] = "disabled"
					continue
				}
				if !equalStringSlices(norm, updated.Status.ApproverGroupMembers[g]) {
					log.Debugw("Group members changed; marking for update", "group", g, "escalation", esc.Name, "oldCount", len(updated.Status.ApproverGroupMembers[g]), "newCount", len(norm))
					updated.Status.ApproverGroupMembers[g] = norm
					changed = true
				}
			}
		}

		if changed {
			log.Infow("Updating escalation status with resolved group members", "escalation", esc.Name, "groupCount", len(groups))
			if err := u.K8sClient.Status().Update(ctx, updated); err != nil {
				log.Errorw("Failed updating escalation status", "escalation", esc.Name, "error", err)
			} else {
				log.Debugw("Updated escalation successfully", "escalation", esc.Name, "groups", groups)
			}
		}
	}
	log.Debugw("Completed escalation status update cycle")
}

// fetchGroupMembersFromMultipleIDPs fetches group members from multiple IDPs and stores in IDP hierarchy structure.
// Returns: map[idpName]map[groupName][]memberList, syncStatus, and error list (never blocks escalation creation)
func (u EscalationStatusUpdater) fetchGroupMembersFromMultipleIDPs(
	ctx context.Context,
	escalation *telekomv1alpha1.BreakglassEscalation,
	idpNames []string,
	groups []string,
	log *zap.SugaredLogger,
) (map[string]map[string][]string, string, []string) {
	// Structure: map[idpName]map[groupName][]memberList
	hierarchy := make(map[string]map[string][]string)
	var syncErrors []string
	successCount := 0
	failureCount := 0

	if u.IDPLoader == nil {
		log.Debugw("IDPLoader not configured; using single resolver fallback", "escalation", escalation.Name)
		// Fallback: use legacy single resolver for backward compatibility
		groupMembers := make(map[string][]string)
		for _, g := range groups {
			if u.Resolver != nil {
				members, err := u.Resolver.Members(ctx, g)
				if err != nil {
					log.Errorw("Failed to resolve group members", "escalation", escalation.Name, "group", g, "error", err)
					continue
				}
				groupMembers[g] = normalizeMembers(members)
			}
		}
		// Store in hierarchy under empty IDP name for backward compat
		if len(groupMembers) > 0 {
			hierarchy[""] = groupMembers
		}
		return hierarchy, "Success", nil
	}

	// Multi-IDP sync: fetch from each IDP for each group
	for _, idpName := range idpNames {
		log.Debugw("Fetching group members from IDP", "escalation", escalation.Name, "idp", idpName, "groups", groups)

		idpConfig, err := u.IDPLoader.LoadIdentityProviderByName(ctx, idpName)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to load IDP config: %v", err)
			log.Errorw("Failed to load IDP configuration", "escalation", escalation.Name, "idp", idpName, "error", err)
			syncErrors = append(syncErrors, errorMsg)
			failureCount++

			// Emit event on IdentityProvider resource
			if u.EventRecorder != nil {
				idp := &telekomv1alpha1.IdentityProvider{}
				idp.SetName(idpName)
				u.EventRecorder.Eventf(idp, "Warning", "GroupSyncConfigLoadFailed",
					"Failed to load IDP config for escalation %s/%s: %v",
					escalation.Namespace, escalation.Name, err)
			}
			continue
		}

		// Create resolver for this IDP
		resolver := u.createResolverForIDP(idpConfig, log)
		if resolver == nil {
			errorMsg := fmt.Sprintf("Failed to create resolver for IDP: %s", idpName)
			log.Warnw("Failed to create resolver for IDP", "escalation", escalation.Name, "idp", idpName)
			syncErrors = append(syncErrors, errorMsg)
			failureCount++

			// Emit event on IdentityProvider resource
			if u.EventRecorder != nil {
				idp := &telekomv1alpha1.IdentityProvider{}
				idp.SetName(idpName)
				u.EventRecorder.Eventf(idp, "Warning", "GroupSyncResolverCreationFailed",
					"Failed to create group sync resolver for escalation %s/%s",
					escalation.Namespace, escalation.Name)
			}
			continue
		}

		// Fetch group members for this IDP
		idpGroupMembers := make(map[string][]string)
		idpSuccess := true

		for _, g := range groups {
			members, err := resolver.Members(ctx, g)
			if err != nil {
				errorMsg := fmt.Sprintf("IDP %s: timeout/error fetching group %s: %v", idpName, g, err)
				log.Warnw("Failed to resolve group members from IDP", "escalation", escalation.Name, "idp", idpName, "group", g, "error", err)
				syncErrors = append(syncErrors, errorMsg)
				idpSuccess = false

				// Emit event on IdentityProvider resource
				if u.EventRecorder != nil {
					idp := &telekomv1alpha1.IdentityProvider{}
					idp.SetName(idpName)
					u.EventRecorder.Eventf(idp, "Warning", "GroupFetchFailed",
						"Failed to fetch group %s for escalation %s/%s: %v",
						g, escalation.Namespace, escalation.Name, err)
				}
				continue
			}
			idpGroupMembers[g] = normalizeMembers(members)
		}

		if idpSuccess {
			successCount++
		} else {
			failureCount++
		}

		// Store members under IDP name in hierarchy
		hierarchy[idpName] = idpGroupMembers
	}

	// Determine sync status
	var syncStatus string
	if failureCount == 0 {
		syncStatus = "Success"
	} else if successCount > 0 && failureCount > 0 {
		syncStatus = "PartialFailure"
	} else {
		syncStatus = "Failed"
	}

	log.Infow("Multi-IDP group sync completed",
		"escalation", escalation.Name,
		"idpCount", len(idpNames),
		"successCount", successCount,
		"failureCount", failureCount,
		"syncStatus", syncStatus,
		"errorCount", len(syncErrors))

	// Emit event on BreakglassEscalation if there were failures
	if failureCount > 0 && u.EventRecorder != nil {
		u.EventRecorder.Eventf(escalation, "Warning", "GroupSyncPartialFailure",
			"Multi-IDP group sync partially failed: %d IDPs succeeded, %d failed. See status.groupSyncErrors for details.",
			successCount, failureCount)
	}

	return hierarchy, syncStatus, syncErrors
}

// createResolverForIDP creates an appropriate resolver for the given IDP config
func (u EscalationStatusUpdater) createResolverForIDP(idpConfig *cfgpkg.IdentityProviderConfig, log *zap.SugaredLogger) GroupMemberResolver {
	if idpConfig == nil {
		return nil
	}

	// Currently only Keycloak is supported
	if idpConfig.Keycloak == nil {
		return nil
	}

	return NewKeycloakGroupMemberResolver(log, *idpConfig.Keycloak)
}

func normalizeMembers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, m := range in {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	// stable order not critical here; could sort if needed
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	amap := map[string]int{}
	for _, v := range a {
		amap[v]++
	}
	for _, v := range b {
		if amap[v] == 0 {
			return false
		}
		amap[v]--
	}
	for _, c := range amap {
		if c != 0 {
			return false
		}
	}
	return true
}

// equalIDPHierarchy compares two IDP hierarchies for equality
func equalIDPHierarchy(a, b map[string]map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for idpName, groupMembers := range a {
		bGroupMembers, ok := b[idpName]
		if !ok {
			return false
		}
		if len(groupMembers) != len(bGroupMembers) {
			return false
		}
		for groupName, members := range groupMembers {
			bMembers, ok := bGroupMembers[groupName]
			if !ok {
				return false
			}
			if !equalStringSlices(members, bMembers) {
				return false
			}
		}
	}
	return true
}

// deduplicateMembersFromHierarchy extracts and deduplicates members from IDP hierarchy for a specific group
// Returns the deduplicated list of members for that group from all IDPs
func deduplicateMembersFromHierarchy(hierarchy map[string]map[string][]string, group string) []string {
	seen := make(map[string]struct{})
	var result []string

	// Iterate through each IDP in hierarchy
	for _, groupMembers := range hierarchy {
		if members, ok := groupMembers[group]; ok {
			for _, member := range members {
				// Normalize and deduplicate
				normalized := strings.TrimSpace(strings.ToLower(member))
				if normalized == "" {
					continue
				}
				if _, alreadySeen := seen[normalized]; !alreadySeen {
					seen[normalized] = struct{}{}
					result = append(result, normalized)
				}
			}
		}
	}

	return result
}
