package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GroupMemberResolver abstracts IdP (Keycloak) group membership queries.
// Implementations should return slice of user identifiers (emails/usernames) for provided group.
type GroupMemberResolver interface {
	Members(ctx context.Context, group string) ([]string, error)
}

// KeycloakGroupMemberResolver is a placeholder; implement actual Keycloak admin API lookup.
type KeycloakGroupMemberResolver struct {
	log    *zap.SugaredLogger
	cfg    cfgpkg.Keycloak
	client *http.Client
	cache  *kcCache
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

func NewKeycloakGroupMemberResolver(log *zap.SugaredLogger, cfg cfgpkg.Keycloak) *KeycloakGroupMemberResolver {
	timeout := 10 * time.Second
	if d, err := time.ParseDuration(cfg.RequestTimeout); err == nil && d > 0 {
		timeout = d
	}
	ttl := 10 * time.Minute
	if d, err := time.ParseDuration(cfg.CacheTTL); err == nil && d > 0 {
		ttl = d
	}
	return &KeycloakGroupMemberResolver{log: log, cfg: cfg, client: &http.Client{Timeout: timeout}, cache: newKCCache(ttl)}
}

func (k *KeycloakGroupMemberResolver) Members(ctx context.Context, group string) ([]string, error) {
	if k == nil {
		return nil, nil
	}
	log := k.log
	if k.cfg.Disable || k.cfg.BaseURL == "" || k.cfg.Realm == "" || k.cfg.ClientID == "" {
		if log != nil {
			log.Debugw("Keycloak resolver disabled or missing configuration; skipping group lookup",
				"group", group,
				"disabled", k.cfg.Disable,
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

	// Determine token: either use ServiceAccountToken or obtain via client_credentials
	var token string
	var err error
	if k.cfg.ServiceAccountToken != "" {
		token = k.cfg.ServiceAccountToken
		if log != nil {
			log.Debugw("Using configured service account token for group query", "group", group)
		}
	} else {
		// Acquire client credentials token
		if log != nil {
			log.Debugw("Attempting to acquire Keycloak token via client_credentials flow", "group", group, "clientID", k.cfg.ClientID)
		}
		startToken := time.Now()
		token, err = k.clientCredsToken(ctx)
		if err != nil {
			if log != nil {
				log.Warnw("Failed to obtain Keycloak token via client_credentials", "group", group, "error", err, "took", time.Since(startToken).String())
			}
			return nil, err
		}
		if log != nil {
			log.Debugw("Successfully obtained Keycloak token via client_credentials", "group", group, "took", time.Since(startToken).String())
		}
	}

	// 1. Find group ID by name
	if log != nil {
		log.Debugw("Starting group search step", "group", group, "baseURL", k.cfg.BaseURL, "realm", k.cfg.Realm)
	}
	gURL := fmt.Sprintf("%s/realms/%s/groups?search=%s", strings.TrimRight(k.cfg.BaseURL, "/"), url.PathEscape(k.cfg.Realm), url.QueryEscape(group))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if log != nil {
		log.Debugw("Executing Keycloak groups search HTTP request", "url", gURL, "group", group, "method", "GET")
	}
	gStart := time.Now()
	resp, err := k.client.Do(req)
	if err != nil {
		if log != nil {
			log.Errorw("Keycloak groups search HTTP request failed", "url", gURL, "group", group, "error", err, "took", time.Since(gStart).String())
		}
		return nil, err
	}
	defer resp.Body.Close()
	// Read body for improved diagnostics
	gBody, _ := io.ReadAll(resp.Body)
	if log != nil {
		log.Debugw("Keycloak groups search HTTP response received", "group", group, "statusCode", resp.StatusCode, "contentLength", len(gBody), "took", time.Since(gStart).String())
	}
	if resp.StatusCode != 200 {
		if log != nil {
			log.Errorw("Keycloak groups search returned non-200 status", "status", resp.StatusCode, "url", gURL, "group", group, "took", time.Since(gStart).String(), "body", string(bytes.TrimSpace(gBody)))
		}
		return nil, fmt.Errorf("keycloak groups search status %d", resp.StatusCode)
	}
	var groups []struct{ ID, Name string }
	if err := json.NewDecoder(bytes.NewReader(gBody)).Decode(&groups); err != nil {
		if log != nil {
			log.Errorw("Failed to decode Keycloak groups response JSON", "error", err, "group", group, "body", string(bytes.TrimSpace(gBody)))
		}
		return nil, err
	}
	if log != nil {
		log.Debugw("Keycloak groups search completed successfully", "group", group, "returnedGroupCount", len(groups), "took", time.Since(gStart).String(), "groups", groups)
	}
	var groupID string
	for _, g := range groups {
		if strings.EqualFold(g.Name, group) {
			groupID = g.ID
			if log != nil {
				log.Debugw("Found matching group by name", "group", group, "groupID", groupID, "matchedName", g.Name)
			}
			break
		}
	}
	if groupID == "" {
		if log != nil {
			log.Warnw("Group not found in Keycloak search results", "group", group, "searchedName", group, "returnedGroups", groups)
		}
		k.cache.set(group, []string{})
		return []string{}, nil
	}

	// 2. List direct group members
	if log != nil {
		log.Debugw("Starting direct members fetch step", "group", group, "groupID", groupID)
	}
	mURL := fmt.Sprintf("%s/realms/%s/groups/%s/members?q=&briefRepresentation=false", strings.TrimRight(k.cfg.BaseURL, "/"), url.PathEscape(k.cfg.Realm), url.PathEscape(groupID))
	mreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, mURL, nil)
	mreq.Header.Set("Authorization", "Bearer "+token)
	if log != nil {
		log.Debugw("Executing Keycloak members fetch HTTP request", "url", mURL, "group", group, "groupID", groupID, "method", "GET")
	}
	mStart := time.Now()
	mresp, err := k.client.Do(mreq)
	if err != nil {
		if log != nil {
			log.Errorw("Keycloak members fetch HTTP request failed", "url", mURL, "group", group, "error", err, "took", time.Since(mStart).String())
		}
		return nil, err
	}
	defer mresp.Body.Close()
	mBody, _ := io.ReadAll(mresp.Body)
	if log != nil {
		log.Debugw("Keycloak members fetch HTTP response received", "group", group, "statusCode", mresp.StatusCode, "contentLength", len(mBody), "took", time.Since(mStart).String())
	}
	if mresp.StatusCode != 200 {
		if log != nil {
			log.Errorw("Keycloak members fetch returned non-200 status", "status", mresp.StatusCode, "url", mURL, "group", group, "took", time.Since(mStart).String(), "body", string(bytes.TrimSpace(mBody)))
		}
		return nil, fmt.Errorf("keycloak members status %d", mresp.StatusCode)
	}
	var membersRaw []struct{ Username, Email string }
	if err := json.NewDecoder(bytes.NewReader(mBody)).Decode(&membersRaw); err != nil {
		if log != nil {
			log.Errorw("Failed to decode Keycloak members response JSON", "error", err, "group", group, "body", string(bytes.TrimSpace(mBody)))
		}
		return nil, err
	}
	if log != nil {
		log.Debugw("Keycloak direct members fetch completed", "group", group, "directMemberCount", len(membersRaw), "took", time.Since(mStart).String())
	}
	out := make([]string, 0, len(membersRaw))
	for i, m := range membersRaw {
		if m.Email != "" {
			out = append(out, m.Email)
			if log != nil {
				log.Debugw("Added direct member by email", "group", group, "index", i, "email", m.Email)
			}
		} else if m.Username != "" {
			out = append(out, m.Username)
			if log != nil {
				log.Debugw("Added direct member by username", "group", group, "index", i, "username", m.Username)
			}
		}
	}

	// 3. Fetch subgroups and their members recursively
	if log != nil {
		log.Debugw("Starting subgroups fetch step", "group", group, "groupID", groupID, "currentMemberCount", len(out))
	}
	sgURL := fmt.Sprintf("%s/realms/%s/groups/%s", strings.TrimRight(k.cfg.BaseURL, "/"), url.PathEscape(k.cfg.Realm), url.PathEscape(groupID))
	sgreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, sgURL, nil)
	sgreq.Header.Set("Authorization", "Bearer "+token)
	if log != nil {
		log.Debugw("Executing Keycloak subgroups fetch HTTP request", "url", sgURL, "group", group, "groupID", groupID, "method", "GET")
	}
	sgStart := time.Now()
	sgresp, err := k.client.Do(sgreq)
	if err != nil {
		if log != nil {
			log.Warnw("Keycloak subgroups fetch HTTP request failed", "url", sgURL, "group", group, "error", err, "took", time.Since(sgStart).String())
		}
		// Continue with direct members if subgroups fetch fails
		if log != nil {
			log.Infow("Continuing with direct members only (subgroups fetch failed)", "group", group, "directMemberCount", len(out))
		}
	} else {
		defer sgresp.Body.Close()
		sgBody, _ := io.ReadAll(sgresp.Body)
		if log != nil {
			log.Debugw("Keycloak subgroups fetch HTTP response received", "group", group, "statusCode", sgresp.StatusCode, "contentLength", len(sgBody), "took", time.Since(sgStart).String())
		}
		if sgresp.StatusCode == 200 {
			var groupDetail struct{ SubGroups []struct{ ID string } }
			if err := json.NewDecoder(bytes.NewReader(sgBody)).Decode(&groupDetail); err == nil {
				if log != nil {
					log.Debugw("Keycloak subgroups fetch decoded successfully", "group", group, "subgroupCount", len(groupDetail.SubGroups), "took", time.Since(sgStart).String())
				}
				// Fetch members from each subgroup
				for sgIdx, sg := range groupDetail.SubGroups {
					if log != nil {
						log.Debugw("Processing subgroup", "group", group, "parentGroupID", groupID, "subgroupIndex", sgIdx, "subgroupID", sg.ID, "totalSubgroups", len(groupDetail.SubGroups))
					}
					sgmURL := fmt.Sprintf("%s/realms/%s/groups/%s/members", strings.TrimRight(k.cfg.BaseURL, "/"), url.PathEscape(k.cfg.Realm), url.PathEscape(sg.ID))
					sgmreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, sgmURL, nil)
					sgmreq.Header.Set("Authorization", "Bearer "+token)
					if log != nil {
						log.Debugw("Executing subgroup members fetch HTTP request", "url", sgmURL, "group", group, "subgroupID", sg.ID, "method", "GET")
					}
					sgmStart := time.Now()
					sgmresp, err := k.client.Do(sgmreq)
					if err != nil {
						if log != nil {
							log.Warnw("Subgroup members fetch HTTP request failed", "group", group, "subgroupID", sg.ID, "error", err, "took", time.Since(sgmStart).String())
						}
						continue
					}
					defer sgmresp.Body.Close()
					if log != nil {
						log.Debugw("Subgroup members fetch HTTP response received", "group", group, "subgroupID", sg.ID, "statusCode", sgmresp.StatusCode, "took", time.Since(sgmStart).String())
					}
					if sgmresp.StatusCode == 200 {
						var sgmembers []struct{ Username, Email string }
						if err := json.NewDecoder(sgmresp.Body).Decode(&sgmembers); err == nil {
							if log != nil {
								log.Debugw("Subgroup members decoded successfully", "group", group, "subgroupID", sg.ID, "memberCount", len(sgmembers))
							}
							for sgmIdx, m := range sgmembers {
								if m.Email != "" {
									out = append(out, m.Email)
									if log != nil {
										log.Debugw("Added subgroup member by email", "group", group, "subgroupID", sg.ID, "memberIndex", sgmIdx, "email", m.Email)
									}
								} else if m.Username != "" {
									out = append(out, m.Username)
									if log != nil {
										log.Debugw("Added subgroup member by username", "group", group, "subgroupID", sg.ID, "memberIndex", sgmIdx, "username", m.Username)
									}
								}
							}
						} else if log != nil {
							log.Warnw("Failed to decode subgroup members JSON", "group", group, "subgroupID", sg.ID, "error", err)
						}
					} else if log != nil {
						log.Warnw("Subgroup members fetch returned non-200 status", "group", group, "subgroupID", sg.ID, "statusCode", sgmresp.StatusCode)
					}
				}
			} else if log != nil {
				log.Warnw("Failed to decode subgroups list JSON", "group", group, "error", err)
			}
		} else if log != nil {
			log.Warnw("Subgroups fetch returned non-200 status", "group", group, "statusCode", sgresp.StatusCode)
		}
	}

	// 4. Normalize and deduplicate members
	if log != nil {
		log.Debugw("Starting member list normalization", "group", group, "beforeNormalizationCount", len(out), "members", out)
	}
	out = normalizeMembers(out)
	if log != nil {
		log.Infow("Keycloak group member resolution completed successfully", "group", group, "directMemberCount", len(membersRaw), "finalResolvedCount", len(out), "members", out)
	}

	// 5. Cache and return results
	if log != nil {
		log.Debugw("Caching group members for TTL", "group", group, "memberCount", len(out), "cacheTTL", k.cfg.CacheTTL)
	}
	k.cache.set(group, out)
	if log != nil {
		log.Debugw("Group member resolution function returning successfully", "group", group, "memberCount", len(out))
	}
	return out, nil
}

func (k *KeycloakGroupMemberResolver) clientCredsToken(ctx context.Context) (string, error) {
	log := k.log
	if log != nil {
		log.Debugw("clientCredsToken function called", "clientID", k.cfg.ClientID, "realm", k.cfg.Realm)
	}
	if k.cfg.ClientSecret == "" {
		if log != nil {
			log.Errorw("clientCredsToken failed: ClientSecret is empty", "clientID", k.cfg.ClientID)
		}
		return "", errors.New("keycloak clientSecret empty; only client_credentials supported now")
	}
	if log != nil {
		log.Debugw("Preparing client credentials form", "clientID", k.cfg.ClientID, "grantType", "client_credentials")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", k.cfg.ClientID)
	form.Set("client_secret", k.cfg.ClientSecret)
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", strings.TrimRight(k.cfg.BaseURL, "/"), url.PathEscape(k.cfg.Realm))
	if log != nil {
		log.Debugw("Executing token request", "tokenURL", tokenURL, "clientID", k.cfg.ClientID, "method", "POST")
	}
	startReq := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.client.Do(req)
	if err != nil {
		if log != nil {
			log.Errorw("Token request HTTP failed", "tokenURL", tokenURL, "clientID", k.cfg.ClientID, "error", err, "took", time.Since(startReq).String())
		}
		return "", err
	}
	defer resp.Body.Close()
	if log != nil {
		log.Debugw("Token request HTTP response received", "tokenURL", tokenURL, "statusCode", resp.StatusCode, "took", time.Since(startReq).String())
	}
	if resp.StatusCode != 200 {
		if log != nil {
			log.Errorw("Token request returned non-200 status", "tokenURL", tokenURL, "statusCode", resp.StatusCode)
		}
		return "", fmt.Errorf("keycloak token status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		if log != nil {
			log.Errorw("Failed to decode token response JSON", "tokenURL", tokenURL, "error", err)
		}
		return "", err
	}
	if tr.AccessToken == "" {
		if log != nil {
			log.Errorw("Token response contained empty access_token", "tokenURL", tokenURL)
		}
		return "", errors.New("empty keycloak access_token")
	}
	if log != nil {
		log.Debugw("clientCredsToken function returning successfully", "clientID", k.cfg.ClientID, "tokenLength", len(tr.AccessToken))
	}
	return tr.AccessToken, nil
}

// EscalationStatusUpdater periodically expands approver groups into member lists and stores in status.
type EscalationStatusUpdater struct {
	Log       *zap.SugaredLogger
	K8sClient client.Client
	Resolver  GroupMemberResolver
	Interval  time.Duration
}

func (u EscalationStatusUpdater) Start(ctx context.Context) {
	// ensure logger present
	log := u.Log

	log = log.With("component", "EscalationStatusUpdater")
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
		changed := false
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
		if changed {
			log.Infow("Updating escalation status with resolved group members", "escalation", esc.Name, "groupCount", len(groups))
			if err := u.K8sClient.Status().Update(ctx, updated); err != nil {
				log.Errorw("Failed updating escalation status", "escalation", esc.Name, "error", err)
			} else {
				log.Debugw("Updated escalation approverGroupMembers successfully", "escalation", esc.Name, "groups", groups)
			}
		}
	}
	log.Debugw("Completed escalation status update cycle")
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
