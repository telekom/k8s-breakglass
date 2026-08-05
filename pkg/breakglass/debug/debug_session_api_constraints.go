package debug

import (
	"context"
	"fmt"
	"sort"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// defaultDebugNamespace is the fallback namespace used when neither the
// template nor the binding defines a default namespace.
const defaultDebugNamespace = "breakglass-debug"

const maxRequiredNodeSelectorTerms = 128

type schedulingOptionRequester struct {
	Username string
	Email    string
	Groups   []string
}

type schedulingOptionAccessError struct {
	optionName string
}

func (e *schedulingOptionAccessError) Error() string {
	return fmt.Sprintf("user is not allowed to select scheduling option '%s'", e.optionName)
}

func (c *DebugSessionAPIController) resolveTargetNamespace(
	ctx context.Context,
	cluster string,
	template *breakglassv1alpha1.DebugSessionTemplate,
	requestedNamespace string,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) (string, error) {
	// Start with template's namespace constraints
	nc := template.Spec.NamespaceConstraints

	// If binding has namespace constraints, merge them without widening the template.
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		nc = c.mergeNamespaceConstraints(template.Spec.NamespaceConstraints, binding.Spec.NamespaceConstraints)
		c.log.Debugw("Merged namespace constraints from binding",
			"template", template.Name,
			"binding", binding.Name,
			"bindingNamespace", binding.Namespace,
			"mergedAllowUserNamespace", nc != nil && nc.AllowUserNamespace,
			"mergedDefaultNamespace", func() string {
				if nc != nil {
					return nc.DefaultNamespace
				}
				return ""
			}(),
		)
	}

	c.log.Debugw("Resolving target namespace",
		"template", template.Name,
		"requestedNamespace", requestedNamespace,
		"hasNamespaceConstraints", nc != nil,
	)

	// If no namespace constraints, use default behavior
	if nc == nil {
		if requestedNamespace != "" {
			c.log.Debugw("No namespace constraints, using requested namespace",
				"template", template.Name,
				"resolvedNamespace", requestedNamespace,
			)
			return requestedNamespace, nil
		}
		c.log.Debugw("No namespace constraints, using default",
			"template", template.Name,
			"resolvedNamespace", defaultDebugNamespace,
		)
		return defaultDebugNamespace, nil // Default namespace
	}

	c.log.Debugw("Namespace constraints found",
		"template", template.Name,
		"allowUserNamespace", nc.AllowUserNamespace,
		"denyUserNamespace", nc.DenyUserNamespace,
		"defaultNamespace", nc.DefaultNamespace,
		"hasAllowedNamespaces", nc.AllowedNamespaces != nil && !nc.AllowedNamespaces.IsEmpty(),
		"hasDeniedNamespaces", nc.DeniedNamespaces != nil && !nc.DeniedNamespaces.IsEmpty(),
	)

	effectiveDefault := nc.DefaultNamespace
	if effectiveDefault == "" {
		effectiveDefault = defaultDebugNamespace
	}

	// If user didn't request a specific namespace, use the default
	if requestedNamespace == "" {
		if err := c.validateEffectiveNamespaceConstraintFilters(ctx, cluster, effectiveDefault, effectiveDefault, template, binding); err != nil {
			c.log.Debugw("Default namespace rejected by namespace constraints",
				"template", template.Name,
				"defaultNamespace", effectiveDefault,
				"templateDefaultSet", nc.DefaultNamespace != "",
				"bindingUsed", binding != nil,
				"error", err,
			)
			return "", err
		}
		c.log.Debugw("No namespace requested, using effective default namespace",
			"template", template.Name,
			"resolvedNamespace", effectiveDefault,
			"bindingUsed", binding != nil,
		)
		return effectiveDefault, nil
	}

	// If the requested namespace matches the default, allow it even when user namespace selection is disabled.
	// This handles the case where the frontend sends the default namespace value in the request.
	if nc.DefaultNamespace != "" && requestedNamespace == nc.DefaultNamespace {
		if err := c.validateEffectiveNamespaceConstraintFilters(ctx, cluster, nc.DefaultNamespace, effectiveDefault, template, binding); err != nil {
			c.log.Debugw("Requested default namespace rejected by namespace constraints",
				"template", template.Name,
				"defaultNamespace", nc.DefaultNamespace,
				"bindingUsed", binding != nil,
				"error", err,
			)
			return "", err
		}
		c.log.Debugw("Requested namespace matches default, allowing",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"defaultNamespace", nc.DefaultNamespace,
		)
		return nc.DefaultNamespace, nil
	}

	// Check if user is allowed to specify a namespace. denyUserNamespace is an
	// explicit narrowing switch and always wins over allowUserNamespace.
	if nc.DenyUserNamespace {
		c.log.Debugw("User-specified namespace explicitly denied",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"denyUserNamespace", true,
		)
		return "", fmt.Errorf(
			"template does not allow user-specified namespaces: namespaceConstraints.denyUserNamespace=true, only defaultNamespace '%s' may be used",
			effectiveDefault)
	}
	if !nc.AllowUserNamespace {
		c.log.Debugw("User-specified namespace not allowed by template",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"allowUserNamespace", nc.AllowUserNamespace,
		)
		return "", fmt.Errorf(
			"template does not allow user-specified namespaces: namespaceConstraints.allowUserNamespace=false, only defaultNamespace '%s' may be used",
			effectiveDefault)
	}

	if err := c.validateEffectiveNamespaceConstraintFilters(ctx, cluster, requestedNamespace, effectiveDefault, template, binding); err != nil {
		c.log.Debugw("Namespace rejected by effective namespace constraints",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"error", err,
		)
		return "", err
	}

	return requestedNamespace, nil
}

// mergeNamespaceConstraints merges template and binding namespace constraints.
// Binding constraints can only narrow what the template allows.
// Returns a new NamespaceConstraints with merged values.
func (c *DebugSessionAPIController) mergeNamespaceConstraints(
	templateNC, bindingNC *breakglassv1alpha1.NamespaceConstraints,
) *breakglassv1alpha1.NamespaceConstraints {
	// If both are nil, return nil
	if templateNC == nil && bindingNC == nil {
		return nil
	}

	// If only one exists, use it
	if templateNC == nil {
		return bindingNC.DeepCopy()
	}
	if bindingNC == nil {
		return templateNC.DeepCopy()
	}

	// Merge both - binding narrows template permissions.
	merged := templateNC.DeepCopy()

	// AllowUserNamespace: binding cannot enable user-selected namespaces when
	// the template disabled them. A false binding value is ambiguous because it
	// is also the zero value, so it is not treated as an override here.
	// Bindings that need to narrow a permissive template set the additive
	// denyUserNamespace field instead.
	merged.AllowUserNamespace = templateNC.AllowUserNamespace

	// DenyUserNamespace: narrowing only, so either side setting it wins.
	merged.DenyUserNamespace = templateNC.DenyUserNamespace || bindingNC.DenyUserNamespace

	// DefaultNamespace: binding can change the default only to a namespace that
	// remains allowed by both template and binding filters.
	if bindingNC.DefaultNamespace != "" &&
		namespaceAllowedByNameFilters(bindingNC.DefaultNamespace, templateNC) &&
		namespaceAllowedByNameFilters(bindingNC.DefaultNamespace, bindingNC) {
		merged.DefaultNamespace = bindingNC.DefaultNamespace
	}

	// AllowedNamespaces: binding filters are the option-specific boundary shown
	// to clients. Runtime validation still evaluates both template and binding
	// filters separately, so bindings cannot widen the template boundary.
	if merged.AllowedNamespaces == nil || merged.AllowedNamespaces.IsEmpty() {
		merged.AllowedNamespaces = nil
	}
	if bindingNC.AllowedNamespaces != nil && !bindingNC.AllowedNamespaces.IsEmpty() {
		merged.AllowedNamespaces = bindingNC.AllowedNamespaces.DeepCopy()
	}

	// DeniedNamespaces: binding can add denies, never remove template denies.
	if bindingNC.DeniedNamespaces != nil && !bindingNC.DeniedNamespaces.IsEmpty() {
		merged.DeniedNamespaces = mergeNamespaceFilters(merged.DeniedNamespaces, bindingNC.DeniedNamespaces)
	}

	return merged
}

func mergeAllowedNamespaceFiltersForResponse(
	templateFilter, bindingFilter *breakglassv1alpha1.NamespaceFilter,
) *breakglassv1alpha1.NamespaceFilter {
	if templateFilter == nil || templateFilter.IsEmpty() {
		if bindingFilter == nil || bindingFilter.IsEmpty() {
			return nil
		}
		return bindingFilter.DeepCopy()
	}
	if bindingFilter == nil || bindingFilter.IsEmpty() {
		return templateFilter.DeepCopy()
	}

	merged := &breakglassv1alpha1.NamespaceFilter{}
	for _, pattern := range bindingFilter.Patterns {
		if namespacePatternSubsetOfAny(pattern, templateFilter.Patterns) {
			merged.Patterns = append(merged.Patterns, pattern)
		}
	}
	if merged.IsEmpty() {
		return nil
	}
	return merged
}

func namespacePatternSubsetOfAny(pattern string, allowedPatterns []string) bool {
	for _, allowed := range allowedPatterns {
		if namespacePatternSubsetOf(pattern, allowed) {
			return true
		}
	}
	return false
}

func namespacePatternSubsetOf(pattern, allowedPattern string) bool {
	if allowedPattern == "*" || pattern == allowedPattern {
		return true
	}
	if !namespacePatternHasGlob(pattern) {
		return matchPattern(allowedPattern, pattern)
	}
	allowedPrefix, allowedOK := namespaceTrailingStarPrefix(allowedPattern)
	patternPrefix, patternOK := namespaceTrailingStarPrefix(pattern)
	return allowedOK && patternOK && strings.HasPrefix(patternPrefix, allowedPrefix)
}

func namespacePatternHasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func namespaceTrailingStarPrefix(pattern string) (string, bool) {
	if strings.Count(pattern, "*") != 1 || !strings.HasSuffix(pattern, "*") {
		return "", false
	}
	prefix := strings.TrimSuffix(pattern, "*")
	if strings.ContainsAny(prefix, "?[") {
		return "", false
	}
	return prefix, true
}

// namespaceAllowedByNameFilters reports whether a namespace passes a single
// constraint set using namespace names only. It is a pre-check used while
// merging constraints (for example to decide whether a binding may move the
// default namespace); the resolved namespace is always validated again by
// validateEffectiveNamespaceConstraintFilters, which additionally evaluates
// selectorTerms against live namespace labels and enforces the
// "empty allowedNamespaces means defaultNamespace only" contract.
func namespaceAllowedByNameFilters(namespace string, constraints *breakglassv1alpha1.NamespaceConstraints) bool {
	if constraints == nil {
		return true
	}
	if !constraints.AllowedNamespaces.IsEmpty() &&
		!matchNamespaceFilter(namespace, constraints.AllowedNamespaces) {
		return false
	}
	if !constraints.DeniedNamespaces.IsEmpty() &&
		matchNamespaceFilter(namespace, constraints.DeniedNamespaces) {
		return false
	}
	return true
}

// namespaceConstraintSource pairs a constraint set with a human-readable field
// path so that rejections can name the offending field and value.
type namespaceConstraintSource struct {
	fieldPath   string
	constraints *breakglassv1alpha1.NamespaceConstraints
}

// validateEffectiveNamespaceConstraintFilters enforces the effective namespace
// boundary of a template and (optionally) a binding.
//
// The allow side is evaluated ONCE against the effective allow-list, which is
// the intersection of every configured allowedNamespaces filter. When no side
// configures an allow-list at all, only defaultNamespace is allowed, as
// documented on NamespaceConstraints.allowedNamespaces. Evaluating each side
// independently would be wrong: DefaultNamespace carries a kubebuilder default,
// so a deny-only binding has an empty allow-list plus a defaulted namespace and
// would reject every namespace on the binding leg.
//
// The deny side is a union: a namespace matching any deniedNamespaces filter is
// rejected. selectorTerms on either side are evaluated against live namespace
// labels fetched from the target cluster; a namespace whose labels cannot be
// resolved is rejected with an error naming the namespace and the selector,
// because silently skipping a selector-based deny is a fail-open on a security
// control.
func (c *DebugSessionAPIController) validateEffectiveNamespaceConstraintFilters(
	ctx context.Context,
	cluster string,
	namespace string,
	defaultNamespace string,
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) error {
	sources := make([]namespaceConstraintSource, 0, 2)
	if template != nil && template.Spec.NamespaceConstraints != nil {
		sources = append(sources, namespaceConstraintSource{
			fieldPath:   fmt.Sprintf("template '%s' spec.namespaceConstraints", template.Name),
			constraints: template.Spec.NamespaceConstraints,
		})
	}
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		sources = append(sources, namespaceConstraintSource{
			fieldPath:   fmt.Sprintf("binding '%s/%s' spec.namespaceConstraints", binding.Namespace, binding.Name),
			constraints: binding.Spec.NamespaceConstraints,
		})
	}
	if len(sources) == 0 {
		return nil
	}

	labels := c.newNamespaceLabelLookup(cluster, namespace)

	if err := c.validateNamespaceAgainstEffectiveAllowList(ctx, namespace, defaultNamespace, sources, labels); err != nil {
		return err
	}
	return c.validateNamespaceAgainstDenyUnion(ctx, namespace, sources, labels)
}

// validateNamespaceAgainstEffectiveAllowList applies the intersection of all
// configured allowedNamespaces filters.
func (c *DebugSessionAPIController) validateNamespaceAgainstEffectiveAllowList(
	ctx context.Context,
	namespace string,
	defaultNamespace string,
	sources []namespaceConstraintSource,
	labels *namespaceLabelLookup,
) error {
	allowSources := make([]namespaceConstraintSource, 0, len(sources))
	for _, source := range sources {
		if !source.constraints.AllowedNamespaces.IsEmpty() {
			allowSources = append(allowSources, source)
		}
	}

	if len(allowSources) == 0 {
		if namespace == defaultNamespace {
			return nil
		}
		return fmt.Errorf(
			"namespace '%s' is not in the allowed namespaces: no namespaceConstraints.allowedNamespaces is configured, so only defaultNamespace '%s' is allowed",
			namespace, defaultNamespace)
	}

	for _, source := range allowSources {
		matched, err := matchNamespaceFilterWithLabels(ctx, namespace, source.constraints.AllowedNamespaces, labels)
		if err != nil {
			return fmt.Errorf("namespace '%s' is not in the allowed namespaces: %s.allowedNamespaces (%s) requires namespace labels: %w",
				namespace, source.fieldPath, describeNamespaceFilter(source.constraints.AllowedNamespaces), err)
		}
		if !matched {
			return fmt.Errorf("namespace '%s' is not in the allowed namespaces: %s.allowedNamespaces (%s) does not match",
				namespace, source.fieldPath, describeNamespaceFilter(source.constraints.AllowedNamespaces))
		}
	}
	return nil
}

// validateNamespaceAgainstDenyUnion rejects the namespace if any configured
// deniedNamespaces filter matches it.
func (c *DebugSessionAPIController) validateNamespaceAgainstDenyUnion(
	ctx context.Context,
	namespace string,
	sources []namespaceConstraintSource,
	labels *namespaceLabelLookup,
) error {
	for _, source := range sources {
		if source.constraints.DeniedNamespaces.IsEmpty() {
			continue
		}
		matched, err := matchNamespaceFilterWithLabels(ctx, namespace, source.constraints.DeniedNamespaces, labels)
		if err != nil {
			return fmt.Errorf("namespace '%s' cannot be validated: %s.deniedNamespaces (%s) requires namespace labels: %w",
				namespace, source.fieldPath, describeNamespaceFilter(source.constraints.DeniedNamespaces), err)
		}
		if matched {
			return fmt.Errorf("namespace '%s' is explicitly denied by %s.deniedNamespaces (%s)",
				namespace, source.fieldPath, describeNamespaceFilter(source.constraints.DeniedNamespaces))
		}
	}
	return nil
}

// describeNamespaceFilter renders a filter for operator-facing error messages.
func describeNamespaceFilter(filter *breakglassv1alpha1.NamespaceFilter) string {
	if filter == nil {
		return "empty"
	}
	parts := make([]string, 0, 2)
	if len(filter.Patterns) > 0 {
		parts = append(parts, fmt.Sprintf("patterns=%v", filter.Patterns))
	}
	if len(filter.SelectorTerms) > 0 {
		parts = append(parts, fmt.Sprintf("selectorTerms=%d", len(filter.SelectorTerms)))
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, ", ")
}

// matchNamespaceFilterWithLabels evaluates patterns first and only fetches live
// namespace labels when the filter carries selectorTerms that could still match.
func matchNamespaceFilterWithLabels(
	ctx context.Context,
	namespace string,
	filter *breakglassv1alpha1.NamespaceFilter,
	labels *namespaceLabelLookup,
) (bool, error) {
	if filter.IsEmpty() {
		return false, nil
	}
	matcher := utils.NewNamespaceMatcher(filter)
	if matcher.Matches(namespace) {
		return true, nil
	}
	if !filter.HasSelectorTerms() {
		return false, nil
	}
	if labels == nil {
		return false, fmt.Errorf("namespace label lookup is not available")
	}
	nsLabels, err := labels.get(ctx)
	if err != nil {
		return false, err
	}
	return matcher.MatchesWithLabels(namespace, nsLabels), nil
}

// namespaceLabelLookup fetches namespace labels from the target cluster at most
// once per validation pass, memoizing both the labels and any failure.
type namespaceLabelLookup struct {
	fetch  func(ctx context.Context) (map[string]string, error)
	done   bool
	labels map[string]string
	err    error
}

func (l *namespaceLabelLookup) get(ctx context.Context) (map[string]string, error) {
	if !l.done {
		l.labels, l.err = l.fetch(ctx)
		l.done = true
	}
	return l.labels, l.err
}

func (c *DebugSessionAPIController) newNamespaceLabelLookup(cluster, namespace string) *namespaceLabelLookup {
	return &namespaceLabelLookup{
		fetch: func(ctx context.Context) (map[string]string, error) {
			return c.fetchTargetNamespaceLabels(ctx, cluster, namespace)
		},
	}
}

// fetchTargetNamespaceLabels reads the namespace from the target (spoke) cluster
// so that selectorTerms can be evaluated. Errors are returned to the caller and
// never treated as "no labels", which would silently disable selector denies.
func (c *DebugSessionAPIController) fetchTargetNamespaceLabels(ctx context.Context, cluster, namespace string) (map[string]string, error) {
	if cluster == "" {
		return nil, fmt.Errorf("target cluster is unknown")
	}
	targetClient, err := c.targetClusterClient(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("get client for cluster '%s': %w", cluster, err)
	}
	if targetClient == nil {
		return nil, fmt.Errorf("no kubernetes client is configured for cluster '%s'", cluster)
	}
	ns := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: namespace}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("namespace '%s' does not exist on cluster '%s'", namespace, cluster)
		}
		return nil, fmt.Errorf("get namespace '%s' on cluster '%s': %w", namespace, cluster, err)
	}
	return ns.Labels, nil
}

// targetClusterClient resolves a client for the target cluster, reusing the same
// ClientProviderInterface machinery as the kubectl-debug handlers.
func (c *DebugSessionAPIController) targetClusterClient(ctx context.Context, cluster string) (ctrlclient.Client, error) {
	if c.clusterClients != nil {
		return c.clusterClients.GetClient(ctx, cluster)
	}
	if c.ccProvider == nil {
		return nil, fmt.Errorf("cluster client provider is not configured")
	}
	return (&clusterClientAdapter{ccProvider: c.ccProvider}).GetClient(ctx, cluster)
}

func mergeNamespaceFilters(
	base, extra *breakglassv1alpha1.NamespaceFilter,
) *breakglassv1alpha1.NamespaceFilter {
	if base == nil || base.IsEmpty() {
		if extra == nil {
			return nil
		}
		return extra.DeepCopy()
	}
	if extra == nil || extra.IsEmpty() {
		return base.DeepCopy()
	}

	merged := base.DeepCopy()
	patternSet := make(map[string]bool, len(merged.Patterns))
	for _, pattern := range merged.Patterns {
		patternSet[pattern] = true
	}
	for _, pattern := range extra.Patterns {
		if !patternSet[pattern] {
			merged.Patterns = append(merged.Patterns, pattern)
		}
	}
	merged.SelectorTerms = append(merged.SelectorTerms, extra.SelectorTerms...)
	return merged
}

// matchNamespaceFilter checks if a namespace name matches a NamespaceFilter
// using patterns only. Selector terms require namespace labels; callers that
// must honour them use matchNamespaceFilterWithLabels instead.
func matchNamespaceFilter(namespace string, filter *breakglassv1alpha1.NamespaceFilter) bool {
	if filter == nil || filter.IsEmpty() {
		return false
	}

	for _, pattern := range filter.Patterns {
		if matchPattern(pattern, namespace) {
			return true
		}
	}

	return false
}

// resolveSchedulingConstraints validates and resolves the scheduling constraints.
// It merges the template's and binding's base constraints with the selected scheduling option.
// When a binding is provided, its base constraints are treated as mandatory additions
// on top of the template, and its scheduling options take precedence over the template's.
// Returns the merged constraints, the selected option name, and any error.
func (c *DebugSessionAPIController) resolveSchedulingConstraints(
	template *breakglassv1alpha1.DebugSessionTemplate,
	selectedOption string,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	requester schedulingOptionRequester,
) (*breakglassv1alpha1.SchedulingConstraints, string, error) {
	// Start with the template's base scheduling constraints and merge in binding-level
	// base constraints (which are documented as mandatory additions on top of the template).
	baseConstraints := template.Spec.SchedulingConstraints
	if binding != nil && binding.Spec.SchedulingConstraints != nil {
		mergedBase, err := mergeSchedulingConstraints(baseConstraints, binding.Spec.SchedulingConstraints)
		if err != nil {
			return nil, "", fmt.Errorf("binding scheduling constraints conflict with template constraints: %w", err)
		}
		baseConstraints = mergedBase
	}
	if err := validateSchedulingConstraints(baseConstraints, "base schedulingConstraints"); err != nil {
		return nil, "", err
	}

	// Resolve effective scheduling options: binding takes precedence over template
	var effectiveOpts *breakglassv1alpha1.SchedulingOptions
	if binding != nil && binding.Spec.SchedulingOptions != nil {
		effectiveOpts = binding.Spec.SchedulingOptions
	} else if template.Spec.SchedulingOptions != nil {
		effectiveOpts = template.Spec.SchedulingOptions
	}

	// If no scheduling options defined (in template or binding), just return base constraints
	// Ignore any user-selected option since neither the template nor binding supports them.
	// This handles cases where the frontend sends a stale scheduling option
	// after switching to a template that doesn't have scheduling options.
	if effectiveOpts == nil || len(effectiveOpts.Options) == 0 {
		if selectedOption != "" {
			c.log.Debugw("Ignoring scheduling option - no options defined in template or binding",
				"template", template.Name,
				"selectedOption", selectedOption,
			)
		}
		return baseConstraints, "", nil
	}

	opts := effectiveOpts

	// If required and no option selected, find the default
	if selectedOption == "" {
		if opts.Required {
			// Find the default option
			for _, opt := range opts.Options {
				if opt.Default {
					selectedOption = opt.Name
					break
				}
			}
			if selectedOption == "" {
				return nil, "", fmt.Errorf("scheduling option is required but none selected and no default defined")
			}
		} else {
			// Not required, no selection - use base constraints only
			return baseConstraints, "", nil
		}
	}

	// Find the selected option
	var selectedOpt *breakglassv1alpha1.SchedulingOption
	for i := range opts.Options {
		if opts.Options[i].Name == selectedOption {
			selectedOpt = &opts.Options[i]
			break
		}
	}

	if selectedOpt == nil {
		return nil, "", fmt.Errorf("scheduling option '%s' not found in template or binding", selectedOption)
	}

	if !isSchedulingOptionAllowedForRequester(selectedOpt, requester) {
		return nil, "", &schedulingOptionAccessError{optionName: selectedOption}
	}

	// Merge base constraints with option's constraints
	merged, err := mergeSchedulingConstraints(baseConstraints, selectedOpt.SchedulingConstraints)
	if err != nil {
		return nil, "", fmt.Errorf("scheduling option %q conflicts with mandatory constraints: %w", selectedOption, err)
	}

	return merged, selectedOption, nil
}

func isSchedulingOptionAllowedForRequester(opt *breakglassv1alpha1.SchedulingOption, requester schedulingOptionRequester) bool {
	if opt == nil || (len(opt.AllowedUsers) == 0 && len(opt.AllowedGroups) == 0) {
		return true
	}

	for _, allowedUser := range opt.AllowedUsers {
		if matchPattern(allowedUser, requester.Username) {
			return true
		}
		if requester.Email != "" && matchPattern(allowedUser, requester.Email) {
			return true
		}
	}

	for _, allowedGroup := range opt.AllowedGroups {
		for _, userGroup := range requester.Groups {
			if matchPattern(allowedGroup, userGroup) {
				return true
			}
		}
	}

	return false
}

// mergeSchedulingConstraints merges base constraints with option constraints.
// Option constraints are additive and must not weaken base constraints.
func mergeSchedulingConstraints(base, option *breakglassv1alpha1.SchedulingConstraints) (*breakglassv1alpha1.SchedulingConstraints, error) {
	if err := validateSchedulingConstraints(base, "base schedulingConstraints"); err != nil {
		return nil, err
	}
	if err := validateSchedulingConstraints(option, "option schedulingConstraints"); err != nil {
		return nil, err
	}
	if base == nil && option == nil {
		return nil, nil
	}
	if base == nil {
		return option.DeepCopy(), nil
	}
	if option == nil {
		return base.DeepCopy(), nil
	}

	merged := base.DeepCopy()

	// Merge nodeSelector additively. Conflicting values cannot be represented
	// without weakening the mandatory selector, so reject the selected option.
	if len(option.NodeSelector) > 0 {
		if merged.NodeSelector == nil {
			merged.NodeSelector = make(map[string]string)
		}
		for k, v := range option.NodeSelector {
			if existing, ok := merged.NodeSelector[k]; ok && existing != v {
				return nil, fmt.Errorf("nodeSelector %q requires both %q and %q", k, existing, v)
			}
			merged.NodeSelector[k] = v
		}
	}

	// Merge deniedNodes (additive)
	if len(option.DeniedNodes) > 0 {
		merged.DeniedNodes = append(merged.DeniedNodes, option.DeniedNodes...)
	}

	// Merge deniedNodeLabels additively. "*" denies all values for the key and
	// therefore dominates exact-value denies for the same key.
	if len(option.DeniedNodeLabels) > 0 {
		if merged.DeniedNodeLabels == nil {
			merged.DeniedNodeLabels = make(map[string]string)
		}
		for k, v := range option.DeniedNodeLabels {
			if existing, ok := merged.DeniedNodeLabels[k]; ok {
				switch {
				case existing == v:
					continue
				case existing == "*":
					continue
				case v == "*":
					merged.DeniedNodeLabels[k] = v
					continue
				default:
					return nil, fmt.Errorf("deniedNodeLabels %q cannot add both %q and %q", k, existing, v)
				}
			}
			merged.DeniedNodeLabels[k] = v
		}
	}

	// Merge tolerations (additive)
	if len(option.Tolerations) > 0 {
		merged.Tolerations = append(merged.Tolerations, option.Tolerations...)
	}

	// For node affinity, option's required affinity is ANDed with base.
	if option.RequiredNodeAffinity != nil {
		combined, err := andNodeSelectors(merged.RequiredNodeAffinity, option.RequiredNodeAffinity)
		if err != nil {
			return nil, fmt.Errorf("requiredNodeAffinity: %w", err)
		}
		merged.RequiredNodeAffinity = combined
	}

	// Preferred affinities are additive
	if len(option.PreferredNodeAffinity) > 0 {
		merged.PreferredNodeAffinity = append(merged.PreferredNodeAffinity, option.PreferredNodeAffinity...)
	}

	// Pod anti-affinity is additive
	if len(option.RequiredPodAntiAffinity) > 0 {
		merged.RequiredPodAntiAffinity = append(merged.RequiredPodAntiAffinity, option.RequiredPodAntiAffinity...)
	}
	if len(option.PreferredPodAntiAffinity) > 0 {
		merged.PreferredPodAntiAffinity = append(merged.PreferredPodAntiAffinity, option.PreferredPodAntiAffinity...)
	}

	if len(option.TopologySpreadConstraints) > 0 {
		merged.TopologySpreadConstraints = append(merged.TopologySpreadConstraints, option.TopologySpreadConstraints...)
	}

	return merged, nil
}

func validateSchedulingConstraints(constraints *breakglassv1alpha1.SchedulingConstraints, context string) error {
	if constraints == nil {
		return nil
	}
	if constraints.RequiredNodeAffinity != nil && len(constraints.RequiredNodeAffinity.NodeSelectorTerms) > maxRequiredNodeSelectorTerms {
		return fmt.Errorf("%s requiredNodeAffinity has %d nodeSelectorTerms, maximum is %d",
			context, len(constraints.RequiredNodeAffinity.NodeSelectorTerms), maxRequiredNodeSelectorTerms)
	}
	if err := validateDeniedNodeLabels(constraints.DeniedNodeLabels, context); err != nil {
		return err
	}
	return nil
}

func validateDeniedNodeLabels(deniedNodeLabels map[string]string, context string) error {
	if len(deniedNodeLabels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(deniedNodeLabels))
	for key := range deniedNodeLabels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if errs := validation.IsQualifiedName(key); len(errs) > 0 {
			return fmt.Errorf("%s deniedNodeLabels key %q is invalid: %s", context, key, strings.Join(errs, "; "))
		}
		value := deniedNodeLabels[key]
		if value == "*" {
			continue
		}
		if errs := validation.IsValidLabelValue(value); len(errs) > 0 {
			return fmt.Errorf("%s deniedNodeLabels[%q] value %q is invalid: %s", context, key, value, strings.Join(errs, "; "))
		}
	}
	return nil
}

func andNodeSelectors(left, right *corev1.NodeSelector) (*corev1.NodeSelector, error) {
	if left == nil {
		if right == nil {
			return nil, nil
		}
		return right.DeepCopy(), nil
	}
	if right == nil {
		return left.DeepCopy(), nil
	}
	if len(left.NodeSelectorTerms) == 0 {
		return right.DeepCopy(), nil
	}
	if len(right.NodeSelectorTerms) == 0 {
		return left.DeepCopy(), nil
	}
	if nodeSelectorTermProductExceedsLimit(len(left.NodeSelectorTerms), len(right.NodeSelectorTerms), maxRequiredNodeSelectorTerms) {
		return nil, fmt.Errorf("combining %d and %d nodeSelectorTerms would exceed maximum of %d resulting terms",
			len(left.NodeSelectorTerms), len(right.NodeSelectorTerms), maxRequiredNodeSelectorTerms)
	}

	if len(left.NodeSelectorTerms) == 1 {
		out := &corev1.NodeSelector{
			NodeSelectorTerms: make([]corev1.NodeSelectorTerm, 0, len(right.NodeSelectorTerms)),
		}
		for _, rightTerm := range right.NodeSelectorTerms {
			out.NodeSelectorTerms = append(out.NodeSelectorTerms, andNodeSelectorTerms(left.NodeSelectorTerms[0], rightTerm))
		}
		return out, nil
	}
	if len(right.NodeSelectorTerms) == 1 {
		out := &corev1.NodeSelector{
			NodeSelectorTerms: make([]corev1.NodeSelectorTerm, 0, len(left.NodeSelectorTerms)),
		}
		for _, leftTerm := range left.NodeSelectorTerms {
			out.NodeSelectorTerms = append(out.NodeSelectorTerms, andNodeSelectorTerms(leftTerm, right.NodeSelectorTerms[0]))
		}
		return out, nil
	}

	out := &corev1.NodeSelector{
		NodeSelectorTerms: make([]corev1.NodeSelectorTerm, 0, len(left.NodeSelectorTerms)*len(right.NodeSelectorTerms)),
	}
	for _, leftTerm := range left.NodeSelectorTerms {
		for _, rightTerm := range right.NodeSelectorTerms {
			out.NodeSelectorTerms = append(out.NodeSelectorTerms, andNodeSelectorTerms(leftTerm, rightTerm))
		}
	}
	return out, nil
}

func nodeSelectorTermProductExceedsLimit(leftTerms, rightTerms, limit int) bool {
	if leftTerms == 0 || rightTerms == 0 {
		return false
	}
	return leftTerms > limit/rightTerms
}

func andNodeSelectorTerms(leftTerm, rightTerm corev1.NodeSelectorTerm) corev1.NodeSelectorTerm {
	term := corev1.NodeSelectorTerm{}
	term.MatchExpressions = append(term.MatchExpressions, leftTerm.MatchExpressions...)
	term.MatchExpressions = append(term.MatchExpressions, rightTerm.MatchExpressions...)
	term.MatchFields = append(term.MatchFields, leftTerm.MatchFields...)
	term.MatchFields = append(term.MatchFields, rightTerm.MatchFields...)
	return term
}

// resolveClusterPatterns expands cluster patterns (e.g., "*", "prod-*") to actual cluster names.
// Returns empty slice if no clusters are available for resolution.
func resolveClusterPatterns(patterns []string, allClusters []string) []string {
	if len(patterns) == 0 {
		return nil
	}
	if len(allClusters) == 0 {
		// No clusters to resolve against - return empty instead of patterns
		// This ensures the frontend shows "no clusters available" instead of pattern strings
		return nil
	}

	// Use a map to deduplicate
	resolved := make(map[string]struct{})
	for _, pattern := range patterns {
		for _, cluster := range allClusters {
			if matchPattern(pattern, cluster) {
				resolved[cluster] = struct{}{}
			}
		}
	}

	// Convert map to sorted slice for consistent output
	result := make([]string, 0, len(resolved))
	for cluster := range resolved {
		result = append(result, cluster)
	}
	// Sort for consistent ordering
	sort.Strings(result)
	return result
}

// sendDebugSessionRequestEmail sends email notification to approvers when a debug session is created
