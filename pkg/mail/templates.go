package mail

import (
	"bytes"
	_ "embed"
	"html/template"
)

type RequestMailParams struct {
	SubjectFullName string
	SubjectEmail    string
	RequestedRole   string
	URL             string
	BrandingName    string
}

type ApprovedMailParams struct {
	SubjectFullName  string
	SubjectEmail     string
	RequestedRole    string
	ApproverFullName string
	ApproverEmail    string
	BrandingName     string

	// Additional tracking and scheduling info
	ApprovedAt     string // When the approval was granted
	ActivationTime string // When access becomes active (may be scheduled)
	ExpirationTime string // When access expires
	IsScheduled    bool   // Whether this is a pre-scheduled approval
	SessionID      string // Reference to the session ID
	Cluster        string // Cluster name
	Username       string // Username for the access
	ApprovalReason string // Why this was approved (optional approver notes)

	// IDP information for multi-IDP setups
	IDPName   string // Name of the identity provider to use
	IDPIssuer string // OIDC issuer URL for the IDP
}

type RejectedMailParams struct {
	SubjectFullName  string
	SubjectEmail     string
	RequestedRole    string
	RejectorFullName string
	RejectorEmail    string
	BrandingName     string

	// Rejection details
	RejectedAt      string // When the rejection occurred
	RejectionReason string // Why this was rejected (optional rejector notes)
	SessionID       string // Reference to the session ID
	Cluster         string // Cluster name
	Username        string // Username for the access
}

// DebugSessionRequestMailParams contains parameters for debug session request emails
type DebugSessionRequestMailParams struct {
	RequesterName     string
	RequesterEmail    string
	RequestedAt       string
	SessionID         string
	Cluster           string
	TemplateName      string
	Namespace         string
	RequestedDuration string
	NodeSelector      string
	Reason            string
	URL               string
	BrandingName      string
}

// DebugSessionApprovedMailParams contains parameters for debug session approval emails
type DebugSessionApprovedMailParams struct {
	RequesterName  string
	RequesterEmail string
	SessionID      string
	Cluster        string
	TemplateName   string
	Namespace      string
	ApproverName   string
	ApproverEmail  string
	ApprovedAt     string
	ApprovalReason string
	Duration       string
	ExpiresAt      string
	BrandingName   string
}

// DebugSessionRejectedMailParams contains parameters for debug session rejection emails
type DebugSessionRejectedMailParams struct {
	RequesterName   string
	RequesterEmail  string
	SessionID       string
	Cluster         string
	TemplateName    string
	Namespace       string
	RejectorName    string
	RejectorEmail   string
	RejectedAt      string
	RejectionReason string
	BrandingName    string
}

// SessionExpiredMailParams contains parameters for session expiration emails
type SessionExpiredMailParams struct {
	SubjectFullName  string
	SubjectEmail     string
	RequestedRole    string
	Cluster          string
	Username         string
	SessionID        string
	StartedAt        string
	ExpiredAt        string
	ExpirationReason string
	BrandingName     string
}

// SessionActivatedMailParams contains parameters for scheduled session activation emails
type SessionActivatedMailParams struct {
	SubjectFullName  string
	SubjectEmail     string
	RequestedRole    string
	Cluster          string
	Username         string
	SessionID        string
	ActivatedAt      string
	ExpirationTime   string
	ApproverFullName string
	ApproverEmail    string
	IDPName          string
	IDPIssuer        string
	BrandingName     string
}

// DebugSessionExpiredMailParams contains parameters for debug session expiration emails
type DebugSessionExpiredMailParams struct {
	RequesterName  string
	RequesterEmail string
	SessionID      string
	Cluster        string
	TemplateName   string
	Namespace      string
	StartedAt      string
	ExpiredAt      string
	Duration       string
	BrandingName   string
}

type RequestBreakglassSessionMailParams struct {
	SubjectEmail       string
	SubjectFullName    string
	RequestingUsername string

	RequestedCluster  string
	RequestedUsername string
	RequestedGroup    string
	RequestReason     string

	// Approver info (for notifications)
	Approver       string
	ApproverGroups []string // Groups that receive this email (for footer)

	// Scheduling information
	ScheduledStartTime  string
	CalculatedExpiresAt string
	ActualStartTime     string
	FormattedDuration   string // Human-readable duration (e.g., "2 hours")
	RequestedAt         string // When the request was made

	// UI/UX enhancements
	RequestedApprovalGroups string // Requested approval groups expression (e.g., "fixed-core OR mobile-core")
	TimeRemaining           string // Time remaining until expiration (e.g., "23 hours 45 minutes")

	URL          string
	BrandingName string
}

var (
	requestTemplate                = template.New("request")
	approvedTempate                = template.New("approved")
	rejectedTemplate               = template.New("rejected")
	breakglassSessionTemplate      = template.New("breakglassSessionRequest")
	breakglassNotificationTemplate = template.New("breakglassSessionNotification")
	debugSessionRequestTemplate    = template.New("debugSessionRequest")
	debugSessionApprovedTemplate   = template.New("debugSessionApproved")
	debugSessionRejectedTemplate   = template.New("debugSessionRejected")
	sessionExpiredTemplate         = template.New("sessionExpired")
	sessionActivatedTemplate       = template.New("sessionActivated")
	debugSessionExpiredTemplate    = template.New("debugSessionExpired")

	//go:embed templates/request.html
	requestTemplateRaw string
	//go:embed templates/approved.html
	approvedTemplateRaw string
	//go:embed templates/rejected.html
	rejectedTemplateRaw string
	//go:embed templates/breakglassSessionRequest.html
	breakglassSessionReqTemplateRaw string
	//go:embed templates/breakglassSessionNotification.html
	breakglassSessionNotifiTemplateRaw string
	//go:embed templates/debug_session_request.html
	debugSessionRequestTemplateRaw string
	//go:embed templates/debug_session_approved.html
	debugSessionApprovedTemplateRaw string
	//go:embed templates/debug_session_rejected.html
	debugSessionRejectedTemplateRaw string
	//go:embed templates/session_expired.html
	sessionExpiredTemplateRaw string
	//go:embed templates/session_activated.html
	sessionActivatedTemplateRaw string
	//go:embed templates/debug_session_expired.html
	debugSessionExpiredTemplateRaw string
)

func init() {
	if _, err := requestTemplate.Parse(requestTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := approvedTempate.Parse(approvedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := rejectedTemplate.Parse(rejectedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := breakglassSessionTemplate.Parse(breakglassSessionReqTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := breakglassNotificationTemplate.Parse(breakglassSessionNotifiTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := debugSessionRequestTemplate.Parse(debugSessionRequestTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := debugSessionApprovedTemplate.Parse(debugSessionApprovedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := debugSessionRejectedTemplate.Parse(debugSessionRejectedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := sessionExpiredTemplate.Parse(sessionExpiredTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := sessionActivatedTemplate.Parse(sessionActivatedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := debugSessionExpiredTemplate.Parse(debugSessionExpiredTemplateRaw); err != nil {
		panic(err)
	}
}

func render(t *template.Template, p any) (string, error) {
	b := bytes.Buffer{}
	err := t.Execute(&b, p)
	return b.String(), err
}

func RenderRequest(p RequestMailParams) (string, error) {
	return render(requestTemplate, p)
}

func RenderApproved(p ApprovedMailParams) (string, error) {
	return render(approvedTempate, p)
}

func RenderRejected(p RejectedMailParams) (string, error) {
	return render(rejectedTemplate, p)
}

func RenderBreakglassSessionRequest(p RequestBreakglassSessionMailParams) (string, error) {
	return render(breakglassSessionTemplate, p)
}

func RenderBreakglassSessionNotification(p RequestBreakglassSessionMailParams) (string, error) {
	return render(breakglassSessionTemplate, p)
}

// RenderDebugSessionRequest renders the debug session request email template
func RenderDebugSessionRequest(p DebugSessionRequestMailParams) (string, error) {
	return render(debugSessionRequestTemplate, p)
}

// RenderDebugSessionApproved renders the debug session approval email template
func RenderDebugSessionApproved(p DebugSessionApprovedMailParams) (string, error) {
	return render(debugSessionApprovedTemplate, p)
}

// RenderDebugSessionRejected renders the debug session rejection email template
func RenderDebugSessionRejected(p DebugSessionRejectedMailParams) (string, error) {
	return render(debugSessionRejectedTemplate, p)
}

// RenderSessionExpired renders the session expiration email template
func RenderSessionExpired(p SessionExpiredMailParams) (string, error) {
	return render(sessionExpiredTemplate, p)
}

// RenderSessionActivated renders the scheduled session activation email template
func RenderSessionActivated(p SessionActivatedMailParams) (string, error) {
	return render(sessionActivatedTemplate, p)
}

// RenderDebugSessionExpired renders the debug session expiration email template
func RenderDebugSessionExpired(p DebugSessionExpiredMailParams) (string, error) {
	return render(debugSessionExpiredTemplate, p)
}
