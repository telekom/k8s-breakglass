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
	breakglassSessionTemplate      = template.New("breakglassSessionRequest")
	breakglassNotificationTemplate = template.New("breakglassSessionNotification")

	//go:embed templates/request.html
	requestTemplateRaw string
	//go:embed templates/approved.html
	approvedTemplateRaw string
	//go:embed templates/breakglassSessionRequest.html
	breakglassSessionReqTemplateRaw string
	//go:embed templates/breakglassSessionNotification.html
	breakglassSessionNotifiTemplateRaw string
)

func init() {
	if _, err := requestTemplate.Parse(requestTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := approvedTempate.Parse(approvedTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := breakglassSessionTemplate.Parse(breakglassSessionReqTemplateRaw); err != nil {
		panic(err)
	}
	if _, err := breakglassNotificationTemplate.Parse(breakglassSessionNotifiTemplateRaw); err != nil {
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

func RenderBreakglassSessionRequest(p RequestBreakglassSessionMailParams) (string, error) {
	return render(breakglassSessionTemplate, p)
}

func RenderBreakglassSessionNotification(p RequestBreakglassSessionMailParams) (string, error) {
	return render(breakglassSessionTemplate, p)
}
