// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

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
}

type ApprovedMailParams struct {
	SubjectFullName  string
	SubjectEmail     string
	RequestedRole    string
	ApproverFullName string
	ApproverEmail    string
}

type RequestBreakglassSessionMailParams struct {
	SubjectEmail    string
	SubjectFullName string

	RequestedCluster  string
	RequestedUsername string
	RequestedGroup    string

	URL string
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
