package accessreview

import (
	"time"

	"k8s.io/kubernetes/pkg/apis/authorization"
)

type AccessReviewApplicationStatus string

const (
	StatusPending  AccessReviewApplicationStatus = "Pending"
	StatusAccepted AccessReviewApplicationStatus = "Accepted"
	StatusRejected AccessReviewApplicationStatus = "Rejected"
)

type AccessReview struct {
	ID       uint                                  `json:"id,omitempty"`
	Cluster  string                                `json:"cluster,omitempty"`
	Subject  authorization.SubjectAccessReviewSpec `json:"subject,omitempty"`
	Status   AccessReviewApplicationStatus         `json:"application_status,omitempty"`
	Until    time.Time                             `json:"until,omitempty"`
	Duration time.Duration                         `json:"duration,omitempty"`
}

func NewAccessReview(cluster string, subject authorization.SubjectAccessReviewSpec,
	duration time.Duration,
) AccessReview {
	until := time.Now().Add(duration)
	ar := AccessReview{
		Cluster:  cluster,
		Subject:  subject,
		Status:   StatusPending,
		Until:    until,
		Duration: duration,
	}

	return ar
}

func (ar AccessReview) IsValid() bool {
	timeNow := time.Now()
	return timeNow.Before(ar.Until)
}
