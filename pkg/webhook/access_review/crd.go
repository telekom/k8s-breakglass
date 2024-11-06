package accessreview

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type CRDManager struct {
	client.Client
}

var scheme = runtime.NewScheme()

const cliTimeout = 5 * time.Minute

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(telekomv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func NewCRDManager() (CRDManager, error) {
	cfg := config.GetConfigOrDie()
	c, err := client.New(cfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return CRDManager{}, errors.Wrap(err, "failed to create new client")
	}

	return CRDManager{c}, nil
}

func (c CRDManager) AddAccessReview(car v1alpha1.ClusterAccessReview) error {
	// TODO: Probably want to add here some logic related to generation of random id or iterating the car id
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	if err := c.Create(ctx, &car); err != nil {
		return errors.Wrap(err, "failed to create new access review")
	}

	return nil
}

func (c CRDManager) GetReviews() ([]v1alpha1.ClusterAccessReview, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	carls := v1alpha1.ClusterAccessReviewList{}
	if err := c.List(ctx, &carls); err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	return carls.Items, nil
}

func (c CRDManager) GetClusterUserReviews(cluster, user string) (car []v1alpha1.ClusterAccessReview, err error) {
	selector := fmt.Sprintf("spec.subject.username=%s,spec.cluster=%s", user, cluster)
	return c.getClusterUserReviewsByFieldSelector(selector)
}

func (c CRDManager) GetClusterAccessReviewsByID(id uint) (car []v1alpha1.ClusterAccessReview, err error) {
	selector := fmt.Sprintf("spec.id=%d", id)
	return c.getClusterUserReviewsByFieldSelector(selector)
}

func (c CRDManager) getClusterUserReviewsByFieldSelector(selector string) ([]v1alpha1.ClusterAccessReview, error) {
	carls := v1alpha1.ClusterAccessReviewList{}
	fs, err := fields.ParseSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to create field selector: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	if err := c.List(ctx, &carls, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list reviews with selector: %q", err)
	}

	return carls.Items, nil
}
