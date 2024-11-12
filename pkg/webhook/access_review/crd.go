package accessreview

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type CRDManager struct {
	client.Client
	writeMutex *sync.Mutex
}

var (
	scheme            = runtime.NewScheme()
	ErrAccessNotFound = errors.New("access not found")
)

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

	return CRDManager{c, new(sync.Mutex)}, nil
}

func (c CRDManager) AddAccessReview(car v1alpha1.ClusterAccessReview) error {
	if car.Spec.Cluster == "" || car.Spec.Subject.Username == "" {
		return errors.New("ClusterAccessReview muse provide spec.cluster name and spec.subject.username")
	}
	if car.Name == "" {
		car.GenerateName = fmt.Sprintf("%s-%s-", car.Spec.Cluster, car.Spec.Subject.Username)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Create(ctx, &car); err != nil {
		return errors.Wrap(err, "failed to create new cluster access review")
	}

	return nil
}

func (c CRDManager) GetReviews() ([]v1alpha1.ClusterAccessReview, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	carls := v1alpha1.ClusterAccessReviewList{}
	if err := c.List(ctx, &carls); err != nil {
		return nil, errors.Wrap(err, "failed to get clusterAccessReviews")
	}

	return carls.Items, nil
}

func (c CRDManager) GetReviewByName() (v1alpha1.ClusterAccessReview, error) {
	return v1alpha1.ClusterAccessReview{}, nil
}

func (c CRDManager) GetClusterUserReviews(cluster, user string) (car []v1alpha1.ClusterAccessReview, err error) {
	selector := fmt.Sprintf("spec.subject.username=%s,spec.cluster=%s", user, cluster)
	return c.getClusterUserReviewsByFieldSelector(selector)
}

func (c CRDManager) GetClusterAccessReviewsByUID(uid types.UID) (v1alpha1.ClusterAccessReview, error) {
	allReviews, err := c.GetReviews()
	if err != nil {
		return v1alpha1.ClusterAccessReview{}, fmt.Errorf("failed to get reviews by uid listing: %w", err)
	}
	for _, ar := range allReviews {
		if ar.UID == uid {
			return ar, nil
		}
	}

	return v1alpha1.ClusterAccessReview{}, ErrAccessNotFound
}

func (c CRDManager) DeleteReviewByName(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Delete(ctx, &v1alpha1.ClusterAccessReview{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		return errors.Wrap(err, "failed to delete cluster access review")
	}

	return nil
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
		return nil, errors.Wrapf(err, "failed to list reviews with selector: %q", selector)
	}

	return carls.Items, nil
}

func (c CRDManager) UpdateReviewStatusByName(resourceName string, status v1alpha1.AccessReviewApplicationStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	toUpdate := v1alpha1.ClusterAccessReview{
		ObjectMeta: metav1.ObjectMeta{Name: resourceName},
		Spec:       v1alpha1.ClusterAccessReviewSpec{Status: status},
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Update(ctx, &toUpdate); err != nil {
		return errors.Wrapf(err, "failed to update review with name %q", resourceName)
	}
	return nil
}

func (c CRDManager) DeleteReviewsOlderThan(t time.Time) error {
	currentReviews, err := c.GetReviews()
	if err != nil {
		return errors.Wrap(err, "failed to list reviews for older deletion")
	}
	doNotDelete := []string{}
	selectorOp := "metadata.name!="
	for _, review := range currentReviews {
		if t.Before(review.Spec.Until.Time) {
			doNotDelete = append(doNotDelete, selectorOp+review.Name)
		}
	}
	selectorString := strings.Join(doNotDelete, ",")
	fs, err := fields.ParseSelector(selectorString)
	if err != nil {
		return fmt.Errorf("delete failed to create field selector: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.DeleteAllOf(ctx, &v1alpha1.ClusterAccessReview{},
		&client.DeleteAllOfOptions{
			ListOptions: client.ListOptions{FieldSelector: fs},
		}); err != nil {
		return errors.Wrapf(err, "failed to delete all of reviews with selector %s", selectorString)
	}

	return nil
}
