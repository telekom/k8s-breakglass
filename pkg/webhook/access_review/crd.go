package accessreview

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
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

func SessionSelector(uname, username, cluster, group string) string {
	selectors := []string{}

	if uname != "" {
		return fmt.Sprintf("metadata.name=%s", uname)
	}

	if username != "" {
		selectors = append(selectors, fmt.Sprintf("spec.username=%s", username))
	}
	if cluster != "" {
		selectors = append(selectors, fmt.Sprintf("spec.cluster=%s", cluster))
	}
	if group != "" {
		selectors = append(selectors, fmt.Sprintf("spec.group=%s", group))
	}

	return strings.Join(selectors, ",")
}

// Get all stored GetClusterGroupAccess
func (c CRDManager) GetAllBreakglassSessions(ctx context.Context) ([]telekomv1alpha1.BreakglassSession, error) {
	cgal := v1alpha1.BreakglassSessionList{}
	if err := c.List(ctx, &cgal); err != nil {
		return nil, errors.Wrap(err, "failed to get BreakglassSessionList")
	}

	return cgal.Items, nil
}

// Get all stored GetClusterGroupAccess
func (c CRDManager) GetBreakglassSessionByName(ctx context.Context, name string) (telekomv1alpha1.BreakglassSession, error) {
	bs := v1alpha1.BreakglassSession{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &bs); err != nil {
		return bs, errors.Wrap(err, "failed to get BreakglassSession by name")
	}

	return bs, nil
}

// Get GetClusterGroupAccess by cluster name.
func (c CRDManager) GetClusterUserBreakglassSessions(ctx context.Context,
	cluster string,
	user string,
) ([]telekomv1alpha1.BreakglassSession, error) {
	selector := fmt.Sprintf("spec.cluster=%s,spec.username=%s",
		cluster,
		user)
	return c.GetBreakglassSessionsWithSelector(ctx, selector)
}

// GetBreakglassSessions with custom field selector.
func (c CRDManager) GetBreakglassSessionsWithSelector(ctx context.Context,
	fieldSelector string,
) ([]telekomv1alpha1.BreakglassSession, error) {
	bsl := v1alpha1.BreakglassSessionList{}

	fs, err := fields.ParseSelector(fieldSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to create field selector %q : %w", fieldSelector, err)
	}

	if err := c.List(ctx, &bsl, &client.ListOptions{FieldSelector: fs}); err != nil {
		return nil, errors.Wrapf(err, "failed to list BreakglassSessionList")
	}

	return bsl.Items, nil
}

// Add new breakglass session.
func (c CRDManager) AddBreakglassSession(ctx context.Context, bs telekomv1alpha1.BreakglassSession) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Create(ctx, &bs); err != nil {
		return errors.Wrap(err, "failed to create new BreakglassSession")
	}

	return nil
}

// Updare breakglass session.
func (c CRDManager) UpdateBreakglassSession(ctx context.Context, bs telekomv1alpha1.BreakglassSession) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Update(ctx, &bs); err != nil {
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}

	return nil
}

func (c CRDManager) UpdateBreakglassSessionStatus(ctx context.Context, bs telekomv1alpha1.BreakglassSession) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if err := c.Status().Update(ctx, &bs); err != nil {
		return errors.Wrapf(err, "failed to update new BreakglassSession")
	}

	return nil
}

// func (c CRDManager) AddAccessReview(ctx context.Context, car v1alpha1.ClusterAccessReview) error {
// 	if car.Spec.Cluster == "" || car.Spec.Subject.Username == "" {
// 		return errors.New("ClusterAccessReview muse provide spec.cluster name and spec.subject.username")
// 	}
// 	if car.Name == "" {
// 		car.GenerateName = fmt.Sprintf("%s-%s-", car.Spec.Cluster, car.Spec.Subject.Username)
// 	}
// 	c.writeMutex.Lock()
// 	defer c.writeMutex.Unlock()
// 	if err := c.Create(ctx, &car); err != nil {
// 		return errors.Wrap(err, "failed to create new cluster access review")
// 	}
//
// 	return nil
// }

// func (c CRDManager) GetReviews(ctx context.Context) ([]v1alpha1.ClusterAccessReview, error) {
// 	carls := v1alpha1.ClusterAccessReviewList{}
// 	if err := c.List(ctx, &carls); err != nil {
// 		return nil, errors.Wrap(err, "failed to get clusterAccessReviews")
// 	}
//
// 	return carls.Items, nil
// }

// func (c CRDManager) GetReviewByName(ctx context.Context, name string) (v1alpha1.ClusterAccessReview, error) {
// 	selector := fmt.Sprintf("metadata.name=%s", name)
// 	reviews, err := c.getClusterUserReviewsByFieldSelector(ctx, selector)
// 	if err != nil {
// 		return v1alpha1.ClusterAccessReview{}, fmt.Errorf("failed to get reviews by name: %w", err)
// 	}
//
// 	if len(reviews) == 0 {
// 		return v1alpha1.ClusterAccessReview{}, fmt.Errorf("failed to get reviews by name not found: %q", name)
// 	}
//
// 	return reviews[0], nil
// }

// func (c CRDManager) GetClusterUserReviews(ctx context.Context, cluster, user string) (car []v1alpha1.ClusterAccessReview, err error) {
// 	selector := fmt.Sprintf("spec.subject.username=%s,spec.cluster=%s", user, cluster)
// 	return c.getClusterUserReviewsByFieldSelector(ctx, selector)
// }
//
// func (c CRDManager) GetClusterAccessReviewsByUID(ctx context.Context, uid types.UID) (v1alpha1.ClusterAccessReview, error) {
// 	allReviews, err := c.GetReviews(ctx)
// 	if err != nil {
// 		return v1alpha1.ClusterAccessReview{}, fmt.Errorf("failed to get reviews by uid listing: %w", err)
// 	}
// 	for _, ar := range allReviews {
// 		if ar.UID == uid {
// 			return ar, nil
// 		}
// 	}
//
// 	return v1alpha1.ClusterAccessReview{}, ErrAccessNotFound
// }
//
// func (c CRDManager) DeleteReviewByName(ctx context.Context, name string) error {
// 	car, err := c.GetReviewByName(ctx, name)
// 	if err != nil {
// 		return errors.Wrap(err, "failed to get review for deletion")
// 	}
// 	c.writeMutex.Lock()
// 	defer c.writeMutex.Unlock()
// 	if err := c.Delete(ctx, &car); err != nil {
// 		return errors.Wrap(err, "failed to delete cluster access review")
// 	}
//
// 	return nil
// }
//
// func (c CRDManager) getClusterUserReviewsByFieldSelector(ctx context.Context, selector string) ([]v1alpha1.ClusterAccessReview, error) {
// 	carls := v1alpha1.ClusterAccessReviewList{}
// 	fs, err := fields.ParseSelector(selector)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create field selector: %w", err)
// 	}
//
// 	if err := c.List(ctx, &carls, &client.ListOptions{FieldSelector: fs}); err != nil {
// 		return nil, errors.Wrapf(err, "failed to list reviews with selector: %q", selector)
// 	}
//
// 	return carls.Items, nil
// }
//
// func (c CRDManager) UpdateReviewStatusByName(ctx context.Context, resourceName string, status v1alpha1.AccessReviewApplicationStatus) error {
// 	st, err := c.GetReviewByName(ctx, resourceName)
// 	if err != nil {
// 		return fmt.Errorf("failed to get resource to update by name: %w", err)
// 	}
// 	st.Spec.Status = status
//
// 	c.writeMutex.Lock()
// 	defer c.writeMutex.Unlock()
// 	if err := c.Update(ctx, &st); err != nil {
// 		return errors.Wrapf(err, "failed to update review with name %q", resourceName)
// 	}
// 	return nil
// }
//
// func (c CRDManager) UpdateReviewStatusByUID(ctx context.Context, uid types.UID, status v1alpha1.AccessReviewApplicationStatus) error {
// 	r, err := c.GetClusterAccessReviewsByUID(ctx, uid)
// 	if err != nil {
// 		return fmt.Errorf(": %w", err)
// 	}
//
// 	r.Spec.Status = status
//
// 	c.writeMutex.Lock()
// 	defer c.writeMutex.Unlock()
// 	if err := c.Update(ctx, &r); err != nil {
// 		return errors.Wrapf(err, "failed to update review with name %q", r.Name)
// 	}
// 	return nil
// }
//
// func (c CRDManager) DeleteReviewsOlderThan(ctx context.Context, t time.Time) error {
// 	currentReviews, err := c.GetReviews(ctx)
// 	if err != nil {
// 		return errors.Wrap(err, "failed to list reviews for older deletion")
// 	}
// 	doNotDelete := []string{}
// 	selectorOp := "metadata.name!="
// 	for _, review := range currentReviews {
// 		if t.Before(review.Spec.Until.Time) {
// 			doNotDelete = append(doNotDelete, selectorOp+review.Name)
// 		}
// 	}
// 	selectorString := strings.Join(doNotDelete, ",")
// 	fs, err := fields.ParseSelector(selectorString)
// 	if err != nil {
// 		return fmt.Errorf("delete failed to create field selector: %w", err)
// 	}
// 	c.writeMutex.Lock()
// 	defer c.writeMutex.Unlock()
// 	if err := c.DeleteAllOf(ctx, &v1alpha1.ClusterAccessReview{},
// 		&client.DeleteAllOfOptions{
// 			ListOptions: client.ListOptions{FieldSelector: fs},
// 		}); err != nil {
// 		return errors.Wrapf(err, "failed to delete all of reviews with selector %s", selectorString)
// 	}
//
// 	return nil
// }
