export interface ClusterAccessReview {
  spec: ClusterAccessReviewSpec;
}

interface ClusterAccessReviewSubject {
  username: string;
  namespace: string;
  resource: string;
  verb: string;
}

interface ClusterAccessReviewSpec{
  cluster: string;
  subject: ClusterAccessReviewSubject;
  duration: string;
  until: string;
  application_status: string;
}
