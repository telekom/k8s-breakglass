export interface ClusterAccessReview {
  name: string;
  uid: string;
  cluster: string;
  subject: ClusterAccessReviewSubject;
  duration: string;
  until: string;
  application_status: string;
}

interface ClusterAccessReviewSubject {
  username: string;
  namespace: string;
  resource: string;
  verb: string;
}
