export interface ClusterAccessReview {
  id: number;
  cluster: string;
  subject: any;
  duration: number;
  until: string;
  status: string;
}

