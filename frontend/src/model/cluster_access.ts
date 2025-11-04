// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

export interface ClusterAccessReview {
  name: string;
  uid: string
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
