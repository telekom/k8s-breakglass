// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package job

import (
	"errors"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
)

// ValidateExecution compares the entire execution contract, allowing only
// standard API defaults and Job-controller identity labels/selectors. Admission
// mutations to commands, credentials, scheduling or security fail closed.
func ValidateExecution(actual, expected batchv1.Job) error {
	for _, key := range []string{"controller-uid", "batch.kubernetes.io/controller-uid", "job-name", "batch.kubernetes.io/job-name"} {
		value, present := actual.Spec.Template.Labels[key]
		if !present {
			continue
		}
		wanted := actual.Name
		if key == "controller-uid" || key == "batch.kubernetes.io/controller-uid" {
			wanted = string(actual.UID)
		}
		if value != wanted {
			return errors.New("diagnostic artifact Job has invalid controller identity labels")
		}
	}
	a, e := actual.DeepCopy(), expected.DeepCopy()
	// The API generates this selector only when manualSelector is false.
	if e.Spec.Selector == nil && (a.Spec.ManualSelector == nil || !*a.Spec.ManualSelector) && a.Spec.Selector != nil {
		selector := a.Spec.Selector
		if len(selector.MatchExpressions) != 0 || len(selector.MatchLabels) != 1 || selector.MatchLabels["batch.kubernetes.io/controller-uid"] != string(a.UID) {
			return errors.New("diagnostic artifact Job has an unexpected selector")
		}
		a.Spec.Selector = nil
	}
	for _, job := range []*batchv1.Job{a, e} {
		for _, key := range []string{"controller-uid", "batch.kubernetes.io/controller-uid", "job-name", "batch.kubernetes.io/job-name"} {
			delete(job.Spec.Template.Labels, key)
		}
		defaultExecution(job)
	}
	if !equality.Semantic.DeepEqual(a.Spec, e.Spec) {
		return errors.New("diagnostic artifact Job execution differs from its approved contract")
	}
	return nil
}

func defaultExecution(job *batchv1.Job) {
	spec := &job.Spec
	if spec.Parallelism == nil {
		spec.Parallelism = int32Ptr(1)
	}
	if spec.Completions == nil {
		spec.Completions = int32Ptr(1)
	}
	if spec.ManualSelector == nil {
		spec.ManualSelector = boolPtr(false)
	}
	if spec.Suspend == nil {
		spec.Suspend = boolPtr(false)
	}
	if spec.CompletionMode == nil {
		value := batchv1.NonIndexedCompletion
		spec.CompletionMode = &value
	}
	if spec.PodReplacementPolicy == nil {
		value := batchv1.TerminatingOrFailed
		spec.PodReplacementPolicy = &value
	}
	pod := &spec.Template.Spec
	if pod.DNSPolicy == "" {
		pod.DNSPolicy = corev1.DNSClusterFirst
	}
	if pod.SchedulerName == "" {
		pod.SchedulerName = corev1.DefaultSchedulerName
	}
	if pod.TerminationGracePeriodSeconds == nil {
		pod.TerminationGracePeriodSeconds = int64Ptr(30)
	}
	if pod.EnableServiceLinks == nil {
		pod.EnableServiceLinks = boolPtr(true)
	}
	for _, containers := range [][]corev1.Container{pod.InitContainers, pod.Containers} {
		for i := range containers {
			if containers[i].TerminationMessagePath == "" {
				containers[i].TerminationMessagePath = corev1.TerminationMessagePathDefault
			}
			if containers[i].TerminationMessagePolicy == "" {
				containers[i].TerminationMessagePolicy = corev1.TerminationMessageReadFile
			}
		}
	}
}
