package escalation

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

// fakeEventRecorder implements events.EventRecorder for testing.
type fakeEventRecorder struct {
	Events chan string
}

func (f fakeEventRecorder) Eventf(_ runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	if f.Events == nil {
		return
	}
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	f.Events <- fmt.Sprintf("%s %s %s %s", eventtype, reason, action, message)
}
