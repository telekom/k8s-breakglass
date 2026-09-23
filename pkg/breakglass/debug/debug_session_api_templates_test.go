package debug

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestExtraDeployVariableResponsePreservesNumericDefaultAsString(t *testing.T) {
	variable := extraDeployVariableResponse(breakglassv1alpha1.ExtraDeployVariable{
		Name:      "count",
		InputType: breakglassv1alpha1.InputTypeNumber,
		Default:   &apiextensionsv1.JSON{Raw: []byte(`9007199254740993`)},
	})
	raw, err := json.Marshal(variable)
	require.NoError(t, err)
	var response map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &response))
	var defaultValue string
	require.NoError(t, json.Unmarshal(response["default"], &defaultValue))
	require.Equal(t, "9007199254740993", defaultValue)
}
