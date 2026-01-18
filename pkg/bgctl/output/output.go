package output

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
	FormatWide  Format = "wide"
)

func WriteObject(w io.Writer, format Format, obj any) error {
	switch format {
	case FormatJSON:
		data, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	case FormatYAML:
		data, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	case FormatTable:
		return fmt.Errorf("table format requires a specific formatter")
	case FormatWide:
		return fmt.Errorf("wide format requires a specific formatter")
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}
