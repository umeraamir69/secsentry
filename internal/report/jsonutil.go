package report

import "encoding/json"

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }

func unmarshalJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
