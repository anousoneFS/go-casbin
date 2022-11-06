package util

// StringSliceToInterfaceSlice ...
func StringSliceToInterfaceSlice(arr []string) []interface{} {
	in := make([]interface{}, len(arr))
	for i, a := range arr {
		in[i] = a
	}
	return in
}

func ContainsString(s []string, v string) bool {
	for _, vv := range s {
		if vv == v {
			return true
		}
	}
	return false
}
