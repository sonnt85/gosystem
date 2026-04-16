package gosystem

// Deprecated: Use GetProcessTree instead.
func GetPocessTree(pid int32) (*ProcessNode, error) {
	return GetProcessTree(pid)
}

// Deprecated: Use KillPid instead.
func KilPid(pidi interface{}) error {
	return KillPid(pidi)
}

// Deprecated: Use KillProcessName instead.
func KilProcessName(name string, isFullname ...bool) error {
	return KillProcessName(name, isFullname...)
}

// Deprecated: Use EnvironmentMap instead.
func EnrovimentMap(envstrings ...string) map[string]string {
	return EnvironmentMap(envstrings...)
}

// Deprecated: Use EnvironmentMergeMap instead.
func EnrovimentMergeMap(evmerge map[string]string) []string {
	return EnvironmentMergeMap(evmerge)
}

// Deprecated: Use EnvironmentMapToStrings instead.
func EnrovimentMapToStrings(me map[string]string) []string {
	return EnvironmentMapToStrings(me)
}

// Deprecated: Use EnvironmentStringAdd instead.
func EnrovimentStringAdd(key, val string, envstrings []string) []string {
	return EnvironmentStringAdd(key, val, envstrings)
}

// Deprecated: Use EnvironmentMapAdd instead.
func EnrovimentMapAdd(key, val string, envstrings ...string) map[string]string {
	return EnvironmentMapAdd(key, val, envstrings...)
}

// Deprecated: Use EnvironmentMergeCurrentEnv instead.
func EnrovimentMergeCurrentEnv(envMap map[string]string) []string {
	return EnvironmentMergeCurrentEnv(envMap)
}

// Deprecated: Use EnvironmentMergeCurrentEnvToMap instead.
func EnrovimentMergeCurrentEnvToMap(envMap map[string]string) map[string]string {
	return EnvironmentMergeCurrentEnvToMap(envMap)
}
