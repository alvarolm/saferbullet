package server

import (
	"strings"
)

func fsProtection(path string, data []byte) error {

	// plugins
	// optimistic detection: ignores path and assumes that files ending with .plug.js are plugins
	if strings.HasSuffix(path, ".plug.js") {
		if err := verifyPlugin(data, !userProtectionConfig.AllowUnsignedPlugins); err != nil {
			return err
		}
	}

	// todo: evaluate other protection mechanisms

	return nil
}
