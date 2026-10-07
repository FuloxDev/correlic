// Package pathfilter provides path-based filtering and classification for file events.
// Platform-specific noise filtering lives in ignore_linux.go / ignore_darwin.go.
package pathfilter

import "strings"

// CategorizeCredentialPath returns a category for the credential type.
func CategorizeCredentialPath(path string) string {
	if strings.Contains(path, ".ssh") {
		return "ssh_key"
	}
	if strings.Contains(path, ".aws") {
		return "aws_credentials"
	}
	if strings.Contains(path, ".kube") {
		return "kubeconfig"
	}
	if strings.Contains(path, ".gnupg") || strings.Contains(path, ".gpg") {
		return "gpg_key"
	}
	if strings.Contains(path, ".azure") {
		return "azure_credentials"
	}
	if strings.Contains(path, "gcloud") {
		return "gcp_credentials"
	}
	if strings.Contains(path, "Login Data") || strings.Contains(path, "logins.json") {
		return "browser_credentials"
	}
	if strings.Contains(path, "Cookies") || strings.Contains(path, "cookies") {
		return "browser_cookies"
	}
	return "credential_file"
}
