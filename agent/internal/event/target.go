package event

type Target struct {
	FilePath string `json:"file_path,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	RepoURL      string `json:"repo_url,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	ContainerImg string `json:"container_img,omitempty"`
	Domain       string `json:"domain,omitempty"`

	// FileSize is the size of the accessed file in bytes.
	// -1 means the size could not be determined (e.g. stat failed due to permissions).
	// 0 means the file is empty or the field was not populated.
	FileSize int64 `json:"file_size,omitempty"`
}
