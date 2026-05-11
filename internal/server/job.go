package server

// NetworkJob is a serializable unit of network configuration.
// Up commands are applied in order; Down commands revert the job.
// Jobs are reverted in LIFO order relative to one another.
type NetworkJob struct {
	Description string   `json:"description"`
	Up          []string `json:"up"`
	Down        []string `json:"down"`
}
