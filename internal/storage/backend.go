// ABOUTME: Defines the StorageBackend interface for observation persistence.
// ABOUTME: Implemented by LocalStorage (JSON files) and SQLCipherStorage (encrypted SQLite).
package storage
type StorageBackend interface {
	SaveObservation(obs *Observation) error
	GetObservation(id string) (*Observation, error)
	ListObservations() ([]Observation, error)
	DeleteObservation(id string) error
	ObservationExists(obs *Observation) (bool, error)
	ExistsBySource(adapter, machine, sourceID string) (bool, error)
	GetStatus() (itemCount int, storageBytes int64, err error)
	Close() error
}
