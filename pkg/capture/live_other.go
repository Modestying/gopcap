//go:build !darwin && !linux

package capture

// OpenLive returns ErrUnsupportedOS on platforms without native pure-Go live capture support.
func OpenLive(cfg LiveConfig) (PacketSource, error) {
	return nil, ErrUnsupportedOS
}
