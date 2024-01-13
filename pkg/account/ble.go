package account

import (
	"context"

	"github.com/teslamotors/vehicle-command/internal/authentication"
	"github.com/teslamotors/vehicle-command/pkg/cache"
	"github.com/teslamotors/vehicle-command/pkg/connector/ble"
	"github.com/teslamotors/vehicle-command/pkg/vehicle"
)

func (a *Account) GetVehicleBLE(ctx context.Context, vin string, privateKey authentication.ECDHPrivateKey, sessions *cache.SessionCache) (*vehicle.Vehicle, error) {

	conn, err := ble.NewConnection(ctx, vin)
	if err != nil {
		return nil, err
	}
	car, err := vehicle.NewVehicle(conn, privateKey, sessions)
	if err != nil {
		conn.Close()
	}
	return car, err
}
