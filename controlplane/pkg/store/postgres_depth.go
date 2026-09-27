package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (p *Postgres) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := p.pool.QueryRow(ctx, `SELECT value FROM setting WHERE key=$1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (p *Postgres) PutSetting(ctx context.Context, key, value string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO setting(key, value, updated_at) VALUES($1,$2,now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, key, value)
	return err
}

func (p *Postgres) DeleteSetting(ctx context.Context, key string) error {
	return execOne(p.pool.Exec(ctx, `DELETE FROM setting WHERE key=$1`, key))
}
