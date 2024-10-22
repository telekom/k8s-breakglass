package accessreview

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
)

const defaultDBPath = "access_review.db"

type AccessReviewDB struct {
	readWriteDB *sql.DB
	readDB      *sql.DB
}

func NewAccessReviewDB(log *zap.SugaredLogger, cfg config.Config) (ar AccessReviewDB, err error) {
	if _, err := os.OpenFile(defaultDBPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
		return AccessReviewDB{}, errors.Wrap(err, "failed to create new file for db")
	}
	openWrite := fmt.Sprintf("file:%s?mode=rw&_journal_mode=WAL", defaultDBPath)
	openRead := fmt.Sprintf("file:%s?mode=ro&_journal_mode=WAL", defaultDBPath)
	ar.readWriteDB, err = sql.Open("sqlite3", openWrite)
	ar.readWriteDB.SetMaxOpenConns(1)
	if err != nil {
		return AccessReviewDB{}, errors.Wrap(err, "failed to open sqlite3 database")
	}
	ar.readDB, _ = sql.Open("sqlite3", openRead)

	create := `CREATE TABLE IF NOT EXISTS access_reviews(
    id INTEGER PRIMARY KEY,
    cluster TEXT NOT NULL,
    subject JSONB NOT NULL,
    status TEXT NOT NULL,
    until INTEGER NOT NULL,
    duration INTEGER NOT NULL
  )`
	if _, err := ar.readWriteDB.Exec(create); err != nil {
		return AccessReviewDB{}, errors.Wrap(err, "failed to create table")
	}

	return ar, nil
}

func (c AccessReviewDB) AddAccessReview(ar AccessReview) error {
	query := `INSERT INTO access_reviews VALUES(NULL,?,?,?,?,?)`
	subjectBytes, err := json.Marshal(ar.Subject)
	if err != nil {
		return errors.Wrap(err, "failed to marshal subject for db insertion")
	}
	if _, err := c.readWriteDB.Exec(query, ar.Cluster, subjectBytes, ar.Status, ar.Until.Unix(), ar.Duration); err != nil {
		return errors.Wrap(err, "failed to insert access review to db")
	}

	return nil
}

func (c AccessReviewDB) getAccessReviewsQuery(query string, args ...any) (ars []AccessReview, err error) {
	rows, err := c.readDB.Query(query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to select access reviews from db")
	}
	for rows.Next() {
		ar := AccessReview{}
		var subjectJSON []byte
		var untilUnix int64
		if err := rows.Scan(
			&ar.ID, &ar.Cluster,
			&subjectJSON, &ar.Status,
			&untilUnix, &ar.Duration); err != nil {
			return nil, errors.Wrap(err, "failed to scan access review")
		}
		if err := json.Unmarshal(subjectJSON, &ar.Subject); err != nil {
			return nil, errors.Wrap(err, "failed to select access reviews from db")
		}
		ar.Until = time.Unix(untilUnix, 0)
		ars = append(ars, ar)
	}

	return ars, nil
}

func (c AccessReviewDB) GetAccessReviews() (ars []AccessReview, err error) {
	query := `SELECT * FROM access_reviews`
	return c.getAccessReviewsQuery(query)
}

func (c AccessReviewDB) GetClusterReviews(cluster string) ([]AccessReview, error) {
	query := `SELECT * FROM access_reviews WHERE cluster=?`
	return c.getAccessReviewsQuery(query, cluster)
}

func (c AccessReviewDB) GetClusterUserReviews(cluster, user string) ([]AccessReview, error) {
	query := `SELECT * FROM access_reviews WHERE cluster=? AND json_extract(subject, '$.User')=?`
	return c.getAccessReviewsQuery(query, cluster, user)
}

func (c AccessReviewDB) UpdateReviewStatus(id uint, status AccessReviewStatus) error {
	query := `UPDATE access_reviews SET status=? WHERE id=?`
	if _, err := c.readWriteDB.Exec(query, status, id); err != nil {
		return errors.Wrap(err, "failed to update access review status")
	}

	return nil
}

func (c AccessReviewDB) DeleteReviewByID(id uint) error {
	query := `DELETE FROM access_reviews WHERE id=?`
	if _, err := c.readWriteDB.Exec(query, id); err != nil {
		return errors.Wrap(err, "failed to update access review status")
	}

	return nil
}

func (c AccessReviewDB) DeleteReviewsOlderThan(time time.Time) error {
	query := `DELETE FROM access_reviews WHERE until<?`
	if _, err := c.readWriteDB.Exec(query, time.Unix()); err != nil {
		return errors.Wrap(err, "failed to remove reviews older than")
	}

	return nil
}
