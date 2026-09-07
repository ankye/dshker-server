package coordinator

import (
	"errors"
	"regexp"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"userId"`
	Username string `json:"username"`
}

type UserSession struct {
	User      User   `json:"user"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$`)

func (store *Store) CreateUser(username, password string) (User, error) {
	if !usernamePattern.MatchString(username) || len(password) < 12 || len(password) > 72 {
		return User{}, errors.New("p2p.invalid_user_credentials")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return User{}, err
	}
	user := User{protocol.NewID(), username}
	if _, err = store.db.Exec("INSERT INTO users(id,username,password_hash) VALUES(?,?,?)", user.ID, username, hash); err != nil {
		return User{}, errors.New("p2p.user_conflict")
	}
	return user, nil
}

func (store *Store) Login(username, password string, now time.Time) (UserSession, error) {
	select {
	case store.logins <- struct{}{}:
		defer func() { <-store.logins }()
	default:
		return UserSession{}, errors.New("p2p.rate_limited")
	}
	if len(username) > 64 || len(password) > 72 {
		return UserSession{}, errors.New("p2p.login_failed")
	}
	var user User
	var hash []byte
	err := store.db.QueryRow("SELECT id,username,password_hash FROM users WHERE username=? AND disabled=0", username).Scan(&user.ID, &user.Username, &hash)
	if err != nil {
		hash = store.unknownPassword
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || err != nil {
		return UserSession{}, errors.New("p2p.login_failed")
	}
	session := UserSession{user, protocol.NewID() + protocol.NewID(), now.Add(24 * time.Hour).Unix()}
	result, err := store.db.Exec("INSERT INTO user_sessions(hash,user_id,expires) SELECT ?,id,? FROM users WHERE id=? AND disabled=0", digest(session.Token), session.ExpiresAt, user.ID)
	if err != nil {
		return UserSession{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return UserSession{}, errors.New("p2p.login_failed")
	}
	return session, nil
}

func (store *Store) AuthenticateUser(token string, now time.Time) (User, error) {
	var user User
	if len(token) != 64 {
		return user, errors.New("p2p.user_unauthorized")
	}
	err := store.db.QueryRow("SELECT u.id,u.username FROM users u JOIN user_sessions s ON s.user_id=u.id WHERE s.hash=? AND s.expires>? AND u.disabled=0", digest(token), now.Unix()).Scan(&user.ID, &user.Username)
	if err != nil {
		return User{}, errors.New("p2p.user_unauthorized")
	}
	return user, nil
}

func (store *Store) Logout(token string) error {
	result, err := store.db.Exec("DELETE FROM user_sessions WHERE hash=?", digest(token))
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.New("p2p.user_unauthorized")
	}
	return nil
}

func (store *Store) DisableUser(id string, now time.Time) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE users SET disabled=1 WHERE id=? AND disabled=0", id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.New("p2p.user_not_found")
	}
	if _, err = tx.Exec("DELETE FROM user_sessions WHERE user_id=?", id); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE pairs SET state='revoked',revision=revision+1 WHERE network_id IN (SELECT id FROM networks WHERE user_id=?) AND state IN ('invited','approved','active')", id); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES('user-disabled',?,?)", id, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
