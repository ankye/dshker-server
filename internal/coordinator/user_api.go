package coordinator

import (
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type nameRequest struct {
	Name string `json:"name"`
}
type networkRequest struct {
	NetworkID string `json:"networkId"`
}
type bindingRequest struct {
	DeviceID string `json:"deviceId"`
}
type limitRequest struct {
	MaxDevices int `json:"maxDevices"`
}

func (server *Server) userRoutes(router *gin.Engine) {
	router.POST("/v1/register", endpoint(func(body registerRequest) (any, error) {
		return server.store.CreateUser(body.Email, body.Password)
	}))
	router.POST("/v1/login", endpoint(func(body loginRequest) (any, error) {
		return server.store.Login(body.Username, body.Password, time.Now())
	}))
	users := router.Group("/v1", func(c *gin.Context) {
		header := c.Request.Header.Values("Authorization")
		if len(header) != 1 || !strings.HasPrefix(header[0], "Bearer ") {
			writeError(c.Writer, errors.New("p2p.user_unauthorized"))
			c.Abort()
			return
		}
		token := strings.TrimPrefix(header[0], "Bearer ")
		user, err := server.store.AuthenticateUser(token, time.Now())
		if err != nil {
			writeError(c.Writer, err)
			c.Abort()
			return
		}
		c.Set("user", user)
		c.Set("token", token)
		c.Next()
	})
	users.GET("/user", func(c *gin.Context) { writeJSON(c.Writer, c.MustGet("user")) })
	users.POST("/logout", userEndpoint(func(c *gin.Context, _ struct{}) (any, error) {
		return map[string]bool{"loggedOut": true}, server.store.Logout(c.MustGet("token").(string))
	}))
	users.GET("/networks", func(c *gin.Context) { value, err := server.store.Networks(currentUser(c)); respond(c, value, err) })
	users.POST("/networks", userEndpoint(func(c *gin.Context, body nameRequest) (any, error) {
		return server.store.CreateNetwork(currentUser(c), body.Name)
	}))
	users.PATCH("/networks/:networkId", userEndpoint(func(c *gin.Context, body nameRequest) (any, error) {
		return server.store.RenameNetwork(currentUser(c), c.Param("networkId"), body.Name)
	}))
	users.PATCH("/networks/:networkId/limit", userEndpoint(func(c *gin.Context, body limitRequest) (any, error) {
		return server.store.UpdateNetworkLimit(currentUser(c), c.Param("networkId"), body.MaxDevices)
	}))
	users.DELETE("/networks/:networkId", userEndpoint(func(c *gin.Context, _ struct{}) (any, error) {
		return map[string]bool{"deleted": true}, server.store.DeleteNetwork(currentUser(c), c.Param("networkId"), time.Now())
	}))
	users.POST("/networks/:networkId/enrollment-tokens", userEndpoint(func(c *gin.Context, _ struct{}) (any, error) {
		now := time.Now()
		token, err := server.store.IssueEnrollmentToken(currentUser(c), c.Param("networkId"), now)
		return map[string]any{"token": token, "networkId": c.Param("networkId"), "expiresAt": now.Add(5 * time.Minute).Unix()}, err
	}))
	users.GET("/devices", func(c *gin.Context) { value, err := server.store.UserDevices(currentUser(c)); respond(c, value, err) })
	users.GET("/networks/:networkId/devices", func(c *gin.Context) {
		value, err := server.store.NetworkDevices(currentUser(c), c.Param("networkId"))
		respond(c, value, err)
	})
	users.POST("/networks/:networkId/devices", userEndpoint(func(c *gin.Context, body bindingRequest) (any, error) {
		return map[string]bool{"bound": true}, server.store.BindDevice(currentUser(c), c.Param("networkId"), body.DeviceID)
	}))
	users.DELETE("/networks/:networkId/devices/:deviceId", userEndpoint(func(c *gin.Context, _ struct{}) (any, error) {
		return map[string]bool{"unbound": true}, server.store.UnbindDevice(currentUser(c), c.Param("networkId"), c.Param("deviceId"), time.Now())
	}))
	users.GET("/networks/:networkId/pairs", func(c *gin.Context) {
		value, err := server.store.NetworkPairs(currentUser(c), c.Param("networkId"))
		respond(c, value, err)
	})
	users.DELETE("/networks/:networkId/pairs/:pairId", userEndpoint(func(c *gin.Context, _ struct{}) (any, error) {
		return map[string]bool{"deleted": true}, server.store.DeletePair(currentUser(c), c.Param("networkId"), c.Param("pairId"), time.Now())
	}))
}

func currentUser(c *gin.Context) string { return c.MustGet("user").(User).ID }

func userEndpoint[T any](operation func(*gin.Context, T) (any, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := readBody[T](c.Request)
		if err != nil {
			writeError(c.Writer, err)
			return
		}
		value, err := operation(c, body)
		respond(c, value, err)
	}
}

func (store *Store) NetworkPairs(userID, networkID string) ([]Pair, error) {
	if _, err := networkOwned(store.db, userID, networkID); err != nil {
		return nil, err
	}
	rows, err := store.db.Query("SELECT p.id,p.network_id,p.initiator,p.target,p.state,p.expires,p.revision FROM pairs p JOIN networks n ON n.id=p.network_id JOIN users u ON u.id=n.user_id WHERE p.network_id=? AND n.user_id=? AND n.deleted=0 AND u.disabled=0 ORDER BY p.rowid", networkID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Pair{}
	for rows.Next() {
		var p Pair
		if err = rows.Scan(&p.ID, &p.NetworkID, &p.Initiator, &p.Target, &p.State, &p.ExpiresAt, &p.Revision); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}
