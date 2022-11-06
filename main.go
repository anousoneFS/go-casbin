package main

import (
	"net/http"

	"github.com/casbin/casbin"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	enforcer := Enforcer{enforcer: casbin.NewEnforcer("model.conf", "policy.csv")}
	// e.Use(enforcer.Enforce)
	e.GET("/foo", func(c echo.Context) error {
		return c.JSON(http.StatusOK, echo.Map{"message": "foo"})
	}, enforcer.Enforce)
	e.POST("/bar", func(c echo.Context) error {
		return c.JSON(http.StatusOK, echo.Map{"message": "bar"})
	}, enforcer.Enforce)
	e.GET("/sai", func(c echo.Context) error {
		return c.JSON(http.StatusOK, echo.Map{"message": "sai"})
	})
	e.Logger.Fatal(e.Start("0.0.0.0:3000"))
}

type Enforcer struct {
	enforcer *casbin.Enforcer
}

func (e *Enforcer) Enforce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, _, _ := c.Request().BasicAuth()
		method := c.Request().Method
		path := c.Request().URL.Path

		result := e.enforcer.Enforce(user, path, method)

		if result {
			return next(c)
		}
		return echo.ErrForbidden
	}
}
