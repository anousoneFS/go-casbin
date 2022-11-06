package middleware

import (
	"log"
	"net/http"
	"strings"

	"learn-casbin/util"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	casbinpgadapter "github.com/cychiuae/casbin-pg-adapter"
	"github.com/labstack/echo/v4"
)

// Config holds the configuration for the middleware
type Config struct {
	// ModelFilePath is path to model file for Casbin.
	// Optional. Default: "./model.conf".
	ModelFilePath string

	// PolicyAdapter is an interface for different persistent providers.
	// Optional. Default: fileadapter.NewAdapter("./policy.csv").
	PolicyAdapter *casbinpgadapter.Adapter

	// Enforcer is an enforcer. If you want to use your own enforcer.
	// Optional. Default: nil
	Enforcer *casbin.Enforcer

	// Lookup is a function that is used to look up current subject.
	// An empty string is considered as unauthenticated user.
	// Optional. Default: func(c *echo.Context) string { return "" }
	Lookup func(*echo.Context) string

	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: func(c *echo.Context) error { return c.SendStatus(401) }
	Unauthorized echo.HandlerFunc

	// Forbidden defines the response body for forbidden responses.
	// Optional. Default: func(c *echo.Context) error { return c.SendStatus(403) }
	Forbidden echo.HandlerFunc
}

// CasbinMiddleware ...
type CasbinMiddleware struct {
	config Config
}

// New creates an authorization middleware for use in echo
func New(config ...Config) *CasbinMiddleware {
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.Enforcer == nil {
		if cfg.ModelFilePath == "" {
			cfg.ModelFilePath = "./model.conf"
		}
		m, _ := model.NewModelFromString(cfg.ModelFilePath)

		enforcer, err := casbin.NewEnforcer(m, cfg.PolicyAdapter)
		if err != nil {
			log.Fatalf("echo: Casbin middleware error -> %v", err)
		}

		cfg.Enforcer = enforcer
	}

	if cfg.Lookup == nil {
		cfg.Lookup = func(c *echo.Context) string { return "" }
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c echo.Context) error {
			return c.JSON(http.StatusUnauthorized, echo.Map{})
		}
	}

	if cfg.Forbidden == nil {
		cfg.Forbidden = func(c echo.Context) error {
			return c.JSON(http.StatusForbidden, echo.Map{})
		}
	}

	return &CasbinMiddleware{
		config: cfg,
	}
}

type validationRule int

const (
	matchAll validationRule = iota
	atLeastOne
)

// MatchAll is an option that defines all permissions
// or roles should match the user.
var MatchAll = func(o *Options) {
	o.ValidationRule = matchAll
}

// AtLeastOne is an option that defines at least on of
// permissions or roles should match to pass.
var AtLeastOne = func(o *Options) {
	o.ValidationRule = atLeastOne
}

// PermissionParserFunc is used for parsing the permission
// to extract object and action usually
type PermissionParserFunc func(str string) []string

func permissionParserWithSeperator(sep string) PermissionParserFunc {
	return func(str string) []string {
		return strings.Split(str, sep)
	}
}

// PermissionParserWithSeperator is an option that parses permission
// with seperators
func PermissionParserWithSeperator(sep string) func(o *Options) {
	return func(o *Options) {
		o.PermissionParser = permissionParserWithSeperator(sep)
	}
}

// Options holds options of middleware
type Options struct {
	ValidationRule   validationRule
	PermissionParser PermissionParserFunc
}

// RequiresPermissions tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
// func (cm *CasbinMiddleware) RequiresPermissions(permissions []string, opts ...func(o *Options)) echo.HandlerFunc {
func (cm *CasbinMiddleware) RequiresPermissions(next echo.HandlerFunc) echo.HandlerFunc {
	permissions := []string{"*:*"}
	options := &Options{
		ValidationRule:   matchAll,
		PermissionParser: permissionParserWithSeperator(":"),
	}
	// for _, o := range opts {
	// 	o(options)
	// }

	return func(c echo.Context) error {
		if len(permissions) == 0 {
			return next(c)
		}
		// sub := cm.config.Lookup(c)
		sub := "userid"
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}
		if options.ValidationRule == matchAll {
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if ok, err := cm.config.Enforcer.Enforce(util.StringSliceToInterfaceSlice(vals)...); err != nil {
					return c.JSON(http.StatusInternalServerError, echo.Map{})
				} else if !ok {
					return cm.config.Forbidden(c)
				}
			}
			return next(c)
		} else if options.ValidationRule == atLeastOne {
			for _, permission := range permissions {
				vals := append([]string{sub}, options.PermissionParser(permission)...)
				if ok, err := cm.config.Enforcer.Enforce(util.StringSliceToInterfaceSlice(vals)...); err != nil {
					return c.JSON(http.StatusInternalServerError, echo.Map{})
				} else if ok {
					return next(c)
				}
			}
			return cm.config.Forbidden(c)
		}
		return next(c)
	}
}

// RoutePermission tries to find the current subject and determine if the
// subject has the required permissions according to predefined Casbin policies.
// This method uses http Path and Method as object and action.
func (cm *CasbinMiddleware) RoutePermission(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// sub := cm.config.Lookup(c)
		sub := "userid"
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		if ok, err := cm.config.Enforcer.Enforce(sub, c.Request().URL.Path, c.Request().Method); err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{})
		} else if !ok {
			return cm.config.Forbidden(c)
		}

		return next(c)
	}
}

// RequiresRoles tries to find the current subject and determine if the
// subject has the required roles according to predefined Casbin policies.
// func (cm *CasbinMiddleware) RequiresRoles(roles []string, opts ...func(o *Options)) echo.HandlerFunc {
func (cm *CasbinMiddleware) RequiresRoles(next echo.HandlerFunc) echo.HandlerFunc {
	roles := []string{"admin"}
	options := &Options{
		ValidationRule:   matchAll,
		PermissionParser: permissionParserWithSeperator(":"),
	}

	// for _, o := range opts {
	// 	o(options)
	// }

	return func(c echo.Context) error {
		if len(roles) == 0 {
			return next(c)
		}

		// sub := cm.config.Lookup(c)
		sub := "userid"
		if len(sub) == 0 {
			return cm.config.Unauthorized(c)
		}

		userRoles, err := cm.config.Enforcer.GetRolesForUser(sub)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{})
		}

		if options.ValidationRule == matchAll {
			for _, role := range roles {
				if !util.ContainsString(userRoles, role) {
					return cm.config.Forbidden(c)
				}
			}
			return next(c)
		} else if options.ValidationRule == atLeastOne {
			for _, role := range roles {
				if util.ContainsString(userRoles, role) {
					return next(c)
				}
			}
			return cm.config.Forbidden(c)
		}

		return next(c)
	}
}

// ReloadEnforcer ...
func (cm *CasbinMiddleware) ReloadEnforcer(modelFilePath string, adapter *casbinpgadapter.Adapter) {
	mc, _ := model.NewModelFromString(modelFilePath)
	enforcer, err := casbin.NewEnforcer(mc, adapter)
	if err := enforcer.LoadPolicy(); err != nil {
		log.Fatalf("echo: Casbin middleware error -> %v", err)
	}
	if err != nil {
		log.Fatalf("echo: Casbin middleware error -> %v", err)
	}
	cm.config.Enforcer = enforcer
}
