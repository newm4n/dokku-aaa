package internal

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	common "github.com/newm4n/dokku-common"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
)

func InitRouter(r *mux.Router) {

	r.Use(common.UserTokenContextMiddleware)

	aaa := &TheHandler{
		DAO: &MemoryDAO{
			UserAccountList:    make([]*UserAccount, 0),
			UserTenantRoleList: make([]*UserTenantRoles, 0),
		},
	}

	r.HandleFunc("/login", aaa.Authenticate).Methods(http.MethodPost)
	r.HandleFunc("/refresh", aaa.Refresh).Methods(http.MethodPost)

	r.HandleFunc("/tenant", aaa.CreateTenant).Methods(http.MethodPost)
	r.HandleFunc("/tenant/{oldtenant}/{newtenant}", aaa.ChangeTenant).Methods(http.MethodPost)
	r.HandleFunc("/tenant/{tenant}", aaa.DeleteTenant).Methods(http.MethodDelete)
	r.HandleFunc("/tenant", aaa.DeleteAllTenant).Methods(http.MethodDelete)
	r.HandleFunc("/tenant/{tenant}", aaa.GetTenant).Methods(http.MethodGet)
	r.HandleFunc("/tenant", aaa.GetAllTenant).Methods(http.MethodGet)
	r.HandleFunc("/tenant/s", aaa.SearchTenant).Methods(http.MethodGet)

	r.HandleFunc("/user/{tenant}/create-user", aaa.CreateUser).Methods(http.MethodPost)
	r.HandleFunc("/user/{tenant}/{user}", aaa.ChangeUserPassword).Methods(http.MethodPut)
	r.HandleFunc("/user/{tenant}/{user}", aaa.DeleteUser).Methods(http.MethodDelete)
	r.HandleFunc("/user/{tenant}/{user}", aaa.GetUser).Methods(http.MethodGet)
	r.HandleFunc("/user/{tenant}/s", aaa.SearchUser).Methods(http.MethodGet)

	r.HandleFunc("/role/{tenant}/{user}", aaa.UserTenantCreateRole).Methods(http.MethodPost)
	r.HandleFunc("/role/{tenant}/{user}/{role}", aaa.UserTenantDeleteRole).Methods(http.MethodDelete)
	r.HandleFunc("/role/{tenant}/{user}", aaa.UserTenantDeleteAllRole).Methods(http.MethodDelete)
	r.HandleFunc("/role/{tenant}/{user}/{role}", aaa.UserTenantGetRole).Methods(http.MethodGet)
	r.HandleFunc("/role/{tenant}/{user}/s", aaa.UserTenantSearchRole).Methods(http.MethodGet)
}

type TheHandler struct {
	DAO DataAccess
}

func (hdler *TheHandler) Authenticate(response http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte("missing request body"))
		return
	}
	bodyBytes, err := io.ReadAll(request.Body)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("err got %s", err.Error())))
		return
	}
	loginRequest := &AuthenticateRequest{}
	err = json.Unmarshal(bodyBytes, &loginRequest)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("canot parse body. got %s", err.Error())))
		return
	}
	at, rt, err := hdler.DAO.Authenticate(request.Context(), loginRequest.Email, loginRequest.Passphrase)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusUnauthorized, nil, []byte(fmt.Sprintf("unauthorized. got %s", err.Error())))
		return
	}

	authResp := &AuthenticateResponse{
		Access:  at,
		Refresh: rt,
	}

	respOk, err := json.Marshal(authResp)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusInternalServerError, nil, []byte(fmt.Sprintf("error while generating response. got %s", err.Error())))
		return
	}
	common.WriteHttpResponse(response, http.StatusOK, map[string][]string{"Content-Type": {"application/json"}}, respOk)
}

func (hdler *TheHandler) Refresh(response http.ResponseWriter, request *http.Request) {
	if request.Body == nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte("missing request body"))
		return
	}
	bodyBytes, err := io.ReadAll(request.Body)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("err got %s", err.Error())))
		return
	}
	refreshRequest := &RefreshRequest{}
	err = json.Unmarshal(bodyBytes, &refreshRequest)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusBadRequest, nil, []byte(fmt.Sprintf("canot parse body. got %s", err.Error())))
		return
	}

	at, err := hdler.DAO.Refresh(request.Context(), refreshRequest.Refresh)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusUnauthorized, nil, []byte(fmt.Sprintf("unauthorized. got %s", err.Error())))
		return
	}

	refResp := &RefreshResponse{
		Access: at,
	}

	respOk, err := json.Marshal(refResp)
	if err != nil {
		common.WriteHttpResponse(response, http.StatusInternalServerError, nil, []byte(fmt.Sprintf("error while generating response. got %s", err.Error())))
		return
	}
	common.WriteHttpResponse(response, http.StatusOK, map[string][]string{"Content-Type": {"application/json"}}, respOk)
}

type CreateTenantRequest struct {
}
type CreateTenantResponse struct {
}

func (hdler *TheHandler) CreateTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) ChangeTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) DeleteTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) DeleteAllTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) GetTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) GetAllTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

func (hdler *TheHandler) SearchTenant(response http.ResponseWriter, request *http.Request) {
	if common.RequestMayThrough(request, "*", "root") {
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
	}
}

/*
r.HandleFunc("/user/{tenant}/create-user", aaa.CreateUser).Methods(http.MethodPost)
*/
func (hdler *TheHandler) CreateUser(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	if tenant, exist := pathVars["tenant"]; exist {
		if common.RequestMayThrough(request, "*", "root") {
			log.Debugf("Tenant=%s", tenant)
			common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
		} else {
			common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
		}
	} else {
		common.WriteHttpResponse(response, http.StatusNotFound, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not found"))
	}
}

/*
r.HandleFunc("/user/{tenant}/{user}", aaa.ChangeUserPassword).Methods(http.MethodPut)
*/
func (hdler *TheHandler) ChangeUserPassword(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	if tenant, exist := pathVars["tenant"]; exist {
		if user, exist := pathVars["user"]; exist {
			if common.RequestMayThrough(request, "*", "root") {
				log.Debugf("Tenant=%s & User=%s", tenant, user)
				// create user here
				common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
			} else {
				common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
			}
		}
	}
	common.WriteHttpResponse(response, http.StatusNotFound, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not found"))
}

/*
r.HandleFunc("/user/{tenant}/{user}", aaa.DeleteUser).Methods(http.MethodDelete)
*/
func (hdler *TheHandler) DeleteUser(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	if tenant, exist := pathVars["tenant"]; exist {
		if user, exist := pathVars["user"]; exist {
			if common.RequestMayThrough(request, "*", "root") {
				log.Debugf("Tenant=%s & User=%s", tenant, user)
				// create user here
				common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
			} else {
				common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
			}
		}
	}
	common.WriteHttpResponse(response, http.StatusNotFound, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not found"))
}

/*
r.HandleFunc("/user/{tenant}/{user}", aaa.GetUser).Methods(http.MethodGet)
*/
func (hdler *TheHandler) GetUser(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	if tenant, exist := pathVars["tenant"]; exist {
		if user, exist := pathVars["user"]; exist {
			if common.RequestMayThrough(request, "*", "root") {
				log.Debugf("Tenant=%s & User=%s", tenant, user)
				// create user here
				common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
			} else {
				common.WriteHttpResponse(response, http.StatusForbidden, map[string][]string{"Content-Type": {"text/plain"}}, []byte("you're provided token is insufficient"))
			}
		}
	}
	common.WriteHttpResponse(response, http.StatusNotFound, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not found"))
}

/*
r.HandleFunc("/user/{tenant}/s", aaa.SearchUser).Methods(http.MethodGet)
*/
func (hdler *TheHandler) SearchUser(response http.ResponseWriter, request *http.Request) {
	pathVars := mux.Vars(request)
	if tenant, exist := pathVars["tenant"]; exist {
		log.Debugf("Tenant=%s", tenant)
		common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
	} else {
		common.WriteHttpResponse(response, http.StatusNotFound, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not found"))
	}
}

func (hdler *TheHandler) UserTenantCreateRole(response http.ResponseWriter, request *http.Request) {
	common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantDeleteRole(response http.ResponseWriter, request *http.Request) {
	common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantDeleteAllRole(response http.ResponseWriter, request *http.Request) {
	common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantGetRole(response http.ResponseWriter, request *http.Request) {
	common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}

func (hdler *TheHandler) UserTenantSearchRole(response http.ResponseWriter, request *http.Request) {
	common.WriteHttpResponse(response, http.StatusNotImplemented, map[string][]string{"Content-Type": {"text/plain"}}, []byte("not yet implemented"))
}
