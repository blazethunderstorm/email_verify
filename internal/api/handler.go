package api

import (
    "encoding/json"
    "log"
    "net/http"
    "strconv"

    "github.com/gorilla/mux"
    "domain-security-checker/internal/checker"
)

type Handler struct {
    checker *checker.Checker
}

func NewHandler(checker *checker.Checker) http.Handler {
    h := &Handler{checker: checker}
    
    r := mux.NewRouter()
    r.HandleFunc("/check/{domain}", h.checkDomain).Methods("GET")
    r.HandleFunc("/history/{domain}", h.getHistory).Methods("GET")
    
    return r
}

func (h *Handler) checkDomain(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    domain := vars["domain"]
    
    if domain == "" {
        http.Error(w, "Domain required", http.StatusBadRequest)
        return
    }

    result, err := h.checker.CheckDomain(domain)
    if err != nil {
        log.Printf("Error checking domain %s: %v", domain, err)
        http.Error(w, "Failed to check domain", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

func (h *Handler) getHistory(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    domain := vars["domain"]
    
    limitStr := r.URL.Query().Get("limit")
    limit := 10
    if limitStr != "" {
        if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
            limit = l
        }
    }

    results, err := h.checker.GetHistory(domain, limit)
    if err != nil {
        log.Printf("Error getting history for %s: %v", domain, err)
        http.Error(w, "Failed to get history", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(results)
}