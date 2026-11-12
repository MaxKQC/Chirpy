package auth

import (
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "04234"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword() returned an empty hash")
	}
	if hash == password {
		t.Fatal("HashPassword() returned the plaintext password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "04234"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	match, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash() error = %v", err)
	}
	if !match {
		t.Fatal("CheckPasswordHash() = false, want true for the correct password")
	}

	match, err = CheckPasswordHash("wrong-password", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash() error = %v", err)
	}
	if match {
		t.Fatal("CheckPasswordHash() = true, want false for the wrong password")
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "my-secret"
	expiresIn := time.Hour

	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	if tokenString == "" {
		t.Fatal("MakeJWT() returned an empty token")
	}

	gotID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if gotID != userID {
		t.Fatalf("ValidateJWT() = %v, want %v", gotID, userID)
	}

	claims := &jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	if parsed.Method != jwt.SigningMethodHS256 {
		t.Fatalf("signing method = %v, want HS256", parsed.Header["alg"])
	}
	if claims.Issuer != "chirpy-access" {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, "chirpy-access")
	}
	if claims.Subject != userID.String() {
		t.Fatalf("subject = %q, want %q", claims.Subject, userID.String())
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		t.Fatal("IssuedAt and ExpiresAt must be set")
	}
	if got := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time); got != expiresIn {
		t.Fatalf("expiresIn = %v, want %v", got, expiresIn)
	}
}

func TestValidateJWTExpired(t *testing.T) {
	tokenString, err := MakeJWT(uuid.New(), "secret", -time.Second)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	_, err = ValidateJWT(tokenString, "secret")
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("ValidateJWT() error = %v, want jwt.ErrTokenExpired", err)
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	tokenString, err := MakeJWT(uuid.New(), "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	_, err = ValidateJWT(tokenString, "wrong-secret")
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("ValidateJWT() error = %v, want jwt.ErrTokenSignatureInvalid", err)
	}
}

func TestMakeRefreshToken(t *testing.T) {
	first := MakeRefreshToken()
	second := MakeRefreshToken()

	decoded, err := hex.DecodeString(first)
	if err != nil {
		t.Fatalf("MakeRefreshToken() = %q, not hex: %v", first, err)
	}
	if len(decoded) != 32 {
		t.Fatalf("MakeRefreshToken() decoded length = %d, want 32", len(decoded))
	}
	if first == second {
		t.Fatal("MakeRefreshToken() returned the same token twice")
	}
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	_, err := GetBearerToken(headers)
	if err == nil {
		t.Fatal("GetBearerToken() error = nil, want error for a missing header")
	}

	headers.Set("Authorization", "Bearer TOKEN_STRING")
	got, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("GetBearerToken() error = %v", err)
	}
	if got != "TOKEN_STRING" {
		t.Fatalf("GetBearerToken() = %q, want %q", got, "TOKEN_STRING")
	}

	headers.Set("Authorization", "Bearer    TOKEN_STRING   ")
	got, err = GetBearerToken(headers)
	if err != nil {
		t.Fatalf("GetBearerToken() error = %v", err)
	}
	if got != "TOKEN_STRING" {
		t.Fatalf("GetBearerToken() = %q, want %q", got, "TOKEN_STRING")
	}

	for _, header := range []string{"TOKEN_STRING", "Bearer", "Basic TOKEN_STRING"} {
		headers.Set("Authorization", header)
		if _, err := GetBearerToken(headers); err == nil {
			t.Fatalf("GetBearerToken(%q) error = nil, want error", header)
		}
	}
}

func TestGetAPIKey(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("GetAPIKey() error = nil, want error for a missing header")
	}

	headers.Set("Authorization", "ApiKey THE_KEY_HERE")
	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	if got != "THE_KEY_HERE" {
		t.Fatalf("GetAPIKey() = %q, want %q", got, "THE_KEY_HERE")
	}

	headers.Set("Authorization", "ApiKey    THE_KEY_HERE   ")
	got, err = GetAPIKey(headers)
	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	if got != "THE_KEY_HERE" {
		t.Fatalf("GetAPIKey() = %q, want %q", got, "THE_KEY_HERE")
	}

	for _, header := range []string{"THE_KEY_HERE", "ApiKey", "Bearer THE_KEY_HERE"} {
		headers.Set("Authorization", header)
		if _, err := GetAPIKey(headers); err == nil {
			t.Fatalf("GetAPIKey(%q) error = nil, want error", header)
		}
	}
}
