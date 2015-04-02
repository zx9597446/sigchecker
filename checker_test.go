package sigchecker

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
)

const testSecret = "abcd"
const headerKey = "X-request-signature"

func makeSignaureHeader(secret string) string {
	timestamp := strconv.Itoa(int(time.Now().Unix()))
	signature := fmt.Sprintf("%x", md5.Sum([]byte(timestamp+secret)))
	return fmt.Sprintf("%s,%s", timestamp, signature)
}

func TestcheckSignature(t *testing.T) {
	secret := "abcd"
	header := makeSignaureHeader(secret)
	if checkSignature(header, secret) == false {
		t.Fatal("TestcheckSignature failed")
	}
}

func prepareApi(t *testing.T, f rest.HandlerFunc) http.Handler {
	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	api.Use(NewSignatureChecker(headerKey, testSecret))
	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		f(w, r)
	}))
	handler := api.MakeHandler()
	if handler == nil {
		t.Fatal("the http.Handler must be have been create")
	}
	return handler
}

func TestCheckerUnauthorized(t *testing.T) {
	handler := prepareApi(t, func(w rest.ResponseWriter, r *rest.Request) {
		w.WriteJson(map[string]string{"Id": "123"})
	})
	recorded := test.RunRequest(t, handler, test.MakeSimpleRequest("GET", "http://localhost/", nil))
	recorded.CodeIs(401)
}

func TestCheckerPassed(t *testing.T) {
	handler := prepareApi(t, func(w rest.ResponseWriter, r *rest.Request) {
		w.WriteJson(map[string]string{"Id": "123"})
	})
	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	header := makeSignaureHeader(testSecret)
	req.Header.Set(headerKey, header)
	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}
