/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package carbide

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2/dsl/core"
	. "github.com/onsi/gomega"
	"github.com/osac-project/fulfillment-common/auth"
)

// fakeTokenSource is a simple token source that always returns a fixed token for testing.
type fakeTokenSource struct{}

func (s *fakeTokenSource) Token(ctx context.Context) (result *auth.Token, err error) {
	result = &auth.Token{
		Access: "fake-token",
	}
	return
}

var _ = Describe("Client", func() {
	var (
		ctx    context.Context
		server *httptest.Server
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Describe("Get", func() {
		It("sends a GET request and deserializes the response", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodGet))
				Expect(r.URL.Path).To(Equal("/v2/org/test-org/carbide/site"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				err := json.NewEncoder(w).Encode([]Site{
					{Id: "site-1", Name: "first-site"},
					{Id: "site-2", Name: "second-site"},
				})
				Expect(err).ToNot(HaveOccurred())
			}))

			client, err := NewClient().
				SetLogger(logger).
				SetUrl(server.URL + "/v2").
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).ToNot(HaveOccurred())

			var sites []Site
			err = client.Get().
				SetEndpoint("site").
				SetOutput(&sites).
				Send(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(sites).To(HaveLen(2))
			Expect(sites[0].Id).To(Equal("site-1"))
			Expect(sites[0].Name).To(Equal("first-site"))
			Expect(sites[1].Id).To(Equal("site-2"))
			Expect(sites[1].Name).To(Equal("second-site"))
		})

		It("includes query parameters in the request", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Query().Get("siteId")).To(Equal("my-site-id"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("[]"))
				Expect(err).ToNot(HaveOccurred())
			}))

			client, err := NewClient().
				SetLogger(logger).
				SetUrl(server.URL + "/v2").
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).ToNot(HaveOccurred())

			var machines []Machine
			err = client.Get().
				SetEndpoint("machine").
				SetQueryParameter("siteId", "my-site-id").
				SetOutput(&machines).
				Send(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(machines).To(BeEmpty())
		})
	})

	Describe("Post", func() {
		It("sends a POST request with a JSON body", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				Expect(r.URL.Path).To(Equal("/v2/org/test-org/carbide/site"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

				body, err := io.ReadAll(r.Body)
				Expect(err).ToNot(HaveOccurred())
				var request Site
				err = json.Unmarshal(body, &request)
				Expect(err).ToNot(HaveOccurred())
				Expect(request.Name).To(Equal("my-site"))
				Expect(request.Description).To(Equal("A test site"))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				err = json.NewEncoder(w).Encode(Site{
					Id:          "new-site-id",
					Name:        request.Name,
					Description: request.Description,
					Status:      "Pending",
				})
				Expect(err).ToNot(HaveOccurred())
			}))

			client, err := NewClient().
				SetLogger(logger).
				SetUrl(server.URL + "/v2").
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).ToNot(HaveOccurred())

			var created Site
			err = client.Post().
				SetEndpoint("site").
				SetInput(&Site{
					Name:        "my-site",
					Description: "A test site",
				}).
				SetOutput(&created).
				Send(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(created.Id).To(Equal("new-site-id"))
			Expect(created.Name).To(Equal("my-site"))
			Expect(created.Description).To(Equal("A test site"))
			Expect(created.Status).To(Equal("Pending"))
		})

		It("returns an error for non-2xx status codes", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, err := w.Write([]byte(`{"message":"forbidden"}`))
				Expect(err).ToNot(HaveOccurred())
			}))

			client, err := NewClient().
				SetLogger(logger).
				SetUrl(server.URL + "/v2").
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).ToNot(HaveOccurred())

			err = client.Post().
				SetEndpoint("site").
				SetInput(&Site{Name: "my-site"}).
				Send(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("403"))
		})
	})

	Describe("Builder validation", func() {
		It("fails without a logger", func() {
			_, err := NewClient().
				SetUrl("http://localhost").
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("logger"))
		})

		It("fails without a URL", func() {
			_, err := NewClient().
				SetLogger(logger).
				SetOrg("test-org").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("URL"))
		})

		It("fails without an organization", func() {
			_, err := NewClient().
				SetLogger(logger).
				SetUrl("http://localhost").
				SetTokenSource(&fakeTokenSource{}).
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("organization"))
		})

		It("fails without a token source", func() {
			_, err := NewClient().
				SetLogger(logger).
				SetUrl("http://localhost").
				SetOrg("test-org").
				Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("token source"))
		})
	})
})
