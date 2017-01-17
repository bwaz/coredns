package policy

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	ibp "github.com/Infoblox-CTO/policy-engine/infoblox_policy"
	log "github.com/Sirupsen/logrus"
)

type OPAResponse struct {
	DomainName string `json:"dn,omitempty"`
	Category   string `json:"category,omitempty"`
	Effect     string `json:"effect,omitempty"`
	RedirectTo string `json:"redirect_to,omitempty"`
}

type OPAClientType struct {
	opaAddrPort string
	client      *http.Client
}

type OPAResultType struct {
	Effect      string
	Redirect_to string
}

func NewClient(opa string) *OPAClientType {
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	c := &http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	}

	return &OPAClientType{opa, c}
}
func (c *OPAClientType) OPAValidate(req ibp.Request) (OPAResultType, error) {
	start := time.Now()
	result := OPAResultType{Effect: "DENY", Redirect_to: ""} // By default return DENY

	httpRequest, err := http.NewRequest("GET", "http://"+c.opaAddrPort+"/v1/data/opa/example/", nil)
	if err != nil {
		return result, err
	}

	values := httpRequest.URL.Query()
	for _, attribute := range req.Attributes {
		values.Add("request", attribute.Id+":\""+attribute.Value+"\"")
	}
	httpRequest.URL.RawQuery = values.Encode()

	httpResponse, err := c.client.Do(httpRequest)
	defer httpResponse.Body.Close()

	var resp OPAResponse
	if err == nil {
		decoder := json.NewDecoder(httpResponse.Body)
		decoder.Decode(&resp)

		result.Effect = resp.Effect
		result.Redirect_to = resp.RedirectTo

	} else {
		log.WithField("error", err).Error("Failed to get response")
		return result, err
	}

	elapsed := time.Since(start)

	log.WithFields(log.Fields{
		"request":       req,
		"response":      resp,
		"url_raw_query": httpRequest.URL.RawQuery,
		"url_path":      httpRequest.URL.Path,
		"url_host":      httpRequest.URL.Host,
	}).Info("OPAValidate ", elapsed)

	return result, err
}
