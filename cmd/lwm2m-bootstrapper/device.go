package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	piondtls "github.com/pion/dtls/v2"
	"github.com/plgd-dev/go-coap/v2/dtls"
	"github.com/plgd-dev/go-coap/v2/message"
	"github.com/plgd-dev/go-coap/v2/message/codes"
	"github.com/plgd-dev/go-coap/v2/mux"
)

// Query parameters used by device management over coap
// - aid - Account ID
// - iep - Device ID (or Bootstrap ID)
// - ep - Endpoint Name

// Certificates
// - Developer Mode Bootstrap Certificate
//		- CN - Bootstrap ID
//		- OU - Account
//		- L - Locality (E.X. "Cambridge")
// - Production Mode Bootstrap Certificate
//		- CN - Endpoint Name
//		- OU - (Optional)
//		- L -  (Optional)
// - Production Mode LWM2M Certificate
//		- CN - Endpoint Name
//		- OU - Account (Optional but required for KaaS)
//		- L -  Device ID (Optional but required for KaaS)

// DeviceFromBootstrapCredentials initializes a new Device object with bootstrap credentials
func DeviceFromBootstrapCredentials(store Store, bsURL string, certPath string, keyPath string) (*Device, error) {

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed loading bootstrap certificate: %v", err)
	}

	bsID, err := CNFromCert(certificate)
	if err != nil {
		return nil, fmt.Errorf("Invalid certificate: %w", err)
	}

	parsedBsURL, err := parseCoapURL(bsURL)
	if err != nil {
		return nil, fmt.Errorf("Bootstrap URL invalid: %v", err)
	}
	account := parsedBsURL.Query()["aid"][0]

	return &Device{
		AccountID: account,
		Store:     store,

		BootstrapID:   &bsID,
		BootstrapURL:  parsedBsURL,
		BootstrapCert: &certificate,
	}, nil
}

// DeviceFromLWM2MCredentials initializes a new Device object with LWM2M credentials
func DeviceFromLWM2MCredentials(store Store, url string, certPath string, keyPath string) (*Device, error) {

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed loading LWM2M certificate: %v", err)
	}

	name, err := CNFromCert(certificate)
	if err != nil {
		return nil, fmt.Errorf("Invalid certificate: %w", err)
	}

	parsedURL, err := parseCoapURL(url)
	if err != nil {
		return nil, fmt.Errorf("LWM2M URL invalid: %v", err)
	}
	account := parsedURL.Query()["aid"][0]

	return &Device{
		AccountID: account,
		Store:     store,

		EndpointName: &name,
		Lwm2mURL:     parsedURL,
		Lwm2mCert:    &certificate,
	}, nil
}

// parseCoapURL converts a string into a URL and validates it
// 	When Valid:
// 	- coapURL.Query()["aid"][0] exists and can be accessed to get account ID
//  - URL protocol is coap
func parseCoapURL(coapURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(coapURL)
	if err != nil {
		return nil, fmt.Errorf("URL invalid: %v", err)
	}
	accounts, ok := parsedURL.Query()["aid"]
	if !ok || len(accounts) == 0 {
		return nil, fmt.Errorf("URL is missing account query parameter - 'aid'")
	}
	if len(accounts) != 1 {
		return nil, fmt.Errorf("URL must have exactly one account query parameter - 'aid'")
	}
	if parsedURL.Scheme != "coaps" {
		return nil, fmt.Errorf("URL scheme \"%v\" not supported, must be \"coap\"", parsedURL.Scheme)
	}
	return parsedURL, nil
}

// Device is a LWM2M device
type Device struct {
	AccountID string
	Store     Store

	// Bootstrap values
	BootstrapID   *string
	BootstrapURL  *url.URL // Bootstrap server URL as reported by Pelion
	BootstrapCert *tls.Certificate

	// LWM2M values
	EndpointName *string
	Lwm2mURL     *url.URL // LWM2M server URL as reported by Pelion
	Lwm2mCert    *tls.Certificate
}

// Register performs LWM2M registration followed by deregistration
func (d *Device) Register(ctx context.Context) error {
	err := d.readyForRegister()
	if err != nil {
		return fmt.Errorf("Unable to register: %w", err)
	}

	config := &piondtls.Config{
		Certificates:         []tls.Certificate{*d.Lwm2mCert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
	}

	m := mux.NewRouter()
	m.DefaultHandleFunc(mux.HandlerFunc(d.handleDefault))

	co, err := dtls.Dial(d.Lwm2mURL.Host, config, dtls.WithMux(m))
	if err != nil {
		return fmt.Errorf("Error dialing: %w", err)
	}
	defer co.Close()

	options := []message.Option{
		{ID: 15, Value: []byte(fmt.Sprintf("ep=%v", *d.EndpointName))},
	}
	for key, values := range d.Lwm2mURL.Query() {
		for _, value := range values {
			options = append(options, message.Option{ID: 15, Value: []byte(fmt.Sprintf("%v=%v", key, value))})
		}
	}

	resp, err := co.Post(ctx, "rd", 110, strings.NewReader("</1>,</2>,</3>,</4>,</5>"), options...)
	if err != nil {
		return fmt.Errorf("Error sending request: %w", err)
	}
	expected := codes.Created
	if resp.Code() != expected {
		return fmt.Errorf("Wrong return code, expected \"%v\" got \"%v\": %v", expected, resp.Code(), resp)
	}
	locationPath := ""
	for _, option := range resp.Options() {
		if option.ID != message.LocationPath {
			continue
		}
		locationPath = locationPath + "/" + string(option.Value)
	}
	log.Printf("Device registered\n")

	resp, err = co.Delete(ctx, locationPath)
	if err != nil {
		return fmt.Errorf("Error sending request: %w", err)
	}
	expected = codes.Deleted
	if resp.Code() != expected {
		return fmt.Errorf("Wrong return code, expected \"%v\" got \"%v\": %v", expected, resp.Code(), resp)
	}
	log.Printf("Device de-registered\n")

	return nil
}

// Bootstrap performs LWM2M bootstrap
func (d *Device) Bootstrap(ctx context.Context) error {
	err := d.readyForBootstrap()
	if err != nil {
		return fmt.Errorf("Unable to bootstrap: %w", err)
	}

	config := &piondtls.Config{
		Certificates:         []tls.Certificate{*d.BootstrapCert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
	}

	var once sync.Once
	bsDone := make(chan struct{})
	handleBsDone := func(w mux.ResponseWriter, r *mux.Message) {
		log.Printf("Bootstrap complete")
		once.Do(func() { close(bsDone) })
	}

	m := mux.NewRouter()
	m.Handle("/0", mux.HandlerFunc(d.bsHandleObjectID))
	m.Handle("/1", mux.HandlerFunc(d.bsHandleObjectID))
	m.Handle("/3", mux.HandlerFunc(d.bsHandleObjectID))
	m.Handle("/bs", mux.HandlerFunc(handleBsDone))
	m.DefaultHandleFunc(mux.HandlerFunc(d.bsHandleDefault))

	co, err := dtls.Dial(d.BootstrapURL.Host, config, dtls.WithMux(m))
	if err != nil {
		return fmt.Errorf("Error dialing: %w", err)
	}
	defer co.Close()

	resp, err := co.Post(context.Background(), "bs", message.TextPlain, nil,
		message.Option{ID: 15, Value: []byte(fmt.Sprintf("ep=%v", *d.BootstrapID))},
		message.Option{ID: 15, Value: []byte(fmt.Sprintf("aid=%v", d.AccountID))},
	)

	if err != nil {
		return fmt.Errorf("Error sending request: %w", err)
	}
	if resp.Code() != codes.Changed {
		return fmt.Errorf("Wrong return code: %v", resp)
	}

	timeout := time.NewTimer(time.Second * 10)
	defer timeout.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("Context expired waiting for bootstrap to finish")
	case <-timeout.C:
		return fmt.Errorf("Timeout waiting for bootstrap to finish")
	case <-bsDone:
	}

	err = d.loadLW2MCredentialsFromStore()
	if err != nil {
		return fmt.Errorf("Invalid credentials returned from bootstrap: %v", err)
	}

	return nil
}

func (d *Device) bsHandleObjectID(w mux.ResponseWriter, r *mux.Message) {
	requestPath, err := r.Options.Path()
	if err != nil {
		log.Printf("Error extracting path for request %v", r)
		setResponse(w, codes.BadRequest)
		return
	}
	objectID, err := strconv.Atoi(requestPath)
	if err != nil {
		log.Printf("Invalid Path %v", requestPath)
		setResponse(w, codes.BadRequest)
		return
	}

	if r.Code == codes.DELETE {
		log.Printf("DELETE %v:  %v from %v\n", objectID, r, w.Client().RemoteAddr())
		setResponse(w, codes.Deleted)
		return
	} else if r.Code == codes.PUT {
		log.Printf("PUT %v:  %v from %v\n", objectID, r, w.Client().RemoteAddr())

		// Check for the right Media Type format
		format, err := r.Options.ContentFormat()
		if err != nil || format != 99 {
			setResponse(w, codes.UnsupportedMediaType)
			return
		}

		if r.Body == nil {
			log.Printf("Nil body for a put request")
			setResponse(w, codes.BadRequest)
			return
		}

		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			setResponse(w, codes.InternalServerError)
			return
		}

		err = storeObjectInstanceTLV(d.Store, objectID, data)
		if err != nil {
			log.Printf("Error storing object: %v", err)
			setResponse(w, codes.BadRequest)
			return
		}

		setResponse(w, codes.Changed)

	} else {
		log.Printf("Message not allowed: %v\n", r.Code)
		setResponse(w, codes.MethodNotAllowed)
	}
}

func (d *Device) handleDefault(w mux.ResponseWriter, r *mux.Message) {
	log.Printf("UNSUPPORTED: %v", r)
	setResponse(w, codes.Forbidden)
}

func (d *Device) bsHandleDefault(w mux.ResponseWriter, r *mux.Message) {
	log.Printf("UNSUPPORTED: %v", r)
	setResponse(w, codes.Forbidden)
}

// setResponse is a helper which sets the response and logs if this failed
func setResponse(w mux.ResponseWriter, code codes.Code) {
	err := w.SetResponse(code, message.TextPlain, nil)
	if err != nil {
		log.Printf("Error setting response: %v", err)
	}
}

func storeObjectInstanceTLV(s Store, objectID int, data []byte) error {

	tlvs, _, err := TLVFromBytes(data)

	if err != nil {
		return fmt.Errorf("Error decoding TLV: %w", err)
	}

	if tlvs.Type != ObjectInstance {
		return fmt.Errorf("Invalid TLV type - Expected %v got %v", ObjectInstance, tlvs.Type)
	}

	for _, child := range tlvs.Children {
		if child.Type != Resource {
			continue
		}
		objectIntance := tlvs.Identifier
		resource := child.Identifier
		s.Put(fmt.Sprintf("/%v/%v/%v", objectID, objectIntance, resource), child.Value)
	}
	return nil
}

// CNFromCert retrieves the endpoint name from a TLS certificate
func CNFromCert(tlsCert tls.Certificate) (string, error) {
	if len(tlsCert.Certificate) == 0 {
		return "", fmt.Errorf("No certificate data present")
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("Error parsing certificate: %w", err)
	}
	return cert.Subject.CommonName, nil
}

// loadLW2MCredentialsFromStore loads and validates the LWM2M credentials in the store
func (d *Device) loadLW2MCredentialsFromStore() error {
	cert := tls.Certificate{}

	// LWM2M URL
	data, err := d.Store.Get("/0/0/0")
	if err != nil {
		return fmt.Errorf("Error retrieving LWM2M URL: %w", err)
	}
	lwm2mURL, err := parseCoapURL(string(data))
	if err != nil {
		return fmt.Errorf("LWM2M URL invalid: %v", err)
	}
	account := lwm2mURL.Query()["aid"][0]
	if account != d.AccountID {
		log.Printf("Warning: Account mismatch, %v != %v", account, d.AccountID)
	}

	// Device Certificate
	data, err = d.Store.Get("/0/0/3")
	if err != nil {
		return fmt.Errorf("Error retrieving Device Certificate: %w", err)
	}
	_, err = x509.ParseCertificate(data)
	if err != nil {
		return fmt.Errorf("Device Certificate is invalid: %w", err)
	}
	cert.Certificate = append(cert.Certificate, data)

	// Device Private Key
	data, err = d.Store.Get("/0/0/5")
	if err != nil {
		return fmt.Errorf("Error retrieving Device Private Key: %w", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("Device Private Key is invalid: %w", err)
	}
	cert.PrivateKey = privateKey

	endpointName, err := CNFromCert(cert)
	if err != nil {
		return fmt.Errorf("Invalid Device Certificate: %v", err)
	}

	if d.EndpointName != nil && *d.EndpointName != endpointName {
		log.Printf("Warning: Endpoint name changed from \"%v\" to \"%v\"", d.EndpointName, endpointName)
	}
	d.EndpointName = &endpointName
	d.Lwm2mURL = lwm2mURL
	d.Lwm2mCert = &cert

	// Sanity check
	err = d.readyForRegister()
	if err != nil {
		log.Fatalf("Internal error causing not ready for registration: %v", err)
	}
	return nil
}

func (d *Device) readyForBootstrap() error {
	if d.BootstrapID == nil {
		return fmt.Errorf("BootstrapID missing")
	}
	if d.BootstrapURL == nil {
		return fmt.Errorf("BootstrapURL missing")
	}
	if d.BootstrapCert == nil {
		return fmt.Errorf("BootstrapCert missing")
	}
	return nil
}

func (d *Device) readyForRegister() error {
	if d.EndpointName == nil {
		return fmt.Errorf("EndpointName missing")
	}
	if d.Lwm2mURL == nil {
		return fmt.Errorf("Lwm2mURL missing")
	}
	if d.Lwm2mCert == nil {
		return fmt.Errorf("Lwm2mCert missing")
	}
	return nil
}
