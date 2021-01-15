package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const modeOptionBootstrap = "bootstrap"
const modeOptionLWM2M = "lwm2m"
const storeOptionMem = "memory"
const storeOptionFS = "filesystem"

const flagCoapURL = "coap-url"
const flagCoapCert = "coap-cert"
const flagCoapKey = "coap-key"
const flagMode = "mode"
const flagCertOut = "dump-cert"
const flagKeyOut = "dump-key"
const flagStore = "store"
const flagStoreDir = "store-filesystem-dir"

var valueCoapURL string
var valueCoapCert string
var valueCoapKey string
var valueMode string
var valueCertOut string
var valueKeyOut string
var valueStore string
var valueStoreDir string

func main() {

	flag.StringVar(&valueCoapURL, flagCoapURL, "", "URL to use")
	flag.StringVar(&valueCoapCert, flagCoapCert, "", "Device certificate")
	flag.StringVar(&valueCoapKey, flagCoapKey, "", "Device private key")
	flag.StringVar(&valueMode, flagMode, "", "Connect mode - \""+modeOptionBootstrap+"\" or \""+modeOptionLWM2M+"\"")
	flag.StringVar(&valueCertOut, flagCertOut, "", "Location to retreived device certificate")
	flag.StringVar(&valueKeyOut, flagKeyOut, "", "Location to retreived device private key")
	flag.StringVar(&valueStore, flagStore, storeOptionMem, "Storage mode - \""+storeOptionMem+"\" or \""+storeOptionFS+"\"")
	flag.StringVar(&valueStoreDir, flagStoreDir, "store", "Storage directory when store is \""+storeOptionFS+"\"")

	flag.Parse()

	// Check for required arguments

	abort := false
	if valueCoapURL == "" {
		fmt.Printf("  --%v required\n", flagCoapURL)
		abort = true
	}
	if valueCoapCert == "" {
		fmt.Printf("  --%v required\n", flagCoapCert)
		abort = true
	}
	if valueCoapKey == "" {
		fmt.Printf("  --%v required\n", flagCoapKey)
		abort = true
	}
	if valueMode != modeOptionBootstrap && valueMode != modeOptionLWM2M {
		fmt.Printf("  --%v required, must be either \"%v\" or \"%v\"\n", flagMode, modeOptionBootstrap, modeOptionLWM2M)
		abort = true
	}
	if valueStore != storeOptionMem && valueStore != storeOptionFS {
		fmt.Printf("  --%v must be either \"%v\" or \"%v\"\n", flagMode, flagStore, storeOptionFS)
		abort = true
	}

	if abort {
		fmt.Printf("Exited due to invalid arguments\n")
		os.Exit(1)
	}

	// Setup storage needed

	var store Store
	switch valueStore {
	case storeOptionMem:
		store = &MemStore{}
	case storeOptionFS:
		store = &FsStore{Base: valueStoreDir}
	default:
		panic("Invalid store option")
	}

	// Create device and register

	var device *Device
	var err error
	switch valueMode {
	case modeOptionBootstrap:
		device, err = DeviceFromBootstrapCredentials(store, valueCoapURL, valueCoapCert, valueCoapKey)
		if err != nil {
			log.Fatalf("Failed to setup: %v", err)
		}

		err = device.Bootstrap(context.Background())
		if err != nil {
			log.Fatalf("Failed to bootstrap: %v", err)
		}
	case modeOptionLWM2M:
		device, err = DeviceFromLWM2MCredentials(store, valueCoapURL, valueCoapCert, valueCoapKey)
		if err != nil {
			log.Fatalf("Failed to setup: %v", err)
		}
	default:
		panic("Invalid mode option")
	}

	err = device.Register(context.Background())
	if err != nil {
		log.Fatalf("Failed to register: %v", err)
	}

	// Wrap Up

	printInfo(store)

	if valueCertOut != "" || valueKeyOut != "" {
		certData, keyData, err := getPemCertAndKey(store)
		if err != nil {
			log.Fatalf("Failed to retreive credentials: %v", err)
		}
		err = ioutil.WriteFile(valueCertOut, certData, 0700)
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
		err = ioutil.WriteFile(valueKeyOut, keyData, 0700)
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}
}

func printInfo(store Store) {
	type ResourceInfo struct {
		Path        string
		Description string
		Printable   bool
	}

	ri := []ResourceInfo{
		{Path: "/0/0/0", Description: "LWM2M URL", Printable: true},
		{Path: "/0/0/3", Description: "Device Certificate", Printable: false},
		{Path: "/0/0/4", Description: "LWM2M Public Key", Printable: false},
		{Path: "/0/0/5", Description: "Device Private Key", Printable: false},
	}

	for _, resource := range ri {
		value, err := store.Get(resource.Path)
		if err != nil {
			fmt.Printf("MISSING RESOURCE: %v - %v\n", resource.Path, resource.Description)
			continue
		}
		if resource.Printable {
			fmt.Printf("%v - %v: %v\n", resource.Path, resource.Description, string(value))
		} else {
			fmt.Printf("%v - %v\n", resource.Path, resource.Description)
		}
	}
}

func getPemCertAndKey(store Store) ([]byte, []byte, error) {

	resource := "/0/0/5"
	data, err := store.Get(resource)
	if err != nil {
		return nil, nil, fmt.Errorf("Cloud not get %v: %w", resource, err)
	}
	_, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not convert %v to PKCS8 key: %w", resource, err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	})
	if privateKey == nil {
		return nil, nil, fmt.Errorf("Failed to convert private key to PEM")
	}

	resource = "/0/0/3"
	data, err = store.Get(resource)
	if err != nil {
		return nil, nil, fmt.Errorf("Cloud not get %v: %w", resource, err)
	}
	_, err = x509.ParseCertificate(data)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not convert %v to Certificate key: %w", resource, err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	})
	if privateKey == nil {
		return nil, nil, fmt.Errorf("Failed to convert certificate to PEM")
	}

	return certificate, privateKey, nil
}
