package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
)

// Store provides a way to save and retrieve resources
type Store interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte) error
}

// FsStore is an implementation of the Store interface
type FsStore struct {
	Base string
}

func escapeKey(key string) string {
	return strings.ReplaceAll(key, "/", "_")
}

// Get gets the given key from the filesytem
func (s *FsStore) Get(key string) ([]byte, error) {
	location := path.Join(s.Base, escapeKey(key))
	data, err := ioutil.ReadFile(location)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return nil, err
	}
	return data, nil
}

// Put writes the given key to the filesytem
func (s *FsStore) Put(key string, data []byte) error {
	location := path.Join(s.Base, escapeKey(key))
	dir := path.Dir(location)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Printf("Error creating directory: %v", err)
		return err
	}
	err = ioutil.WriteFile(location, data, 0700)
	if err != nil {
		log.Printf("Error writing to file: %v", err)
		return err
	}

	return nil
}

// MemStore is an implementation of the Store interface
type MemStore map[string][]byte

// Get gets the given key from the memory
func (s *MemStore) Get(key string) ([]byte, error) {
	if *s == nil {
		*s = map[string][]byte{}
	}
	data, ok := (*s)[key]
	if ok {
		copyData := make([]byte, len(data))
		copy(copyData, data)
		return copyData, nil
	}
	return nil, fmt.Errorf("Not found")
}

// Put writes the given key to the memory
func (s *MemStore) Put(key string, data []byte) error {
	if *s == nil {
		*s = map[string][]byte{}
	}
	copyData := make([]byte, len(data))
	copy(copyData, data)
	(*s)[key] = copyData

	return nil
}
