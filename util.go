package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

func getConf(path string) (*config, error) {
	c := &config{}
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
