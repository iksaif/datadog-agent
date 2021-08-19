// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package cgroups

import (
	"fmt"
	"path"
	"strings"

	"github.com/karrick/godirwalk"
)

const (
	controllersFile = "cgroup.controllers"
)

type readerV2 struct {
	cgroupRoot        string
	cgroupControllers map[string]struct{}
	filter            ReaderFilter
}

func newReaderV2(cgroupRoot string, filter ReaderFilter) (*readerV2, error) {
	controllers, err := readCgroupControllers(cgroupRoot)
	if err != nil {
		return nil, err
	}

	return &readerV2{
		cgroupRoot:        cgroupRoot,
		cgroupControllers: controllers,
		filter:            filter,
	}, nil
}

func readCgroupControllers(cgroupRoot string) (map[string]struct{}, error) {
	controllersMap := make(map[string]struct{})
	err := parseFile(defaultFileReader, path.Join(cgroupRoot, controllersFile), func(s string) error {
		controllers := strings.Fields(s)
		for _, c := range controllers {
			controllersMap[c] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(controllersMap) == 0 {
		return nil, fmt.Errorf("no cgroup controllers activated at: %s", path.Join(cgroupRoot, controllersFile))
	}

	return controllersMap, nil
}

func (r *readerV2) parseCgroups() (map[string]Cgroup, error) {
	res := make(map[string]Cgroup)

	err := godirwalk.Walk(r.cgroupRoot, &godirwalk.Options{
		AllowNonDirectory: true,
		Unsorted:          true,
		Callback: func(fullPath string, de *godirwalk.Dirent) error {
			if de.IsDir() {
				id, err := r.filter(fullPath, de.Name())
				if id != "" {
					res[id] = newCgroupV2(id, fullPath, r.cgroupControllers)

					if err != nil {
						return err
					}
				}

				return err
			}

			return nil
		},
	})

	return res, err
}
