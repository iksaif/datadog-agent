// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build docker

package listeners

// func TestMain(m *testing.M) {
// 	// Temporary measure until we rework the listener
// 	// to use common docker methods and move that testing
// 	// to integration tests
// 	docker.EnableTestingMode()
// 	os.Exit(m.Run())
// }
//
// func TestCreateService(t *testing.T) {
// 	d, err := docker.GetDockerUtil()
// 	if err != nil {
// 		t.Fatalf("cannot get docker util: %s", err)
// 	}
//
// 	filters, err := newContainerFilters()
// 	if err != nil {
// 		t.Fatalf("cannot create container filters: %s", err)
// 	}
//
// 	l := &DockerListener{
// 		dockerUtil: d,
// 		filters:    filters,
// 		services:   make(map[string]Service),
// 		newService: make(chan<- Service, 100),
// 	}
//
// 	imageName := "test"
// 	cID := "12345678901234567890123456789012"
// 	cacheKey := docker.GetInspectCacheKey(cID, false)
//
// 	tests := []struct {
// 		name      string
// 		container types.ContainerJSON
// 		service   Service
// 	}{
// 		{
// 			name: "container running",
// 			container: types.ContainerJSON{
// 				ContainerJSONBase: &types.ContainerJSONBase{
// 					ID:    cID,
// 					Image: imageName,
// 					State: &types.ContainerState{
// 						Running: true,
// 					},
// 				},
// 				Config: &container.Config{},
// 			},
// 			service: &DockerService{
// 				cID:             cID,
// 				adIdentifiers:   []string{fmt.Sprintf("docker://%s", cID), imageName},
// 				creationTime:    1,
// 				hosts:           map[string]string{},
// 				ports:           []ContainerPort{},
// 				metricsExcluded: false,
// 				logsExcluded:    false,
// 			},
// 		},
// 		{
// 			name: "stopped container, not too old",
// 			container: types.ContainerJSON{
// 				ContainerJSONBase: &types.ContainerJSONBase{
// 					ID:    cID,
// 					Image: imageName,
// 					State: &types.ContainerState{
// 						Running:    false,
// 						FinishedAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
// 					},
// 				},
// 				Config: &container.Config{},
// 			},
// 			service: &DockerService{
// 				cID:             cID,
// 				adIdentifiers:   []string{fmt.Sprintf("docker://%s", cID), imageName},
// 				creationTime:    1,
// 				hosts:           map[string]string{},
// 				ports:           []ContainerPort{},
// 				metricsExcluded: false,
// 				logsExcluded:    false,
// 			},
// 		},
// 		{
// 			name: "stopped container, too old",
// 			container: types.ContainerJSON{
// 				ContainerJSONBase: &types.ContainerJSONBase{
// 					ID:    cID,
// 					Image: imageName,
// 					State: &types.ContainerState{
// 						Running:    false,
// 						FinishedAt: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
// 					},
// 				},
// 				Config: &container.Config{},
// 			},
// 			service: nil,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			cache.Cache.Set(cacheKey, tt.container, time.Minute)
// 			defer cache.Cache.Delete(cacheKey)
//
// 			ctx := context.Background()
// 			l.createService(ctx, cID)
// 			defer delete(l.services, cID)
//
// 			assert.Equal(t, tt.service, l.services[cID])
// 		})
// 	}
// }
