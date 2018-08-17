// Copyright 2018 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensor

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/expression"
	"github.com/capsule8/capsule8/pkg/sys/perf"

	"github.com/golang/protobuf/ptypes/wrappers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"

	"google.golang.org/genproto/googleapis/rpc/code"

	"google.golang.org/grpc"
)

// Custom gRPC Dialer that understands "unix:/path/to/sock" as well as TCP addrs
func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	var network, address string

	parts := strings.Split(addr, ":")
	if len(parts) > 1 && parts[0] == "unix" {
		network = "unix"
		address = parts[1]
	} else {
		network = "tcp"
		address = addr
	}

	return net.DialTimeout(network, address, timeout)
}

func newTelemetryStream(
	t *testing.T,
	client api.TelemetryServiceClient,
	sub *api.Subscription,
) (api.TelemetryService_GetEventsClient, context.CancelFunc, error) {
	streamContext, streamCancel := context.WithCancel(context.Background())
	stream, err := client.GetEvents(streamContext, &api.GetEventsRequest{
		Subscription: sub,
	})
	require.NoError(t, err)

	return stream, streamCancel, err
}

func TestTelemetryService(t *testing.T) {
	var start, stop, getEventsRequest, getEventsResponse bool

	options := []TelemetryServiceOption{
		WithStartFunc(func() { start = true }),
		WithStopFunc(func() { stop = true }),
		WithGetEventsRequestFunc(func(request *api.GetEventsRequest) { getEventsRequest = true }),
		WithGetEventsResponseFunc(func(response *api.GetEventsResponse, err error) { getEventsResponse = true }),
	}

	sensor := newUnitTestSensor(t)
	address := "unix:" + filepath.Join(sensor.runtimeDir, "socket")
	service := NewTelemetryService(sensor, address, options...)
	assert.NotZero(t, service.Name())

	config.Sensor.UseTLS = false
	go service.Serve()
	time.Sleep(200 * time.Millisecond)

	// Establish a connection to the telemetry service that'll be reused
	// for various tests to check request handling.
	connContext, connCancel := context.WithCancel(context.Background())

	conn, err := grpc.DialContext(connContext, address,
		grpc.WithDialer(dialer),
		grpc.WithBlock(),
		grpc.WithTimeout(1*time.Second),
		grpc.WithInsecure())
	require.NoError(t, err)
	client := api.NewTelemetryServiceClient(conn)

	// These subscription requests should all return errors immediately.
	badSubscriptions := []*api.Subscription{
		// Invalid subscription (no EventFilter)
		&api.Subscription{},
		// Invalid subscription (empty EventFilter)
		&api.Subscription{
			EventFilter: &api.EventFilter{},
		},
		// LimitModifier is invalid (0)
		&api.Subscription{
			EventFilter: &api.EventFilter{},
			Modifier: &api.Modifier{
				Limit: &api.LimitModifier{
					Limit: 0,
				},
			},
		},
		// ThrottleModifier interval is invalid (0)
		&api.Subscription{
			EventFilter: &api.EventFilter{},
			Modifier: &api.Modifier{
				Throttle: &api.ThrottleModifier{
					Interval: 0,
				},
			},
		},
		// ThrottleModifier interval type is invalid (8888)
		&api.Subscription{
			EventFilter: &api.EventFilter{},
			Modifier: &api.Modifier{
				Throttle: &api.ThrottleModifier{
					IntervalType: 8888,
					Interval:     8,
				},
			},
		},
	}
	for _, sub := range badSubscriptions {
		var (
			stream       api.TelemetryService_GetEventsClient
			streamCancel context.CancelFunc
		)
		stream, streamCancel, err = newTelemetryStream(t, client, sub)
		if assert.NoErrorf(t, err, "%#v", sub) {
			_, err = stream.Recv()
			assert.Error(t, err, "%#v", sub)
			streamCancel()
		}
	}

	// This should return a response with status information and then an
	// error after that.
	sub := &api.Subscription{
		EventFilter: &api.EventFilter{
			KernelEvents: []*api.KernelFunctionCallFilter{
				&api.KernelFunctionCallFilter{
					Type:   api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_EXIT,
					Symbol: "alksdfjha",
					Arguments: map[string]string{
						"ret": "$retval:u64",
					},
				},
			},
		},
		ContainerFilter: &api.ContainerFilter{
			Ids:        []string{"abc", "def", "ghi"},
			Names:      []string{"jkl", "mno", "pqrs"},
			ImageIds:   []string{"tuv", "wxyz"},
			ImageNames: []string{"123", "456", "7890"},
		},
	}
	stream, streamCancel, err := newTelemetryStream(t, client, sub)
	if assert.NoErrorf(t, err, "%#v", sub) {
		var response *api.GetEventsResponse
		response, err = stream.Recv()
		if assert.NoError(t, err) {
			assert.NotZero(t, response.Statuses)
			assert.NotEqual(t, int32(code.Code_OK), response.Statuses[0].Code)

			response, err = stream.Recv()
			assert.Error(t, err)
		}
		streamCancel()
	}

	// This should be successful! The first event returned should just be
	// a status indicating OK. Then there should be 8 events that follow.
	// And finally, the last stream.Recv() should be an error.
	sub = &api.Subscription{
		EventFilter: &api.EventFilter{
			ChargenEvents: []*api.ChargenEventFilter{
				&api.ChargenEventFilter{
					Length: 10,
				},
			},
		},
		Modifier: &api.Modifier{
			Limit: &api.LimitModifier{
				Limit: 8,
			},
		},
	}
	stream, streamCancel, err = newTelemetryStream(t, client, sub)
	if assert.NoErrorf(t, err, "%#v", sub) {
		var response *api.GetEventsResponse
		response, err = stream.Recv()
		require.NoError(t, err)
		if assert.NotZero(t, len(response.Statuses)) {
			assert.Equal(t, int32(code.Code_OK), response.Statuses[0].Code)
		}

		gotError := false
		var events []*api.ReceivedTelemetryEvent
		for len(events) < 10 {
			response, err = stream.Recv()
			if err != nil {
				gotError = true
				break
			}
			events = append(events, response.Events...)
		}
		assert.Len(t, events, 8)
		assert.True(t, gotError)

		streamCancel()
	}

	connCancel()

	service.Stop()

	assert.True(t, start)
	assert.True(t, stop)
	assert.True(t, getEventsRequest)
	assert.True(t, getEventsResponse)
}

func TestRegisterChargenEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.ChargenEventFilter{
		&api.ChargenEventFilter{
			Length: 32,
		},
		&api.ChargenEventFilter{
			Length: 4,
		},
		&api.ChargenEventFilter{
			Length: 57,
		},
	}

	s := newTestSubscription(t, sensor)
	s.registerChargenEvents(events)
	verifyRegisterChargenEventFilter(t, s, len(events))
}

func TestRegisterContainerEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.ContainerEventFilter{
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED,
			View: api.ContainerEventView_FULL,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING,
			View: api.ContainerEventView_FULL,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
			FilterExpression: expression.Equal(
				expression.Identifier("exit_signal"),
				expression.Value(uint32(11))),
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED,
		},
	}
	invalidEvents := []*api.ContainerEventFilter{
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_UNKNOWN,
		},
		&api.ContainerEventFilter{
			Type: api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED,
			FilterExpression: expression.BitwiseAnd(
				expression.Identifier("asdfa"),
				expression.Value(make(chan bool))),
		},
	}

	s := newTestSubscription(t, sensor)
	s.registerContainerEvents(events)
	s.registerContainerEvents(invalidEvents)
	verifyContainerEventRegistration(t, s, len(events))
}

func TestRegisterFileEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	eventSet1 := []*api.FileEventFilter{
		&api.FileEventFilter{
			Type:           api.FileEventType_FILE_EVENT_TYPE_OPEN,
			Filename:       &wrappers.StringValue{Value: "/etc/passwd"},
			OpenFlagsMask:  &wrappers.Int32Value{Value: 823467},
			CreateModeMask: &wrappers.Int32Value{Value: 234},
		},
	}
	eventSet2 := []*api.FileEventFilter{
		&api.FileEventFilter{
			Type:            api.FileEventType_FILE_EVENT_TYPE_OPEN,
			FilenamePattern: &wrappers.StringValue{Value: "/bin/*"},
		},
	}
	eventSet3 := []*api.FileEventFilter{
		&api.FileEventFilter{
			Type: api.FileEventType_FILE_EVENT_TYPE_OPEN,
		},
	}
	invalidEvents := []*api.FileEventFilter{
		&api.FileEventFilter{
			Type: api.FileEventType_FILE_EVENT_TYPE_UNKNOWN,
		},
		&api.FileEventFilter{
			Type: api.FileEventType_FILE_EVENT_TYPE_OPEN,
			FilterExpression: expression.Equal(
				expression.Identifier("asdf"),
				expression.Value(make(chan bool))),
		},
	}

	s := newTestSubscription(t, sensor)
	prepareForRegisterFileOpenEventFilter(t, s, 0)
	prepareForRegisterFileOpenEventFilter(t, s, 1)
	prepareForRegisterFileOpenEventFilter(t, s, 2)
	s.registerFileEvents(eventSet1)
	s.registerFileEvents(eventSet2)
	s.registerFileEvents(eventSet3)
	s.registerFileEvents(invalidEvents)
	verifyRegisterFileOpenEventFilter(t, s, len(eventSet1)+len(eventSet2)+len(eventSet3))
}

func TestRegisterKernelFunctionCallEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.KernelFunctionCallFilter{
		&api.KernelFunctionCallFilter{
			Type:   api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_ENTER,
			Symbol: "sys_connect",
		},
		&api.KernelFunctionCallFilter{
			Type:   api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_EXIT,
			Symbol: "sys_connect",
		},
	}
	invalidEvents := []*api.KernelFunctionCallFilter{
		&api.KernelFunctionCallFilter{
			Type: api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_UNKNOWN,
		},
		&api.KernelFunctionCallFilter{
			Type: api.KernelFunctionCallEventType_KERNEL_FUNCTION_CALL_EVENT_TYPE_EXIT,
			FilterExpression: expression.Equal(
				expression.Identifier("asdfasdf"),
				expression.Value(make(chan bool))),
		},
	}

	for x := range events {
		newUnitTestKprobe(t, sensor, uint64(x), networkKprobeFormat)
	}

	s := newTestSubscription(t, sensor)
	s.registerKernelFunctionCallEvents(events)
	s.registerKernelFunctionCallEvents(invalidEvents)
	verifyRegisterKernelFunctionCallEventFilter(t, s, len(events))
}

func TestRegisterNetworkEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.NetworkEventFilter{
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT,
			FilterExpression: expression.Equal(
				expression.Identifier("backlog"),
				expression.Value(uint64(1024))),
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT,
		},
	}
	invalidEvents := []*api.NetworkEventFilter{
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_UNKNOWN,
		},
		&api.NetworkEventFilter{
			Type: api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT,
			FilterExpression: expression.Equal(
				expression.Identifier("asdf"),
				expression.Value(make(chan bool))),
		},
	}

	s := newTestSubscription(t, sensor)
	prepareForRegisterNetworkBindAttemptEventFilter(t, s, 0)
	prepareForRegisterNetworkConnectAttemptEventFilter(t, s, 1)
	prepareForRegisterNetworkSendtoAttemptEventFilter(t, s, 2)
	s.registerNetworkEvents(events)
	s.registerNetworkEvents(invalidEvents)
	verifyNetworkEventRegistration(t, s, "(telemetry api)", len(events)+6)
}

func TestRegisterPerformanceEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.PerformanceEventFilter{
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_PERIOD,
			SampleRate:     &api.PerformanceEventFilter_Period{345},
			Events: []*api.PerformanceEventCounter{
				&api.PerformanceEventCounter{
					Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE,
					Config: 394857,
				},
				&api.PerformanceEventCounter{
					Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE,
					Config: 32478,
				},
			},
		},
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_FREQUENCY,
			SampleRate:     &api.PerformanceEventFilter_Frequency{345},
			Events: []*api.PerformanceEventCounter{
				&api.PerformanceEventCounter{
					Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE,
					Config: 394857,
				},
			},
		},
	}
	invalidEvents := []*api.PerformanceEventFilter{
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_PERIOD,
		},
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_FREQUENCY,
		},
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_UNKNOWN,
		},
		&api.PerformanceEventFilter{
			SampleRateType: api.SampleRateType_SAMPLE_RATE_TYPE_FREQUENCY,
			SampleRate:     &api.PerformanceEventFilter_Frequency{345},
			Events: []*api.PerformanceEventCounter{
				&api.PerformanceEventCounter{
					Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_UNKNOWN,
					Config: 394857,
				},
			},
		},
	}

	s := newTestSubscription(t, sensor)
	s.registerPerformanceEvents(events)
	s.registerPerformanceEvents(invalidEvents)
	verifyRegisterPerformanceEventFilter(t, s, len(events))
}

func TestRegisterProcessEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	eventSet1 := []*api.ProcessEventFilter{
		&api.ProcessEventFilter{
			Type:         api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
			ExecFilename: &wrappers.StringValue{Value: "/bin/bash"},
		},
		&api.ProcessEventFilter{
			Type:     api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
			ExitCode: &wrappers.Int32Value{Value: 88},
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE,
		},
	}
	eventSet2 := []*api.ProcessEventFilter{
		/*	FIXME
			A second registration of an external event for the same
			subscription will overwrite the first one. Fixing this
			correctly is extremely low priority and requires
			extensive changes.

			&api.ProcessEventFilter{
				Type:                api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
				ExecFilenamePattern: &wrappers.StringValue{"/sbin/*"},
			},
		*/
	}
	invalidEvents := []*api.ProcessEventFilter{
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_UNKNOWN,
		},
		&api.ProcessEventFilter{
			Type: api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
			FilterExpression: expression.Equal(
				expression.Identifier("asdf"),
				expression.Value(make(chan bool))),
		},
	}

	s := newTestSubscription(t, sensor)
	s.registerProcessEvents(eventSet1)
	s.registerProcessEvents(eventSet2)
	s.registerProcessEvents(invalidEvents)
	verifyProcessEventRegistration(t, s, len(eventSet1)+len(eventSet2))
}

func TestContainsIDFilter(t *testing.T) {
	expr := expression.Equal(
		expression.Identifier("id"),
		expression.Value(int64(8)))
	assert.True(t, containsIDFilter(expr))

	expr = expression.NotEqual(
		expression.Identifier("id"),
		expression.Value(int64(88)))
	assert.False(t, containsIDFilter(expr))

	expr = expression.Equal(
		expression.Value(int64(88)),
		expression.Identifier("id"))
	assert.False(t, containsIDFilter(expr))

	expr = expression.LogicalAnd(
		expression.Equal(expression.Identifier("id"), expression.Value(int64(8))),
		expression.Equal(expression.Identifier("foo"), expression.Value(int32(4))))
	assert.True(t, containsIDFilter(expr))

	expr = expression.LogicalAnd(
		expression.Equal(expression.Identifier("foo"), expression.Value(int32(4))),
		expression.Equal(expression.Identifier("id"), expression.Value(int64(8))))
	assert.True(t, containsIDFilter(expr))

	expr = expression.LogicalOr(
		expression.Equal(expression.Identifier("id"), expression.Value(int64(8))),
		expression.Equal(expression.Identifier("foo"), expression.Value(int32(4))))
	assert.False(t, containsIDFilter(expr))

	expr = expression.LogicalOr(
		expression.Equal(expression.Identifier("foo"), expression.Value(int32(4))),
		expression.Equal(expression.Identifier("id"), expression.Value(int64(8))))
	assert.False(t, containsIDFilter(expr))

	expr = expression.LogicalOr(
		expression.Equal(expression.Identifier("id"), expression.Value(int64(4))),
		expression.Equal(expression.Identifier("id"), expression.Value(int64(8))))
	assert.True(t, containsIDFilter(expr))
}

func TestRegisterSyscallEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	enterEvents := []*api.SyscallEventFilter{
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
			Id:   &wrappers.Int64Value{Value: 8},
			Arg0: &wrappers.UInt64Value{Value: 11},
			Arg1: &wrappers.UInt64Value{Value: 22},
			Arg2: &wrappers.UInt64Value{Value: 33},
			Arg3: &wrappers.UInt64Value{Value: 44},
			Arg4: &wrappers.UInt64Value{Value: 55},
			Arg5: &wrappers.UInt64Value{Value: 66},
		},
	}
	exitEvents := []*api.SyscallEventFilter{
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
			Id:   &wrappers.Int64Value{Value: 8},
			Ret:  &wrappers.Int64Value{Value: 0},
		},
	}
	invalidEvents := []*api.SyscallEventFilter{
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_UNKNOWN,
			Id:   &wrappers.Int64Value{Value: 8},
		},
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
		},
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
		},
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
			Id:   &wrappers.Int64Value{Value: 8},
			FilterExpression: expression.Equal(
				expression.Identifier("asdf"),
				expression.Value(make(chan bool))),
		},
		&api.SyscallEventFilter{
			Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
			Id:   &wrappers.Int64Value{Value: 8},
			FilterExpression: expression.Equal(
				expression.Identifier("asdf"),
				expression.Value(make(chan bool))),
		},
	}

	s := newTestSubscription(t, sensor)
	prepareForRegisterSyscallEnterEventFilter(t, s)
	s.registerSyscallEvents(enterEvents)
	verifyRegisterSyscallEnterEventFilter(t, s, len(enterEvents))

	s = newTestSubscription(t, sensor)
	s.registerSyscallEvents(exitEvents)
	verifyRegisterSyscallExitEventFilter(t, s, len(exitEvents))

	s = newTestSubscription(t, sensor)
	s.registerSyscallEvents(invalidEvents)
	assert.Len(t, s.eventSinks, 0)
}

func TestRegisterTickerEvents(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	events := []*api.TickerEventFilter{
		&api.TickerEventFilter{
			Interval: 24378,
		},
		&api.TickerEventFilter{
			Interval: 374,
		},
	}

	s := newTestSubscription(t, sensor)
	s.registerTickerEvents(events)
	verifyRegisterTickerEventFilter(t, s, len(events))
}

func TestNewTelemetryEvent(t *testing.T) {
	data := TelemetryEventData{
		EventID:        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678./",
		MonotimeNanos:  2837465342,
		SequenceNumber: 293847,
		ProcessID:      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678./",
		PID:            872364,
		TGID:           28734,
		CPU:            3,
		HasCredentials: true,
		Credentials:    Cred{12, 34, 56, 78, 90, 98, 76, 54},
		Container: ContainerInfo{
			ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
			Name:       "capsule8-sensor-container",
			ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
			ImageName:  "capsule8-sensor-image",
			Pid:        872364,
			ExitCode:   255,
			Runtime:    ContainerRuntimeDocker,
			State:      ContainerStateRunning,
			JSONConfig: "This is the JSON config that isn't actually JSON",
			OCIConfig:  "This is the OCI config that isn't real",
		},
	}

	e := newTelemetryEvent(data)
	assert.Equal(t, data.EventID, e.Id)
	assert.Equal(t, data.ProcessID, e.ProcessId)
	assert.Equal(t, data.PID, int(e.ProcessPid))
	assert.Equal(t, data.Container.ID, e.ContainerId)
	assert.Equal(t, data.SensorID, e.SensorId)
	assert.Equal(t, data.SequenceNumber, e.SensorSequenceNumber)
	assert.Equal(t, data.MonotimeNanos, e.SensorMonotimeNanos)
	assert.Nil(t, e.ProcessLineage)
	assert.Equal(t, data.Container.Name, e.ContainerName)
	assert.Equal(t, data.Container.ImageID, e.ImageId)
	assert.Equal(t, data.Container.ImageName, e.ImageName)
	assert.Equal(t, data.CPU, uint32(e.Cpu))
	assert.Equal(t, data.Credentials.UID, e.Credentials.Uid)
	assert.Equal(t, data.Credentials.GID, e.Credentials.Gid)
	assert.Equal(t, data.Credentials.EUID, e.Credentials.Euid)
	assert.Equal(t, data.Credentials.EGID, e.Credentials.Egid)
	assert.Equal(t, data.Credentials.SUID, e.Credentials.Suid)
	assert.Equal(t, data.Credentials.SGID, e.Credentials.Sgid)
	assert.Equal(t, data.Credentials.FSUID, e.Credentials.Fsuid)
	assert.Equal(t, data.Credentials.FSGID, e.Credentials.Fsgid)
	assert.Equal(t, data.TGID, int(e.ProcessTgid))
}

func TestTranslateNetworkAddress(t *testing.T) {
	type testCase struct {
		data     NetworkAddressTelemetryEventData
		expected *api.NetworkAddress
	}

	testCases := []testCase{
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:   unix.AF_LOCAL,
				UnixPath: "/tmp/capsule8/local.socket",
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
				Address: &api.NetworkAddress_LocalAddress{
					LocalAddress: "/tmp/capsule8/local.socket",
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:      unix.AF_INET,
				IPv4Address: 0x7f000001,
				IPv4Port:    0x1f90,
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET,
				Address: &api.NetworkAddress_Ipv4Address{
					Ipv4Address: &api.IPv4AddressAndPort{
						Address: &api.IPv4Address{
							Address: 0x7f000001,
						},
						Port: 0x1f90,
					},
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family:          unix.AF_INET6,
				IPv6AddressHigh: 0x1122334455667788,
				IPv6AddressLow:  0x9900aabbccddeeff,
				IPv6Port:        0x01bb,
			},
			expected: &api.NetworkAddress{
				Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_INET6,
				Address: &api.NetworkAddress_Ipv6Address{
					Ipv6Address: &api.IPv6AddressAndPort{
						Address: &api.IPv6Address{
							High: 0x1122334455667788,
							Low:  0x9900aabbccddeeff,
						},
						Port: 0x01bb,
					},
				},
			},
		},
		testCase{
			data: NetworkAddressTelemetryEventData{
				Family: unix.AF_APPLETALK,
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		got := translateNetworkAddress(tc.data)
		assert.Equal(t, tc.expected, got)
	}
}

func TestTranslateEvent(t *testing.T) {
	sensor := newUnitTestSensor(t)
	defer sensor.Stop()

	s := newTestSubscription(t, sensor)

	type testCase struct {
		event    TelemetryEvent
		expected *api.TelemetryEvent
	}

	testCases := []testCase{
		// Chargen
		testCase{
			event: ChargenTelemetryEvent{
				Index:      65,
				Characters: "abcdefghijklmnopqrstuvwxyz",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Chargen{
					Chargen: &api.ChargenEvent{
						Index:      65,
						Characters: "abcdefghijklmnopqrstuvwxyz",
					},
				},
			},
		},
		// ContainerCreated
		testCase{
			event: ContainerCreatedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_CREATED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerDestroyed
		testCase{
			event: ContainerDestroyedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_DESTROYED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerExited (WaitStatus.Exited)
		testCase{
			event: ContainerExitedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   88 << 8,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						ExitCode:         88 << 8,
						ExitStatus:       88,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerExited (WaitStatus.Signaled SIGSEGV w/ CoreDump)
		testCase{
			event: ContainerExitedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   int(unix.SIGSEGV) | 0x80,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_EXITED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						ExitCode:         int32(unix.SIGSEGV) | 0x80,
						ExitSignal:       uint32(unix.SIGSEGV),
						ExitCoreDumped:   true,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerRunning
		testCase{
			event: ContainerRunningTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_RUNNING,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// ContainerUpdated
		testCase{
			event: ContainerUpdatedTelemetryEvent{
				TelemetryEventData{
					Container: ContainerInfo{
						ID:         "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
						Name:       "capsule8-sensor-container",
						ImageID:    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:  "capsule8-sensor-image",
						Pid:        872364,
						ExitCode:   255,
						Runtime:    ContainerRuntimeDocker,
						State:      ContainerStateRunning,
						JSONConfig: "This is the JSON config that isn't actually JSON",
						OCIConfig:  "This is the OCI config that isn't real",
					},
				},
			},
			expected: &api.TelemetryEvent{
				ContainerId:   "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
				ContainerName: "capsule8-sensor-container",
				ImageId:       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
				ImageName:     "capsule8-sensor-image",
				Event: &api.TelemetryEvent_Container{
					Container: &api.ContainerEvent{
						Type:             api.ContainerEventType_CONTAINER_EVENT_TYPE_UPDATED,
						Name:             "capsule8-sensor-container",
						ImageId:          "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./",
						ImageName:        "capsule8-sensor-image",
						HostPid:          872364,
						DockerConfigJson: "This is the JSON config that isn't actually JSON",
						OciConfigJson:    "This is the OCI config that isn't real",
					},
				},
			},
		},
		// FileOpen
		testCase{
			event: FileOpenTelemetryEvent{
				Filename: "/path/to/foo.bar",
				Flags:    8276354,
				Mode:     0644,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_File{
					File: &api.FileEvent{
						Type:      api.FileEventType_FILE_EVENT_TYPE_OPEN,
						Filename:  "/path/to/foo.bar",
						OpenFlags: 8276354,
						OpenMode:  0644,
					},
				},
			},
		},
		// KernelFunctionCall
		testCase{
			event: KernelFunctionCallTelemetryEvent{
				Arguments: perf.TraceEventSampleData{
					"bytes":  []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
					"string": "string_value",
					"sint8":  int8(-8),
					"sint16": int16(-16),
					"sint32": int32(-32),
					"sint64": int64(-64),
					"uint8":  uint8(8),
					"uint16": uint16(16),
					"uint32": uint32(32),
					"uint64": uint64(64),
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_KernelCall{
					KernelCall: &api.KernelFunctionCallEvent{
						Arguments: map[string]*api.KernelFunctionCallEvent_FieldValue{
							"bytes": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_BYTES,
								Value: &api.KernelFunctionCallEvent_FieldValue_BytesValue{
									BytesValue: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
								},
							},
							"string": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_STRING,
								Value: &api.KernelFunctionCallEvent_FieldValue_StringValue{
									StringValue: "string_value",
								},
							},
							"sint8": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT8,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-8),
								},
							},
							"sint16": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT16,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-16),
								},
							},
							"sint32": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT32,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-32),
								},
							},
							"sint64": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_SINT64,
								Value: &api.KernelFunctionCallEvent_FieldValue_SignedValue{
									SignedValue: int64(-64),
								},
							},
							"uint8": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT8,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(8),
								},
							},
							"uint16": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT16,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(16),
								},
							},
							"uint32": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT32,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(32),
								},
							},
							"uint64": &api.KernelFunctionCallEvent_FieldValue{
								FieldType: api.KernelFunctionCallEvent_UINT64,
								Value: &api.KernelFunctionCallEvent_FieldValue_UnsignedValue{
									UnsignedValue: uint64(64),
								},
							},
						},
					},
				},
			},
		},
		// NetworkAcceptAttemptTelemetryEvent
		testCase{
			event: NetworkAcceptAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_ATTEMPT,
						Sockfd: 82734,
					},
				},
			},
		},
		// NetworkAcceptResultTelemetryEvent
		testCase{
			event: NetworkAcceptResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_ACCEPT_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkBindAttemptTelemetryEvent
		testCase{
			event: NetworkBindAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkBindResultTelemetryEvent
		testCase{
			event: NetworkBindResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_BIND_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkConnectAttemptTelemetryEvent
		testCase{
			event: NetworkConnectAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkConnectResultTelemetryEvent
		testCase{
			event: NetworkConnectResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_CONNECT_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkListenAttemptTelemetryEvent
		testCase{
			event: NetworkListenAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				Backlog: 24576,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:    api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_ATTEMPT,
						Sockfd:  82734,
						Backlog: 24576,
					},
				},
			},
		},
		// NetworkListenResultTelemetryEvent
		testCase{
			event: NetworkListenResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_LISTEN_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkRecvfromAttemptTelemetryEvent
		testCase{
			event: NetworkRecvfromAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_ATTEMPT,
						Sockfd: 82734,
					},
				},
			},
		},
		// NetworkRecvfromResultTelemetryEvent
		testCase{
			event: NetworkRecvfromResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_RECVFROM_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// NetworkSendtoAttemptTelemetryEvent
		testCase{
			event: NetworkSendtoAttemptTelemetryEvent{
				NetworkAttemptTelemetryEventData: NetworkAttemptTelemetryEventData{
					FD: 82734,
				},
				NetworkAddressTelemetryEventData: NetworkAddressTelemetryEventData{
					Family:   unix.AF_LOCAL,
					UnixPath: "/path/to/local.socket",
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_ATTEMPT,
						Sockfd: 82734,
						Address: &api.NetworkAddress{
							Family: api.NetworkAddressFamily_NETWORK_ADDRESS_FAMILY_LOCAL,
							Address: &api.NetworkAddress_LocalAddress{
								LocalAddress: "/path/to/local.socket",
							},
						},
					},
				},
			},
		},
		// NetworkSendtoResultTelemetryEvent
		testCase{
			event: NetworkSendtoResultTelemetryEvent{
				NetworkResultTelemetryEventData: NetworkResultTelemetryEventData{
					Return: 293478,
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Network{
					Network: &api.NetworkEvent{
						Type:   api.NetworkEventType_NETWORK_EVENT_TYPE_SENDTO_RESULT,
						Result: 293478,
					},
				},
			},
		},
		// PerformanceTelemetryEvent
		testCase{
			event: PerformanceTelemetryEvent{
				TotalTimeEnabled: 23984756,
				TotalTimeRunning: 92873456,
				Counters: []perf.CounterEventValue{
					perf.CounterEventValue{
						EventType: perf.EventTypeHardware,
						Config:    29384756,
						Value:     20938457,
					},
					perf.CounterEventValue{
						EventType: perf.EventTypeHardwareCache,
						Config:    928734,
						Value:     9203784,
					},
					perf.CounterEventValue{
						EventType: perf.EventTypeSoftware,
						Config:    192873,
						Value:     495867,
					},
				},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Performance{
					Performance: &api.PerformanceEvent{
						TotalTimeEnabled: 23984756,
						TotalTimeRunning: 92873456,
						Values: []*api.PerformanceEventValue{
							&api.PerformanceEventValue{
								Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE,
								Config: 29384756,
								Value:  20938457,
							},
							&api.PerformanceEventValue{
								Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_HARDWARE_CACHE,
								Config: 928734,
								Value:  9203784,
							},
							&api.PerformanceEventValue{
								Type:   api.PerformanceEventType_PERFORMANCE_EVENT_TYPE_SOFTWARE,
								Config: 192873,
								Value:  495867,
							},
						},
					},
				},
			},
		},
		// ProcessExec
		testCase{
			event: ProcessExecTelemetryEvent{
				Filename:    "/bin/bash",
				CommandLine: []string{"bash", "-l"},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:            api.ProcessEventType_PROCESS_EVENT_TYPE_EXEC,
						ExecFilename:    "/bin/bash",
						ExecCommandLine: []string{"bash", "-l"},
					},
				},
			},
		},
		// ProcessExit (WaitStatus.Exited)
		testCase{
			event: ProcessExitTelemetryEvent{
				ExitCode:   88 << 8,
				ExitStatus: 88,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:       api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
						ExitCode:   88 << 8,
						ExitStatus: 88,
					},
				},
			},
		},
		// ProcessExit (WaitStatus.Signaled SIGSEGV w/ CoreDump)
		testCase{
			event: ProcessExitTelemetryEvent{
				ExitCode:       int32(unix.SIGSEGV) | 0x80,
				ExitSignal:     uint32(unix.SIGSEGV),
				ExitCoreDumped: true,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:           api.ProcessEventType_PROCESS_EVENT_TYPE_EXIT,
						ExitCode:       int32(unix.SIGSEGV) | 0x80,
						ExitSignal:     uint32(unix.SIGSEGV),
						ExitCoreDumped: true,
					},
				},
			},
		},
		// ProcessFork
		testCase{
			event: ProcessForkTelemetryEvent{
				ChildPID:       872364,
				ChildProcessID: "some random string for a child process id",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:         api.ProcessEventType_PROCESS_EVENT_TYPE_FORK,
						ForkChildId:  "some random string for a child process id",
						ForkChildPid: 872364,
					},
				},
			},
		},
		// ProcessUpdate
		testCase{
			event: ProcessUpdateTelemetryEvent{
				CWD: "/var/run/capsule8",
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Process{
					Process: &api.ProcessEvent{
						Type:      api.ProcessEventType_PROCESS_EVENT_TYPE_UPDATE,
						UpdateCwd: "/var/run/capsule8",
					},
				},
			},
		},
		// SyscallEnter
		testCase{
			event: SyscallEnterTelemetryEvent{
				ID:        374186,
				Arguments: [6]uint64{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Syscall{
					Syscall: &api.SyscallEvent{
						Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_ENTER,
						Id:   374186,
						Arg0: 0x11,
						Arg1: 0x22,
						Arg2: 0x33,
						Arg3: 0x44,
						Arg4: 0x55,
						Arg5: 0x66,
					},
				},
			},
		},
		// SyscallExit
		testCase{
			event: SyscallExitTelemetryEvent{
				ID:     987364,
				Return: 9286745,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Syscall{
					Syscall: &api.SyscallEvent{
						Type: api.SyscallEventType_SYSCALL_EVENT_TYPE_EXIT,
						Id:   987364,
						Ret:  9286745,
					},
				},
			},
		},
		// Ticker
		testCase{
			event: TickerTelemetryEvent{
				Seconds:     2347856,
				Nanoseconds: 238764529,
			},
			expected: &api.TelemetryEvent{
				Event: &api.TelemetryEvent_Ticker{
					Ticker: &api.TickerEvent{
						Seconds:     2347856,
						Nanoseconds: 238764529,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		got := s.translateEvent(tc.event)
		assert.Equal(t, tc.expected, got)
	}
}
