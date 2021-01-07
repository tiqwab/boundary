// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package services

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// SessionServiceClient is the client API for SessionService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SessionServiceClient interface {
	// GetSession allows a worker to retrieve session information from the
	// controller.
	LookupSession(ctx context.Context, in *LookupSessionRequest, opts ...grpc.CallOption) (*LookupSessionResponse, error)
	// ActivateSession allows a worker to activate a session on a controller.
	ActivateSession(ctx context.Context, in *ActivateSessionRequest, opts ...grpc.CallOption) (*ActivateSessionResponse, error)
	// CancelSession allows a worker to request that the controller cancel a session.
	CancelSession(ctx context.Context, in *CancelSessionRequest, opts ...grpc.CallOption) (*CancelSessionResponse, error)
	// AuthorizeConnection allows a worker to activate a session on a controller.
	AuthorizeConnection(ctx context.Context, in *AuthorizeConnectionRequest, opts ...grpc.CallOption) (*AuthorizeConnectionResponse, error)
	// ConnectConnection updates a connection to set it to connected
	ConnectConnection(ctx context.Context, in *ConnectConnectionRequest, opts ...grpc.CallOption) (*ConnectConnectionResponse, error)
	// CloseConnections updates a connection to set it to closed
	CloseConnection(ctx context.Context, in *CloseConnectionRequest, opts ...grpc.CallOption) (*CloseConnectionResponse, error)
}

type sessionServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSessionServiceClient(cc grpc.ClientConnInterface) SessionServiceClient {
	return &sessionServiceClient{cc}
}

func (c *sessionServiceClient) LookupSession(ctx context.Context, in *LookupSessionRequest, opts ...grpc.CallOption) (*LookupSessionResponse, error) {
	out := new(LookupSessionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/LookupSession", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sessionServiceClient) ActivateSession(ctx context.Context, in *ActivateSessionRequest, opts ...grpc.CallOption) (*ActivateSessionResponse, error) {
	out := new(ActivateSessionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/ActivateSession", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sessionServiceClient) CancelSession(ctx context.Context, in *CancelSessionRequest, opts ...grpc.CallOption) (*CancelSessionResponse, error) {
	out := new(CancelSessionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/CancelSession", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sessionServiceClient) AuthorizeConnection(ctx context.Context, in *AuthorizeConnectionRequest, opts ...grpc.CallOption) (*AuthorizeConnectionResponse, error) {
	out := new(AuthorizeConnectionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/AuthorizeConnection", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sessionServiceClient) ConnectConnection(ctx context.Context, in *ConnectConnectionRequest, opts ...grpc.CallOption) (*ConnectConnectionResponse, error) {
	out := new(ConnectConnectionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/ConnectConnection", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sessionServiceClient) CloseConnection(ctx context.Context, in *CloseConnectionRequest, opts ...grpc.CallOption) (*CloseConnectionResponse, error) {
	out := new(CloseConnectionResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionService/CloseConnection", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SessionServiceServer is the server API for SessionService service.
// All implementations must embed UnimplementedSessionServiceServer
// for forward compatibility
type SessionServiceServer interface {
	// GetSession allows a worker to retrieve session information from the
	// controller.
	LookupSession(context.Context, *LookupSessionRequest) (*LookupSessionResponse, error)
	// ActivateSession allows a worker to activate a session on a controller.
	ActivateSession(context.Context, *ActivateSessionRequest) (*ActivateSessionResponse, error)
	// CancelSession allows a worker to request that the controller cancel a session.
	CancelSession(context.Context, *CancelSessionRequest) (*CancelSessionResponse, error)
	// AuthorizeConnection allows a worker to activate a session on a controller.
	AuthorizeConnection(context.Context, *AuthorizeConnectionRequest) (*AuthorizeConnectionResponse, error)
	// ConnectConnection updates a connection to set it to connected
	ConnectConnection(context.Context, *ConnectConnectionRequest) (*ConnectConnectionResponse, error)
	// CloseConnections updates a connection to set it to closed
	CloseConnection(context.Context, *CloseConnectionRequest) (*CloseConnectionResponse, error)
	mustEmbedUnimplementedSessionServiceServer()
}

// UnimplementedSessionServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSessionServiceServer struct{}

func (UnimplementedSessionServiceServer) LookupSession(context.Context, *LookupSessionRequest) (*LookupSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LookupSession not implemented")
}

func (UnimplementedSessionServiceServer) ActivateSession(context.Context, *ActivateSessionRequest) (*ActivateSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateSession not implemented")
}

func (UnimplementedSessionServiceServer) CancelSession(context.Context, *CancelSessionRequest) (*CancelSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CancelSession not implemented")
}

func (UnimplementedSessionServiceServer) AuthorizeConnection(context.Context, *AuthorizeConnectionRequest) (*AuthorizeConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthorizeConnection not implemented")
}

func (UnimplementedSessionServiceServer) ConnectConnection(context.Context, *ConnectConnectionRequest) (*ConnectConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConnectConnection not implemented")
}

func (UnimplementedSessionServiceServer) CloseConnection(context.Context, *CloseConnectionRequest) (*CloseConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CloseConnection not implemented")
}
func (UnimplementedSessionServiceServer) mustEmbedUnimplementedSessionServiceServer() {}

// UnsafeSessionServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SessionServiceServer will
// result in compilation errors.
type UnsafeSessionServiceServer interface {
	mustEmbedUnimplementedSessionServiceServer()
}

func RegisterSessionServiceServer(s grpc.ServiceRegistrar, srv SessionServiceServer) {
	s.RegisterService(&_SessionService_serviceDesc, srv)
}

func _SessionService_LookupSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LookupSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).LookupSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/LookupSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).LookupSession(ctx, req.(*LookupSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SessionService_ActivateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).ActivateSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/ActivateSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).ActivateSession(ctx, req.(*ActivateSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SessionService_CancelSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CancelSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).CancelSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/CancelSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).CancelSession(ctx, req.(*CancelSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SessionService_AuthorizeConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizeConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).AuthorizeConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/AuthorizeConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).AuthorizeConnection(ctx, req.(*AuthorizeConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SessionService_ConnectConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConnectConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).ConnectConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/ConnectConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).ConnectConnection(ctx, req.(*ConnectConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SessionService_CloseConnection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CloseConnectionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).CloseConnection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionService/CloseConnection",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).CloseConnection(ctx, req.(*CloseConnectionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _SessionService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "controller.servers.services.v1.SessionService",
	HandlerType: (*SessionServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "LookupSession",
			Handler:    _SessionService_LookupSession_Handler,
		},
		{
			MethodName: "ActivateSession",
			Handler:    _SessionService_ActivateSession_Handler,
		},
		{
			MethodName: "CancelSession",
			Handler:    _SessionService_CancelSession_Handler,
		},
		{
			MethodName: "AuthorizeConnection",
			Handler:    _SessionService_AuthorizeConnection_Handler,
		},
		{
			MethodName: "ConnectConnection",
			Handler:    _SessionService_ConnectConnection_Handler,
		},
		{
			MethodName: "CloseConnection",
			Handler:    _SessionService_CloseConnection_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/servers/services/v1/session_service.proto",
}
