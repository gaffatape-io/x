// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.0
// source: nmap.proto

package nmap

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PortReport struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Port    string `protobuf:"bytes,1,opt,name=port,proto3" json:"port,omitempty"`
	State   string `protobuf:"bytes,2,opt,name=state,proto3" json:"state,omitempty"`
	Service string `protobuf:"bytes,3,opt,name=service,proto3" json:"service,omitempty"`
}

func (x *PortReport) Reset() {
	*x = PortReport{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nmap_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PortReport) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PortReport) ProtoMessage() {}

func (x *PortReport) ProtoReflect() protoreflect.Message {
	mi := &file_nmap_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PortReport.ProtoReflect.Descriptor instead.
func (*PortReport) Descriptor() ([]byte, []int) {
	return file_nmap_proto_rawDescGZIP(), []int{0}
}

func (x *PortReport) GetPort() string {
	if x != nil {
		return x.Port
	}
	return ""
}

func (x *PortReport) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *PortReport) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

type ScanReport struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id    string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Id2   string        `protobuf:"bytes,2,opt,name=id2,proto3" json:"id2,omitempty"`
	Ports []*PortReport `protobuf:"bytes,3,rep,name=ports,proto3" json:"ports,omitempty"`
}

func (x *ScanReport) Reset() {
	*x = ScanReport{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nmap_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanReport) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanReport) ProtoMessage() {}

func (x *ScanReport) ProtoReflect() protoreflect.Message {
	mi := &file_nmap_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanReport.ProtoReflect.Descriptor instead.
func (*ScanReport) Descriptor() ([]byte, []int) {
	return file_nmap_proto_rawDescGZIP(), []int{1}
}

func (x *ScanReport) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ScanReport) GetId2() string {
	if x != nil {
		return x.Id2
	}
	return ""
}

func (x *ScanReport) GetPorts() []*PortReport {
	if x != nil {
		return x.Ports
	}
	return nil
}

type ScanResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StartedAt *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=started_at,json=startedAt,proto3" json:"started_at,omitempty"`
	Duration  *durationpb.Duration   `protobuf:"bytes,2,opt,name=duration,proto3" json:"duration,omitempty"`
	Reports   map[string]*ScanReport `protobuf:"bytes,3,rep,name=reports,proto3" json:"reports,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ScanResult) Reset() {
	*x = ScanResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nmap_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanResult) ProtoMessage() {}

func (x *ScanResult) ProtoReflect() protoreflect.Message {
	mi := &file_nmap_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanResult.ProtoReflect.Descriptor instead.
func (*ScanResult) Descriptor() ([]byte, []int) {
	return file_nmap_proto_rawDescGZIP(), []int{2}
}

func (x *ScanResult) GetStartedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.StartedAt
	}
	return nil
}

func (x *ScanResult) GetDuration() *durationpb.Duration {
	if x != nil {
		return x.Duration
	}
	return nil
}

func (x *ScanResult) GetReports() map[string]*ScanReport {
	if x != nil {
		return x.Reports
	}
	return nil
}

var File_nmap_proto protoreflect.FileDescriptor

var file_nmap_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6e, 0x6d, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x50, 0x0a,
	0x0a, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x70,
	0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22,
	0x51, 0x0a, 0x0a, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x10, 0x0a,
	0x03, 0x69, 0x64, 0x32, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x69, 0x64, 0x32, 0x12,
	0x21, 0x0a, 0x05, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0b,
	0x2e, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x05, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x22, 0xfb, 0x01, 0x0a, 0x0a, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x12, 0x39, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x35, 0x0a, 0x08,
	0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x32, 0x0a, 0x07, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x2e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07,
	0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x1a, 0x47, 0x0a, 0x0c, 0x52, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x21, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x52,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x61, 0x66, 0x66, 0x61, 0x74, 0x61, 0x70, 0x65, 0x2d, 0x69, 0x6f, 0x2f, 0x78, 0x2f, 0x74, 0x6f,
	0x6f, 0x6c, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x6e, 0x6d, 0x61, 0x70, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_nmap_proto_rawDescOnce sync.Once
	file_nmap_proto_rawDescData = file_nmap_proto_rawDesc
)

func file_nmap_proto_rawDescGZIP() []byte {
	file_nmap_proto_rawDescOnce.Do(func() {
		file_nmap_proto_rawDescData = protoimpl.X.CompressGZIP(file_nmap_proto_rawDescData)
	})
	return file_nmap_proto_rawDescData
}

var file_nmap_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_nmap_proto_goTypes = []interface{}{
	(*PortReport)(nil),            // 0: PortReport
	(*ScanReport)(nil),            // 1: ScanReport
	(*ScanResult)(nil),            // 2: ScanResult
	nil,                           // 3: ScanResult.ReportsEntry
	(*timestamppb.Timestamp)(nil), // 4: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),   // 5: google.protobuf.Duration
}
var file_nmap_proto_depIdxs = []int32{
	0, // 0: ScanReport.ports:type_name -> PortReport
	4, // 1: ScanResult.started_at:type_name -> google.protobuf.Timestamp
	5, // 2: ScanResult.duration:type_name -> google.protobuf.Duration
	3, // 3: ScanResult.reports:type_name -> ScanResult.ReportsEntry
	1, // 4: ScanResult.ReportsEntry.value:type_name -> ScanReport
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_nmap_proto_init() }
func file_nmap_proto_init() {
	if File_nmap_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nmap_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PortReport); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_nmap_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanReport); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_nmap_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanResult); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nmap_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_nmap_proto_goTypes,
		DependencyIndexes: file_nmap_proto_depIdxs,
		MessageInfos:      file_nmap_proto_msgTypes,
	}.Build()
	File_nmap_proto = out.File
	file_nmap_proto_rawDesc = nil
	file_nmap_proto_goTypes = nil
	file_nmap_proto_depIdxs = nil
}
