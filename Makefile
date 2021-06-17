PROTOS := \
	**/*.proto

PHONY += protobuf
protobuf:
	@for d in $$(find ./ -type f -name "*.proto"); do		\
  		protoc -I=$(CURDIR)  -I=$(GOPATH)/src -I=$(GOPATH)/src/github.com/gogo/protobuf/protobuf --gogofaster_out=Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,paths=source_relative:. $(CURDIR)/$$d; \
	done;

.PHONY: $(PHONY)