# Marshalling

## Building protobufs

Types are defined in `.proto` files alongside the other sources. 
To generate `.pb.go` Go files, run `make` in the root of the repository.

## Custom Cast Types with GoGo

In order to nicely generate structures which contain `big.Int` or slices thereof, 
we use the `castwithtype` option from the `https://github.com/trasc/protobuf` fork.

```shell
git clone https://github.com/gogo/protobuf $GOPATH/src/github.com/gogo/protobuf
cd $GOPATH/src/github.com/gogo/protobuf
git remote add trasc https://github.com/trasc/protobuf.git
git fetch trasc
git merge trasc/casttypewith
cd protoc-gen-gogoslick
go build
cp protoc-gen-gogoslick $GOPATH/bin
```