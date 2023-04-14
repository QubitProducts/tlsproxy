TARGET=deb
PACKAGE_NAME=tlsproxy
PACKAGE_VERSION=20160602
PACKAGE_REVISION=1
PACKAGE_ARCH=amd64
PACKAGE_MAINTAINER=tristan@qubit.com
PACKAGE_FILE=$(PACKAGE_NAME)_$(PACKAGE_VERSION)-$(PACKAGE_REVISION)_$(PACKAGE_ARCH).$(TARGET)

GOPKG=github.com/QubitProducts/tlsproxy
BINNAME=tlsproxy

PWD=$(shell pwd)

all: package

binary: clean-binary
	mkdir -p build/$(PACKAGE_NAME)/src/$(GOPKG)
	cp *.go build/$(PACKAGE_NAME)/src/$(GOPKG)
	GOPATH=$(PWD)/build/$(PACKAGE_NAME) cd build/$(PACKAGE_NAME)/src/${GOPKG} && go build -a -o target ./
	mkdir -p dist/usr/local/bin
	install -m755 build/$(PACKAGE_NAME)/src/${GOPKG}/target dist/usr/local/bin/$(BINNAME)
	mkdir -p dist/etc/init
	install -m644 $(BINNAME).conf dist/etc/init/$(BINNAME).conf

clean-binary:
	rm -f dist/usr/local/bin/$(BINNAME)

package: clean binary
	cd dist && \
	  fpm \
	  -t $(TARGET) \
	  -m $(PACKAGE_MAINTAINER) \
	  -n $(PACKAGE_NAME) \
	  -a $(PACKAGE_ARCH) \
	  -v $(PACKAGE_VERSION) \
	  --iteration $(PACKAGE_REVISION) \
	  -s dir \
	  -p ../$(PACKAGE_FILE) \
	  .


clean:
	rm -f $(PACKAGE_FILE)
	rm -rf dist
	rm -rf build
