# Makefile
ENCRYPT_APP = encrypt_benchmark
DECRYPT_APP = decrypt_benchmark
SRCDIR = .

# Add OpenFHE include paths
OPENFHE_INCLUDE = -I/usr/local/include/openfhe -I/usr/local/include -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/core/  -I/usr/local/include/openfhe/binfhe/  -I/usr/local/include/openfhe/cereal/

CFLAGS = -Wall -O2 -fopenmp
CXXFLAGS = $(CFLAGS) -std=c++17 $(OPENFHE_INCLUDE)

# Add OpenMP library
LDFLAGS = -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -fopenmp

.PHONY: all
all: $(ENCRYPT_APP) $(DECRYPT_APP) $(ENCRYPT_APP).manifest $(DECRYPT_APP).manifest
ifeq ($(SGX),1)
all: $(ENCRYPT_APP).manifest.sgx $(ENCRYPT_APP).sig $(DECRYPT_APP).manifest.sgx $(DECRYPT_APP).sig
endif

$(ENCRYPT_APP): encrypt_benchmark.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(DECRYPT_APP): decrypt_benchmark.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(ENCRYPT_APP).manifest: $(ENCRYPT_APP).manifest.template
	gramine-manifest \
		-Dlog_level=debug \
		-Darch_libdir=/lib/$(shell gcc -dumpmachine) \
		$< > $@

$(DECRYPT_APP).manifest: $(DECRYPT_APP).manifest.template
	gramine-manifest \
		-Dlog_level=debug \
		-Darch_libdir=/lib/$(shell gcc -dumpmachine) \
		$< > $@

$(ENCRYPT_APP).manifest.sgx: $(ENCRYPT_APP).manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $@

$(DECRYPT_APP).manifest.sgx: $(DECRYPT_APP).manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $@

$(ENCRYPT_APP).sig: $(ENCRYPT_APP).manifest.sgx

$(DECRYPT_APP).sig: $(DECRYPT_APP).manifest.sgx

.PHONY: clean
clean:
	$(RM) $(ENCRYPT_APP) $(DECRYPT_APP) *.manifest *.manifest.sgx *.sig *.token

.PHONY: distclean
distclean: clean
