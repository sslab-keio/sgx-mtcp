CC=gcc
DEFS=
INCLUDE=-I.
CCASFLAGS=-g -O2 -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -D_FORTIFY_SOURCE=2 -fstack-protector-all -DHAVE_GNU_STACK -Wno-implicit-function-declaration
CFLAGS=-g -O2 -Wall -Werror -std=gnu99 -fno-strict-aliasing -fno-strict-overflow -D_FORTIFY_SOURCE=2 -fstack-protector-all -DHAVE_GNU_STACK -Wno-pointer-sign
LIBS=-lpthread
LDFLAGS=-Wl,-z,relro -Wl,-z,now

all: socketapiserver socketapiclient socketapiserver_sgx signed_enclave

########## Intel SGX ############

##### Parameters #####

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_PRERELEASE ?= 1
SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

SGX_COMMON_CFLAGS += -g -O2

ifeq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
else
	Urts_Library_Name := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

Enclave_Config_File := enclave.config.xml

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name)

ifeq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service
else
	App_Link_Flags += -lsgx_uae_service_sim
endif

#################################

##### App Objects #####

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -Wno-implicit-function-declaration

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

enclave_u.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --untrusted enclave.edl --search-path . --search-path $(SGX_SDK)/include

enclave_u.o: enclave_u.c
	$(CC) $(App_C_Flags) -DDONT_DEFINE_STRUCTS -I$(SGX_SDK)/include -c $< -o $@

socketapiserver_sgx.o: socketapiserver_sgx.c
	$(CC) $(App_C_Flags) -g -O2 -fPIC -DPIC -Werror -I$(SGX_SDK)/include -c $< -o $@

##### Enclave Objects #####

Enclave_Include_Paths := -I. -I../include -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcmalloc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave.lds

enclave_t.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --trusted ./enclave.edl --search-path . --search-path $(SGX_SDK)/include

enclave_t.o: enclave_t.c
	$(CC) $(Enclave_C_Flags) -DDEFINE_TIME_STRUCT -c $< -o $@

#################################

sgxserver_thread.o: sgxserver_thread.c enclave_t.c
	$(eval srcbasefile=$(basename $@))
	$(eval dstbasefile=$(basename $(notdir $@)))
	$(eval maindir=$(dir $@))
	$(CC) $(DEFS) $(INCLUDE) $(CPPFLAGS) $(CFLAGS) -I$(SGX_SDK)/include -E -o $(maindir)$(dstbasefile).i $(srcbasefile).c
	$(CC) $(DEFS) $(INCLUDE) $(CPPFLAGS) $(CFLAGS) $(Enclave_C_Flags) -I$(SGX_SDK)/include -fPIC -DPIC -c -o $(maindir)$(dstbasefile).o $(maindir)$(dstbasefile).i

enclave: enclave_t.o sgxserver_thread.o
	$(CC) enclave_t.o sgxserver_thread.o -o $(Enclave_Name) $(Enclave_Link_Flags)

signed_enclave: enclave
	$(SGX_ENCLAVE_SIGNER) sign -key enclave_private.pem -enclave $(Enclave_Name) -out $(Signed_Enclave_Name) -config $(Enclave_Config_File)

socketapiserver_sgx: enclave_u.o socketapiserver_sgx.o
	$(CC) $(CFLAGS) -o $@ enclave_u.o socketapiserver_sgx.o -lpthread $(App_Link_Flags) -lpthread

##### Not SGX stuff #####

socketapiclient.o: socketapiclient.c
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c -o $@ $<

socketapiserver.o: socketapiserver.c
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c -o $@ $<

socketapiserver: socketapiserver.o
	$(CC) -o $@ $^ $(LIBS)

socketapiclient: socketapiclient.o
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm socketapiserver
	rm socketapiclient
	find . -iname "enclave_u.?" -delete
	find . -iname "enclave_t.?" -delete
	find . -iname "$(Enclave_Name)" -delete
	find . -iname "$(Signed_Enclave_Name)" -delete
	find . -iname "*\.o" -delete
	find . -iname "*\.i" -delete


