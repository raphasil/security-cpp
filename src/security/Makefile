include ../../Makefile.opt

OBJDIR = $(BASEOBJDIR)/security

SRCS = 	security_bf_cipher.cpp \
	security_xor_cipher.cpp \
	security_rng.cpp \
	security_rsa_cipher.cpp \
	security_sha_digest.cpp \
	security_version.cpp

OBJS = $(SRCS:%.cpp=$(OBJDIR)/%.o)

TESTSRCS = security_test.cpp

TESTOBJS = $(TESTSRCS:%.cpp=$(OBJDIR)/%.o)


INSTALL_HEADERS = 	security_bf_cipher.h \
			security_xor_cipher.h \
			security_symetric_cryptograph.h \
			security_rng.h \
			security_asymetric_cryptograph.h \
			security_rsa_cipher.h \
			security_sha_digest.h \
			security_version.h

LIB = phsecurity
LIBVERSION = 0.2

LDDIRS = -L$(libdir) -L/usr/lib
LDLIBS = -lssl -lcrypto -l$(LIB)-$(LIBVERSION) -lphenconder-0.1
INCDIRS = -I$(incdir)
DEFINES = 

LDFLAGS = $(LDDIRS) $(LDLIBS)
CXXFLAGS = $(INCDIRS) $(DEFINES) $(LDFLAGS) -Wall -Wextra $(OPTIMFLAGS) -pthread
OUTPUT = $(OBJDIR)/lib$(LIB)-$(LIBVERSION).a
TESTPRG = $(OBJDIR)/sectest


all: clean $(OUTPUT) install

install: $(LIBRARY)
	-@$(MKDIR_ALL) $(libdir)
	$(CP) $(OUTPUT) $(libdir)/
	-@$(MKDIR_ALL) $(incdir)
	$(CP) $(INSTALL_HEADERS) $(incdir)/

clean:
	@$(RMDIR) $(OBJDIR)

depend:
	$(MAKEDEPEND) -- $(CXXFLAGS) -- -p$(OBJDIR)/ $(SRCS) $(TESTSRCS) 2> /dev/null
	@$(RM) Makefile.bak

$(OBJDIR)/%.o : %.cpp 
	@[ -d $(OBJDIR) ] || (echo "create object directory $(OBJDIR)" && $(MKDIR_ALL) $(OBJDIR))
	$(CXX) -c $(CXXFLAGS) -o $@ $<

$(OUTPUT): $(OBJS) 
	$(MAKELIB) $(OUTPUT) $(OBJS)

test: $(TESTPRG)

$(TESTPRG): $(TESTOBJS) 
	$(CXX) -g -o $(TESTPRG) $(TESTOBJS) $(LDFLAGS)
