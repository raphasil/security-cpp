include ../../Makefile.opt

OBJDIR = $(BASEOBJDIR)/encoder

SRCS = 	encoder_base64.cpp \
	encoder_hex.cpp

OBJS = $(SRCS:%.cpp=$(OBJDIR)/%.o)

TESTSRCS = encoder_test.cpp

TESTOBJS = $(TESTSRCS:%.cpp=$(OBJDIR)/%.o)


INSTALL_HEADERS = 	encoder_base64.h \
			encoder_basic.h \
			encoder_hex.h

LIB = phenconder
LIBVERSION = 0.1

LDDIRS = -L$(libdir) -L/usr/lib
LDLIBS = -lssl -lcrypto -l$(LIB)-$(LIBVERSION)
INCDIRS = -I$(incdir)
DEFINES = 

LDFLAGS = $(LDDIRS) $(LDLIBS)
CXXFLAGS = $(INCDIRS) $(DEFINES) $(LDFLAGS) -Wall -Wextra $(OPTIMFLAGS) -pthread
OUTPUT = $(OBJDIR)/lib$(LIB)-$(LIBVERSION).a
TESTPRG = $(OBJDIR)/enctest


all: clean $(OUTPUT) install

install: $(LIBRARY)
	-$(MKDIR_ALL) $(libdir)
	$(CP) $(OUTPUT) $(libdir)/
	-$(MKDIR_ALL) $(incdir)
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

