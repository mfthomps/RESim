ifneq ($(CROSSCOMPILE),)
	CC := $(CROSSCOMPILE)gcc
endif

OBJPRE ?=

ifneq ($(SIMICS_BASE),)
VPATH = $(SIMICS_BASE)/src/misc/simics-agent
include $(HOST_DIR)/host-config
else
TARGET_DIR ?= .
CFLAGS_LOCAL += -std=gnu99
DEP_CFLAGS = -MM
DEP_CC=$(CC)
OBJEXT=o
endif

UNITS=agent util proto
LIBS=-L$(TARGET_DIR)
CFLAGS_LOCAL += -static
LDFLAGS_LOCAL_FIRST = -static

ifeq ($(OS),Windows_NT)
	RM=del
	UNITS += util_win32 proto_win32
	ifeq ($(SIMICS_BASE),)
		EXEEXT=exe
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LIBS += -lrt
		UNITS += util_linux proto_linux
	else
		$(error System not supported: $(UNAME_S))
	endif
endif

TARGET=$(TARGET_DIR)/simics-agent$(EXEEXT)
OBJECTS=$(patsubst %,$(OBJPRE)%.$(OBJEXT),$(UNITS))
DEPENDS=$(UNITS:=.d)

.PHONY: all clean
.DEFAULT: all

all: $(TARGET)

clean:
	$(RM) -rf $(TARGET) $(OBJECTS) $(DEPENDS)

-include $(DEPENDS)

$(TARGET): $(OBJECTS)
	@echo "Linking $@ "
	$(CC) $(CCLDFLAGS) $(LDFLAGS_LOCAL_FIRST) -o $@ $^ $(LIBS)

$(OBJPRE)%.$(OBJEXT): %.c
	@echo "Compiling $*.c "
	$(CC) $(CFLAGS) $(CFLAGS_LOCAL) -c -o $@ $<

CDEPSED = sed 's!^\( *$(subst .,\.,$*.$(OBJEXT)) *:\)!$@ \1!g'
%.d: %.c
	@echo Creating dependencies: "$(<F) "
	$(DEP_CC) $(DEP_CFLAGS) $(CFLAGS_COMMON) $< | $(CDEPSED) > $@
