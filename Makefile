-include Config.mk

################ Source files ##########################################

exe	:= $O${name}.so
srcs	:= $(wildcard *.c)
objs	:= $(addprefix $O,$(srcs:.c=.o))
deps	:= ${objs:.o=.d}
confs	:= Config.mk
oname   := $(notdir $(abspath $O))

################ Compilation ###########################################

.SUFFIXES:
.PHONY: all clean distclean maintainer-clean

all:	${exe}

run:	${exe}
	@${exe}

${exe}:	${objs}
	@echo "Linking $@ ..."
	@${CC} -shared ${ldflags} -o $@ $^ ${libs}

$O%.o:	%.c
	@echo "    Compiling $< ..."
	@${CC} ${cflags} -MMD -MT "$(<:.c=.s) $@" -o $@ -c $<

%.s:	%.c
	@echo "    Compiling $< to assembly ..."
	@${CC} ${cflags} -S -o $@ -c $<

################ Installation ##########################################

.PHONY:	install installdirs
.PHONY: uninstall uninstall-man uninstall-pam uninstall-svc

ifdef libdir
exed	:= ${DESTDIR}${libdir}/security
exei	:= ${exed}/$(notdir ${exe})

${exed}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${exei}:	${exe} | ${exed}
	@echo "Installing $@ ..."
	@${INSTALL_PROGRAM} $< $@

installdirs:	${exed}
install:	${exei}
uninstall:
	@if [ -f ${exei} ]; then\
	    echo "Removing ${exei} ...";\
	    rm -f ${exei};\
	fi
endif
ifdef man8dir
mand	:= ${DESTDIR}${man8dir}
mani	:= ${mand}/${name}.8

${mand}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${mani}:	${name}.8 | ${mand}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

installdirs:	${mand}
install:	${mani}
uninstall:	uninstall-man
uninstall-man:
	@if [ -f ${mani} ]; then\
	    echo "Removing ${mani} ...";\
	    rm -f ${mani};\
	fi
endif

################ Maintenance ###########################################

clean:
	@if [ -d ${builddir} ]; then\
	    rm -f ${exe} ${objs} ${deps} $O.d;\
	    rmdir ${builddir};\
	fi

distclean:	clean
	@rm -f ${oname} ${confs} config.status

maintainer-clean: distclean

${builddir}/.d:
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@touch $@
$O.d:	| ${builddir}/.d
	@[ -h ${oname} ] || ln -sf ${builddir} ${oname}

${objs}:	Makefile ${confs} | $O.d
Config.mk:	Config.mk.in
${confs}:	configure
	@if [ -x config.status ]; then echo "Reconfiguring ...";\
	    ./config.status;\
	else echo "Running configure ...";\
	    ./configure;\
	fi

-include ${deps}
