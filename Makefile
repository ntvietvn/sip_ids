CFLAGS=-L/usr/local/lib -L/usr/local/lib/libcvia -lpcap -lcvia -liptc -lpthread -lconfig -lzmq
INCL=-I/usr/local/include/libiptc -I/usr/local/include/libcvia
#CC=gcc -fpermissive -Wall
CC=gcc -Wall
#OPTIONS=-DSTATEFUL 
OPTIONS= 
DST_FOLDER=/usr/local/etc/sip_ids

BIN=sip_ids
OBJS=sip_ids.o ipt_cmd.o elem_stat.o sip_fct.o ids_engine.o raw_udp.o tsqueue.o ids_elem.o dialog.o watchdog.o config.o remote.o

${BIN}: ${OBJS}
	${CC} ${OPTIONS} -o $@ ${OBJS} ${CFLAGS}

%.o: %.c 
	${CC} -c ${OPTIONS} $< ${INCL}

clean:
	rm -f a.out *.o ${BIN}

install:
	mkdir -p ${DST_FOLDER}
	if [ ! -f ${DST_FOLDER}/sip_ids.cfg ]; then cp sip_ids.cfg ${DST_FOLDER}; fi
	if [ ! -f ${DST_FOLDER}/known_peers.data ]; then cp known_peers.data ${DST_FOLDER}; fi
	cp blip.data ${DST_FOLDER}
	mkdir -p /var/log/sip_ids/
	cp -f sip_ids /usr/bin/
