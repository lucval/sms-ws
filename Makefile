all: sms_ws prx_emu

sms_ws: sms_ws.c
	gcc -W -Wall -g -O0 -lcurl -lpthread -o sms_ws sms_ws.c `pkg-config --cflags --libs libpjproject`

prx_emu: prx_emu.c
	gcc -W -Wall -g -O0 -lcurl -lpthread -o prx_emu prx_emu.c `pkg-config --cflags --libs libpjproject`

clean:
	rm sms_ws
	rm prx_emu
