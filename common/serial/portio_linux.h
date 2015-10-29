#ifndef PORTIO_LINUX__H
#define PORTIO_LINUX__H

#include <port_io.h>
#include <stdio.h>

extern void bf_outb(uint16_t port, uint8_t value);
extern void bf_outw(uint16_t port, uint16_t value);
extern uint8_t bf_inb(uint16_t port);
extern uint16_t bf_inw(uint16_t port);

#define TRACE() printf("%s:%d\n", __PRETTY_FUNCTION__, __LINE__)
#define TRACE_INT(x) printf("[%s:%d] - %08X\n", __PRETTY_FUNCTION__, __LINE__, x)

class portio_linux : public port_io {
public:

	portio_linux();
	~portio_linux();

	void port_write_8(uint16_t port, uint8_t value);
	void port_write_16(uint16_t port, uint16_t value);

	uint8_t port_read_8(uint16_t port);
	uint16_t port_read_16(uint16_t port);
};

#endif