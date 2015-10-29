#ifndef ARCH__H
#define ARCH__H

#include <bf_stdint.h>

class arch_handler {

public:
	arch_handler() {}
	virtual ~arch_handler() {}

	virtual void port_write(uint16_t port, uint8_t value) = 0;
	virtual void port_write(uint16_t port, uint16_t value) = 0;

	virtual uint8_t port_read(uint16_t port) = 0;
	virtual uint16_t port_read16(uint16_t port) = 0;

};

#endif // ARCH__H
