#include <bf_stdint.h>
#include <serial_port.h>
#include <serial_port_x86.h>
#include <portio_linux.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	portio_linux io;
	serial_port_x86 tmp(io);
	serial_port *com = &tmp;

	com->open();

	setbuf(stdout, NULL);

	do
	{
		if(com->data_ready())
		{
			*com << com->read();
		}
	} while(1);

	return 0;
}
