#include <bf_stdint.h>
#include <serial_port.h>
#include <serial_port_x86.h>
#include <portio_linux.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	portio_linux io;
	serial_port *com = new serial_port_x86(io);

	com->open();

	setbuf(stdout, NULL);

	while(1)
	{
		if(com->data_ready())
		{
			com->write(com->read());
		}
	}

	return 0;
}
