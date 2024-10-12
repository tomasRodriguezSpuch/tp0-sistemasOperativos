#ifndef MEMORIA_HANDLE_CPU_CONNECTIONS_H_
#define MEMORIA_HANDLE_CPU_CONNECTIONS_H_

#include "globals.h"
#include "shared.h"

void procesar_cpu(void *args);
void recibir_actualizar_contexto(int socket_cliente);
void recibir_WRITE_MEM(int socket_cliente);
t_paquete *recibir_obtener_contexto(int socket_cliente);
t_paquete *recibir_obtener_instruccion(int socket_cliente);
t_paquete *empaquetar_instruccion(char *instruccion);
t_paquete *recibir_READ_MEM(int socket_cliente);

#endif
