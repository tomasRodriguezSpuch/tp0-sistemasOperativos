#ifndef MEMORIA_MAIN_H_
#define MEMORIA_MAIN_H_

#include "globals.h"
#include "handle_cpu_connections.h"
#include "handle_kernel_connections.h"
#include "config.h"
#include "shared.h"

void procesar_conexiones();
int escuchar_kernel();
void terminar_programa();
void inicializar_semaforos();
void inicializar_memoria_usuario();
void inicializar_listas_segun_esquema();
#endif