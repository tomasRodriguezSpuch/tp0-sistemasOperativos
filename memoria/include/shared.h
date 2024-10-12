#ifndef MEMORIA_SHARED_H_
#define MEMORIA_SHARED_H_

#include "globals.h"
#include "shared.h"

//FUNCIONES COMPARTIDAS ENTRE HANDLE_KERNEL Y HANDLE_CPU CONNECTIONS
t_list * leer_pseudocodigo(char* ruta);

//FUNCIONES PARA BUSCAR DENTRO DE LISTAS
t_proceso* buscar_proceso(int pid);
t_hilo *buscar_hilo(int pid, int tid);

//FUNCIONES PARA EMPAQUETAR
void empaquetar_registros(t_paquete *paquete, t_hilo *hilo);
void empaquetar_base_y_limite(t_paquete *paquete, t_proceso *proceso);

//FUNCIONES PARA EL MANEJO DE MEMORIA DE USUARIO
t_particion* buscar_particion_por_base(uint32_t base);

#endif