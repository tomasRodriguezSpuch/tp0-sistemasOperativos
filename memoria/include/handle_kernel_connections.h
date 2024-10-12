#ifndef MEMORIA_HANDLE_KERNEL_CONNECTIONS_H_
#define MEMORIA_HANDLE_KERNEL_CONNECTIONS_H_

#include "globals.h"
#include "shared.h"

//FUNCION PRINCIPAL
void procesar_kernel(void *void_socket);

//CREACION DEL PROCESO
t_nuevo_proceso* recibir_process_create(int socket_cliente);
t_operation_code crear_proceso(int pid, char* path, uint32_t tamanio);

//FINALIACION DEL PROCESO
int recibir_pid_a_finalizar(int socket_cliente);
void finalizar_proceso(int pid);
void liberar_proceso(t_proceso* proceso_a_finalizar);

//CREACION DEL HILO
t_nuevo_hilo* recibir_thread_create(int socket_cliente);
void crear_hilo(int pid, char* path, int tid);
t_registros_cpu* inicializar_registro_cpu();

//FINALIZACION DEL HILO
t_pid_tid* recibir_pid_tid(int socket_cliente);
void finalizar_hilo(int pid , int tid);
int encontrar_posicion_hilo_en_lista(t_list* lista_tids_proceso, int tid);

//MANEJO DE MEMORIA DE USUARIO 

t_particion* crear_particion(int pid, uint32_t base, uint32_t tamanio);
t_operation_code buscar_espacio_memoria(uint32_t tamanio);
t_particion* asignar_particion(int pid,uint32_t tamanio);
t_particion* buscar_particion(uint32_t base);
void achicar_particion(t_particion* nueva_particion, t_particion* particion_a_modificar);
void liberar_particion(t_particion* particion_a_liberar);
void juntar_particiones(t_particion* particion_a_liberar, t_particion* particion_vacia_a_juntar);
int encontrar_posicion_particion_en_lista(t_particion *particion);
t_particion* buscar_particion_libre(t_particion* particion, bool buscar_derecha);

//ALGORITMOS DE BUSQUEDA

t_particion* encontrar_particion_first(uint32_t tamanio);
t_particion* encontrar_particion_best(uint32_t tamanio);
t_particion* encontrar_particion_worst(uint32_t tamanio);

//MEMORY DUMP
t_operation_code memory_dump(int pid , int tid);

#endif