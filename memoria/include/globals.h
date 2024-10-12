#ifndef MEMORIA_GLOBALS_H_
#define MEMORIA_GLOBALS_H_

#include <commons/log.h>
#include <commons/string.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <commons/config.h>
#include <pthread.h>

#include <../../utils/src/utils/process.h>
#include <../../utils/src/utils/instructions.h>
#include <../../utils/src/utils/operation_handler.h>
#include <../../utils/src/utils/serialization.h>
#include <../../utils/src/utils/sockets.h>
#include <../../utils/src/utils/utils.h>


//Estructuras para el manejo de PROCESOS
typedef struct{
	char* path;
	int pid;
	uint32_t tamanio;
}t_nuevo_proceso;

typedef struct {
	int pid;
	uint32_t base;
	uint32_t limite;
	t_list* lista_tids;
	pthread_mutex_t mutex_lista_tids;
}t_proceso;//para armar mi lista de procesos en memoria

//Estructuras para el manejo de HILOS
typedef struct{
	char* path;
	int pid;
	int tid;
}t_nuevo_hilo; // Avisarle a los de kernel que tienen que mandar esto

typedef struct{
	int pid;
	int tid
}t_pid_tid; //No se que nombre ponerle a esta estructura xd

typedef struct {
	int tid;
	t_registros_cpu *registros_cpu;
	t_list* instrucciones;
}t_hilo;//para armar mi lista de procesos en memoria

//Estructuras para el manejo de la memoria de usurio
typedef struct {
	int pid; //-1 si esta libre
	uint32_t base; 		
	uint32_t tamanio;
}t_particion;


//Estructura para guardar el config
typedef struct
{
	t_config *config;
	char *puerto_esucha;
	char *ip_fs;
	char *puerto_fs;
	int tam_memoria;
	char *path_instrucciones;
	int retardo;
	char *esquema;
	char *algoritmo_busqueda;
	char **particiones;
	char *log_level;

}t_memoria_config;


//Variables globales
extern void *memoria_usuario;

extern t_memoria_config *memoria_config;

extern t_log *logger_memoria;

extern int fileSystem_connection;
extern int memoria_servidor;
extern char* modulo_conectado;

extern t_list* lista_procesos;
extern pthread_mutex_t mutex_lista_procesos;
void inicializar_semaforos();

extern pthread_mutex_t mutex_memoria_usuario;
extern pthread_mutex_t mutex_lista_huecos;
extern pthread_mutex_t mutex_lista_particiones;

extern t_list* lista_huecos;
extern t_list* lista_particiones;

#endif