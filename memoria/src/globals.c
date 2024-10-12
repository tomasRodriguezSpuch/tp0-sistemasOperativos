#include <../include/globals.h>


int fileSystem_connection = 0;
int memoria_servidor = 0;


void *memoria_usuario = NULL;
t_log *logger_memoria = NULL;
t_memoria_config *memoria_config = NULL;

t_list* lista_procesos = NULL;
t_list* lista_huecos = NULL;
t_list* lista_particiones = NULL;

char* modulo_conectado = NULL;


pthread_mutex_t mutex_lista_procesos;
pthread_mutex_t mutex_memoria_usuario; 
pthread_mutex_t mutex_lista_huecos;
pthread_mutex_t mutex_lista_particiones;

void inicializar_semaforos(){ 
	pthread_mutex_init(&mutex_lista_procesos, NULL);
	pthread_mutex_init(&mutex_memoria_usuario, NULL);
}


