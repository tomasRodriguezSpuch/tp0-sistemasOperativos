#include "../include/config.h"

t_memoria_config *create_memoria_config(char *path_a_config){
    t_memoria_config *memoria_config = malloc(sizeof(t_memoria_config));
    memoria_config->config = config_create(path_a_config);
    memoria_config->puerto_esucha = config_get_string_value(memoria_config->config,"PUERTO_ESCUCHA");
    memoria_config->ip_fs = config_get_string_value(memoria_config->config,"IP_FILESYSTEM");
    memoria_config->puerto_fs = config_get_string_value(memoria_config->config,"PUERTO_FILESYSTEM");
    memoria_config->tam_memoria = config_get_int_value(memoria_config->config,"TAM_MEMORIA");
    memoria_config->path_instrucciones = config_get_string_value(memoria_config->config,"PATH_INSTRUCCIONES");
    memoria_config->retardo = config_get_int_value(memoria_config->config,"RETARDO_RESPUESTA");
    memoria_config->esquema = config_get_string_value(memoria_config->config,"ESQUEMA");
    memoria_config->algoritmo_busqueda = config_get_string_value(memoria_config->config,"ALGORITMO_BUSQUEDA");
    memoria_config->particiones = config_get_array_value(memoria_config->config,"PARTICIONES");
    memoria_config->log_level = config_get_string_value(memoria_config->config,"LOG_LEVEL");

    return memoria_config;
}

void destroy_memoria_config(t_memoria_config *memoria_config){
    free((void*)memoria_config->puerto_esucha);
    free((void*)memoria_config->ip_fs);
    free((void*)memoria_config->puerto_fs);
    free((void*)memoria_config->path_instrucciones);
    free((void*)memoria_config->esquema);
    free((void*)memoria_config->algoritmo_busqueda);
    free((void*)memoria_config->particiones);
    free((void*)memoria_config->log_level);
    free((void*)memoria_config->config);
    free((void*)memoria_config);
}