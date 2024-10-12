#ifndef MEMORIA_CONFIG_H_
#define MEMORIA_CONFIG_H_

#include "globals.h"
#include "shared.h"

t_memoria_config *create_memoria_config(char *path_a_config);
void destroy_memoria_config(t_memoria_config *memoria_config);

#endif