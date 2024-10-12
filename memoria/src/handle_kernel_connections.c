#include "../include/handle_kernel_connections.h"

void procesar_kernel(void *void_socket){
	int *socket = (int*) void_socket;
	int socket_cliente = *socket;
	t_operation_code confirmacion_de_operacion = OK;
	t_operation_code operacion;
	
	if (recv(socket_cliente, &operacion, sizeof(operacion), MSG_WAITALL) != sizeof(operacion)) { 
			log_warning(logger_memoria, "ERROR en el envio del COD-OP por parte del CLIENTE"); 
			free(socket);
			return;
	}
	switch (operacion){ 
	case PROCESS_CREATE:

		t_nuevo_proceso* nuevo_proceso = recibir_process_create(socket_cliente);
		confirmacion_de_operacion = crear_proceso(nuevo_proceso->pid,nuevo_proceso->path,nuevo_proceso->tamanio);

		free(nuevo_proceso->path);
		free(nuevo_proceso);
		break;
	case FINISH_PROCESS:

		int pid_a_finalizar = recibir_pid_a_finalizar(socket_cliente);
		finalizar_proceso(pid_a_finalizar);

		break;
	case THREAD_CREATE:

		t_nuevo_hilo* nuevo_hilo = recibir_thread_create(socket_cliente);
		crear_hilo(nuevo_hilo->pid, nuevo_hilo->path, nuevo_hilo->tid);

		free(nuevo_hilo); 
		break;
	case FINISH_THREAD:

		t_pid_tid* hilo_a_eliminar = recibir_pid_tid(socket_cliente);
		finalizar_hilo(hilo_a_eliminar->pid , hilo_a_eliminar->tid);

		free(hilo_a_eliminar);
		break;
	case MEMORY_DUMP:
		t_pid_tid* datos_proceso = recibir_pid_tid(socket_cliente);
		confirmacion_de_operacion = memory_dump(datos_proceso->pid , datos_proceso->tid);

		free(datos_proceso);
		break;
	default:
		break;
	}

	send(socket_cliente, &confirmacion_de_operacion, sizeof(t_operation_code), 0);
}

// CREACION DEL PROCESO

t_nuevo_proceso* recibir_process_create(int socket_cliente){
	t_list *paquete = recibir_paquete(socket_cliente);
	t_nuevo_proceso* nuevo_proceso = malloc(sizeof(t_nuevo_proceso));

	//EL ORDEN PUEDE CAMBIAR DEPENDIENDO DE COMO LO MANDE KERNEL. Estar atentos a cuando lo implementen
	int* pid = (int*)list_get(paquete,0);
	nuevo_proceso->pid = *pid;

	nuevo_proceso->path = strdup((char*)list_get(paquete, 1));

	uint32_t* tamanio = (uint32_t*) list_get(paquete,2);
	nuevo_proceso->tamanio = *tamanio;

	list_destroy_and_destroy_elements(paquete,free);
	return(nuevo_proceso);

}

//Se que es flashero que CREAR UN PROCESO devuelva un codigo de operacion, pero lo que devuelve es OK o ERROR si se creo o no. 
//Si hay duda preguntar, es por un problema de sincronizacion que encontre

t_operation_code crear_proceso(int pid, char* path, uint32_t tamanio){


	pthread_mutex_lock(&mutex_lista_particiones);

	t_operation_code confirmacion_espacio = buscar_espacio_memoria(tamanio);
	switch (confirmacion_espacio)
	{
	case OK:
		t_particion* particion_asignada = asignar_particion(pid,tamanio); 
		pthread_mutex_unlock(&mutex_lista_particiones);

		t_proceso* nuevo_proceso = malloc(sizeof(t_proceso));
		nuevo_proceso->pid = pid;
		nuevo_proceso->base = particion_asignada->base; 
		nuevo_proceso->limite = (particion_asignada->base) + (particion_asignada->tamanio); 
		nuevo_proceso->lista_tids = list_create();
		pthread_mutex_init(&(nuevo_proceso->mutex_lista_tids), NULL); 
		log_info(logger_memoria,"## Proceso Creado -  PID: %d - Tamaño: %d",pid, tamanio);

		crear_hilo(pid, path, 0);
		
		push_con_mutex(lista_procesos, nuevo_proceso, &mutex_lista_procesos); 
		

		return OK;

		break;
	case ERROR:

		pthread_mutex_unlock(&mutex_lista_particiones);

		return ERROR;
		break;
	default:
		log_debug(logger_memoria,"buscar_espacio_memoria FALLA y no devuelve un COD-OP correcto");

		pthread_mutex_unlock(&mutex_lista_particiones);
		return ERROR;
		break;
	}	
}

// CREACION DEL HILO

t_nuevo_hilo* recibir_thread_create(int socket_cliente){
	t_list* paquete = recibir_paquete(socket_cliente);
	t_nuevo_hilo* nuevo_hilo = malloc(sizeof(t_nuevo_hilo));


	int* pid = (int*)list_get(paquete,0);
	nuevo_hilo->pid = *pid;
	free(pid);

	nuevo_hilo->path = strdup((char*)list_get(paquete, 1));

	int*tid = (int*)list_get(paquete,2);
	nuevo_hilo->tid = *tid;
	free(tid);

	list_destroy_and_destroy_elements(paquete,free);
	return nuevo_hilo;

}

void crear_hilo(int pid, char* path, int tid){
	
	char* ruta_completa = string_from_format("%s%s", memoria_config->path_instrucciones,path); 
	t_list *lista_de_instrucciones = leer_pseudocodigo(ruta_completa);
	free(ruta_completa);
	

	t_hilo* nuevo_hilo = malloc(sizeof(t_hilo));
	nuevo_hilo->tid = tid;
	nuevo_hilo->registros_cpu = inicializar_registro_cpu();
	nuevo_hilo->instrucciones = lista_de_instrucciones;
	log_info(logger_memoria,"## Hilo Creado - (PID:TID) - (%d:%d)",pid, tid);

	t_proceso *proceso_padre = buscar_proceso(pid);
	
	push_con_mutex(proceso_padre->lista_tids, nuevo_hilo, &(proceso_padre->mutex_lista_tids)); 
}

t_registros_cpu* inicializar_registro_cpu() {
	t_registros_cpu* nuevo_registros_cpu = malloc(sizeof(t_registros_cpu));

	nuevo_registros_cpu->AX = 0;
	nuevo_registros_cpu->BX = 0;
	nuevo_registros_cpu->CX = 0;
	nuevo_registros_cpu->DX = 0;
	nuevo_registros_cpu->EX = 0;
	nuevo_registros_cpu->FX = 0;
	nuevo_registros_cpu->GX = 0;
	nuevo_registros_cpu->HX = 0;
	nuevo_registros_cpu->PC = 0;

	return nuevo_registros_cpu;
}

//FINALIZACION DEL HILO

t_pid_tid* recibir_pid_tid(int socket_cliente){
	t_list* paquete = recibir_paquete(socket_cliente);
	t_pid_tid* hilo_a_eliminar = malloc(sizeof(t_pid_tid));

	int* pid = (int*)list_get(paquete,0);
	hilo_a_eliminar->pid = *pid;
	free(pid);

	int* tid = (int*)list_get(paquete,0);
	hilo_a_eliminar->tid = *tid;
	free(tid);

	list_destroy_and_destroy_elements(paquete,free);
	return hilo_a_eliminar;
}

void finalizar_hilo(int pid , int tid){
	t_proceso* proceso_del_hilo = buscar_proceso(pid);

	pthread_mutex_lock(&(proceso_del_hilo->mutex_lista_tids));

	int posicion_hilo = encontrar_posicion_hilo_en_lista(proceso_del_hilo->lista_tids,tid);
	list_remove_and_destroy_element(proceso_del_hilo->lista_tids, posicion_hilo, free);
	
	pthread_mutex_unlock(&(proceso_del_hilo->mutex_lista_tids));

	log_info(logger_memoria,"## Hilo <Creado/Destruido> - (PID:TID) - (%d:%d)",pid,tid);
}

int encontrar_posicion_hilo_en_lista(t_list* lista_tids_proceso, int tid){

	for(int i = 0; i < list_size(lista_tids_proceso); i++){
		t_hilo* hilo_aux = list_get(lista_tids_proceso,i);

		if (hilo_aux -> tid == tid){
			return i;
		}
	}
	return (-1);
}

//FINALIZACION DEL PROCESO

int recibir_pid_a_finalizar(int socket_cliente){
	t_list *paquete = recibir_paquete(socket_cliente);

	int* PID = (int*)list_get(paquete,0);
	int pid = *PID;
	
	list_destroy_and_destroy_elements(paquete,free);
	return pid;
}

void finalizar_proceso(int pid){
	t_proceso* proceso_a_finalizar = buscar_proceso(pid);

	log_info(logger_memoria, "## Proceso Destruido -  PID: %d - Tamaño: %d",pid, proceso_a_finalizar->limite - proceso_a_finalizar->base);

	pthread_mutex_lock(&mutex_lista_particiones);
	t_particion* particion_a_liberar = buscar_particion_por_base(proceso_a_finalizar->base); 
	liberar_particion(particion_a_liberar); 
	pthread_mutex_unlock(&mutex_lista_particiones);

	pthread_mutex_lock(&mutex_lista_procesos);
	liberar_proceso(proceso_a_finalizar);
	list_remove_element(lista_particiones, proceso_a_finalizar);
	pthread_mutex_unlock(&mutex_lista_procesos); 

	
}

void liberar_proceso(t_proceso* proceso_a_finalizar){

	pthread_mutex_destroy(&(proceso_a_finalizar->mutex_lista_tids));

	if(proceso_a_finalizar-> lista_tids != NULL){
		list_destroy_and_destroy_elements(proceso_a_finalizar->lista_tids, free);
	}

	free(proceso_a_finalizar);
}

//MANEJO DE MEMORIA DE USUARIO

t_operation_code buscar_espacio_memoria(uint32_t tamanio){

	/* DEJO LA LOGICA SIN LA FUNCION DE LA COMMONS POR LAS DUDAS (DESPUES LO BORRO)
	for (int i = 0; i < list_size(lista_particiones); i++){
		t_particion* particion = list_get(lista_particiones, i);

		if (particion->pid == (-1) && particion->tamanio >= tamanio){
			return OK;
		}
	}
	*/

	bool buscar_vacio(void* particion){
	t_particion* particion_aux = (t_particion*) particion;

	if (particion_aux -> pid == (-1) && particion_aux->tamanio >= tamanio){
		return true;
	}else{
		return false;
		}
	}
	
	if(list_any_satisfy(lista_particiones, (void*) buscar_vacio)){
		return OK;
	}else{
		return ERROR;
	}
}

t_particion* crear_particion(int pid, uint32_t base, uint32_t tamanio){
	
	t_particion* nueva_particion = malloc(sizeof(t_particion));
	nueva_particion->pid = pid;
	nueva_particion->base = base;
	nueva_particion->tamanio = tamanio;

	return nueva_particion;

}

t_particion* asignar_particion(int pid,uint32_t tamanio){
	t_particion* particion;
	
	if(strcmp(memoria_config->algoritmo_busqueda,"FIRST") == 0){
		particion = encontrar_particion_first(tamanio);
	}else if(strcmp(memoria_config->algoritmo_busqueda,"BEST") == 0){
		particion = encontrar_particion_best(tamanio);
	}else if(strcmp(memoria_config->algoritmo_busqueda, "WORST") == 0){
		particion = encontrar_particion_worst(tamanio);
	}else{
		log_debug(logger_memoria,"NO se esta reconociendo correctamente el algoritmo de busqueda");
	}

	if (strcmp(memoria_config->esquema,"DINAMICAS") == 0){
		t_particion* nueva_particion = crear_particion(pid, particion->base, tamanio);
		list_add(lista_particiones,nueva_particion);
		achicar_particion(nueva_particion,particion);
	}else{
		particion->pid = pid;
	}
	

	return particion;

}

void achicar_particion(t_particion* nueva_particion, t_particion* particion_a_modificar){
	particion_a_modificar->base = nueva_particion->base + nueva_particion ->tamanio;
	particion_a_modificar->tamanio = particion_a_modificar->tamanio - nueva_particion->tamanio;
	particion_a_modificar->pid = (-1); //Esto es al pedo pero para chequear 100% que quede como vacio

	int posicion = encontrar_posicion_particion_en_lista(particion_a_modificar);

	if(particion_a_modificar->tamanio == 0){
		list_remove(lista_particiones,posicion);
	}

}

int encontrar_posicion_particion_en_lista(t_particion *particion){
	for(int i = 0; i < list_size(lista_particiones); i++){
		t_particion* particion_aux = list_get(lista_particiones,i);

		if (particion_aux -> base == particion -> base){
			return i;
		}
	}
	return -1;
}

void liberar_particion(t_particion* particion_a_liberar){
	
	if(strcmp(memoria_config->esquema, "DINAMICAS") == 0){
		t_particion* particion_libre_derecha = buscar_particion_libre(particion_a_liberar, true); //Leer el comentario de la funcion para entender porq el bool
		
		if(particion_libre_derecha){
			juntar_particiones(particion_a_liberar, particion_libre_derecha);
		}

		t_particion* particion_libre_izquierda = buscar_particion_libre(particion_a_liberar, false); //Leer el comentario de la funcion para entender porq el bool

		if(particion_libre_izquierda){
			juntar_particiones(particion_libre_izquierda, particion_a_liberar);
		}
	}else{
		particion_a_liberar -> pid = -1;
	}
}

//Poner true si queres buscar a la derecha y false si queres buscar a la izquierda
t_particion* buscar_particion_libre(t_particion* particion, bool buscar_derecha) {

    int posicion_particion = encontrar_posicion_particion_en_lista(particion);
    
    // El (?) es como un if. Si buscar_derecha es TRUE hace posicion_particion + 1, si es FALSE hace posicion_particion - 1
    t_particion* particion_adjacente = list_get(lista_particiones, buscar_derecha ? posicion_particion + 1 : posicion_particion - 1);
    
    if (particion_adjacente && particion_adjacente->pid == -1) {
        return particion_adjacente;
    } else {
        return NULL;
    }
}

void juntar_particiones(t_particion* particion_izquierda, t_particion* particion_derecha){

	particion_izquierda->tamanio += particion_derecha->tamanio;
	particion_izquierda->pid = -1; //NO va a hacer falta siempre ponerlo en -1 porq a veces ya va a venir libre pero lo dejo asi para las veces q no viene libre

	int posicion_particion_derecha = encontrar_posicion_particion_en_lista(particion_derecha);
	list_remove_and_destroy_element(lista_particiones, posicion_particion_derecha, free);
	

}

//ALGORITMOS DE BUSQUEDA

t_particion* encontrar_particion_first(uint32_t tamanio){

	bool buscar_por_pid(void* particion){
	t_particion* particion_aux = (t_particion*) particion;

	if (particion_aux -> pid == (-1) && particion_aux->tamanio >= tamanio){
		return 1;
	}else{
		return 0;
		}
	}

	t_particion* particion = list_find(lista_particiones,(void*) buscar_por_pid);
	
	return particion;
}

t_particion* encontrar_particion_best(uint32_t tamanio) {

	bool cumple_condicion(void* particion) {

	t_particion* particion_aux = (t_particion*) particion;
	return (particion_aux->pid == -1 && particion_aux->tamanio >= tamanio);
    
	}

    bool es_menor(void* particion1, void* particion2) {

        t_particion* p1 = (t_particion*) particion1;
        t_particion* p2 = (t_particion*) particion2;

        return (p1->tamanio < p2->tamanio);
    
	}

    // Filtra las particiones vacias con tamanio suficiente
    t_list* particiones_validas = list_filter(lista_particiones, cumple_condicion);
    // Obtener la partición con el menor tamaño
    t_particion* particion_best = list_get_minimum(particiones_validas,(void* ) es_menor);

    list_destroy_and_destroy_elements(particiones_validas,free);
    return particion_best;
}

t_particion* encontrar_particion_worst(uint32_t tamanio){

    bool cumple_condicion(void* particion) {

        t_particion* particion_aux = (t_particion*) particion;
        return (particion_aux->pid == -1 && particion_aux->tamanio >= tamanio);

    }

    bool es_mayor(void* particion1, void* particion2) {

        t_particion* p1 = (t_particion*) particion1;
        t_particion* p2 = (t_particion*) particion2;

        return (p1->tamanio > p2->tamanio);

    }


    t_list* particiones_validas = list_filter(lista_particiones, cumple_condicion);
    t_particion* particion_worst = list_get_maximum(particiones_validas,(void *) es_mayor);

    list_destroy_and_destroy_elements(particiones_validas,free);
    return particion_worst;

}

//MEMORY DUMP

t_operation_code memory_dump(int pid , int tid){
	t_operation_code confirmacion_de_operacion;

	fileSystem_connection = create_connection(logger_memoria, "FILESYSTEM", memoria_config->ip_fs, memoria_config->puerto_fs, TYPE_SOCKET_CLIENT);
	if(!send_handshake(fileSystem_connection,MEMORY,FILESYSTEM,logger_memoria)){
		abort();
	}
	
	log_info(logger_memoria,"## Memory Dump solicitado - (PID:TID) - (%d:%d)",pid, tid);

	t_proceso* proceso = buscar_proceso(pid);
	uint32_t tamanio_asignado = (uint32_t)(proceso->limite - proceso->base); // No hace falta el casteo pero por las dudas

	char* buffer = malloc(tamanio_asignado);

	pthread_mutex_lock(&mutex_memoria_usuario);
	memcpy(buffer, memoria_usuario + proceso->base, tamanio_asignado);
	pthread_mutex_unlock(&mutex_memoria_usuario);

	t_paquete* paquete = crear_paquete(MEMORY_DUMP);
	agregar_a_paquete(paquete, &pid, sizeof(int));
	agregar_a_paquete(paquete, &tid, sizeof(int));
	agregar_a_paquete(paquete, &tamanio_asignado , sizeof(uint32_t));
	agregar_a_paquete(paquete, buffer, tamanio_asignado);
	
	enviar_paquete(paquete, fileSystem_connection);
	
	eliminar_paquete(paquete);
	free(buffer);

	recv(fileSystem_connection, &confirmacion_de_operacion, sizeof(confirmacion_de_operacion), MSG_WAITALL); //VA A RECIBIR OK o ERROR

	destroy_socket(fileSystem_connection);

	return confirmacion_de_operacion;
}

