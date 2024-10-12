#include <../include/shared.h>

//FUNCIONES COMPARTIDAS ENTRE HANDLE_KERNEL Y HANDLE_CPU CONNECTIONS
t_list* leer_pseudocodigo(char* ruta_completa) {
	FILE *archivo_pseudocodigo = fopen(ruta_completa, "r");

	if (archivo_pseudocodigo == NULL) {
		log_error(logger_memoria, "No se pudo abrir el archivo");
		return NULL;
	}

	
	t_list *lista_de_instrucciones = list_create();
	char instruccion[1024];


	while (fgets(instruccion, sizeof(instruccion), archivo_pseudocodigo)) {
		instruccion[strcspn(instruccion, "\n")] = 0; // Elimina el salto de linea

		//No agrego directamente 'instruccion' a la lista ya todos los punteros terminarian apuntando a la ultima instruccion leida, por eso uso strdup que le asigna un nuevo espacio en mem
		char *copia_instruccion = strdup(instruccion); 
		list_add(lista_de_instrucciones, copia_instruccion);
	}

	fclose(archivo_pseudocodigo);
	return lista_de_instrucciones;
}

t_proceso* buscar_proceso(int pid){

//No se porq estan las cosa en blanco, no tiene sentido

	bool buscar_por_pid(void* proceso){
		t_proceso* proceso_aux = (t_proceso*) proceso;
		if (proceso_aux -> pid == pid)
			return 1;
		return 0;
	}

	pthread_mutex_lock(&mutex_lista_procesos);
	t_proceso* proceso = list_find(lista_procesos,(void*) buscar_por_pid);
	pthread_mutex_unlock(&mutex_lista_procesos);
	
	return proceso;
}

t_hilo *buscar_hilo(int pid, int tid){
	bool buscar_por_tid(void *hilo){
		t_hilo *hilo_aux = (t_hilo*) hilo;
		if(hilo_aux -> tid == tid)
			return 1;
		return 0;
	}
	t_proceso *proceso_padre = buscar_proceso(pid);

	pthread_mutex_lock( &(proceso_padre->mutex_lista_tids) );
	t_hilo *hilo = list_find( proceso_padre->lista_tids,(void*) buscar_por_tid);
	pthread_mutex_unlock( &(proceso_padre->mutex_lista_tids) );

	return hilo;
}

void empaquetar_registros(t_paquete *paquete, t_hilo *hilo){
	agregar_a_paquete(paquete,&(hilo->registros_cpu->PC),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->AX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->BX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->CX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->DX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->EX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->FX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->GX),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(hilo->registros_cpu->HX),sizeof(uint32_t));
}

void empaquetar_base_y_limite(t_paquete *paquete, t_proceso *proceso){
	agregar_a_paquete(paquete,&(proceso->base),sizeof(uint32_t));
	agregar_a_paquete(paquete,&(proceso->limite),sizeof(uint32_t));
}

//FUNCIONES PARA MANEJO DE MEMORIA DEL USUARIO

t_particion* buscar_particion_por_base(uint32_t base){
	
	bool buscar_por_base(void* particion){
	t_particion* particion_aux = (t_particion*) particion;

	if (particion_aux -> base == base)
		return 1;
	return 0;
	}

	t_particion* particion = list_find(lista_particiones,(void*) buscar_por_base);

	
	return particion;
}