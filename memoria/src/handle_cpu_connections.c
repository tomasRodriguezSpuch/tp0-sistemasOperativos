#include "../include/handle_cpu_connections.h"

void procesar_cpu(void *void_socket){ // Ya se que los nombres son mierda, pero sino tenia poner "args" y me parecia mucho menos expresivo 
	int *socket = (int*) void_socket;
	int socket_cliente = *socket;
	t_operation_code handshake = MEMORY;
	t_operation_code confirmacion_de_operacion = OK;
	t_operation_code operacion;
	t_paquete *paquete;
	while (socket_cliente != -1){
	if (recv(socket_cliente, &operacion, sizeof(operacion), MSG_WAITALL) != sizeof(operacion)) { 
			log_warning(logger_memoria, "ERROR en el envio del COD-OP por parte del CLIENTE"); 
			free(socket);
			return;
		}
		switch (operacion){
		
		case CPU:
			modulo_conectado = translate_header(CPU);
			log_info(logger_memoria, "Se conecto: %s", modulo_conectado);
			send(socket_cliente,&handshake,sizeof(t_operation_code),0);
			break;
		case OBTENER_CONTEXTO:
			paquete = recibir_obtener_contexto(socket_cliente);
			enviar_paquete(paquete,socket_cliente);
			eliminar_paquete(paquete);
			break;
		case ACTUALIZAR_CONTEXTO:
			recibir_actualizar_contexto(socket_cliente);
			send(socket_cliente,&confirmacion_de_operacion,sizeof(t_operation_code),0);
		case OBTENER_INSTRUCCION:
			paquete = recibir_obtener_instruccion(socket_cliente);
			enviar_paquete(paquete,socket_cliente);
			eliminar_paquete(paquete);
		case READ_MEM:
			usleep(memoria_config->retardo * 1000);
			paquete = recibir_READ_MEM(socket_cliente);
			enviar_paquete(paquete,socket_cliente);
			eliminar_paquete(paquete);
			break;
		case WRITE_MEM:
			usleep(memoria_config->retardo * 1000);
			recibir_WRITE_MEM(socket_cliente);
			send(socket_cliente,&confirmacion_de_operacion,sizeof(t_operation_code),0);
			break;
		default:
			break;
		}
		
	}
	
}

t_paquete *recibir_obtener_contexto(int socket_cliente){
	t_list *paquete_recibido = recibir_paquete(socket_cliente);

	int *pid = (int*)list_get(paquete_recibido,0);
	int *tid = (int*)list_get(paquete_recibido,1);

	t_proceso *proceso_padre = buscar_proceso(*pid);
	t_hilo *hilo = buscar_hilo(*pid,*tid);
	t_paquete *paquete = crear_paquete(OBTENER_CONTEXTO);
	empaquetar_registros(paquete,hilo);
	empaquetar_base_y_limite(paquete, proceso_padre);

	list_destroy_and_destroy_elements(paquete_recibido,free);
	return paquete;
}

void recibir_actualizar_contexto(int socket_cliente){
	t_list *paquete_recibido = recibir_paquete(socket_cliente);
	//DESEMPAQUETAR REGISTROS
	int *pid = (int*)list_get(paquete_recibido,0);
	int *tid = (int*)list_get(paquete_recibido,1);
	uint32_t *p_PC = (uint32_t*)list_get(paquete_recibido,2);
	uint32_t *p_AX = (uint32_t*)list_get(paquete_recibido,3);
	uint32_t *p_BX = (uint32_t*)list_get(paquete_recibido,4);
	uint32_t *p_CX = (uint32_t*)list_get(paquete_recibido,5);
	uint32_t *p_DX = (uint32_t*)list_get(paquete_recibido,6);
	uint32_t *p_EX = (uint32_t*)list_get(paquete_recibido,7);
	uint32_t *p_FX = (uint32_t*)list_get(paquete_recibido,8);
	uint32_t *p_GX = (uint32_t*)list_get(paquete_recibido,9);
	uint32_t *p_HX = (uint32_t*)list_get(paquete_recibido,10);

	//ACTUALIZAR REGISTROS
	t_hilo *hilo = buscar_hilo(*pid,*tid);
	(hilo->registros_cpu)->PC = &p_PC;
	(hilo->registros_cpu)->AX = &p_AX;
	(hilo->registros_cpu)->BX = &p_BX;
	(hilo->registros_cpu)->CX = &p_CX;
	(hilo->registros_cpu)->DX = &p_DX;
	(hilo->registros_cpu)->EX = &p_EX;
	(hilo->registros_cpu)->FX = &p_FX;
	(hilo->registros_cpu)->GX = &p_GX;
	(hilo->registros_cpu)->HX = &p_HX;

	//LIBERAR REGISTROS PASADOS	
	free(p_PC);
	free(p_AX);
	free(p_BX);
	free(p_CX);
	free(p_DX);
	free(p_EX);
	free(p_FX);
	free(p_GX);
	free(p_HX);
	list_destroy_and_destroy_elements(paquete_recibido,free);

}

t_paquete *recibir_obtener_instruccion(int socket_cliente){
	t_list *paquete_recibido = recibir_paquete(socket_cliente);
	int *pid = (int*)list_get(paquete_recibido,0);
	int *tid = (int*)list_get(paquete_recibido,1);
	int *nro_instruccion = (int*)list_get(paquete_recibido,2);
	t_hilo *hilo = buscar_hilo(*pid,*tid);

	char *sgte_instruccion = list_get(hilo->instrucciones,*nro_instruccion);
	t_paquete *paquete = empaquetar_instruccion(sgte_instruccion);

	list_destroy_and_destroy_elements(paquete_recibido,free);

	return paquete;
}

t_paquete *empaquetar_instruccion(char *instruccion){
	t_paquete *paquete = crear_paquete(OBTENER_INSTRUCCION);
	char *aux = string_from_format("%s%s",instruccion,"\0");
	agregar_a_paquete(paquete,&(instruccion),strlen(aux)-1);
	free(aux);
	return paquete;
}

t_paquete *recibir_READ_MEM(int socket_cliente){
	t_list *paquete_recibido = recibir_paquete(socket_cliente);
	uint8_t *direccion_recibida = (uint8_t*) list_get(paquete_recibido, 0);//lo pongo uint8_t porque apunta a 1 byte
	uint8_t *direccion = (uint8_t *) memoria_usuario + (uintptr_t)direccion_recibida;
	uint32_t registro = 0;//sizeof(uint32_t) = 4

	pthread_mutex_lock(&mutex_memoria_usuario);
	memcpy(&registro, direccion, sizeof(uint32_t));
	pthread_mutex_unlock(&mutex_memoria_usuario);

	t_paquete * paquete = crear_paquete(READ_MEM);
	agregar_a_paquete(paquete,&registro,sizeof(uint32_t));

	list_destroy_and_destroy_elements(paquete_recibido,free);
	return paquete;
}

void recibir_WRITE_MEM(int socket_cliente){
	t_list *paquete_recibido = recibir_paquete(socket_cliente);
	uint8_t *direccion_recibida = (uint8_t*) list_get(paquete_recibido, 0);//lo pongo uint8_t porque apunta a 1 byte
	uint8_t *direccion = (uint8_t *) memoria_usuario + (uintptr_t)direccion_recibida;
	uint32_t *registro = (uint32_t*) list_get(paquete_recibido, 1);

	pthread_mutex_lock(&mutex_memoria_usuario);
	memcpy(direccion,registro, sizeof(uint32_t));
	pthread_mutex_unlock(&mutex_memoria_usuario);

	list_destroy_and_destroy_elements(paquete_recibido,free);
}
