#include "client.h"

int main(void)
{
	/*---------------------------------------------------PARTE 2-------------------------------------------------------------*/

	int conexion;
	char* ip;
	char* puerto;
	char* valor;

	t_log* logger;
	t_config* config;

	/* ---------------- LOGGING ---------------- */

	logger = iniciar_logger();
	log_info(logger,"Hola! Soy un log");

	/* ---------------- ARCHIVOS DE CONFIGURACION ---------------- */

	config = iniciar_config();
	ip = config_get_string_value(config,"IP");
	puerto = config_get_string_value(config ,"PUERTO");
	valor = config_get_string_value(config ,"CLAVE");

	log_info(logger, "El ip es: %s, el puerto es: %s y la CLAVE es: %s" , ip,puerto,valor);
	// Usando el config creado previamente, leemos los valores del config y los 
	// dejamos en las variables 'ip', 'puerto' y 'valor'

	// Loggeamos el valor de config


	/* ---------------- LEER DE CONSOLA ---------------- */

	leer_consola(logger);

	/*---------------------------------------------------PARTE 3-------------------------------------------------------------*/

	// ADVERTENCIA: Antes de continuar, tenemos que asegurarnos que el servidor esté corriendo para poder conectarnos a él

	// Creamos una conexión hacia el servidor
	conexion = crear_conexion(ip, puerto);

	// Enviamos al servidor el valor de CLAVE como mensaje
	enviar_mensaje(valor,conexion);

	// Armamos y enviamos el paquete
	paquete(conexion);
	

	terminar_programa(conexion, logger, config);

	/*---------------------------------------------------PARTE 5-------------------------------------------------------------*/
	// Proximamente
}

t_log* iniciar_logger(void)
{
	t_log* logger;

	if ((logger = log_create("tp0.log","TP0",1, LOG_LEVEL_INFO)) == NULL)
	{
		printf("NO pude LOGEAR");
		exit(1);
	}
	
	return logger;
}

t_config* iniciar_config(void)
{
	t_config* config;
	if ((config = config_create("./cliente.config")) == NULL)
	{
		printf("NO se pudo CREAR el config");
		exit(2);
	}
	
	return config;
}

void leer_consola(t_log* logger)
{
	char* leido;

	while (1)
	{
		leido = readline(">");
		if(leido){
			log_info(logger,leido);
		}
		if (!strcmp(leido,"\0"))
		{
			free(leido);
			break;
		}
		
		printf("%s\n", leido);
		free(leido);
	}
}

void paquete(int conexion)
{
	// Ahora toca lo divertido!
	char* leido;
	t_paquete* paquete;

	paquete = crear_paquete();
	while (1)
	{
		leido = readline(">");

		if(leido){
			agregar_a_paquete(paquete, leido , sizeof(leido) +1);
		}
		if (!strcmp(leido,"\0"))
		{
			free(leido);
			break;
		}
		
		printf("%s\n", leido);
		free(leido);
	}
	enviar_paquete(paquete,conexion);
	eliminar_paquete(paquete);
	
	// Leemos y esta vez agregamos las lineas al paquete


	// ¡No te olvides de liberar las líneas y el paquete antes de regresar!
	
}

void terminar_programa(int conexion, t_log* logger, t_config* config)
{
	if(logger != NULL){
		log_destroy(logger);
	}

	if(config != NULL){
		config_destroy(config);
	}

	liberar_conexion(conexion);
}
