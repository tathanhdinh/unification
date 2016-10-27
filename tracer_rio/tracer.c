//#include <dr_api.h>
//
//#include <stdio.h>
//
//static void event_exit(void);
//
//DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
//{
//  printf("tracer with DynamoRIO\n");
//  dr_set_client_name("tracer", "https://github.com/tathanhdinh/unification");
//  dr_register_exit_event(event_exit);
//}
//
//static void event_exit()
//{
//  printf("tracer with DynamoRIO\n");
//  dr_printf("tracer with DynamoRIO\n");
//  return;
//}