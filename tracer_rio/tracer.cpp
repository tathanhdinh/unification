#include <dr_api.h>

//#include <cstdio>
struct bb_counts
{
  uint64 blocks;
  uint64 total_size;
};

static bb_counts counts_as_built;
void *as_built_lock;

static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
  dr_set_client_name("tracer", "https://github.com/tathanhdinh/unification");
  dr_register_exit_event(event_exit);
  dr_register_bb_event(event_basic_block);
}

static void event_exit()
{
  dr_printf("%s\n", "a DynamoRIO based tracer");
  return;
}

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
  return DR_EMIT_DEFAULT;
}