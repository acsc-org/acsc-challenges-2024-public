#include <yara/modules.h>
#include <stdio.h>

#define MODULE_NAME acsc

define_function(check)
{
  YR_MEMORY_BLOCK* block;
  const uint8_t* block_data;

  RE* regex = regexp_argument(1);

  block = first_memory_block(yr_scan_context());
  block_data = block->fetch_data(block);

  if (block_data == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  int match_result = yr_re_match(yr_scan_context(), regex, (const char* )&block_data[yr_get_integer(yr_module(), "key_offset")]);
  if ( match_result != -1) {
    return_integer(1);
  } else {
    return_integer(0);
  }
}

int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  yr_set_integer(0x2010, module_object, "key_offset");
  return ERROR_SUCCESS;
}

int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

begin_declarations;

  declare_function("check", "r", "i", check);
  declare_integer("key_offset");

end_declarations;


#undef MODULE_NAME