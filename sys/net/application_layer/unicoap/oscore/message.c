/**
 * @file
 * @ingroup net_unicoap_oscore
 * @brief   OSCORE implementation
 * @author  Lukas Sebrantke <lukas.sebrantke@haw-hamburg.de>
 */

#include <string.h>

#include "thread.h"
#include "compiler_hints.h"

#include "private/oscore.h"

#include "oscore_native/message.h"

uint8_t oscore_msg_native_get_code(oscore_msg_native_t msg)
{
    
}

void oscore_msg_native_set_code(oscore_msg_native_t msg, uint8_t code)
{

}

oscore_msgerr_native_t oscore_msg_native_append_option(oscore_msg_native_t msg, uint16_t option_number, const uint8_t *value, size_t value_len)
{

}

oscore_msgerr_native_t oscore_msg_native_update_option(oscore_msg_native_t msg, uint16_t option_number, size_t option_occurrence, const uint8_t *value, size_t value_len)
{
    
}

void oscore_msg_native_optiter_init(oscore_msg_native_t msg, oscore_msg_native_optiter_t *iter)
{
    
}

bool oscore_msg_native_optiter_next(oscore_msg_native_t msg, oscore_msg_native_optiter_t *iter, uint16_t *option_number, const uint8_t **value, size_t *value_len)
{

}

oscore_msgerr_native_t oscore_msg_native_optiter_finish(oscore_msg_native_t msg, oscore_msg_native_optiter_t *iter)
{

}

oscore_msgerr_native_t oscore_msg_native_map_payload(oscore_msg_native_t msg, uint8_t **payload, size_t *payload_len)
{
    
}

oscore_msgerr_native_t oscore_msg_native_trim_payload(oscore_msg_native_t msg, size_t payload_len)
{
    
}

bool oscore_msgerr_native_is_error(oscore_msgerr_native_t)
{
    
}
