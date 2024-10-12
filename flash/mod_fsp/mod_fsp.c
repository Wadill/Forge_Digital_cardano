/**
 * Flash Socket Policy Apache Module.
 *
 * This module provides a flash socket policy file on the same port that
 * serves HTTP on Apache, simplifying cross-domain communication for flash.
 *
 * Note: Memory management in Apache involves allocating data from pools,
 * which are cleaned up automatically. This prevents manual memory management.
 *
 * @author Dave Longley
 * @copyright 2010 Digital Bazaar, Inc.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "ap_compat.h"

#include <string.h>

// Length of a policy file request.
#define POLICY_REQUEST_LENGTH 23

// Declare the module.
module AP_MODULE_DECLARE_DATA fsp_module;

// Module configuration structure.
typedef struct fsp_config {
   char* policy;                 // The cross-domain policy to serve.
   apr_size_t policy_length;     // Length of the policy.
} fsp_config;

// Filter state structure to track detected policy file requests.
typedef struct filter_state {
   fsp_config* cfg;              // Module configuration.
   int checked;                  // Whether the request has been checked.
   int found;                    // Whether the policy file request was found.
} filter_state;

// Function declarations for registering hooks, filters, etc.
static void fsp_register_hooks(apr_pool_t *p);
static int fsp_pre_connection(conn_rec *c, void *csd);

// Input/output filter declarations.
static apr_status_t fsp_input_filter(
   ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, 
   apr_read_type_e block, apr_off_t nbytes);
static int fsp_output_filter(ap_filter_t* f, apr_bucket_brigade* bb);

// Function for finding policy file requests.
static apr_status_t find_policy_file_request(ap_filter_t* f, filter_state* state);

/**
 * Registers the hooks for this module.
 *
 * @param p Pool for memory allocation.
 */
static void fsp_register_hooks(apr_pool_t* p) {
   // Register pre-connection hook to add filters.
   ap_hook_pre_connection(fsp_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);

   // Register input/output filters for processing requests/responses.
   ap_register_input_filter("fsp_request", fsp_input_filter, NULL, AP_FTYPE_CONNECTION);
   ap_register_output_filter("fsp_response", fsp_output_filter, NULL, AP_FTYPE_CONNECTION);
}

/**
 * Pre-connection hook to install filters based on the module configuration.
 *
 * @param c Connection record.
 * @param csd Connection socket descriptor.
 *
 * @return OK on success.
 */
static int fsp_pre_connection(conn_rec* c, void* csd) {
   fsp_config* cfg = ap_get_module_config(c->base_server->module_config, &fsp_module);
   if (cfg && cfg->policy) {
      filter_state* state = apr_palloc(c->pool, sizeof(filter_state));
      if (state) {
         state->cfg = cfg;
         state->checked = state->found = 0;

         ap_add_input_filter("fsp_request", state, NULL, c);
         ap_add_output_filter("fsp_response", state, NULL, c);
      }
   }
   return OK;
}

/**
 * Looks for a flash socket policy request in the incoming data.
 *
 * @param f Input filter.
 * @param state Filter state.
 *
 * @return APR_SUCCESS on success or another status code on failure.
 */
static apr_status_t find_policy_file_request(ap_filter_t* f, filter_state* state) {
   apr_status_t status = APR_SUCCESS;
   apr_bucket_brigade* tmp = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
   status = ap_get_brigade(f->next, tmp, AP_MODE_SPECULATIVE, APR_BLOCK_READ, POLICY_REQUEST_LENGTH);

   if (status == APR_SUCCESS) {
      const char* data;
      apr_size_t length;
      apr_bucket* b = APR_BRIGADE_FIRST(tmp);
      status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);

      if (status == APR_SUCCESS && length > 0 && data[0] == '<') {
         char pfr[POLICY_REQUEST_LENGTH] = {0};
         memcpy(pfr, data, length);

         while (status == APR_SUCCESS && length < POLICY_REQUEST_LENGTH && (b = APR_BUCKET_NEXT(b)) != APR_BRIGADE_SENTINEL(tmp)) {
            status = apr_bucket_read(b, &data, &length, APR_BLOCK_READ);
            memcpy(pfr + length, data, length);
         }

         if (strncmp(pfr, "<policy-file-request/>", POLICY_REQUEST_LENGTH - 1) == 0 && pfr[POLICY_REQUEST_LENGTH - 1] == '\0') {
            state->found = 1;
         }
      }
   }
   return status;
}

/**
 * Input filter to process data and look for a flash socket policy request.
 *
 * @param f Input filter.
 * @param bb Bucket brigade.
 * @param mode Read mode.
 * @param block Blocking type.
 * @param nbytes Number of bytes to read.
 *
 * @return APR_SUCCESS, APR_EOF, or another status code.
 */
static apr_status_t fsp_input_filter(
   ap_filter_t* f, apr_bucket_brigade* bb, ap_input_mode_t mode, 
   apr_read_type_e block, apr_off_t nbytes) {

   filter_state* state = f->ctx;
   apr_status_t status = APR_SUCCESS;

   if (state->checked) {
      status = ap_get_brigade(f->next, bb, mode, block, nbytes);
   } else {
      status = find_policy_file_request(f, state);
      state->checked = 1;

      if (state->found) {
         status = APR_EOF;
      } else {
         status = ap_get_brigade(f->next, bb, mode, block, nbytes);
      }
   }
   return status;
}

/**
 * Output filter to send a cross-domain policy response if requested.
 *
 * @param f Output filter.
 * @param bb Bucket brigade.
 *
 * @return APR_SUCCESS on success.
 */
static int fsp_output_filter(ap_filter_t* f, apr_bucket_brigade* bb) {
   filter_state* state = f->ctx;

   if (state->found) {
      apr_bucket* bucket = apr_bucket_immortal_create(state->cfg->policy, state->cfg->policy_length, bb->bucket_alloc);
      APR_BRIGADE_INSERT_HEAD(bb, bucket);
   }
   return ap_pass_brigade(f->next, bb);
}

/**
 * Create the module's configuration structure.
 *
 * @param p Memory pool.
 * @param s Server record.
 *
 * @return Configuration structure.
 */
static void* fsp_create_config(apr_pool_t* p, server_rec* s) {
   fsp_config* cfg = apr_palloc(p, sizeof(fsp_config));
   cfg->policy = NULL;
   cfg->policy_length = 0;
   return cfg;
}

/**
 * Set the cross-domain policy file from the configuration.
 *
 * @param parms Command parameters.
 * @param userdata Unused.
 * @param arg Policy file path.
 *
 * @return NULL on success, error message otherwise.
 */
static const char* fsp_set_policy_file(cmd_parms* parms, void* userdata, const char* arg) {
   fsp_config* cfg = ap_get_module_config(parms->server->module_config, &fsp_module);
   apr_pool_t* pool = parms->pool;
   char* fname = ap_server_root_relative(pool, arg);

   if (!fname) {
      return apr_psprintf(pool, "%s: Invalid policy file '%s'", parms->cmd->name, arg);
   }

   apr_file_t* fd;
   apr_finfo_t finfo;
   apr_status_t rv = apr_file_open(&fd, fname, APR_READ, APR_OS_DEFAULT, pool);

   if (rv != APR_SUCCESS) {
      char errmsg[120];
      return apr_psprintf(pool, "%s: Unable to open policy file '%s' (%s)", parms->cmd->name, fname, apr_strerror(rv, errmsg, sizeof(errmsg)));
   }

   rv = apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
   if (rv == APR_SUCCESS && finfo.size > 0) {
      cfg->policy_length = finfo.size;
      cfg->policy = apr_palloc(pool, finfo.size + 1);
      apr_file_read_full(fd, cfg->policy, finfo.size, NULL);
      cfg->policy[finfo.size] = '\0';
   } else {
      apr_file_close(fd);
      return apr_psprintf(pool, "%s: Empty or invalid policy file '%s'", parms->cmd->name, fname);
   }

   apr_file_close(fd);
   return NULL;
}

// Command table for setting the policy file.
static const command_rec fsp_cmds[] = {
   AP_INIT_TAKE1("FSPPolicyFile", fsp_set_policy_file, NULL, RSRC_CONF, "The cross-domain policy file to use."),
   {NULL}
};

// Module definition.
module AP_MODULE_DECLARE_DATA fsp_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    fsp_create_config,
    NULL,
    fsp_cmds,
    fsp_register_hooks
};
