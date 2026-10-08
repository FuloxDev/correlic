//go:build darwin && esf

// This file is compiled by cgo as part of the esf package. The build
// constraint above keeps it out of non-ESF builds, where the package has no
// cgo files and `go build` would otherwise reject a stray C source file.

#include "esf.h"
#include <mach/mach.h>
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Internal helper: extract event fields from es_message_t into our flat struct
// ---------------------------------------------------------------------------

static void fill_process(correlic_es_event_t *out, const es_process_t *proc) {
    if (!proc) return;

    out->pid  = audit_token_to_pid(proc->audit_token);
    out->ppid = proc->ppid;
    out->uid  = audit_token_to_euid(proc->audit_token);

    if (proc->executable && proc->executable->path.data) {
        size_t n = proc->executable->path.length;
        if (n >= sizeof(out->exe_path)) n = sizeof(out->exe_path) - 1;
        memcpy(out->exe_path, proc->executable->path.data, n);
        out->exe_path[n] = '\0';

        // comm = basename of exe_path
        const char *slash = strrchr(out->exe_path, '/');
        const char *base  = slash ? slash + 1 : out->exe_path;
        size_t bn = strlen(base);
        if (bn >= sizeof(out->comm)) bn = sizeof(out->comm) - 1;
        memcpy(out->comm, base, bn);
        out->comm[bn] = '\0';
    }
}

static void fill_args(correlic_es_event_t *out, const es_event_exec_t *exec) {
    uint32_t argc = es_exec_arg_count(exec);
    if (argc > 64) argc = 64; // safety cap

    size_t offset = 0;
    out->args_count = 0;

    for (uint32_t i = 0; i < argc; i++) {
        es_string_token_t arg = es_exec_arg(exec, i);
        if (!arg.data || arg.length == 0) continue;

        size_t avail = sizeof(out->args) - offset - 1;
        if (avail == 0) break;

        size_t n = arg.length < avail ? arg.length : avail;
        memcpy(out->args + offset, arg.data, n);
        out->args[offset + n] = '\0';
        offset += n + 1; // null-separate
        out->args_count++;
    }
}

// ---------------------------------------------------------------------------
// ESF message callback — called by the kernel on every subscribed event
// ---------------------------------------------------------------------------

static void esf_message_handler(es_client_t *client, const es_message_t *msg, void *ctx) {
    correlic_es_client_t *wrapper = (correlic_es_client_t *)ctx;

    correlic_es_event_t ev;
    memset(&ev, 0, sizeof(ev));

    ev.event_type = (uint32_t)msg->event_type;
    fill_process(&ev, msg->process);

    switch (msg->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            fill_process(&ev, msg->event.exec.target);
            fill_args(&ev, &msg->event.exec);
            break;

        case ES_EVENT_TYPE_NOTIFY_OPEN: {
            const es_file_t *f = msg->event.open.file;
            if (f && f->path.data) {
                size_t n = f->path.length;
                if (n >= sizeof(ev.file_path)) n = sizeof(ev.file_path) - 1;
                memcpy(ev.file_path, f->path.data, n);
                ev.file_path[n] = '\0';
            }
            ev.open_flags = msg->event.open.fflag;
            break;
        }

#if CORRELIC_ES_HAS_LOOKUP
        case ES_EVENT_TYPE_NOTIFY_LOOKUP: {
            const es_string_token_t *name = &msg->event.lookup.relative_target;
            if (name->data) {
                size_t n = name->length;
                if (n >= sizeof(ev.domain)) n = sizeof(ev.domain) - 1;
                memcpy(ev.domain, name->data, n);
                ev.domain[n] = '\0';
            }
            break;
        }
#endif

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            ev.exit_code = msg->event.exit.stat;
            break;

        default:
            break;
    }

    // Forward to Go via CGO export
    correlic_send_event(wrapper->go_handle, &ev);

    // Auto-respond to AUTH events (we only subscribe to NOTIFY, but be safe)
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

correlic_es_client_t *correlic_es_new_client(uintptr_t go_handle, char **out_err) {
    correlic_es_client_t *wrapper = calloc(1, sizeof(correlic_es_client_t));
    if (!wrapper) {
        if (out_err) *out_err = strdup("out of memory");
        return NULL;
    }
    wrapper->go_handle = go_handle;

    es_new_client_result_t result = es_new_client(&wrapper->es_client, ^(es_client_t *c, const es_message_t *msg) {
        esf_message_handler(c, msg, wrapper);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        free(wrapper);
        if (out_err) {
            switch (result) {
                case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                    *out_err = strdup("missing entitlement: com.apple.developer.endpoint-security.client");
                    break;
                case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                    *out_err = strdup("not running as root");
                    break;
                case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                    *out_err = strdup("not permitted (grant the agent Full Disk Access in System Settings)");
                    break;
                case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                    *out_err = strdup("too many Endpoint Security clients on this host");
                    break;
                default:
                    *out_err = strdup("es_new_client failed");
            }
        }
        return NULL;
    }

    return wrapper;
}

int correlic_es_subscribe(correlic_es_client_t *client,
                          es_event_type_t *events,
                          uint32_t count) {
    es_return_t r = es_subscribe(client->es_client, events, count);
    return (r == ES_RETURN_SUCCESS) ? 0 : 1;
}

void correlic_es_mute_self(correlic_es_client_t *client) {
    // Mute the agent's own process so its file and exec activity does not
    // feed back into the collectors.
    audit_token_t token;
    mach_msg_type_number_t info_count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &info_count) != KERN_SUCCESS) {
        return;
    }
    es_mute_process(client->es_client, &token);
}

void correlic_es_destroy(correlic_es_client_t *client) {
    if (!client) return;
    if (client->es_client) {
        es_unsubscribe_all(client->es_client);
        es_delete_client(client->es_client);
    }
    free(client);
}
