#ifndef CORRELIC_ESF_H
#define CORRELIC_ESF_H

#include <Availability.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdint.h>
#include <stdlib.h>

// ES_EVENT_TYPE_NOTIFY_LOOKUP is an enumerator, not a macro, so it cannot be
// probed with #if defined(). It was added in the macOS 12.0 SDK, so key off
// the SDK's availability macros instead.
#if defined(__MAC_12_0) && defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && (__MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_12_0)
#define CORRELIC_ES_HAS_LOOKUP 1
#else
#define CORRELIC_ES_HAS_LOOKUP 0
#endif

// correlic_es_event_t is a flattened, cgo-friendly representation of an ESF event.
// We extract all fields from es_message_t in C to avoid passing complex structs to Go.
typedef struct {
    uint32_t event_type;  // es_event_type_t cast to uint32

    // Process fields (always populated)
    pid_t    pid;
    pid_t    ppid;
    uid_t    uid;
    char     comm[64];
    char     exe_path[1024];

    // Process exec fields (NOTIFY_EXEC)
    char     args[4096];  // null-separated arg list; args_count entries
    uint32_t args_count;

    // File open fields (NOTIFY_OPEN)
    char     file_path[1024];
    int32_t  open_flags;

    // Network fields (NOTIFY_REMOTE_OPEN / future)
    char     dst_addr[64];
    uint16_t dst_port;
    uint8_t  ip_version;  // 4 or 6

    // DNS fields (NOTIFY_LOOKUP)
    char     domain[256];

    // Exit fields (NOTIFY_EXIT)
    int32_t  exit_code;
} correlic_es_event_t;

// correlic_es_client_t wraps es_client_t with a Go callback channel pointer.
typedef struct {
    es_client_t *es_client;
    void        *go_chan;  // unsafe.Pointer to Go channel — passed back in callback
} correlic_es_client_t;

// correlic_es_new_client creates an ESF client and subscribes the given Go channel pointer
// as the event sink. Events are written via correlic_send_event (implemented in esf.go CGO exports).
// Returns NULL and sets out_err on failure (caller must free out_err).
correlic_es_client_t *correlic_es_new_client(void *go_chan, char **out_err);

// correlic_es_subscribe subscribes the client to the given event types.
// Returns 0 on success, non-zero on failure.
int correlic_es_subscribe(correlic_es_client_t *client,
                          es_event_type_t *events,
                          uint32_t count);

// correlic_es_mute_self mutes the calling process to prevent feedback loops.
void correlic_es_mute_self(correlic_es_client_t *client);

// correlic_es_destroy tears down the ESF client and frees memory.
void correlic_es_destroy(correlic_es_client_t *client);

// correlic_send_event is the bridge called from the C callback into Go.
// Implemented as a CGO export in esf.go.
extern void correlic_send_event(void *go_chan, correlic_es_event_t *ev);

// SDK-safe accessors for event type constants — avoids hardcoding numeric values in Go.
static inline uint32_t correlic_event_exec(void)   { return (uint32_t)ES_EVENT_TYPE_NOTIFY_EXEC; }
static inline uint32_t correlic_event_exit(void)   { return (uint32_t)ES_EVENT_TYPE_NOTIFY_EXIT; }
static inline uint32_t correlic_event_open(void)   { return (uint32_t)ES_EVENT_TYPE_NOTIFY_OPEN; }
// ES_EVENT_TYPE_NOTIFY_LOOKUP is available on macOS 12.0+ (Monterey); older
// SDKs get a sentinel so the Go side can skip the DNS runner.
static inline uint32_t correlic_event_lookup(void) {
#if CORRELIC_ES_HAS_LOOKUP
    return (uint32_t)ES_EVENT_TYPE_NOTIFY_LOOKUP;
#else
    return UINT32_MAX; // sentinel: DNS not available on this SDK
#endif
}

#endif // CORRELIC_ESF_H
