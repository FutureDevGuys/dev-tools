#include <stddef.h>
#include <stdio.h>
#include <sudo_plugin.h>

/* Header-owned C ABI layout only: no plugin load, passwords or host mutation. */
int main(void) {
    int result = printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
        sizeof(struct audit_plugin),
        offsetof(struct audit_plugin, open),
        offsetof(struct audit_plugin, accept),
        offsetof(struct audit_plugin, event_alloc),
        sizeof(struct approval_plugin),
        offsetof(struct approval_plugin, check),
        sizeof(struct sudoers_group_plugin),
        offsetof(struct sudoers_group_plugin, query),
        sizeof(sudo_conv_t),
        sizeof(struct sudo_conv_message),
        offsetof(struct sudo_conv_message, msg),
        sizeof(struct sudo_conv_reply));
    return result < 0 ? 1 : 0;
}
