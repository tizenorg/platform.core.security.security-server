#include <smack-check.h>

#include <stdlib.h>
#include <sys/smack.h>

#include <dpl/log/log.h>

namespace SecurityServer {

int smack_label_is_valid(const char *smack_label)
{
	int i;

	if(!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
		goto err;

	for(i = 0; smack_label[i]; ++i) {
		if(i >= SMACK_LABEL_LEN)
			goto err;
		switch(smack_label[i]) {
		case '~':
		case ' ':
		case '/':
		case '"':
		case '\\':
		case '\'':
			goto err;
		default:
			break;
		}
	}

	return 1;
err:
	return 0;
}

int smack_runtime_check(void)
{
    static int smack_present = -1;
    if (-1 == smack_present) {
        if (NULL == smack_smackfs_path()) {
            LogDebug("no smack found on device");
            smack_present = 0;
        } else {
            LogDebug("found smack on device");
            smack_present = 1;
        }
    }
    return smack_present;
}

int smack_check(void)
{
#ifndef SMACK_ENABLED
    return 0;
#else
    return smack_runtime_check();
#endif
}

} // namespace SecurityServer
