#include "sysdeps_shared.hpp"

namespace mlibc {

int Sysdeps<Sigaction>::operator()(
      int signal,
      const struct sigaction *action,
      struct sigaction *old_action) {
  if (signal <= 0 || signal >= _NSIG)
      return EINVAL;

  // STUBBED
  if (old_action) {
      memset(old_action, 0, sizeof(*old_action));
      old_action->sa_handler = SIG_DFL;
  }

  (void)action;
  return 0;
}


} // namespace mlibc
