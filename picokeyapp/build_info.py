# -*- coding: utf-8 -*-
"""Build identity written into the first line of every log.

The workflow can overwrite COMMIT with the short SHA of the source revision
before packaging. When it does not (local builds, ad-hoc uploads), the log says
"dev" instead of inventing a hash. Keeping this in its own tiny module means
the log header never has to guess from a zip filename or an environment
variable that does not exist on Android.
"""

COMMIT = "dev"
